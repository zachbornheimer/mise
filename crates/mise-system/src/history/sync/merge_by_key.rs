//! Structured conflicts settle by key, not by line.
//!
//! After byte equality and normalized-text equality, a `.json`, `.toml`,
//! `.yaml`, or `.yml` path whose three sides all parse merges by key. Maps
//! merge recursively. Arrays and scalars are atomic. A key one side changed
//! takes that side; a key both sides changed the same way is kept; a key both
//! sides changed differently, or one deleted while the other edited, stays a
//! conflict. Local bytes stand when the parsed values are equal. A real
//! semantic clash is never hidden by a clean line merge, and conflict markers
//! are never saved.

use std::collections::{BTreeMap, BTreeSet};

use super::files::{self, encode};
use super::reconcile::{self, Object};
use super::run::settle_conflicts;
use super::state::SyncRecord;
use crate::history::manifest::{Enrollment, Manifest};
use crate::history::shadow::{HistoryRepo, Overlay};

const ONE_MIB: usize = 1024 * 1024;

fn open() -> (tempfile::TempDir, HistoryRepo) {
    let dir = tempfile::tempdir().unwrap();
    let repo = HistoryRepo::open_or_init_in(dir.path()).unwrap().unwrap();
    (dir, repo)
}

fn blob(repo: &HistoryRepo, bytes: &[u8]) -> Object {
    ("100644".into(), repo.hash_blob(bytes).unwrap())
}

fn commit(repo: &HistoryRepo, parent: Option<&str>, files: &[(&str, &Object)]) -> String {
    let empty = repo.empty_object("tree").unwrap();
    let tree = repo
        .compose(
            &empty,
            &files
                .iter()
                .map(|(path, object)| Overlay {
                    path: (*path).into(),
                    object: Some((*object).clone()),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    repo.commit_tree(&tree, parent.into_iter().collect(), "saved")
        .unwrap()
}

fn seal(repo: &HistoryRepo, path: &str, bytes: &[u8], key: &age::x25519::Identity) -> Object {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
    let encoded = encode(path, "100644", bytes, "test", &recipients).unwrap();
    ("100644".into(), repo.hash_blob(&encoded).unwrap())
}

fn manifest_tree(
    repo: &HistoryRepo,
    tree: &str,
    path: &str,
    key: &age::x25519::Identity,
) -> String {
    Manifest {
        enrollment: vec![Enrollment {
            path: path.into(),
            autosave: true,
            encrypt: true,
            allow_plaintext: None,
            variants: vec![],
            exclude: None,
            include: None,
        }],
        recipients: vec![key.to_public().to_string()],
        ..Default::default()
    }
    .write(repo, tree)
    .unwrap()
}

struct Sides {
    base: String,
    local: String,
    remote: String,
    merged: String,
    conflicts: Vec<String>,
}

fn branched(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
) -> Sides {
    let base_commit = commit(repo, None, &[(path, base)]);
    let local_commit = commit(repo, Some(&base_commit), &[(path, local)]);
    let remote_commit = commit(repo, Some(&base_commit), &[(path, remote)]);
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    Sides {
        base: base_commit,
        local: local_commit,
        remote: remote_commit,
        merged,
        conflicts,
    }
}

fn diverged(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
) -> Sides {
    assert_ne!(base, local, "local must change the base");
    assert_ne!(base, remote, "remote must change the base");
    let sides = branched(repo, path, base, local, remote);
    assert!(
        sides.conflicts.iter().any(|conflict| conflict == path),
        "both sides changed {path}; Git reported {:?}",
        sides.conflicts
    );
    sides
}

fn settle(repo: &HistoryRepo, sides: &Sides) -> (String, Vec<String>) {
    settle_conflicts(
        repo,
        Some(&sides.base),
        &sides.local,
        &sides.remote,
        &sides.merged,
        sides.conflicts.clone(),
    )
    .unwrap()
}

fn bytes_of(repo: &HistoryRepo, tree: &str, path: &str) -> Vec<u8> {
    let object = repo.object_at(tree, path).unwrap().unwrap();
    repo.cat_object(&object.1).unwrap()
}

fn text_of(repo: &HistoryRepo, tree: &str, path: &str) -> String {
    String::from_utf8(bytes_of(repo, tree, path)).unwrap()
}

fn record(object: &Object) -> SyncRecord {
    SyncRecord {
        acknowledged: Some(object.clone()),
        reconciled: Some(object.clone()),
        applied: Some(object.clone()),
        upstream_commit: None,
    }
}

fn still_listed(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
) -> bool {
    let plans = reconcile::reconcile(
        repo,
        &BTreeMap::from([(path.to_string(), local.clone())]),
        &reconcile::Upstream {
            files: BTreeMap::from([(path.to_string(), remote.clone())]),
            ..Default::default()
        },
        &BTreeMap::from([(path.to_string(), record(base))]),
        &BTreeSet::new(),
    )
    .unwrap();
    plans.into_iter().any(|plan| plan.conflict.is_some())
}

struct Case {
    path: &'static str,
    base: &'static str,
    local: &'static str,
    remote: &'static str,
}

fn settled_text(case: &Case) -> String {
    let (_dir, repo) = open();
    let base = blob(&repo, case.base.as_bytes());
    let local = blob(&repo, case.local.as_bytes());
    let remote = blob(&repo, case.remote.as_bytes());
    let sides = diverged(&repo, case.path, &base, &local, &remote);
    let (tree, remaining) = settle(&repo, &sides);
    assert!(
        remaining.is_empty(),
        "{} must settle by key, not stay a conflict: {remaining:?}",
        case.path
    );
    let saved = text_of(&repo, &tree, case.path);
    assert!(
        !saved.contains("<<<<<<<") && !saved.contains(">>>>>>>"),
        "a settled file must not hold conflict markers:\n{saved}"
    );
    assert!(
        !still_listed(&repo, case.path, &base, &local, &remote),
        "listing must not report a path the key merge settled"
    );
    saved
}

fn stays(case: &Case) {
    let (_dir, repo) = open();
    let base = blob(&repo, case.base.as_bytes());
    let local = blob(&repo, case.local.as_bytes());
    let remote = blob(&repo, case.remote.as_bytes());
    let sides = diverged(&repo, case.path, &base, &local, &remote);
    let (tree, remaining) = settle(&repo, &sides);
    assert!(
        remaining.iter().any(|conflict| conflict == case.path),
        "{} is a real semantic clash and must stay a conflict: {remaining:?}",
        case.path
    );
    let saved = text_of(&repo, &tree, case.path);
    assert!(
        !saved.contains("<<<<<<<") && !saved.contains(">>>>>>>"),
        "an unsettled clash must keep a saved side, not conflict markers:\n{saved}"
    );
    assert!(
        saved == case.local || saved == case.remote,
        "an unsettled clash must not invent a merged file"
    );
    assert!(still_listed(&repo, case.path, &base, &local, &remote));
}

fn json_value(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

fn toml_value(text: &str) -> toml::Value {
    toml::from_str(text).unwrap()
}

fn yaml_value(text: &str) -> mise_util::yaml::Value {
    mise_util::yaml::from_str(text).unwrap()
}

fn independent_adds(
    path: &'static str,
    base: &'static str,
    local: &'static str,
    remote: &'static str,
    expect: &'static str,
    parse: fn(&str),
) {
    let saved = settled_text(&Case {
        path,
        base,
        local,
        remote,
    });
    assert_eq!(saved, expect, "{path} must keep local order and formatting");
    parse(&saved);
}

#[test]
fn json_independent_adds_merge_and_keep_local_formatting() {
    independent_adds(
        "home/.config/app/settings.json",
        "{\n  \"shared\": 1\n}\n",
        "{\n  \"shared\": 1,\n  \"local\": true\n}\n",
        "{\n  \"shared\": 1,\n  \"remote\": \"added\"\n}\n",
        "{\n  \"shared\": 1,\n  \"local\": true,\n  \"remote\": \"added\"\n}\n",
        |text| {
            assert_eq!(
                json_value(text),
                serde_json::json!({"shared": 1, "local": true, "remote": "added"})
            );
        },
    );
}

#[test]
fn toml_independent_adds_merge_and_keep_local_comments() {
    independent_adds(
        "home/.config/app/settings.toml",
        "shared = 1\n",
        "# local note\nshared = 1\nlocal = true\n",
        "shared = 1\nremote = \"added\"\n",
        "# local note\nshared = 1\nlocal = true\nremote = \"added\"\n",
        |text| {
            assert!(text.contains("# local note"));
            assert_eq!(
                toml_value(text)
                    .get("remote")
                    .and_then(|value| value.as_str()),
                Some("added")
            );
        },
    );
}

#[test]
fn yaml_independent_adds_merge_and_keep_local_comments() {
    independent_adds(
        "home/.config/app/settings.yaml",
        "shared: 1\n",
        "# local note\nshared: 1\nlocal: true\n",
        "shared: 1\nremote: added\n",
        "# local note\nshared: 1\nlocal: true\nremote: added\n",
        |text| {
            assert!(text.contains("# local note"));
            assert_eq!(
                yaml_value(text)
                    .get("remote")
                    .and_then(|value| value.as_str()),
                Some("added")
            );
        },
    );
}

#[test]
fn yml_extension_merges_the_same_way_as_yaml() {
    let saved = settled_text(&Case {
        path: "home/.config/app/settings.yml",
        base: "shared: 1\n",
        local: "shared: 1\nlocal: true\n",
        remote: "shared: 1\nremote: added\n",
    });
    assert_eq!(saved, "shared: 1\nlocal: true\nremote: added\n");
}

#[test]
fn json_same_value_different_key_order_keeps_exact_local_bytes() {
    let local = "{\n  \"b\": 2,\n  \"a\": 1\n}\n";
    let saved = settled_text(&Case {
        path: "home/.config/app/order.json",
        base: "{\n  \"a\": 1\n}\n",
        local,
        remote: "{\n  \"a\": 1,\n  \"b\": 2\n}\n",
    });
    assert_eq!(saved, local);
}

#[test]
fn toml_same_value_different_key_order_keeps_exact_local_bytes() {
    let local = "b = 2\na = 1\n";
    let saved = settled_text(&Case {
        path: "home/.config/app/order.toml",
        base: "a = 1\n",
        local,
        remote: "a = 1\nb = 2\n",
    });
    assert_eq!(saved, local);
}

#[test]
fn yaml_same_value_different_key_order_keeps_exact_local_bytes() {
    let local = "b: 2\na: 1\n";
    let saved = settled_text(&Case {
        path: "home/.config/app/order.yaml",
        base: "a: 1\n",
        local,
        remote: "a: 1\nb: 2\n",
    });
    assert_eq!(saved, local);
}

#[test]
fn json_same_key_different_value_stays_a_conflict() {
    stays(&Case {
        path: "home/.config/app/clash.json",
        base: "{\"name\": \"base\"}\n",
        local: "{\"name\": \"local\"}\n",
        remote: "{\"name\": \"remote\"}\n",
    });
}

#[test]
fn toml_same_key_different_value_stays_a_conflict() {
    stays(&Case {
        path: "home/.config/app/clash.toml",
        base: "name = \"base\"\n",
        local: "name = \"local\"\n",
        remote: "name = \"remote\"\n",
    });
}

#[test]
fn yaml_same_key_different_value_stays_a_conflict() {
    stays(&Case {
        path: "home/.config/app/clash.yaml",
        base: "name: base\n",
        local: "name: local\n",
        remote: "name: remote\n",
    });
}

#[test]
fn json_deletion_of_an_untouched_key_is_applied() {
    let saved = settled_text(&Case {
        path: "home/.config/app/drop.json",
        base: "{\n  \"keep\": 1,\n  \"gone\": 2\n}\n",
        local: "{\n  \"keep\": 1\n}\n",
        remote: "{\n  \"keep\": 1,\n  \"gone\": 2,\n  \"added\": 3\n}\n",
    });
    assert_eq!(saved, "{\n  \"keep\": 1,\n  \"added\": 3\n}\n");
    assert_eq!(
        json_value(&saved),
        serde_json::json!({"keep": 1, "added": 3})
    );
}

#[test]
fn toml_deletion_of_an_untouched_key_is_applied() {
    let saved = settled_text(&Case {
        path: "home/.config/app/drop.toml",
        base: "keep = 1\ngone = 2\n",
        local: "keep = 1\n",
        remote: "keep = 1\ngone = 2\nadded = 3\n",
    });
    assert_eq!(saved, "keep = 1\nadded = 3\n");
}

#[test]
fn yaml_deletion_of_an_untouched_key_is_applied() {
    let saved = settled_text(&Case {
        path: "home/.config/app/drop.yaml",
        base: "keep: 1\ngone: 2\n",
        local: "keep: 1\n",
        remote: "keep: 1\ngone: 2\nadded: 3\n",
    });
    assert_eq!(saved, "keep: 1\nadded: 3\n");
}
#[test]
fn json_remote_deletion_of_an_untouched_key_keeps_the_local_edit() {
    let saved = settled_text(&Case {
        path: "home/.config/app/remote-drop.json",
        base: "{\n  \"keep\": 1,\n  \"gone\": 2\n}\n",
        local: "{\n  \"keep\": 1,\n  \"gone\": 2,\n  \"extra\": true\n}\n",
        remote: "{\n  \"keep\": 1\n}\n",
    });
    assert_eq!(saved, "{\n  \"keep\": 1,\n  \"extra\": true\n}\n");
}

#[test]
fn toml_remote_deletion_keeps_the_comment_on_a_changed_key() {
    let saved = settled_text(&Case {
        path: "home/.config/app/remote-drop.toml",
        base: "keep = 1\ngone = 2\n",
        local: "keep = 9 # kept\ngone = 2\nextra = true\n",
        remote: "keep = 1\n",
    });
    assert!(saved.contains("# kept"), "{saved}");
    assert_eq!(
        toml_value(&saved)
            .get("keep")
            .and_then(|value| value.as_integer()),
        Some(9)
    );
    assert!(toml_value(&saved).get("gone").is_none(), "{saved}");
    assert_eq!(
        toml_value(&saved)
            .get("extra")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[test]
fn yaml_remote_deletion_keeps_the_comment_on_a_changed_key() {
    let saved = settled_text(&Case {
        path: "home/.config/app/remote-drop.yaml",
        base: "keep: 1\ngone: 2\n",
        local: "keep: 9 # kept\ngone: 2\nextra: true\n",
        remote: "keep: 1\n",
    });
    assert!(saved.contains("# kept"), "{saved}");
    assert!(saved.contains("keep: 9"), "{saved}");
    assert!(saved.contains("extra"));
    assert!(!saved.contains("gone"));
}
#[test]
fn yaml_nested_null_is_not_treated_as_an_empty_map() {
    stays(&Case {
        path: "home/.config/app/null.yaml",
        base: "name: ~\n",
        local: "name: {}\n",
        remote: "name: kept\n",
    });
}

#[test]
fn yaml_non_string_key_is_not_settled_by_dropping_it() {
    stays(&Case {
        path: "home/.config/app/numeric-key.yaml",
        base: "1: base\n",
        local: "1: local\nadded: true\n",
        remote: "1: remote\n",
    });
}

#[test]
fn yaml_changed_value_keeps_the_local_inline_comment() {
    let saved = settled_text(&Case {
        path: "home/.config/app/comment.yaml",
        base: "keep: 1\n",
        local: "keep: 9 # kept\n",
        remote: "keep: 1\nadded: true\n",
    });
    assert!(saved.contains("# kept"), "{saved}");
    assert!(saved.contains("keep: 9"), "{saved}");
    assert!(saved.contains("added"));
}

#[test]
fn a_key_deleted_on_one_side_and_edited_on_the_other_stays_a_conflict() {
    stays(&Case {
        path: "home/.config/app/delete-edit.json",
        base: "{\"name\": \"base\"}\n",
        local: "{}\n",
        remote: "{\"name\": \"remote\"}\n",
    });
    stays(&Case {
        path: "home/.config/app/delete-edit.toml",
        base: "name = \"base\"\n",
        local: "name = \"local\"\n",
        remote: "",
    });
    stays(&Case {
        path: "home/.config/app/delete-edit.yaml",
        base: "name: base\n",
        local: "{}\n",
        remote: "name: remote\n",
    });
}

#[test]
fn nested_maps_merge_and_arrays_stay_atomic() {
    let saved = settled_text(&Case {
        path: "home/.config/app/nested.json",
        base: "{\n  \"outer\": {\n    \"kept\": 1\n  },\n  \"items\": [1]\n}\n",
        local: "{\n  \"outer\": {\n    \"kept\": 1,\n    \"local\": true\n  },\n  \"items\": [1]\n}\n",
        remote: "{\n  \"outer\": {\n    \"kept\": 1,\n    \"remote\": \"x\"\n  },\n  \"items\": [1, 2]\n}\n",
    });
    assert_eq!(
        saved,
        "{\n  \"outer\": {\n    \"kept\": 1,\n    \"local\": true,\n    \"remote\": \"x\"\n  },\n  \"items\": [1, 2]\n}\n"
    );
    stays(&Case {
        path: "home/.config/app/array-clash.json",
        base: "{\"items\": [1]}\n",
        local: "{\"items\": [1, 2]}\n",
        remote: "{\"items\": [1, 3]}\n",
    });
}
#[test]
fn json_array_of_reordered_objects_keeps_local_bytes() {
    let local = "{\n  \"items\": [{\"b\": 2, \"a\": 1}]\n}\n";
    let saved = settled_text(&Case {
        path: "home/.config/app/array-order.json",
        base: "{\n  \"items\": []\n}\n",
        local,
        remote: "{\n  \"items\": [{\"a\": 1, \"b\": 2}]\n}\n",
    });
    assert_eq!(saved, local);
}

#[test]
fn json_duplicate_keys_are_not_settled_by_picking_one() {
    stays(&Case {
        path: "home/.config/app/duplicate.json",
        base: "{\"a\": 1}\n",
        local: "{\"a\": 1, \"a\": 2}\n",
        remote: "{\"a\": 3}\n",
    });
}

#[test]
fn the_same_change_on_both_sides_is_kept_in_local_bytes() {
    let local = "{\n  \"name\": \"both\"\n}\n";
    let saved = settled_text(&Case {
        path: "home/.config/app/same.json",
        base: "{\n  \"name\": \"base\"\n}\n",
        local,
        remote: "{\"name\":\"both\"}\n",
    });
    assert_eq!(saved, local);
}

#[test]
fn a_clean_line_merge_does_not_hide_a_parsed_semantic_clash() {
    // Different lines, so git merge-file would combine them. The parsed
    // values disagree on `name`, so the path must stay a conflict.
    stays(&Case {
        path: "home/.config/app/line-clean.json",
        base: "{\n  \"name\": \"base\"\n}\n",
        local: "{\n  \"name\": \"local\",\n  \"from\": \"local\"\n}\n",
        remote: "{\n  \"name\": \"remote\",\n  \"from\": \"remote\"\n}\n",
    });
}

#[test]
fn an_unparsable_side_falls_through_to_the_earlier_tiers() {
    stays(&Case {
        path: "home/.config/app/broken.json",
        base: "{\"name\": \"base\"}\n",
        local: "{\"name\": \"local\"\n",
        remote: "{\"name\": \"remote\"}\n",
    });
}

#[test]
fn a_file_over_one_mibibyte_is_not_parsed() {
    let base = format!("{{\"name\": \"{}\"}}\n", "b".repeat(ONE_MIB));
    let local = format!("{{\"name\": \"{}\"}}\n", "l".repeat(ONE_MIB));
    let remote = format!("{{\"name\": \"{}\"}}\n", "r".repeat(ONE_MIB));
    let (_dir, repo) = open();
    let path = "home/.config/app/huge.json";
    let base_object = blob(&repo, base.as_bytes());
    let local_object = blob(&repo, local.as_bytes());
    let remote_object = blob(&repo, remote.as_bytes());
    let sides = diverged(&repo, path, &base_object, &local_object, &remote_object);
    let (tree, remaining) = settle(&repo, &sides);
    assert!(
        remaining.iter().any(|conflict| conflict == path),
        "an oversized structured file must not be parsed into a settlement: {remaining:?}"
    );
    let saved = text_of(&repo, &tree, path);
    assert!(saved == local || saved == remote);
}

#[test]
fn another_extension_is_left_to_the_earlier_tiers() {
    stays(&Case {
        path: "home/.config/app/settings.conf",
        base: "name = base\n",
        local: "name = local\nadded = 1\n",
        remote: "name = remote\nadded = 2\n",
    });
}

#[test]
fn an_encrypted_json_add_is_stored_encrypted() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/.config/app/secret.json";
    let base = "{\n  \"shared\": 1\n}\n";
    let local = "{\n  \"shared\": 1,\n  \"local\": true\n}\n";
    let remote = "{\n  \"shared\": 1,\n  \"remote\": \"added\"\n}\n";
    let base_sealed = seal(&repo, path, base.as_bytes(), &key);
    let local_sealed = seal(&repo, path, local.as_bytes(), &key);
    let remote_sealed = seal(&repo, path, remote.as_bytes(), &key);
    let base_commit = {
        let commit = commit(&repo, None, &[(path, &base_sealed)]);
        let tree = repo.output_tree_of(&commit).unwrap();
        let tree = manifest_tree(&repo, &tree, path, &key);
        repo.commit_tree(&tree, vec![], "saved encrypted").unwrap()
    };
    let local_commit = {
        let parent_tree = repo.output_tree_of(&base_commit).unwrap();
        let tree = repo
            .compose(
                &parent_tree,
                &[Overlay {
                    path: path.into(),
                    object: Some(local_sealed.clone()),
                }],
            )
            .unwrap();
        repo.commit_tree(&tree, vec![&base_commit], "local encrypted")
            .unwrap()
    };
    let remote_commit = {
        let parent_tree = repo.output_tree_of(&base_commit).unwrap();
        let tree = repo
            .compose(
                &parent_tree,
                &[Overlay {
                    path: path.into(),
                    object: Some(remote_sealed.clone()),
                }],
            )
            .unwrap();
        repo.commit_tree(&tree, vec![&base_commit], "remote encrypted")
            .unwrap()
    };
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    assert!(conflicts.iter().any(|conflict| conflict == path));
    let (tree, remaining) = settle_conflicts(
        &repo,
        Some(&base_commit),
        &local_commit,
        &remote_commit,
        &merged,
        conflicts,
    )
    .unwrap();
    assert!(remaining.is_empty(), "{remaining:?}");
    let saved = repo.object_at(&tree, path).unwrap().unwrap();
    assert!(
        repo.blob_starts_with(&saved.1, files::MAGIC).unwrap(),
        "the settled object must stay an encrypted envelope"
    );
    let plain = files::decrypt(&repo, path, &saved, false).unwrap();
    let text = String::from_utf8(repo.cat_object(&plain.1).unwrap()).unwrap();
    assert_eq!(
        text,
        "{\n  \"shared\": 1,\n  \"local\": true,\n  \"remote\": \"added\"\n}\n"
    );
    assert_eq!(
        json_value(&text),
        serde_json::json!({"shared": 1, "local": true, "remote": "added"})
    );
}

/// Two machines edit different regions of one encrypted **text** file. The
/// path settles: the merge is made on the decrypted sides and stored as one
/// envelope. A text path has no keys, so `merge_by_key` reports
/// `Inapplicable`; without a fallback the path stays a repository conflict
/// and `incoming_repository_tree` pauses every machine at its next sync.
#[test]
fn non_overlapping_edits_to_one_encrypted_text_file_settle() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/.agents/sync-probe/4b-regions.txt";
    let base = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n";
    let local = "MAC-LINE\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n";
    let remote = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nVPS-LINE\n";
    let base_sealed = seal(&repo, path, base.as_bytes(), &key);
    let local_sealed = seal(&repo, path, local.as_bytes(), &key);
    let remote_sealed = seal(&repo, path, remote.as_bytes(), &key);
    let base_commit = {
        let commit = commit(&repo, None, &[(path, &base_sealed)]);
        let tree = repo.output_tree_of(&commit).unwrap();
        let tree = manifest_tree(&repo, &tree, path, &key);
        repo.commit_tree(&tree, vec![], "saved encrypted").unwrap()
    };
    let local_commit = {
        let parent_tree = repo.output_tree_of(&base_commit).unwrap();
        let tree = repo
            .compose(
                &parent_tree,
                &[Overlay {
                    path: path.into(),
                    object: Some(local_sealed.clone()),
                }],
            )
            .unwrap();
        repo.commit_tree(&tree, vec![&base_commit], "local encrypted")
            .unwrap()
    };
    let remote_commit = {
        let parent_tree = repo.output_tree_of(&base_commit).unwrap();
        let tree = repo
            .compose(
                &parent_tree,
                &[Overlay {
                    path: path.into(),
                    object: Some(remote_sealed.clone()),
                }],
            )
            .unwrap();
        repo.commit_tree(&tree, vec![&base_commit], "remote encrypted")
            .unwrap()
    };
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    assert!(
        conflicts.iter().any(|conflict| conflict == path),
        "two sides of one ciphertext cannot be merged as text by Git: {conflicts:?}"
    );
    let (tree, remaining) = settle_conflicts(
        &repo,
        Some(&base_commit),
        &local_commit,
        &remote_commit,
        &merged,
        conflicts,
    )
    .unwrap();
    assert!(
        remaining.is_empty(),
        "an encrypted text path must settle, not pause the repository: {remaining:?}"
    );
    let saved = repo.object_at(&tree, path).unwrap().unwrap();
    assert!(
        repo.blob_starts_with(&saved.1, files::MAGIC).unwrap(),
        "the settled object must stay an encrypted envelope"
    );
    let plain = files::decrypt(&repo, path, &saved, false).unwrap();
    let text = String::from_utf8(repo.cat_object(&plain.1).unwrap()).unwrap();
    assert_eq!(
        text,
        "MAC-LINE\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nVPS-LINE\n"
    );
    assert!(!text.contains("<<<<<<<"));
}

fn age_key() -> (mise_util::testing::EnvVarGuard, age::x25519::Identity) {
    use age::secrecy::ExposeSecret;
    let key = age::x25519::Identity::generate();
    let mut environment = mise_util::testing::EnvVarGuard::new();
    environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
    (environment, key)
}
