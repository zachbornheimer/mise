//! Line-ending and trailing-whitespace equality is not object identity.
//!
//! Two saved versions of one path can differ only in CRLF versus LF, spaces
//! or tabs at the end of a line, or a missing final newline. Those versions
//! are the same file: the conflict settles, this machine's saved object is
//! the one that stands, and listing reports no conflict. A change to a
//! non-whitespace byte, to leading whitespace, or to the mode is a real
//! conflict. A binary file and a symlink are equal only when their bytes are.

use std::collections::{BTreeMap, BTreeSet};

use super::files::{self, encode};
use super::reconcile::{self, ConflictKind, Object};
use super::run::settle_conflicts;
use super::state::SyncRecord;
use crate::history::manifest::{Enrollment, Manifest};
use crate::history::shadow::{HistoryRepo, Overlay};

fn open() -> (tempfile::TempDir, HistoryRepo) {
    let dir = tempfile::tempdir().unwrap();
    let repo = HistoryRepo::open_or_init_in(dir.path()).unwrap().unwrap();
    (dir, repo)
}

fn blob(repo: &HistoryRepo, bytes: &[u8]) -> Object {
    ("100644".into(), repo.hash_blob(bytes).unwrap())
}

fn link(repo: &HistoryRepo, target: &[u8]) -> Object {
    ("120000".into(), repo.hash_blob(target).unwrap())
}

fn executable(repo: &HistoryRepo, bytes: &[u8]) -> Object {
    ("100755".into(), repo.hash_blob(bytes).unwrap())
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

fn seal(
    repo: &HistoryRepo,
    path: &str,
    mode: &str,
    bytes: &[u8],
    key: &age::x25519::Identity,
) -> Object {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
    let encoded = encode(path, mode, bytes, "test", &recipients).unwrap();
    // An envelope is always stored as a regular file. The mode it was saved
    // with is inside it, not in this object's mode.
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

fn encrypted_commit(
    repo: &HistoryRepo,
    parent: Option<&str>,
    path: &str,
    bytes: &[u8],
    key: &age::x25519::Identity,
) -> (String, Object) {
    let sealed = seal(repo, path, "100644", bytes, key);
    let empty = repo.empty_object("tree").unwrap();
    let tree = repo
        .compose(
            &empty,
            &[Overlay {
                path: path.into(),
                object: Some(sealed.clone()),
            }],
        )
        .unwrap();
    let tree = manifest_tree(repo, &tree, path, key);
    let commit = repo
        .commit_tree(&tree, parent.into_iter().collect(), "saved encrypted")
        .unwrap();
    (commit, sealed)
}

struct Sides {
    base: String,
    local: String,
    remote: String,
    merged: String,
    conflicts: Vec<String>,
}

/// Both sides changed `path` from a genuinely different base, so Git reports
/// the path. Callers that need an unchanged side use [`branched`] instead.
fn diverged(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
) -> Sides {
    assert_ne!(
        base, local,
        "local must change the base, or Git does not conflict"
    );
    assert_ne!(
        base, remote,
        "remote must change the base, or Git does not conflict"
    );
    let sides = branched(repo, path, base, local, remote);
    assert!(
        sides.conflicts.iter().any(|conflict| conflict == path),
        "both sides changed {path}; Git reported {:?}",
        sides.conflicts
    );
    sides
}

/// The two branches, whether or not Git reports `path`. An identical object
/// on both sides is a clean merge, not a conflict to invent.
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

fn object_of(repo: &HistoryRepo, tree: &str, path: &str) -> Object {
    repo.object_at(tree, path).unwrap().unwrap()
}

fn bytes_of(repo: &HistoryRepo, object: &Object) -> Vec<u8> {
    repo.cat_object(&object.1).unwrap()
}

/// Settling a real Git conflict keeps this machine's saved object.
fn keeps_local_object(path: &str, base: &[u8], local: &[u8], remote: &[u8]) {
    let (_dir, repo) = open();
    let base = blob(&repo, base);
    let local = blob(&repo, local);
    let remote = blob(&repo, remote);
    let sides = diverged(&repo, path, &base, &local, &remote);
    let (tree, remaining) = settle(&repo, &sides);
    assert!(
        remaining.is_empty(),
        "{path} differs only in line ending, trailing whitespace, or a final newline: {remaining:?}"
    );
    assert_eq!(
        object_of(&repo, &tree, path),
        local,
        "settling must keep this machine's saved object, not rewrite its bytes"
    );
    assert_eq!(listed(&repo, path, &base, &local, &remote), None);
}

/// Both sides changed the file, and the difference is not one normalization ignores.
fn stays_conflict(path: &str, base: &[u8], local: &[u8], remote: &[u8]) {
    let (_dir, repo) = open();
    let base = blob(&repo, base);
    let local = blob(&repo, local);
    let remote = blob(&repo, remote);
    let sides = diverged(&repo, path, &base, &local, &remote);
    let (tree, remaining) = settle(&repo, &sides);
    assert!(
        remaining.iter().any(|conflict| conflict == path),
        "{path} is a real difference and must stay a conflict: {remaining:?}"
    );
    let kept = object_of(&repo, &tree, path);
    assert!(
        kept == local || kept == remote,
        "an unsettled conflict keeps a saved side, not a synthesized file"
    );
    assert!(listed(&repo, path, &base, &local, &remote).is_some());
}

fn record(object: &Object) -> SyncRecord {
    SyncRecord {
        acknowledged: Some(object.clone()),
        reconciled: Some(object.clone()),
        applied: Some(object.clone()),
        upstream_commit: None,
    }
}

/// Listing uses the repository that hashed these objects, so it can read them.
fn listed(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
) -> Option<ConflictKind> {
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
    plans
        .into_iter()
        .find_map(|plan| plan.conflict.map(|conflict| conflict.kind))
}

fn age_key() -> (mise_util::testing::EnvVarGuard, age::x25519::Identity) {
    use age::secrecy::ExposeSecret;
    let key = age::x25519::Identity::generate();
    let mut environment = mise_util::testing::EnvVarGuard::new();
    environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
    (environment, key)
}

/// An encrypted difference Git reports settles onto the local envelope.
fn encrypted_keeps_local(base: &[u8], local: &[u8], remote: &[u8]) {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let (base_commit, _) = encrypted_commit(&repo, None, path, base, &key);
    let (local_commit, local_sealed) =
        encrypted_commit(&repo, Some(&base_commit), path, local, &key);
    let (remote_commit, remote_sealed) =
        encrypted_commit(&repo, Some(&base_commit), path, remote, &key);
    assert_ne!(local_sealed.1, remote_sealed.1, "encryption is randomized");
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    assert!(
        conflicts.iter().any(|conflict| conflict == path),
        "encrypted sides must start as a Git conflict: {conflicts:?}"
    );
    let local_bytes = bytes_of(&repo, &local_sealed);
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
    let kept = object_of(&repo, &tree, path);
    assert_eq!(kept, local_sealed);
    assert_eq!(bytes_of(&repo, &kept), local_bytes);

    let base_sealed = repo.object_at(&base_commit, path).unwrap().unwrap();
    let base_plain = files::decrypt(&repo, path, &base_sealed, false).unwrap();
    let local_plain = files::decrypt(&repo, path, &local_sealed, false).unwrap();
    let remote_plain = files::decrypt(&repo, path, &remote_sealed, false).unwrap();
    assert_ne!(base_plain, local_plain);
    assert_ne!(base_plain, remote_plain);
    let upstream = reconcile::upstream(&repo, Some(&remote_commit)).unwrap();
    assert_eq!(upstream.files[path], remote_plain);
    assert_eq!(
        listed(&repo, path, &base_plain, &local_plain, &remote_plain),
        None,
        "listing both decrypted sides against their base must not report a conflict"
    );
}

#[test]
fn crlf_and_lf_settle_and_keep_the_local_object() {
    // The base is neither side: both machines changed it, in ways that normalize equal.
    keeps_local_object(
        "tracked/home/.zshrc", // portable-home-ok
        b"one\ntwo",
        b"one\r\ntwo\r\n",
        b"one\ntwo\n",
    );
}

#[test]
fn trailing_spaces_and_tabs_settle_and_keep_the_local_object() {
    keeps_local_object(
        "tracked/home/.gitconfig", // portable-home-ok
        b"name = ada",
        b"name = ada  \n\temail = a@b\t\n",
        b"name = ada\n\temail = a@b\n",
    );
}

#[test]
fn a_missing_final_newline_settles_and_keeps_the_local_object() {
    keeps_local_object(
        "tracked/home/.vimrc", // portable-home-ok
        b"older\n",
        b"set nocompatible\nset hidden",
        b"set nocompatible\nset hidden\n",
    );
}

#[test]
fn combined_line_ending_trailing_whitespace_and_final_newline_settle() {
    keeps_local_object(
        "tracked/home/.profile", // portable-home-ok
        b"export A=1\nexport B=2",
        b"export A=1\r\nexport B=2  ",
        b"export A=1\nexport B=2\t\n",
    );
}

#[test]
fn a_changed_non_whitespace_byte_stays_a_conflict() {
    stays_conflict(
        "tracked/home/.zshrc", // portable-home-ok
        b"alpha\n",
        b"alpha beta\n",
        b"alpha gamma\n",
    );
}

#[test]
fn leading_whitespace_stays_a_conflict() {
    stays_conflict("tracked/home/.zshrc", b"alpha\n", b" alpha\n", b"\talpha\n"); // portable-home-ok
}

#[test]
fn a_mode_difference_stays_a_conflict_even_when_bytes_match() {
    let (_dir, repo) = open();
    let path = "tracked/home/tool"; // portable-home-ok
    let base = blob(&repo, b"#!/bin/sh\necho base\n");
    let local = executable(&repo, b"#!/bin/sh\necho changed\n");
    let remote = blob(&repo, b"#!/bin/sh\necho changed\r\n");
    let sides = diverged(&repo, path, &base, &local, &remote);
    let (_tree, remaining) = settle(&repo, &sides);
    assert_eq!(remaining, vec![path.to_string()]);
    assert!(
        listed(&repo, path, &base, &local, &remote).is_some(),
        "a mode difference stays a conflict even when the bytes normalize equal"
    );
}

#[test]
fn a_binary_file_is_equal_only_byte_for_byte() {
    stays_conflict("tracked/home/icon", b"a\0base\n", b"a\0b\n", b"a\0b\r\n"); // portable-home-ok

    // Identical bytes are not a conflict to invent, even with a NUL.
    let (_dir, repo) = open();
    let path = "tracked/home/icon"; // portable-home-ok
    let bytes = b"a\0b\r\n  ";
    let base = blob(&repo, b"a\0older\n");
    let local = blob(&repo, bytes);
    let remote = blob(&repo, bytes);
    let sides = branched(&repo, path, &base, &local, &remote);
    assert!(
        !sides.conflicts.iter().any(|conflict| conflict == path),
        "identical objects are a clean merge: {:?}",
        sides.conflicts
    );
    let (tree, remaining) = settle(&repo, &sides);
    assert!(remaining.is_empty());
    assert_eq!(object_of(&repo, &tree, path), local);
    assert_eq!(listed(&repo, path, &base, &local, &remote), None);
}

#[test]
fn a_symlink_is_equal_only_byte_for_byte() {
    let (_dir, repo) = open();
    let path = "tracked/home/link"; // portable-home-ok
    let base = link(&repo, b"../old");
    let local = link(&repo, b"../new");
    let remote = link(&repo, b"../new\n");
    let sides = diverged(&repo, path, &base, &local, &remote);
    let (_tree, remaining) = settle(&repo, &sides);
    assert_eq!(remaining, vec![path.to_string()]);
    assert_eq!(
        listed(&repo, path, &base, &local, &remote),
        Some(ConflictKind::LinkTarget)
    );

    let same = link(&repo, b"../new");
    let sides = branched(&repo, path, &base, &local, &same);
    assert!(!sides.conflicts.iter().any(|conflict| conflict == path));
    assert_eq!(listed(&repo, path, &base, &local, &same), None);
}

#[test]
fn invalid_utf8_is_equal_only_byte_for_byte() {
    stays_conflict(
        "tracked/home/data", // portable-home-ok
        b"older\n",
        b"caf\xff\n",
        b"caf\xff\r\n",
    );
}

#[test]
fn listing_reports_no_conflict_when_normalization_settles_the_path() {
    let (_dir, repo) = open();
    let path = "tracked/home/.zshrc"; // portable-home-ok
    let base = blob(&repo, b"one");
    let local = blob(&repo, b"one\r\n");
    let remote = blob(&repo, b"one \n");
    assert_eq!(listed(&repo, path, &base, &local, &remote), None);
    let plans = reconcile::reconcile(
        &repo,
        &BTreeMap::from([(path.to_string(), local.clone())]),
        &reconcile::Upstream {
            files: BTreeMap::from([(path.to_string(), remote)]),
            ..Default::default()
        },
        &BTreeMap::from([(path.to_string(), record(&base))]),
        &BTreeSet::new(),
    )
    .unwrap();
    let plan = plans.iter().find(|plan| plan.branch_path == path).unwrap();
    assert!(plan.conflict.is_none());
    assert_eq!(plan.next.acknowledged.as_ref(), Some(&local));
    assert_eq!(plan.next.applied.as_ref(), Some(&local));
    assert!(plan.apply.is_none(), "the local saved side already stands");
}

#[test]
fn encrypted_crlf_and_lf_settle_without_rewriting_ciphertext() {
    encrypted_keeps_local(b"token = one", b"token = one\r\n", b"token = one\n");
}

#[test]
fn encrypted_trailing_spaces_and_tabs_settle_without_rewriting_ciphertext() {
    encrypted_keeps_local(b"token = one", b"token = one  \n", b"token = one\t\n");
}

#[test]
fn an_encrypted_executable_compares_its_recovered_mode() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let local = seal(&repo, path, "100755", b"#!/bin/sh\necho one\r\n", &key);
    let remote = seal(&repo, path, "100755", b"#!/bin/sh\necho one\n", &key);
    assert!(
        files::normalized_equal(&repo, path, &local, &remote, false).unwrap(),
        "two encrypted executables differ only by a line ending"
    );
    let regular = seal(&repo, path, "100644", b"#!/bin/sh\necho one\n", &key);
    assert!(
        !files::normalized_equal(&repo, path, &local, &regular, false).unwrap(),
        "an encrypted executable is not the same file as an encrypted regular file"
    );
}

#[test]
fn an_encrypted_symlink_is_equal_only_byte_for_byte() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let local = seal(&repo, path, "120000", b"../target", &key);
    let remote = seal(&repo, path, "120000", b"../target\n", &key);
    assert!(!files::normalized_equal(&repo, path, &local, &remote, false).unwrap());
    let same = seal(&repo, path, "120000", b"../target", &key);
    assert!(files::normalized_equal(&repo, path, &local, &same, false).unwrap());
}

#[test]
fn encrypted_missing_final_newline_settles_without_rewriting_ciphertext() {
    encrypted_keeps_local(
        b"older token\n",
        b"token = one\nnext",
        b"token = one\nnext\n",
    );
}

#[test]
fn a_lone_cr_is_not_a_line_ending_to_ignore() {
    stays_conflict(
        "tracked/home/.zshrc", // portable-home-ok
        b"older\n",
        b"one\r\ntwo\r\n",
        b"one\rtwo\n",
    );
}

#[test]
fn trailing_unicode_whitespace_stays_a_conflict() {
    stays_conflict(
        "tracked/home/.zshrc", // portable-home-ok
        b"older\n",
        "name = ada\n".as_bytes(),
        "name = ada\u{00a0}\n".as_bytes(),
    );
}

#[test]
fn an_extra_blank_line_stays_a_conflict() {
    stays_conflict(
        "tracked/home/.zshrc", // portable-home-ok
        b"older\n",
        b"one\ntwo\n",
        b"one\ntwo\n\n",
    );
}

#[test]
fn an_encrypted_content_change_stays_a_conflict() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let (base_commit, _) = encrypted_commit(&repo, None, path, b"base\n", &key);
    let (local_commit, _) = encrypted_commit(&repo, Some(&base_commit), path, b"left\n", &key);
    let (remote_commit, _) = encrypted_commit(&repo, Some(&base_commit), path, b"right\n", &key);
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    let (_tree, remaining) = settle_conflicts(
        &repo,
        Some(&base_commit),
        &local_commit,
        &remote_commit,
        &merged,
        conflicts,
    )
    .unwrap();
    assert_eq!(remaining, vec![path.to_string()]);
}

#[test]
#[test]
fn both_machines_appending_different_lines_keeps_both() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let (base_commit, _) = encrypted_commit(&repo, None, path, b"shared\n", &key);
    let (local_commit, _) =
        encrypted_commit(&repo, Some(&base_commit), path, b"shared\nfrom-mac\n", &key);
    let (remote_commit, _) = encrypted_commit(
        &repo,
        Some(&base_commit),
        path,
        b"shared\nfrom-vps\n",
        &key,
    );
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
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
        "disjoint additions must not pause the setup: {remaining:?}"
    );
    let object = object_of(&repo, &tree, path);
    let decrypted = files::decrypt(&repo, path, &object, false).unwrap();
    assert_eq!(
        bytes_of(&repo, &decrypted),
        b"shared\nfrom-mac\nfrom-vps\n",
        "both appended lines stand, local then remote"
    );
}

#[test]
fn a_reencrypted_unchanged_origin_keeps_the_local_change() {
    // Another machine saved the same content again, which writes a new
    // envelope. This machine edited the file. Only one side changed it.
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let (base_commit, base_sealed) = encrypted_commit(&repo, None, path, b"base\n", &key);
    let (local_commit, local_sealed) =
        encrypted_commit(&repo, Some(&base_commit), path, b"edited here\n", &key);
    let (remote_commit, remote_sealed) =
        encrypted_commit(&repo, Some(&base_commit), path, b"base\n", &key);
    assert_ne!(base_sealed, remote_sealed);
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    assert_eq!(conflicts, vec![path.to_string()]);
    let (tree, remaining) = settle_conflicts(
        &repo,
        Some(&base_commit),
        &local_commit,
        &remote_commit,
        &merged,
        conflicts,
    )
    .unwrap();
    assert_eq!(remaining, Vec::<String>::new());
    assert_eq!(object_of(&repo, &tree, path), local_sealed);
}

#[test]
fn a_decryption_failure_is_not_treated_as_equality() {
    let (_dir, repo) = open();
    let (_environment, key) = age_key();
    let path = "home/secret";
    let (base_commit, _) = encrypted_commit(&repo, None, path, b"base\n", &key);
    let (local_commit, local_sealed) =
        encrypted_commit(&repo, Some(&base_commit), path, b"same\r\n", &key);
    let other: Vec<Box<dyn age::Recipient + Send>> =
        vec![Box::new(age::x25519::Identity::generate().to_public())];
    let foreign = (
        "100644".into(),
        repo.hash_blob(&encode(path, "100644", b"same\n", "test", &other).unwrap())
            .unwrap(),
    );
    let remote_commit = {
        let empty = repo.empty_object("tree").unwrap();
        let tree = repo
            .compose(
                &empty,
                &[Overlay {
                    path: path.into(),
                    object: Some(foreign),
                }],
            )
            .unwrap();
        let tree = manifest_tree(&repo, &tree, path, &key);
        repo.commit_tree(&tree, vec![base_commit.as_str()], "foreign")
            .unwrap()
    };
    let (merged, conflicts) = repo.merge_tree(&local_commit, &remote_commit).unwrap();
    let result = settle_conflicts(
        &repo,
        Some(&base_commit),
        &local_commit,
        &remote_commit,
        &merged,
        conflicts,
    );
    // A locked side is not equal. Current code may report that as an error
    // or leave the Git conflict; either way the path is not settled, and the
    // local envelope is not rewritten to match the foreign one.
    match result {
        Err(err) => {
            let message = format!("{err:#}");
            assert!(message.contains(path), "{message}");
            assert!(
                message.contains("cannot unlock") || message.contains("not a readable"),
                "{message}"
            );
        }
        Ok((tree, remaining)) => {
            assert_eq!(remaining, vec![path.to_string()]);
            assert_eq!(object_of(&repo, &tree, path), local_sealed);
        }
    }
}

#[test]
fn status_rows_follow_the_conflicts_reconcile_recorded() {
    let (_dir, repo) = open();
    let path = "tracked/home/.zshrc"; // portable-home-ok
    let base = blob(&repo, b"older\n");
    let local = blob(&repo, b"one\r\n");
    let remote = blob(&repo, b"one\n");
    let plans = reconcile::reconcile(
        &repo,
        &BTreeMap::from([(path.to_string(), local)]),
        &reconcile::Upstream {
            files: BTreeMap::from([(path.to_string(), remote)]),
            ..Default::default()
        },
        &BTreeMap::from([(path.to_string(), record(&base))]),
        &BTreeSet::new(),
    )
    .unwrap();
    let conflicts: Vec<_> = plans
        .iter()
        .filter_map(|plan| plan.conflict.clone())
        .collect();
    assert!(
        conflicts.is_empty(),
        "a normalized-equal path must not reach status as a conflict"
    );
    assert!(super::apply::describe_conflicts(&conflicts).is_empty());
}
