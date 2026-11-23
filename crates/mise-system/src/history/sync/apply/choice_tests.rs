//! Two machines edit the same line of one encrypted text file, so neither the
//! key merge nor the line merge can settle it. The path is one conflict, on its
//! real path, that `mise dot pull --keep-local <path>` or `--take-remote <path>`
//! decides; it is not a repository conflict that pauses every path.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::super::merge_by_key::{age_key, commit, manifest_tree, seal};
use super::super::network::UPSTREAM_REF;
use super::*;
use crate::history::manifest::Manifest;
use crate::history::shadow::Overlay;

const BASE: &str = "line 1\nline 2\nline 3\n";
const LOCAL: &str = "LOCAL\nline 2\nline 3\n";
const REMOTE: &str = "REMOTE\nline 2\nline 3\n";

/// One machine whose saved history and origin both changed `secret.txt` on
/// its first line; the live file holds the saved local text.
struct Machine {
    _key: mise_util::testing::EnvVarGuard,
    _state: tempfile::TempDir,
    _live_dir: tempfile::TempDir,
    store: Store,
    live: PathBuf,
    branch_path: String,
    local: Object,
    remote: Object,
    tracked: TrackedSet,
}

fn diverged_machine() -> Machine {
    let (key_guard, key) = age_key();
    let state = tempfile::tempdir().unwrap();
    let store = Store::open_in(state.path()).unwrap();
    let repo = store.repo().unwrap();
    let roots = Roots::current();
    let live_dir = tempfile::Builder::new()
        .prefix(".mise-choice-test-")
        .tempdir_in(&roots.home)
        .unwrap();
    let live = live_dir.path().join("secret.txt");
    let branch_path = roots.branch_path(&live, None).unwrap();
    let sealed = |text: &str| seal(repo, &branch_path, text.as_bytes(), &key);
    let (base, local, remote) = (sealed(BASE), sealed(LOCAL), sealed(REMOTE));
    let first = commit(repo, None, &[(&branch_path, &base)]);
    let tree = manifest_tree(
        repo,
        &repo.output_tree_of(&first).unwrap(),
        &branch_path,
        &key,
    );
    let base_commit = repo.commit_tree(&tree, vec![], "base").unwrap();
    let child = |object: &Object, message: &str| {
        let tree = repo
            .compose(
                &repo.output_tree_of(&base_commit).unwrap(),
                &[Overlay {
                    path: branch_path.clone(),
                    object: Some(object.clone()),
                }],
            )
            .unwrap();
        repo.commit_tree(&tree, vec![&base_commit], message)
            .unwrap()
    };
    let local_commit = child(&local, "local edit");
    let remote_commit = child(&remote, "remote edit");
    repo.update_ref(HistoryRepo::HISTORY_REF, &local_commit, None)
        .unwrap();
    repo.update_ref(UPSTREAM_REF, &remote_commit, None).unwrap();
    std::fs::write(&live, LOCAL).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let tracked = Manifest::read(repo, &local_commit)
        .unwrap()
        .unwrap()
        .tracking()
        .unwrap();
    Machine {
        _key: key_guard,
        _state: state,
        _live_dir: live_dir,
        store,
        live,
        branch_path,
        local,
        remote,
        tracked,
    }
}

/// What one `mise dot pull` decided before it writes anything: the status it
/// left, and the repository tree it would adopt when no conflict remains.
struct Pulled {
    status: SyncStatus,
    tree: Option<String>,
}

fn pull(machine: &Machine, take_remote: Vec<PathBuf>, keep_local: Vec<PathBuf>) -> Result<Pulled> {
    let store = &machine.store;
    let repo = store.repo().unwrap();
    let incoming = run::incoming_tracking(repo, &machine.tracked)?;
    let req = ApplyRequest {
        paths: vec![],
        dry_run: false,
        take_remote,
        keep_local,
        take_remote_all: false,
        keep_local_all: false,
        automatic: false,
        plan_only: false,
        wait: None,
    };
    let mut status = run::read_status(store.state_dir())?;
    run::refresh_with_interaction(store, &incoming, &mut status, false)?;
    let pull = Pull {
        store,
        repo,
        tracked: &incoming,
        req: &req,
        roots: Roots::current(),
        state_dir: store.state_dir(),
        planned_head: repo.ref_oid(HistoryRepo::HISTORY_REF)?,
    };
    pull.choose(&mut status)?;
    let tree = if status.conflicts.is_empty() {
        pull.inventory_tree(&status)?
    } else {
        None
    };
    Ok(Pulled { status, tree })
}

fn adopted(machine: &Machine, pulled: &Pulled) -> Object {
    let repo = machine.store.repo().unwrap();
    let tree = pulled.tree.as_deref().expect("the pull adopts a tree");
    repo.object_at(tree, &machine.branch_path)
        .unwrap()
        .expect("the path is in the adopted tree")
}

#[test]
fn keep_local_settles_the_path_to_the_saved_local_envelope() {
    let machine = diverged_machine();
    let pulled = pull(&machine, vec![], vec![machine.live.clone()]).unwrap();
    assert!(
        pulled.status.conflicts.is_empty(),
        "a chosen path is decided: {:?}",
        pulled.status.conflicts
    );
    assert_eq!(adopted(&machine, &pulled), machine.local);
}

#[test]
fn take_remote_settles_the_path_to_the_origin_envelope() {
    let machine = diverged_machine();
    let pulled = pull(&machine, vec![machine.live.clone()], vec![]).unwrap();
    assert!(
        pulled.status.conflicts.is_empty(),
        "a chosen path is decided: {:?}",
        pulled.status.conflicts
    );
    assert_eq!(adopted(&machine, &pulled), machine.remote);
}

#[test]
fn without_a_choice_the_repository_merge_names_the_path() {
    let machine = diverged_machine();
    let repo = machine.store.repo().unwrap();
    let incoming = run::incoming_tracking(repo, &machine.tracked).unwrap();
    let error = run::incoming_repository_tree(repo, &incoming, &BTreeMap::new()).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("reconcile repository conflicts first")
            && message.contains(&machine.branch_path),
        "an undecided path still pauses the merge and is named: {message}"
    );
    let pulled = pull(&machine, vec![], vec![]).unwrap();
    assert_eq!(pulled.tree, None, "nothing is adopted without a choice");
    assert_eq!(
        pulled
            .status
            .conflicts
            .iter()
            .map(|conflict| conflict.branch_path.as_str())
            .collect::<Vec<_>>(),
        vec![machine.branch_path.as_str()],
        "the conflict is the real path, not the enrollment manifest"
    );
}

#[test]
fn the_listing_shows_both_decrypted_sides_on_the_real_path() {
    let machine = diverged_machine();
    let store = &machine.store;
    let repo = store.repo().unwrap();
    let incoming = run::incoming_tracking(repo, &machine.tracked).unwrap();
    let mut status = run::read_status(store.state_dir()).unwrap();
    run::refresh_with_interaction(store, &incoming, &mut status, false)
        .expect("a conflict on one path does not stop the listing");
    let [conflict] = status.conflicts.as_slice() else {
        panic!("one conflict expected: {:?}", status.conflicts);
    };
    assert_eq!(conflict.branch_path, machine.branch_path);
    let text = |side: &Option<Object>| {
        String::from_utf8(repo.cat_object(&side.as_ref().unwrap().1).unwrap()).unwrap()
    };
    assert_eq!(text(&conflict.local), LOCAL);
    assert_eq!(text(&conflict.remote), REMOTE);
    let rows = describe_conflicts(&status.conflicts);
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].0.ends_with("secret.txt"),
        "status names the file, not .mise-history/manifest.json: {rows:?}"
    );
    assert!(resolution_advice(&rows[0].0, &rows[0].1).contains("--keep-local"));
}
