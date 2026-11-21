//! Saved active file versions for live comparison. Publication always uses
//! the complete ordinary branch, not this machine-specific view.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::Result;

use super::layout::{Located, Roots};
use crate::history::shadow::HistoryRepo;
use crate::history::tracked::TrackedSet;

#[derive(Clone, Debug)]
pub(crate) struct SharedFile {
    pub local: PathBuf,
    pub mode: String,
    pub oid: String,
}

#[derive(Debug, Default)]
pub(crate) struct ShareReport {
    pub files: BTreeMap<String, SharedFile>,
    pub checkpoint: Option<String>,
    /// Paths of selected streams whose saved version this machine does not
    /// hold (see [`crate::history::held`]), each with the version
    /// it last held, if any: their `files` are the live ones, and that
    /// version, not the shared one, is their baseline.
    pub unheld: BTreeMap<String, Option<(String, String)>>,
}

impl ShareReport {
    pub(crate) fn objects(&self) -> BTreeMap<String, (String, String)> {
        self.files
            .iter()
            .map(|(path, file)| (path.clone(), (file.mode.clone(), file.oid.clone())))
            .collect()
    }
}

#[cfg(test)]
thread_local! {
    /// Forces the walk's thread count, so a test can compare both paths on a
    /// fixture too small to reach the threshold on its own.
    static WALK_THREADS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_walk_threads(threads: Option<usize>) {
    WALK_THREADS.with(|slot| slot.set(threads));
}

/// Files a listing must hold before the walk spreads over threads: below it
/// the handoff costs more than the decrypts it saves.
const WALK_FILES_MIN: usize = 64;

/// Most threads the walk uses. Each worker opens its own repository handle, so
/// a thread is not free, and past this the per-file decrypts stop gaining.
const WALK_THREADS_MAX: usize = 8;
/// One thread per core, capped at [`WALK_THREADS_MAX`].
fn walk_threads() -> usize {
    #[cfg(test)]
    if let Some(forced) = WALK_THREADS.with(std::cell::Cell::get) {
        return forced;
    }
    std::thread::available_parallelism()
        .map(|cores| cores.get())
        .unwrap_or(1)
        .min(WALK_THREADS_MAX)
}

/// Read committed files, including manually saved files missing on disk.
/// Live directory enumeration is never the authority for a saved version.
pub(crate) fn current(repo: &HistoryRepo, tracked: &TrackedSet) -> Result<ShareReport> {
    if !tracked.invalid.is_empty() {
        eyre::bail!("invalid dotfile declarations; correct them before publishing");
    }
    let mut report = ShareReport::default();
    let Some(head) = repo.ref_oid(HistoryRepo::HISTORY_REF)? else {
        return Ok(report);
    };
    report.checkpoint = Some(head.clone());
    let roots = Roots::current();
    let record = crate::history::held::Held::load(repo)?;
    // One open for the walk. Opening this repository scans every pack index,
    // so restoring or looking up each file through it opened it once per
    // file, and a sync of a few thousand files spent seconds scanning
    // indexes before it read a byte.
    let objects = repo.gix()?;
    // one listing and one manifest read for the walk: looking each file up
    // again by path, and reading the manifest per file, made a sync of a
    // few thousand files spend seconds here
    let listing = repo.ls_tree_in(&objects, &head)?;
    let saved: BTreeMap<&str, (String, String)> = listing
        .iter()
        .map(|entry| (entry.path.as_str(), (entry.mode.clone(), entry.oid.clone())))
        .collect();
    let encrypted_paths = repo.encrypted_paths_of_in(&objects, &head)?;
    let restored = |objects: &gix::Repository, path: &str| -> Result<Option<(String, String)>> {
        saved
            .get(path)
            .cloned()
            .map(|object| repo.restored_in(objects, &encrypted_paths, path, object))
            .transpose()
    };
    // One file's share, as the walk finds it. `unheld` records the baseline a
    // live file was measured against, and is reported even when that file
    // contributes no object of its own.
    struct Found {
        path: String,
        unheld: Option<Option<(String, String)>>,
        file: Option<SharedFile>,
    }

    // One caller waits on each decrypt in turn, so the walk costs 0.226 ms per
    // file where the same decrypts spread across cores cost 0.088 ms. Small
    // listings keep the serial loop: a thread costs more than it saves there.
    let walk = |file: &crate::history::shadow::TreeEntry,
                objects: &gix::Repository,
                holds: &mut BTreeMap<String, bool>|
     -> Result<Option<Found>> {
        let (local, variant) = match roots.locate(&file.path) {
            Located::Config(path) => (path, None),
            Located::Tracked { path, variant } => (path, variant),
            Located::Marker | Located::Unmapped => return Ok(None),
        };
        let Some(entry) = tracked.entry_for(&local) else {
            return Ok(None);
        };
        if entry.variant != variant {
            return Ok(None);
        }
        let stream = entry.tree_path(&entry.path)?;
        let held = match holds.get(&stream) {
            Some(held) => *held,
            None => {
                let held = record.always_holds(&stream)
                    || record.holds(
                        &stream,
                        match saved.get(stream.as_str()) {
                            Some(object) => Some(object.clone()),
                            None => repo.object_at_in(objects, &head, &stream)?,
                        }
                        .as_ref(),
                    );
                holds.insert(stream.clone(), held);
                held
            }
        };
        let mut found = Found {
            path: file.path.clone(),
            unheld: None,
            file: None,
        };
        // another machine's version is not this one's to compare against:
        // the live file is what this machine has
        let object = if held {
            restored(objects, &file.path)?
        } else if let Some(live) = usable_live(repo, &local)? {
            // a file missing here while its stream was not selected is not
            // a deletion this machine made: without a base, the pull
            // applies the saved version
            found.unheld = Some(match &live {
                Some(_) => held_base_in(repo, objects, &head, &record, &stream, &file.path)?,
                None => None,
            });
            live
        } else {
            // a directory or unreadable path where the file belongs is that
            // path's own conflict, decided when the pull plans it, not a
            // reason to stop every other file
            restored(objects, &file.path)?
        };
        if let Some((mode, oid)) = object {
            found.file = Some(SharedFile { local, mode, oid });
        }
        if found.unheld.is_none() && found.file.is_none() {
            return Ok(None);
        }
        Ok(Some(found))
    };
    let mut merge = |found: Vec<Found>| {
        for found in found {
            if let Some(base) = found.unheld {
                report.unheld.insert(found.path.clone(), base);
            }
            if let Some(file) = found.file {
                report.files.insert(found.path, file);
            }
        }
    };

    let threads = walk_threads();
    if threads > 1 && listing.len() > WALK_FILES_MIN {
        let chunk = listing.len().div_ceil(threads);
        let walked: Vec<Result<Vec<Found>>> = std::thread::scope(|scope| {
            let walk = &walk;
            let handles: Vec<_> = listing
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        let objects = repo.gix()?;
                        let mut holds = BTreeMap::new();
                        let mut found = Vec::new();
                        for file in part {
                            if let Some(one) = walk(file, &objects, &mut holds)? {
                                found.push(one);
                            }
                        }
                        Ok(found)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("history walk thread"))
                .collect()
        });
        for part in walked {
            merge(part?);
        }
    } else {
        let mut holds = BTreeMap::new();
        let mut found = Vec::new();
        for file in &listing {
            if let Some(one) = walk(file, &objects, &mut holds)? {
                found.push(one);
            }
        }
        merge(found);
    }
    Ok(report)
}

/// The version of `path` this machine last held, from its stream's frozen
/// version, to compare the live file with. An encrypted version is
/// compared by what it decrypts to, like the live file; one that cannot be
/// decrypted here gives no baseline, so the pull asks rather than guesses.
/// The caller's open repository is passed through, so a walk over many files
/// opens it once rather than once per file.
fn held_base_in(
    repo: &HistoryRepo,
    objects: &gix::Repository,
    head: &str,
    held: &crate::history::held::Held,
    stream: &str,
    path: &str,
) -> Result<Option<(String, String)>> {
    let Some(frozen) = held.frozen(stream) else {
        return Ok(None);
    };
    let object = if path == stream {
        Some(frozen.clone())
    } else {
        match path
            .strip_prefix(stream)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            Some(relative) if frozen.0 == "040000" => {
                repo.object_at_in(objects, &frozen.1, relative)?
            }
            _ => None,
        }
    };
    let Some(object) = object else {
        return Ok(None);
    };
    let encrypted =
        crate::history::manifest::Manifest::read_in(objects, head)?.is_some_and(|manifest| {
            manifest.encrypted_paths().iter().any(|prefix| {
                path == prefix
                    || path
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        });
    if !encrypted {
        return Ok(Some(object));
    }
    Ok(super::files::decrypt_in(
        repo,
        objects,
        path,
        &object,
        console::user_attended_stderr(),
    )
    .ok())
}

/// The live object at `path`, or `None` when the path itself cannot stand
/// in for a file (see [`super::apply::UnusableLive`]).
pub(super) fn usable_live(
    repo: &HistoryRepo,
    path: &std::path::Path,
) -> Result<Option<Option<(String, String)>>> {
    match super::apply::live_object(repo, path) {
        Ok(live) => Ok(Some(live)),
        Err(err) if err.downcast_ref::<super::apply::UnusableLive>().is_some() => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_enrollment_blocks_publication_independently_of_wording() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::history::checkpoint::Store::open_in(temp.path()).unwrap();
        let Some(repo) = store.repo() else { return };
        let tracked = TrackedSet {
            invalid: vec![crate::history::store::PathReason {
                path: "unrepresentable".into(),
                reason: "not a portable location".into(),
            }],
            ..Default::default()
        };
        assert!(current(repo, &tracked).is_err());
    }

    /// A store whose saved tree holds `files` encrypted files, every one of
    /// them present and unchanged on disk.
    fn encrypted_walk_fixture(
        name: &str,
        files: usize,
    ) -> (
        tempfile::TempDir,
        HistoryRepo,
        std::path::PathBuf,
        TrackedSet,
        age::x25519::Identity,
    ) {
        use crate::history::manifest::{Enrollment, Manifest};
        use crate::history::tracked::TrackedEntry;

        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let roots = Roots::current();
        let dir = roots.home.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let entries: Vec<(String, String, String)> = (0..files)
            .map(|index| {
                let path = roots
                    .branch_path(&dir.join(format!("file-{index}")), None)
                    .unwrap();
                let contents = format!("contents {index}");
                std::fs::write(dir.join(format!("file-{index}")), &contents).unwrap();
                let encoded = super::super::files::encode(
                    &path,
                    "100644",
                    contents.as_bytes(),
                    "test",
                    &recipients,
                )
                .unwrap();
                ("100644".into(), repo.hash_blob(&encoded).unwrap(), path)
            })
            .collect();
        let tree = repo.write_tree(&entries).unwrap();
        let tree = Manifest {
            enrollment: vec![Enrollment {
                path: roots.branch_path(&dir, None).unwrap(),
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
        .write(&repo, &tree)
        .unwrap();
        let commit = repo.commit_tree(&tree, vec![], "encrypted files").unwrap();
        repo.update_history_head(&commit, None).unwrap();

        let mut policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        policy.encrypt = true;
        let tracked = TrackedSet {
            entries: vec![TrackedEntry::new(dir.clone(), "track", policy)],
            ..Default::default()
        };
        (tmp, repo, dir, tracked, key)
    }

    /// A walk of the saved files opens the repository once, not once per
    /// file. Opening this repository scans every pack index, so a decryption
    /// per file made a sync of a few thousand files spend seconds scanning
    /// indexes before it compared a single live file.
    #[test]
    fn a_saved_file_walk_opens_the_repository_once() {
        use crate::history::shadow::{gix_opens, reset_gix_opens};
        use age::secrecy::ExposeSecret;

        const FILES: usize = 40;

        let (_tmp, repo, dir, tracked, key) = encrypted_walk_fixture("dot-walk-open-count", FILES);
        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
        reset_gix_opens();
        let report = current(&repo, &tracked).unwrap();
        let opens = gix_opens();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            report.files.len(),
            FILES,
            "the walk did not read every saved file: {:?}",
            report.files.keys().collect::<Vec<_>>()
        );
        assert!(
            opens <= 8,
            "a walk of {FILES} saved files opened the repository {opens} times"
        );
    }

    /// The walk answers the same spread across threads as it does on one: same
    /// objects, same baselines, same checkpoint.
    #[test]
    fn the_parallel_walk_agrees_with_the_serial_one() {
        use age::secrecy::ExposeSecret;

        let (_tmp, repo, dir, tracked, key) = encrypted_walk_fixture("dot-walk-parallel", 130);
        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());

        set_walk_threads(Some(1));
        let serial = current(&repo, &tracked).unwrap();
        set_walk_threads(Some(4));
        let parallel = current(&repo, &tracked).unwrap();
        set_walk_threads(None);

        let _ = std::fs::remove_dir_all(&dir);
        let shape = |report: &ShareReport| {
            report
                .files
                .iter()
                .map(|(path, file)| {
                    (
                        path.clone(),
                        file.mode.clone(),
                        file.oid.clone(),
                        file.local.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&serial), shape(&parallel));
        assert_eq!(serial.unheld, parallel.unheld);
        assert_eq!(serial.checkpoint, parallel.checkpoint);
        assert_eq!(serial.files.len(), 130, "the walk lost files");
    }
}
