//! Capturing checkpoints: the one entry point every capture goes through.
//!
//! Content is deduplicated, records are not: an automatic capture whose
//! snapshot tree and coverage equal the newest checkpoint's records nothing,
//! while a draft carrying metadata of its own (a description, a label, an
//! operation) always writes an ordinary commit, reusing the tracked-file tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr};

use std::collections::BTreeSet;

/// A subtree promotion: the entry's index and the children that were named.
type PartialPromotion = (usize, Vec<PathBuf>);

use super::shadow::{self, HistoryRepo, Overlay};
use super::store::{
    self, Annotation, Changes, Checkpoint, DescriptionSource, Entry, Index, IndexEntry, Machine,
    Operation, TreeInfo, Trigger,
};
use super::tracked::{TrackedEntry, TrackedSet, tree_path_to_display};
use mise_util::file::display_path;
use mise_util::lock_file::LockFile;

mod preimages;

/// The most paths a computed description names before `+N more`.
const DESCRIPTION_PATHS: usize = 6;
const DESCRIPTION_MAX: usize = 200;
/// The most paths a `changes` record lists.
const CHANGES_MAX: usize = 2000;

/// What a caller wants captured.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub trigger: Option<Trigger>,
    /// A caller-supplied description; the computed one is kept as `summary`.
    pub description: Option<String>,
    pub description_source: Option<DescriptionSource>,
    pub task: Option<String>,
    pub labels: Vec<String>,
    /// Live contents captured for a `*-before` checkpoint; never promoted.
    pub protective: bool,
    pub operation: Option<Operation>,
    /// A uuid reserved when the operation began, so the marker and the
    /// pending record name the outcome before it exists.
    pub uuid: Option<String>,
    /// Paths named explicitly: manual-save entries covering them are read
    /// live and promoted, becoming their new saved version.
    pub explicit_paths: Vec<PathBuf>,
    /// Explicit enrollment removals; never remove the corresponding live files.
    pub untrack: Vec<PathBuf>,
    /// Paths the watcher is throttling: their files are carried forward
    /// from the newest checkpoint instead of read live, so a capture for
    /// another path never defeats their schedule. Ignored by protective
    /// captures and explicit saves.
    pub held: Vec<PathBuf>,
    /// Record nothing when the snapshot equals the newest checkpoint's,
    /// even though the draft carries metadata: re-tracking a path that is
    /// already tracked has something to say only if it changed.
    pub skip_unchanged: bool,
    /// Re-encrypt to the current recipients every encrypted file the
    /// checkpoint holds under other recipients, including the saved
    /// versions it carries forward rather than reads live.
    pub re_encrypt: bool,
    /// Commit the snapshot without moving the published history. A fresh
    /// adoption's protective snapshot records files this machine does not have
    /// as absent; publishing that would delete them for every other machine.
    pub recovery_only: bool,
}

impl Draft {
    pub fn new(trigger: Trigger) -> Self {
        Self {
            trigger: Some(trigger),
            ..Default::default()
        }
    }

    fn trigger(&self) -> Trigger {
        self.trigger.unwrap_or(Trigger::Edit)
    }

    /// Whether the draft carries something a deduplicated capture would lose.
    fn has_metadata(&self) -> bool {
        !self.trigger().is_automatic()
            || self.description.is_some()
            || self.task.is_some()
            || !self.labels.is_empty()
            || self.protective
            || self.operation.is_some()
    }
}

/// Whether two captures omitted, left incomplete and skipped the same paths.
/// Reasons are not compared: a checkpoint read back from Git keeps the paths
/// but not the wording, and records nested repositories among the omitted.
fn same_coverage(previous: &store::Coverage, current: &store::Coverage) -> bool {
    let omitted = |coverage: &store::Coverage| -> BTreeSet<String> {
        coverage
            .omitted
            .iter()
            .chain(&coverage.nested)
            .map(|reason| reason.path.clone())
            .collect()
    };
    let incomplete = |coverage: &store::Coverage| -> BTreeSet<String> {
        coverage
            .incomplete
            .iter()
            .map(|reason| reason.path.clone())
            .collect()
    };
    // the capture state (live, saved, protective) varies with the trigger,
    // and a checkpoint read back from Git does not keep where it was declared
    let entries = |coverage: &store::Coverage| -> Vec<store::CoverageEntry> {
        coverage
            .entries
            .iter()
            .cloned()
            .map(|mut entry| {
                entry.state.clear();
                entry.declared_in = None;
                entry
            })
            .collect()
    };
    omitted(previous) == omitted(current)
        && incomplete(previous) == incomplete(current)
        && entries(previous) == entries(current)
        && previous.exclude == current.exclude
        && previous.matcher == current.matcher
}

#[derive(Debug)]
pub enum Outcome {
    Created(Box<Entry>),
    /// The tracked state equals the newest checkpoint's; nothing recorded.
    Unchanged,
    /// No capture could be taken (no usable git); the reason.
    Unavailable(String),
}

/// An open history store.
#[derive(Debug)]
pub struct Store {
    state_dir: PathBuf,
    repo: Option<HistoryRepo>,
    unavailable: Option<String>,
    machine: Machine,
}

impl Store {
    pub(crate) fn open_in(state_dir: &Path) -> Result<Self> {
        store::ensure_store_dir_in(state_dir)?;
        let machine = store::machine();
        let (repo, unavailable) = match HistoryRepo::open_or_init_in(state_dir) {
            Ok(Some(repo)) => (Some(repo), None),
            Ok(None) => (None, Some(shadow::unavailable_reason())),
            Err(err) => (None, Some(format!("{err:#}"))),
        };
        let store = Self {
            state_dir: state_dir.to_path_buf(),
            repo,
            unavailable,
            machine,
        };
        super::purge::recover_interrupted(&store)?;
        // the index is a cache of the repository: rebuild it when it is
        // missing but checkpoints exist
        if !store::index_exists_in(state_dir)
            && let Some(repo) = &store.repo
            && repo.ref_oid(HistoryRepo::HISTORY_REF)?.is_some()
        {
            info!("history: rebuilding the checkpoint index from the repository");
            store.rebuild_index()?;
        }
        Ok(store)
    }

    pub fn open() -> Result<Self> {
        Self::open_in(&super::local::root())
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn repo(&self) -> Option<&HistoryRepo> {
        self.repo.as_ref()
    }

    pub(crate) fn machine(&self) -> &Machine {
        &self.machine
    }

    /// Why no content can be captured, if git is unusable.
    pub fn unavailable(&self) -> Option<&str> {
        self.unavailable.as_deref()
    }

    /// Serializes captures and index writes.
    pub(crate) fn lock(&self) -> Result<fslock::LockFile> {
        LockFile::at(&store::store_lock_path_in(&self.state_dir))
            .with_callback(|path| {
                debug!("waiting for the history store lock {}", display_path(path));
            })
            .lock()
    }

    pub(crate) fn list(&self) -> Result<Vec<Entry>> {
        store::list_in(&self.state_dir)
    }

    /// How many checkpoints are indexed, without reading their records.
    pub fn checkpoint_count(&self) -> Result<usize> {
        store::count_in(&self.state_dir)
    }

    /// The newest checkpoint, without reading the older ones.
    pub fn latest(&self) -> Result<Option<Entry>> {
        store::latest_in(&self.state_dir)
    }

    /// The newest checkpoint holding a content snapshot, without reading the
    /// older ones.
    pub fn latest_with_snapshot(&self) -> Result<Option<Entry>> {
        store::latest_snapshot_entry_in(&self.state_dir)
    }

    /// The id and uuid of the newest checkpoint holding a content snapshot:
    /// the one an unchanged capture compares against.
    pub(crate) fn latest_snapshot(&self) -> Result<Option<(u64, String)>> {
        let index = store::load_index_in(&self.state_dir)?;
        Ok(index.entries.iter().rev().find_map(|entry| {
            store::read_meta_cache_in(&self.state_dir, &entry.uuid)
                .ok()
                .flatten()
                .is_some_and(|checkpoint| checkpoint.tree.snapshot.is_some())
                .then(|| (entry.id, entry.uuid.clone()))
        }))
    }

    /// Reserves the next checkpoint id.
    pub(crate) fn reserve_id(&self) -> Result<u64> {
        let mut index = store::load_index_in(&self.state_dir)?;
        let id = index.next_id.max(1);
        index.next_id = id + 1;
        store::write_index_in(&self.state_dir, &index)?;
        Ok(id)
    }

    /// Captures the tracked set into a checkpoint. Takes the store lock.
    pub fn attempt(&self, tracked: &TrackedSet, draft: Draft) -> Result<Outcome> {
        let _lock = self.lock()?;
        self.attempt_locked(tracked, draft, None)
    }

    /// Like [`attempt`], with a reserved id and the lock already held.
    pub(crate) fn attempt_locked(
        &self,
        tracked: &TrackedSet,
        draft: Draft,
        reserved_id: Option<u64>,
    ) -> Result<Outcome> {
        if self.repo.is_none() {
            return Ok(Outcome::Unavailable(
                self.unavailable
                    .clone()
                    .unwrap_or_else(shadow::unavailable_reason),
            ));
        }
        let resolved = match &self.repo {
            Some(repo) => super::enrollment::resolve(
                &self.state_dir,
                repo,
                tracked,
                if draft.trigger() == Trigger::Baseline {
                    &draft.explicit_paths
                } else {
                    &[]
                },
                &draft.untrack,
            )?,
            None => tracked.clone(),
        };
        let tracked = &resolved;
        if tracked.entries.is_empty()
            && !draft.has_metadata()
            && self
                .repo
                .as_ref()
                .map(|repo| repo.ref_oid(HistoryRepo::HISTORY_REF))
                .transpose()?
                .flatten()
                .is_none()
        {
            // A service may watch policy before the first enrollment. Do not
            // manufacture an unrelated empty root before --adopt adoption.
            return Ok(Outcome::Unchanged);
        }
        let mut index = store::load_index_in(&self.state_dir)?;
        // Append only to an index current in both senses: the branch head it
        // ends at, and the local context that localized its entries. Otherwise
        // the capture would stamp the current context onto stale views.
        let head_matches = match &self.repo {
            Some(repo) => {
                repo.ref_oid(HistoryRepo::HISTORY_REF)?.as_deref()
                    == index.entries.last().map(|entry| entry.commit.as_str())
            }
            None => true,
        };
        if !head_matches || !store::index_context_matches_in(&self.state_dir)? {
            index = self.rebuild_index_locked()?;
        }
        // Metadata-only records (for example an operation while git was
        // unavailable) must not hide the last usable content baseline.
        let previous_tree = index.entries.iter().rev().find_map(|entry| {
            store::read_meta_cache_in(&self.state_dir, &entry.uuid)
                .ok()
                .flatten()
                .and_then(|checkpoint| {
                    checkpoint
                        .tree
                        .snapshot
                        .clone()
                        .map(|tree| (checkpoint, tree))
                })
        });
        let uuid = draft.uuid.clone().unwrap_or_else(store::new_uuid);
        // **The refusal lives here, where a checkpoint is about to be
        // written, and nowhere earlier.** An `[history] exclude` rule the
        // matcher cannot compile must not quietly broaden a stored — and
        // publishable — snapshot to the paths it was written to leave out.
        // Walking is not storing: `mise dot paths`, the previews, `mise
        // dot status` and the watch set all still work and report the
        // rule, so the command that diagnoses the problem is not the
        // command it breaks.
        let (mut walk, walk_error) = match tracked
            .refuse_unusable_exclusions()
            .and_then(|()| tracked.walk())
        {
            Ok(walk) => (walk, None),
            Err(err) if draft.operation.is_some() => {
                // Keep the operation journal even when its outcome cannot be
                // captured. Never substitute a partial or empty snapshot.
                warn!("history: snapshot failed: {err:#}");
                (Default::default(), Some(format!("{err:#}")))
            }
            Err(err) => return Err(err),
        };
        let scan_notices: Vec<_> = walk
            .warnings
            .iter()
            .map(|warning| format!("history: {warning}"))
            .collect();
        self.deliver_capture_notices(&scan_notices, !draft.protective && heard(&draft));
        report_omissions(&walk, &draft);
        // manual-save entries: carried forward from their promoted version
        // unless named explicitly (promoted) or captured protectively
        let promoted: BTreeSet<String> = previous_tree
            .as_ref()
            .map(|(record, _)| {
                record
                    .tree
                    .coverage
                    .entries
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect()
            })
            .unwrap_or_default();
        let manual = manual_plan(&walk, &draft, &promoted);
        // a selected stream whose saved version this machine never held is
        // carried like a manual one, not captured: see `super::held`
        let parent_commit = match &self.repo {
            Some(repo) => repo.ref_oid(HistoryRepo::HISTORY_REF)?,
            None => None,
        };
        let mut held = match &self.repo {
            Some(repo) => Some(super::held::Held::load(repo)?),
            None => None,
        };
        let streams = match (&self.repo, &held) {
            (Some(repo), Some(held)) => {
                super::held::streams(repo, held, parent_commit.as_deref(), &walk)?
            }
            _ => super::held::Streams::default(),
        };
        // said to a save the user ran; a pull's own protective capture is
        // about to apply these, and the watcher's would repeat it on every
        // edit
        if !streams.carry.is_empty() && !draft.protective && heard(&draft) {
            let notices: Vec<String> = streams
                .carry
                .iter()
                .map(|index| {
                    format!(
                        "history: {} has a version saved by another machine while it was not selected here; `mise dot pull` applies it, and saves resume after that",
                        walk.entries[*index].display()
                    )
                })
                .collect();
            self.deliver_capture_notices(&notices, true);
        }
        let carried: Vec<usize> = manual.carry.iter().chain(&streams.carry).copied().collect();
        // a carried entry's live files are neither read nor recorded: its
        // content and modes come from the parent
        if !carried.is_empty() {
            let owners: BTreeSet<usize> = carried.iter().copied().collect();
            let dropped: BTreeSet<PathBuf> = walk
                .files
                .iter()
                .filter(|(_, (owner, _))| owners.contains(owner))
                .map(|(path, _)| path.clone())
                .collect();
            for path in &dropped {
                walk.files.remove(path);
            }
            for root in &mut walk.roots {
                root.files
                    .retain(|rel| !dropped.contains(&root.path.join(rel)));
            }
        }
        // Live modes plus the ordinary parent's modes for carried entries.
        // Protective commits use the same history, not a separate saved state.
        let roots = super::sync::layout::Roots::current();
        let mut modes = file_modes(&walk, &roots);
        // a directory the live walk observed has its live mode (or the
        // default), never a saved one carried forward
        let observed: BTreeSet<String> = walk
            .files
            .iter()
            .flat_map(|(path, (owner, _))| mode_ancestors(path, &walk.entries[*owner].path, &roots))
            .map(display_path)
            .collect();
        if !carried.is_empty() {
            let carried: Vec<String> = carried
                .iter()
                .map(|index| walk.entries[*index].display())
                .collect();
            for (path, bits) in self.saved_modes(&index, &carried) {
                if !observed.contains(&path) {
                    modes.entry(path).or_insert(bits);
                }
            }
        }
        // a held path keeps the mode the previous checkpoint recorded (or
        // none), like its content
        if !draft.held.is_empty() && !draft.protective && draft.explicit_paths.is_empty() {
            for held in &draft.held {
                let display = display_path(held);
                modes.remove(&display);
                if let Some((previous_checkpoint, _)) = &previous_tree
                    && let Some(bits) = previous_checkpoint.tree.modes.get(&display)
                {
                    modes.insert(display, *bits);
                }
            }
        }
        let mut coverage = tracked.coverage(&walk);
        // a re-encryption records the current recipients even when every
        // encrypted file is carried forward
        let recipients =
            if draft.re_encrypt || walk.files.values().any(|(_, policy)| policy.encrypt) {
                tracked.manifest.recipients.clone()
            } else {
                vec![]
            };
        let mut re_encrypted = vec![];
        // the snapshot before re-encryption: the description names content
        // changes, and re-encrypting a file changes no contents
        let mut content_tree = None;
        let (snapshot, roots, available, reason) = match (&self.repo, walk_error) {
            (_, Some(reason)) => (None, vec![], false, Some(reason)),
            (Some(repo), None) => {
                match repo.capture_tracked(&walk, &recipients, console::user_attended_stderr()) {
                    Ok(result) => {
                        coverage.omitted.extend(result.omitted.iter().cloned());
                        for denial in &result.permission_denied {
                            if !walk
                                .permission_denied
                                .iter()
                                .any(|found| found.path == denial.path)
                            {
                                walk.permission_denied.push(denial.clone());
                            }
                        }
                        let mut warned = std::collections::BTreeSet::new();
                        for denial in &walk.permission_denied {
                            if warned.insert(denial.path.as_str()) {
                                warn!(
                                    "history: {}",
                                    super::health::permission_report(&denial.path, &denial.reason)
                                );
                            }
                        }
                        for omitted in &result.omitted {
                            if !walk
                                .permission_denied
                                .iter()
                                .any(|denial| denial.path == omitted.path)
                            {
                                warn!(
                                    "history: {} was not captured: {}",
                                    omitted.path, omitted.reason
                                );
                            }
                        }
                        let (composed, partial) = self.compose_manual(
                            repo,
                            &result.tree,
                            ManualContext {
                                entries: &walk.entries,
                                manual: &manual,
                                parent_commit: parent_commit.as_deref(),
                                draft: &draft,
                            },
                        )?;
                        let composed = carry_streams(
                            repo,
                            &composed,
                            parent_commit.as_deref(),
                            &walk.entries,
                            &streams.carry,
                        )?;
                        // a subtree promotion keeps the saved modes of the
                        // siblings it did not name, like their content
                        for (entry_index, children) in &partial {
                            let entry = walk.entries[*entry_index].display();
                            let named: Vec<String> =
                                children.iter().map(mise_util::file::display_path).collect();
                            let is_named =
                                |path: &str| named.iter().any(|child| under_entry(path, child));
                            // an unnamed sibling file keeps its saved mode; a
                            // directory the walk observed (the entry itself, a
                            // subdirectory, a parent) has its live mode
                            modes.retain(|path, _| {
                                !under_entry(path, &entry)
                                    || is_named(path)
                                    || observed.contains(path)
                            });
                            for (path, bits) in
                                self.saved_modes(&index, std::slice::from_ref(&entry))
                            {
                                if !is_named(&path) && !observed.contains(&path) {
                                    modes.entry(path).or_insert(bits);
                                }
                            }
                        }
                        let composed = self.hold_paths(
                            repo,
                            &composed,
                            &draft,
                            previous_tree.as_ref().map(|(_, tree)| tree.as_str()),
                            &walk.entries,
                        )?;
                        let omissions: Vec<_> = coverage
                            .omitted
                            .iter()
                            .chain(&coverage.incomplete)
                            .collect();
                        let composed = retain_omitted(
                            repo,
                            &composed,
                            previous_tree
                                .as_ref()
                                .map(|(record, tree)| (record, tree.as_str())),
                            tracked,
                            &omissions,
                            &mut modes,
                            &walk,
                        )?;
                        let mut manifest = super::manifest::Manifest::read(repo, &composed)?
                            .ok_or_else(|| {
                                eyre::eyre!("captured tree is missing enrollment metadata")
                            })?;
                        manifest.capture_permissions(&walk.entries, &modes)?;
                        let mut composed = manifest.write(repo, &composed)?;
                        if draft.re_encrypt {
                            content_tree = Some(composed.clone());
                            (composed, re_encrypted) = super::sync::files::re_encrypt(
                                repo,
                                &composed,
                                previous_tree.as_ref().map(|(_, tree)| tree.as_str()),
                                console::user_attended_stderr(),
                            )?;
                        }
                        (Some(composed), result.roots, true, None)
                    }
                    Err(err) => {
                        warn!("history: snapshot failed: {err:#}");
                        (None, vec![], false, Some(format!("{err:#}")))
                    }
                }
            }
            (None, None) => (None, vec![], false, self.unavailable.clone()),
        };
        for (index, entry) in walk.entries.iter().enumerate() {
            if entry.policy.autosave {
                continue;
            }
            let Some(record) = coverage
                .entries
                .iter_mut()
                .find(|record| record.path == entry.display())
            else {
                continue;
            };
            if manual.promote.contains(&index) {
                record.state = "live".into();
            } else {
                record.state = "saved".into();
            }
        }
        if (!draft.has_metadata() || draft.skip_unchanged)
            && let Some((previous_checkpoint, tree)) = &previous_tree
            && snapshot.as_deref() == Some(tree.as_str())
            && (!cfg!(unix) || previous_checkpoint.tree.modes == modes)
            // a reused checkpoint must also have judged coverage the same
            // way: an omission it never recorded would read as a covered
            // path that is absent
            && (!draft.skip_unchanged || same_coverage(
                &previous_checkpoint.tree.coverage,
                &tracked.shared_coverage(coverage.clone(), &walk)
            ))
        {
            debug!(
                "history: nothing changed since checkpoint {}",
                previous_checkpoint.uuid
            );
            if let Some(repo) = &self.repo {
                super::enrollment::confirm(&self.state_dir, repo, tracked)?;
            }
            if let (Some(repo), Some(held)) = (&self.repo, &mut held) {
                observe_held(repo, held, streams, parent_commit.as_deref())?;
            }
            if draft.re_encrypt {
                info!("history: {}", re_encrypt_report(&re_encrypted));
            }
            record_permission_denials(&self.state_dir, &walk.permission_denied)?;
            return Ok(Outcome::Unchanged);
        }
        if !draft.has_metadata() && snapshot.is_none() {
            return Ok(Outcome::Unavailable(
                reason.unwrap_or_else(shadow::unavailable_reason),
            ));
        }
        // Enrollment is transactional with its initial content baseline. Do
        // not commit even a labeled Baseline record when capture failed: the
        // caller will restore the declaration after receiving Unavailable.
        if draft.trigger() == Trigger::Baseline && snapshot.is_none() {
            return Ok(Outcome::Unavailable(
                reason.unwrap_or_else(shadow::unavailable_reason),
            ));
        }
        let mut changes = match (&self.repo, &snapshot) {
            (Some(repo), Some(tree)) => {
                let since = previous_tree
                    .as_ref()
                    .map(|(checkpoint, _)| checkpoint.uuid.clone());
                let from = previous_tree.as_ref().map(|(_, tree)| tree.as_str());
                let to = content_tree.as_deref().unwrap_or(tree);
                changes_from(repo, from, to, since)?
            }
            _ => Changes::default(),
        };
        // the same bytes under other permissions is a change the tree diff
        // does not show: a path-scoped `latest` and `--path` must see it
        if snapshot.is_some()
            && let Some((previous_checkpoint, _)) = &previous_tree
        {
            let previous_modes = &previous_checkpoint.tree.modes;
            let mode_only: BTreeSet<&String> = modes
                .keys()
                .chain(previous_modes.keys())
                .filter(|path| modes.get(*path) != previous_modes.get(*path))
                .filter(|path| !changes.touches(path))
                .collect();
            changes.modified.extend(mode_only.into_iter().cloned());
        }
        // a manual-save entry carried forward holds its saved version by
        // definition: a difference against a protective capture of its live
        // contents is not a change this checkpoint made, and neither is an
        // unheld stream's
        if !carried.is_empty() {
            let under = |path: &str, entry: &str| {
                path == entry
                    || path
                        .strip_prefix(entry)
                        .is_some_and(|rest| rest.starts_with('/'))
            };
            // an entry nested in a carried one and captured itself keeps
            // its changes (see `carry_streams`)
            let captured: Vec<String> = walk
                .entries
                .iter()
                .enumerate()
                .filter(|(index, _)| !carried.contains(index))
                .map(|(_, entry)| entry.display())
                .collect();
            let carried: Vec<String> = carried
                .iter()
                .map(|index| walk.entries[*index].display())
                .collect();
            let keep = |path: &String| {
                !carried.iter().any(|entry| under(path, entry))
                    || captured.iter().any(|nested| {
                        under(path, nested)
                            && carried
                                .iter()
                                .any(|entry| under(nested, entry) && nested != entry)
                    })
            };
            changes.added.retain(keep);
            changes.modified.retain(keep);
            changes.removed.retain(keep);
        }
        let total_files: u64 = roots.iter().map(|root| root.files).sum();
        let mut summary = describe(&draft, &changes, previous_tree.is_some(), total_files);
        if changes.is_empty() && !re_encrypted.is_empty() && previous_tree.is_some() {
            summary = re_encrypt_report(&re_encrypted);
        }
        let (description, description_source) = match &draft.description {
            Some(text) => (
                text.clone(),
                draft.description_source.unwrap_or(DescriptionSource::User),
            ),
            None => (summary.clone(), DescriptionSource::Computed),
        };
        let mut operation = draft.operation.clone();
        if let Some(operation) = &mut operation
            && matches!(
                operation.kind,
                store::OperationKind::Bootstrap | store::OperationKind::Capture
            )
        {
            let mut affected: BTreeSet<String> = changes
                .added
                .iter()
                .chain(&changes.modified)
                .chain(&changes.removed)
                .cloned()
                .collect();
            // Display summaries are capped; the recovery contract is not.
            if changes.truncated
                && let (Some(repo), Some(tree)) = (&self.repo, &snapshot)
            {
                affected.extend(
                    repo.changes(previous_tree.as_ref().map(|(_, tree)| tree.as_str()), tree)?
                        .into_iter()
                        .filter(|change| !change.path.starts_with(".mise-history/"))
                        .map(|change| tree_path_to_display(&change.path)),
                );
            }
            operation.affected.clear();
            for path in affected {
                let local = mise_util::file::replace_path(&path);
                // Enrollment changes are not file deletions. Nor can a newly
                // enrolled file acquire a fictional, absent before version.
                let previously_tracked = previous_tree.as_ref().is_some_and(|(record, _)| {
                    record
                        .tree
                        .coverage
                        .entries
                        .iter()
                        .any(|entry| under_entry(&path, &entry.path))
                });
                if previously_tracked
                    && tracked.would_retain(&local)?
                    && (operation.kind == store::OperationKind::Capture
                        || draft
                            .explicit_paths
                            .iter()
                            .any(|selected| local.starts_with(selected)))
                {
                    operation.affected.push(path);
                }
            }
        }
        let checkpoint = Checkpoint {
            schema_version: store::SCHEMA_VERSION,
            uuid,
            machine: self.machine.clone(),
            created_at: store::now_rfc3339(),
            mise_version: mise_util::deprecation::VERSION_PLAIN.clone(),
            trigger: draft.trigger(),
            description,
            description_source,
            summary,
            task: draft.task.clone(),
            labels: draft.labels.clone(),
            tree: TreeInfo {
                snapshot: snapshot.clone(),
                available,
                reason,
                roots,
                coverage,
                modes,
            },
            changes,
            operation,
        };
        let mut messages: Vec<String> = walk
            .capture_warnings
            .iter()
            .map(|warning| format!("history: {warning}"))
            .collect();
        if available
            && snapshot.is_some()
            && let Some(repo) = &self.repo
        {
            let previous_commit = previous_tree
                .as_ref()
                .and_then(|(checkpoint, _)| {
                    index
                        .entries
                        .iter()
                        .rev()
                        .find(|entry| entry.uuid == checkpoint.uuid)
                })
                .map(|entry| entry.commit.as_str());
            match narrowed_notices(repo, previous_commit, tracked) {
                Ok(narrowed) => messages.extend(narrowed),
                Err(err) => debug!("history: could not compare the previous selection: {err:#}"),
            }
        }
        let entry = self.commit_record_locked(
            checkpoint,
            index,
            reserved_id,
            &messages,
            !draft.protective && heard(&draft),
            draft.recovery_only,
        )?;
        if available
            && snapshot.is_some()
            && let Some(repo) = &self.repo
        {
            super::enrollment::confirm(&self.state_dir, repo, tracked)?;
            if let Some(held) = &mut held {
                observe_held(repo, held, streams, parent_commit.as_deref())?;
            }
        }
        if draft.re_encrypt && snapshot.is_some() {
            info!("history: {}", re_encrypt_report(&re_encrypted));
        }
        if available && snapshot.is_some() {
            record_permission_denials(&self.state_dir, &walk.permission_denied)?;
        }
        Ok(Outcome::Created(entry))
    }

    fn deliver_capture_notices(&self, messages: &[String], speak: bool) {
        for message in messages {
            if speak {
                super::notices::say(message);
            } else if let Err(err) = super::notices::record_in(&self.state_dir, message) {
                super::notices::say(message);
                debug!("history: could not keep the notice: {err}");
            }
        }
        if speak && let Err(err) = super::notices::forget_in(&self.state_dir, messages) {
            debug!("history: could not take back the said notices: {err}");
        }
    }

    /// Append one ordinary record while the store lock is held.
    fn commit_record_locked(
        &self,
        mut checkpoint: Checkpoint,
        mut index: Index,
        reserved_id: Option<u64>,
        messages: &[String],
        speak: bool,
        recovery_only: bool,
    ) -> Result<Box<Entry>> {
        let id = reserved_id.unwrap_or_else(|| {
            let id = index.next_id.max(1);
            index.next_id = id + 1;
            id
        });
        let commit = match &self.repo {
            Some(repo) => {
                let parent = repo.ref_oid(HistoryRepo::HISTORY_REF)?;
                let commit = repo
                    .write_checkpoint_commit(checkpoint.tree.snapshot.as_deref(), &checkpoint)
                    .wrap_err("writing the checkpoint")?;
                let advanced = if recovery_only {
                    // The snapshot stays reachable for undo, and out of the
                    // history every other machine fetches.
                    repo.retain_recovery(&commit)
                } else {
                    repo.update_history_head(&commit, parent.as_deref())
                };
                // Updating the ref makes the snapshot durable. Even a later
                // symbolic-HEAD, metadata-cache, index, or enrollment failure
                // must not lose its warnings. A failed snapshot can still
                // produce a journal record, but did not capture these files.
                if checkpoint.tree.available
                    && checkpoint.tree.snapshot.is_some()
                    && (advanced.is_ok()
                        || repo
                            .ref_oid(HistoryRepo::HISTORY_REF)
                            .ok()
                            .flatten()
                            .as_deref()
                            == Some(commit.as_str()))
                {
                    self.deliver_capture_notices(messages, speak);
                }
                advanced.wrap_err("recording the checkpoint")?;
                commit
            }
            None => String::new(),
        };
        if let Some(repo) = &self.repo {
            // The record is read back from Git so every machine reads the
            // same one. Skipped repositories are the exception: nothing is
            // written to the tree for them, and the shared commit trailer
            // is a format older clients parse with `deny_unknown_fields`,
            // so adding a field for them would stop those clients reading
            // this history at all. The list stays in this machine's own
            // record, which is where a rollback here consults it.
            let nested = std::mem::take(&mut checkpoint.tree.coverage.nested);
            // derived before the record is replaced, while the coverage
            // entries that decide a path's stream are still here
            let skipped = skipped_as_rebuilt(&checkpoint, &nested);
            checkpoint = repo.read_meta(&commit)?;
            // The trailer carried each of them as an ordinary omission,
            // which is how another machine learns about the skip at all.
            // On this one the better answer has just come back, so the
            // generic copy goes: one skip, said once, with the reason
            // that can be acted on.
            checkpoint
                .tree
                .coverage
                .omitted
                .retain(|omitted| !skipped.contains(&omitted.path));
            checkpoint.tree.coverage.nested = nested;
        }
        store::write_meta_cache_in(&self.state_dir, &checkpoint)?;
        index.entries.push(IndexEntry {
            id,
            uuid: checkpoint.uuid.clone(),
            commit: commit.clone(),
            created_at: checkpoint.created_at.clone(),
            trigger: checkpoint.trigger,
        });
        if index.next_id <= id {
            index.next_id = id + 1;
        }
        store::write_index_in(&self.state_dir, &index)?;
        store::write_index_context_in(&self.state_dir)?;
        debug!(
            "history: recorded checkpoint {id} ({}): {}",
            checkpoint.trigger.as_str(),
            checkpoint.description
        );
        Ok(Box::new(Entry {
            id,
            commit,
            checkpoint,
        }))
    }

    /// Carries the draft's held paths forward from the previous checkpoint:
    /// their live content is not what this capture records. Protective
    /// captures and explicit saves hold nothing.
    /// Held paths (files whose save is not due yet) take their previous
    /// version, or previous absence, from the newest checkpoint: a change,
    /// a creation, and a deletion are all held until the path is due. Held
    /// paths are files, matched exactly.
    fn hold_paths(
        &self,
        repo: &HistoryRepo,
        tree: &str,
        draft: &Draft,
        previous: Option<&str>,
        entries: &[TrackedEntry],
    ) -> Result<String> {
        if draft.held.is_empty() || draft.protective || !draft.explicit_paths.is_empty() {
            return Ok(tree.to_string());
        }
        let mut overlays = vec![];
        for held in &draft.held {
            let Some(entry) = super::tracked::owning_entry(entries, held) else {
                continue;
            };
            let tree_path = entry.tree_path(held)?;
            overlays.push(Overlay {
                object: previous
                    .map(|parent| repo.object_at(parent, &tree_path))
                    .transpose()?
                    .flatten(),
                path: tree_path,
            });
        }
        repo.compose(tree, &overlays)
    }

    fn compose_manual(
        &self,
        repo: &HistoryRepo,
        live_tree: &str,
        context: ManualContext<'_>,
    ) -> Result<(String, Vec<PartialPromotion>)> {
        let ManualContext {
            entries,
            manual,
            parent_commit,
            draft,
        } = context;
        let mut overlays = vec![];
        let mut partial_entries = vec![];
        for index in &manual.carry {
            let entry = &entries[*index];
            let path = entry.tree_path(&entry.path)?;
            let object = parent_commit
                .map(|head| repo.object_at(head, &path))
                .transpose()?
                .flatten();
            overlays.push(Overlay { path, object });
        }
        // A selective save replaces only named children of a manual directory.
        // Its siblings come from the ordinary parent, not a promotion branch.
        if let Some(head) = parent_commit {
            for index in &manual.promote {
                let entry = &entries[*index];
                let children: Vec<PathBuf> = draft
                    .explicit_paths
                    .iter()
                    .filter(|path| path.starts_with(&entry.path) && **path != entry.path)
                    .cloned()
                    .collect();
                if children.is_empty()
                    || draft
                        .explicit_paths
                        .iter()
                        .any(|path| entry.path.starts_with(path))
                {
                    continue;
                }
                let path = entry.tree_path(&entry.path)?;
                overlays.push(Overlay {
                    object: repo.object_at(head, &path)?,
                    path,
                });
                for child in &children {
                    let path = entry.tree_path(child)?;
                    overlays.push(Overlay {
                        object: repo.object_at(live_tree, &path)?,
                        path,
                    });
                }
                partial_entries.push((*index, children));
            }
        }
        Ok((repo.compose(live_tree, &overlays)?, partial_entries))
    }

    /// Manual files carry permission metadata from the ordinary parent,
    /// including the directories that contain them.
    fn saved_modes(&self, index: &store::Index, entries: &[String]) -> BTreeMap<String, u32> {
        index
            .entries
            .last()
            .and_then(|entry| {
                store::read_meta_cache_in(&self.state_dir, &entry.uuid)
                    .ok()
                    .flatten()
            })
            .map(|record| {
                record
                    .tree
                    .modes
                    .into_iter()
                    .filter(|(path, _)| {
                        entries
                            .iter()
                            .any(|entry| under_entry(path, entry) || under_entry(entry, path))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rebuilds the local index from ordinary commit ancestry.
    pub(crate) fn rebuild_index(&self) -> Result<Index> {
        let _lock = self.lock()?;
        self.rebuild_index_locked()
    }

    /// Brings the local index up to the branch head.
    ///
    /// When the index already covers an ancestor of the head, only the commits
    /// above it are read: a pulled checkpoint or an annotation must not replay
    /// and re-derive every historical commit before a capture.
    pub(crate) fn rebuild_index_locked(&self) -> Result<Index> {
        let Some(repo) = &self.repo else {
            return store::load_index_in(&self.state_dir);
        };
        let mut existing = store::load_index_in(&self.state_dir)?;
        // The index's entries carry metadata localized to the context that
        // derived it, so an index from another HOME or configuration must be
        // replayed, not extended. The newest baseline's view must also still
        // hold the snapshot a capture composes against.
        let extend = match existing.entries.last() {
            Some(last) => {
                repo.ref_oid(HistoryRepo::HISTORY_REF)?.as_deref() != Some(last.commit.as_str())
                    && store::index_context_matches_in(&self.state_dir)?
                    && store::read_meta_cache_in(&self.state_dir, &last.uuid)?
                        .is_some_and(|checkpoint| checkpoint.tree.snapshot.is_some())
            }
            None => false,
        };
        if extend {
            let last = existing
                .entries
                .last()
                .expect("checked above")
                .commit
                .clone();
            if let Some(fresh) = fresh_history(repo, &last)?
                && self.append_index_locked(repo, &mut existing, fresh)?
            {
                return Ok(existing);
            }
        }
        self.rebuild_full_index_locked(repo, existing)
    }

    /// Recomputes the index from ordinary ancestry, re-deriving a checkpoint's
    /// metadata whenever its cache is absent.
    fn rebuild_full_index_locked(
        &self,
        repo: &HistoryRepo,
        existing: store::Index,
    ) -> Result<Index> {
        let mut entries = vec![];
        let messages = repo.history_messages()?;
        // A fresh adoption's protective snapshot is not an ancestor of the
        // published history. Undo finds it by the commit the operation
        // recorded, so the rebuilt index keeps every private recovery tip.
        // Published history stays last: it is the baseline the next capture
        // compares against.
        let published: std::collections::BTreeSet<String> =
            messages.iter().map(|(commit, _)| commit.clone()).collect();
        let mut recovery = vec![];
        for (commit, message) in repo.recovery_commits()? {
            if !published.contains(&commit) {
                recovery.push((commit, message));
            }
        }
        // Recovery tips come first and published history last. Reversing the
        // combined list would make a private snapshot the baseline.
        let commits: Vec<_> = recovery
            .into_iter()
            .chain(messages.into_iter().rev())
            .map(|(commit, message)| Ok((commit, HistoryRepo::annotation_from_message(&message)?)))
            .collect::<Result<_>>()?;
        let mut annotations: BTreeMap<String, Vec<Annotation>> = BTreeMap::new();
        for (_, annotation) in &commits {
            if let Some((target, annotation)) = annotation {
                annotations
                    .entry(target.clone())
                    .or_default()
                    .push(annotation.clone());
            }
        }
        let gix = repo.gix()?;
        let mut caches = store::CacheBatch::new(&self.state_dir);
        for (commit, annotation) in commits {
            // Annotation commits remain in Git ancestry, but are not new file
            // checkpoints and must not move `latest` in the history browser.
            if annotation.is_some() {
                continue;
            }
            let mut checkpoint = match store::read_commit_meta_cache_in(&self.state_dir, &commit)? {
                Some(checkpoint) => checkpoint,
                None => {
                    let checkpoint = HistoryRepo::read_meta_in(&gix, &commit)?;
                    caches.write_commit_meta(&commit, &checkpoint)?;
                    checkpoint
                }
            };
            if let Some(annotations) = annotations.get(&commit) {
                for annotation in annotations {
                    annotation.apply_to(&mut checkpoint);
                }
            }
            caches.write_meta(&checkpoint)?;
            let id = existing.by_uuid(&commit).map(|entry| entry.id);
            entries.push((id, checkpoint, commit));
        }
        caches.finish()?;
        let mut next_id = existing.next_id.max(1);
        let mut index = Index {
            next_id,
            entries: vec![],
        };
        for (id, checkpoint, commit) in entries {
            let id = id.unwrap_or_else(|| {
                let id = next_id;
                next_id += 1;
                id
            });
            index.entries.push(IndexEntry {
                id,
                uuid: checkpoint.uuid,
                commit,
                created_at: checkpoint.created_at,
                trigger: checkpoint.trigger,
            });
        }
        index.next_id = next_id.max(index.entries.iter().map(|e| e.id + 1).max().unwrap_or(1));
        store::write_index_in(&self.state_dir, &index)?;
        store::write_index_context_in(&self.state_dir)?;
        Ok(index)
    }

    /// Extends an index that already covers `last` with only the commits above
    /// it. Existing checkpoint ids are kept; new checkpoints and annotations
    /// apply in ancestry order, as a full rebuild would have ordered them.
    fn append_index_locked(
        &self,
        repo: &HistoryRepo,
        index: &mut store::Index,
        commits: Vec<(String, String)>,
    ) -> Result<bool> {
        let gix = repo.gix()?;
        let mut parsed = Vec::with_capacity(commits.len());
        let mut annotations: BTreeMap<String, Vec<Annotation>> = BTreeMap::new();
        for (commit, message) in commits {
            let annotation = HistoryRepo::annotation_from_message(&message)?;
            if let Some((target, annotation)) = &annotation {
                annotations
                    .entry(target.clone())
                    .or_default()
                    .push(annotation.clone());
            }
            parsed.push((commit, annotation));
        }
        let mut caches = store::CacheBatch::new(&self.state_dir);
        // An annotation names a checkpoint that may already be indexed: its
        // index row (id, commit, time, trigger) does not change, and the
        // commit cache must stay annotation-free so removing the annotation
        // restores the derived metadata. Only the view is refreshed.
        //
        // A view derived here would have to re-apply every annotation this
        // commit already carried above the loaded view; the full rebuild
        // applies them in ancestry order. Load every view before touching
        // anything, so a missing one leaves the index whole for that rebuild.
        let mut views = BTreeMap::new();
        for target in annotations.keys() {
            let Some(entry) = index.entries.iter().find(|entry| &entry.commit == target) else {
                continue;
            };
            let Some(checkpoint) = store::read_meta_cache_in(&self.state_dir, &entry.uuid)? else {
                return Ok(false);
            };
            views.insert(target.clone(), checkpoint);
        }
        for (target, annotations) in &annotations {
            let Some(mut checkpoint) = views.remove(target) else {
                continue;
            };
            for annotation in annotations {
                annotation.apply_to(&mut checkpoint);
            }
            caches.write_meta(&checkpoint)?;
        }
        let mut next_id = index.next_id.max(1);
        for (commit, annotation) in parsed {
            if annotation.is_some() {
                continue;
            }
            let mut checkpoint = match store::read_commit_meta_cache_in(&self.state_dir, &commit)? {
                Some(checkpoint) => checkpoint,
                None => {
                    let checkpoint = HistoryRepo::read_meta_in(&gix, &commit)?;
                    caches.write_commit_meta(&commit, &checkpoint)?;
                    checkpoint
                }
            };
            if let Some(annotations) = annotations.get(&commit) {
                for annotation in annotations {
                    annotation.apply_to(&mut checkpoint);
                }
            }
            caches.write_meta(&checkpoint)?;
            index.entries.push(IndexEntry {
                id: next_id,
                uuid: checkpoint.uuid,
                commit,
                created_at: checkpoint.created_at,
                trigger: checkpoint.trigger,
            });
            next_id += 1;
        }
        caches.finish()?;
        index.next_id = next_id.max(
            index
                .entries
                .iter()
                .map(|entry| entry.id + 1)
                .max()
                .unwrap_or(1),
        );
        store::write_index_in(&self.state_dir, &index)?;
        store::write_index_context_in(&self.state_dir)?;
        Ok(true)
    }
}

/// The commits above `last` on a linear branch, oldest first, or `None` when
/// the head is not a linear descendant of `last`.
///
/// Only a linear suffix can be appended safely: a merge carries side ancestry
/// that an index built from the first-parent walk would silently omit, and a
/// topological walk of the whole branch can reach `last` before that side
/// ancestry. Any commit with other than one parent therefore sends the caller
/// back to the full rebuild.
fn fresh_history(repo: &HistoryRepo, last: &str) -> Result<Option<Vec<(String, String)>>> {
    let gix = repo.gix()?;
    let Some(mut head) = gix.try_find_reference(HistoryRepo::HISTORY_REF)? else {
        return Ok(None);
    };
    let mut commit = head.peel_to_id()?.detach();
    let mut fresh = vec![];
    loop {
        let id = commit.to_string();
        if id == last {
            fresh.reverse();
            return Ok(Some(fresh));
        }
        let object = gix.find_commit(commit)?;
        let mut parents = object.parent_ids();
        let Some(parent) = parents.next() else {
            return Ok(None);
        };
        if parents.next().is_some() {
            return Ok(None);
        }
        let message = object.message_raw()?;
        let message = String::from_utf8_lossy(message.as_ref()).trim().to_string();
        fresh.push((id, message));
        commit = parent.detach();
    }
}

/// Append annotation metadata to ordinary history and rebuild its derived view.
pub fn annotate(store: &Store, entry: &Entry, annotation: Annotation) -> Result<()> {
    let _lock = store.lock()?;
    if let Some(repo) = store.repo()
        && !entry.commit.is_empty()
    {
        repo.write_annotation(&entry.commit, &annotation)?;
        store.rebuild_index_locked()?;
        return Ok(());
    }
    let mut checkpoint = entry.checkpoint.clone();
    annotation.apply_to(&mut checkpoint);
    store::write_meta_cache_in(store.state_dir(), &checkpoint)
}

/// Everything composing manual-save entries into a snapshot needs.
struct ManualContext<'a> {
    entries: &'a [TrackedEntry],
    manual: &'a ManualPlan,
    parent_commit: Option<&'a str>,
    draft: &'a Draft,
}

/// Which manual-save entries a capture carries forward and which it
/// promotes.
#[derive(Debug, Default)]
struct ManualPlan {
    carry: Vec<usize>,
    promote: Vec<usize>,
}

/// Tells the user what the walk left out, so a credential store or a
/// nested repository under a tracked directory never looks saved. A
/// command the user ran (a save, a baseline, a bootstrap, rollback, or
/// undo outcome) lists each path; the watcher's captures and the
/// protective captures before an operation get one summary line, since
/// they run on every edit or are followed by the outcome's full report. A
/// baseline reports only the paths it enrolls, not those under entries
/// tracked earlier.
///
/// **One writer, so the comparison can be exact.** The skips reach the
/// trailer as tree paths, through `Checkpoint::portable_path`, and come
/// back as display paths through `tree_path_to_display`. The walk's own
/// display paths are written by `display_path`, which keeps the host's
/// separator and, off unix, does not shorten `$HOME` to `~` — so on
/// Windows the same skip is `C:\Users\me\.native\plugin` on one side
/// and `~/.native/plugin` on the other. Matching those two spellings is
/// not something a comparison can be taught: folding separators would
/// still leave the home prefix, and on unix it would call
/// `~/a/b` and a file genuinely named `a\b` the same path. So both sides
/// are put through the same pair of conversions and compared with `==`.
fn skipped_as_rebuilt(
    checkpoint: &Checkpoint,
    nested: &[super::store::PathReason],
) -> BTreeSet<String> {
    nested
        .iter()
        .filter_map(|skip| checkpoint.portable_path(&skip.path))
        .map(|tree_path| tree_path_to_display(&tree_path))
        .collect()
}

/// Writes the denials a capture observed into `health.json`, replacing
/// earlier denial lines and leaving every other degraded reason. An empty
/// list clears the denials: the observation could read what it tried.
fn record_permission_denials(state_dir: &Path, denied: &[super::store::PathReason]) -> Result<()> {
    let lines: Vec<String> = denied
        .iter()
        .map(|denial| super::health::permission_report(&denial.path, &denial.reason))
        .collect();
    let mut health = super::health::read(state_dir).unwrap_or_default();
    let before = health.watcher.degraded.clone();
    super::health::replace_permission_denials(&mut health.watcher.degraded, &lines);
    if health.watcher.degraded == before {
        return Ok(());
    }
    super::health::write(state_dir, &mut health)
}

fn report_omissions(walk: &super::tracked::Walk, draft: &Draft) {
    let trigger = draft.trigger();
    let explicit = trigger != Trigger::Edit && !draft.protective;
    let roots: Vec<String> = if trigger == Trigger::Baseline {
        draft.explicit_paths.iter().map(display_path).collect()
    } else {
        vec![]
    };
    let enrolled = |reported: &&store::PathReason| {
        roots.is_empty()
            || roots
                .iter()
                .any(|root| super::tracked::display_under(&reported.path, root))
    };
    let omitted: Vec<store::PathReason> = walk
        .omitted
        .iter()
        .filter(enrolled)
        .filter(|omitted| {
            !walk
                .permission_denied
                .iter()
                .any(|denial| denial.path == omitted.path)
        })
        .cloned()
        .collect();
    let nested: Vec<store::PathReason> = walk.nested.iter().filter(enrolled).cloned().collect();
    if omitted.is_empty() && nested.is_empty() {
        return;
    }
    if explicit {
        for line in super::tracked::omission_report(&omitted, &nested) {
            warn!("history: {line}");
        }
    } else {
        info!(
            "history: {}",
            super::tracked::omission_summary(&omitted, &nested)
        );
    }
}

/// Each carried stream keeps its saved version from the parent.
fn carry_streams(
    repo: &HistoryRepo,
    tree: &str,
    parent: Option<&str>,
    entries: &[TrackedEntry],
    carry: &[usize],
) -> Result<String> {
    let mut overlays = vec![];
    for index in carry {
        let entry = &entries[*index];
        let path = entry.tree_path(&entry.path)?;
        let object = parent
            .map(|head| repo.object_at(head, &path))
            .transpose()?
            .flatten();
        // an entry nested in the carried one, and captured itself, keeps
        // what this capture saved for it; overlays apply in order
        let mut nested = vec![];
        for (other, child) in entries.iter().enumerate() {
            let child_path = child.tree_path(&child.path)?;
            if !carry.contains(&other) && child_path.starts_with(&format!("{path}/")) {
                nested.push(Overlay {
                    object: repo.object_at(tree, &child_path)?,
                    path: child_path,
                });
            }
        }
        overlays.push(Overlay { path, object });
        overlays.extend(nested);
    }
    repo.compose(tree, &overlays)
}

fn observe_held(
    repo: &HistoryRepo,
    held: &mut super::held::Held,
    streams: super::held::Streams,
    parent: Option<&str>,
) -> Result<()> {
    held.observe(streams.held, |stream| {
        Ok(parent
            .map(|head| repo.object_at(head, stream))
            .transpose()?
            .flatten())
    })?;
    held.save(repo)
}

fn manual_plan(
    walk: &super::tracked::Walk,
    draft: &Draft,
    promoted: &std::collections::BTreeSet<String>,
) -> ManualPlan {
    let mut plan = ManualPlan::default();
    for (index, entry) in walk.entries.iter().enumerate() {
        if entry.policy.autosave {
            continue;
        }
        let named = draft
            .explicit_paths
            .iter()
            .any(|path| path.starts_with(&entry.path) || entry.path.starts_with(path));
        // an entry that was never promoted has no saved version to carry
        // forward: its first capture is its baseline
        let never_promoted = !promoted.contains(&entry.display());
        if named || never_promoted {
            plan.promote.push(index);
        } else {
            plan.carry.push(index);
        }
    }
    plan
}

/// What a re-encrypting capture did, for the user and a computed description.
fn re_encrypt_report(paths: &[String]) -> String {
    match paths.len() {
        0 => "every encrypted file already uses the current recipients".into(),
        1 => "re-encrypted 1 file to the current recipients".into(),
        n => format!("re-encrypted {n} files to the current recipients"),
    }
}

/// Whether `path` is the entry itself or below it.
fn under_entry(path: &str, entry: &str) -> bool {
    path == entry
        || path
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Explicit capture triggers report inline. Other triggers may run in
/// the background and queue notices; foreground dotfiles and bootstrap
/// commands drain that queue on both success and failure.
fn heard(draft: &Draft) -> bool {
    matches!(
        draft.trigger,
        Some(
            store::Trigger::Save
                | store::Trigger::Capture
                | store::Trigger::Agent
                | store::Trigger::Update
                | store::Trigger::Baseline
                | store::Trigger::BootstrapBefore
                | store::Trigger::Bootstrap
        )
    )
}

/// Says how much an entry's `include` list now leaves out of what an
/// earlier checkpoint held.
///
/// Narrowing a list drops paths already in history from every checkpoint
/// after it. That is what the user asked for, but it happens silently —
/// nothing about the tree changed — so it is said at the point of change.
///
/// **There is exactly one opportunity to say it, and it is taken
/// whatever caused the save.** The checkpoint that applies the narrowing
/// is the last one whose parent still holds those paths; from the next
/// one on there is nothing left to compare against and the drop can
/// never be reported. Which command ran is not something the paths care
/// about, and the watcher saving first is not a reason for the user to
/// hear nothing — so a `mise dot save`, a `mise dot track` applying a
/// hand-edited list, and the watcher's own save all report it. It cannot
/// repeat: the narrowing changes the tree, so the checkpoint is written,
/// and the next parent is the narrowed one.
fn narrowed_notices(
    repo: &HistoryRepo,
    parent_commit: Option<&str>,
    tracked: &TrackedSet,
) -> Result<Vec<String>> {
    let Some(parent) = parent_commit else {
        return Ok(vec![]);
    };
    if tracked.entries.iter().all(|entry| entry.include.is_none()) {
        return Ok(vec![]);
    }
    // **Nothing narrowed, nothing to scan.** The lists are recorded with
    // the checkpoint, so the cheap question — are this save's enrollment
    // and `include` values the ones the parent already holds? — is
    // answered from the manifest, and only a difference pays for a walk
    // of the parent tree. An entry added or removed counts as a
    // difference, because either can change what an existing entry owns.
    if let Some(previous) = super::manifest::Manifest::read(repo, parent)? {
        let selection = |manifest: &super::manifest::Manifest| {
            manifest
                .enrollment
                .iter()
                .map(|entry| (entry.path.clone(), entry.include.clone()))
                .collect::<Vec<_>>()
        };
        if selection(&previous) == selection(&tracked.manifest) {
            return Ok(vec![]);
        }
    }
    let roots = super::sync::layout::Roots::current();
    let mut dropped: BTreeMap<String, u64> = BTreeMap::new();
    for file in repo.ls_tree(parent)? {
        let located = roots.locate(&file.path);
        let Some(path) = located.path() else { continue };
        let Some(entry) = tracked.entry_for(path) else {
            continue;
        };
        if entry.include.is_none() || entry.is_included(path) {
            continue;
        }
        *dropped.entry(entry.display()).or_default() += 1;
    }
    let previous = super::short(parent);
    Ok(dropped.into_iter().map(|(entry, count)| format!(
        "history: {entry}: its include list leaves out {count} path(s) held by checkpoint {previous}; they are no longer saved"
    )).collect())
}

/// A failed observation is not evidence of deletion. Carry only saved objects
/// still permitted by explicit enrollment and exclusions; successful reads win.
fn retain_omitted(
    repo: &HistoryRepo,
    tree: &str,
    previous: Option<(&Checkpoint, &str)>,
    tracked: &TrackedSet,
    omissions: &[&store::PathReason],
    modes: &mut BTreeMap<String, u32>,
    walk: &super::tracked::Walk,
) -> Result<String> {
    let Some((record, parent)) = previous.filter(|_| !omissions.is_empty()) else {
        return Ok(tree.into());
    };
    let roots = super::sync::layout::Roots::current();
    let omitted: Vec<_> = omissions
        .iter()
        .map(|failure| mise_util::file::replace_path(&failure.path))
        .collect();
    let mut overlays = vec![];
    let observed_directories: BTreeSet<_> = walk
        .files
        .keys()
        .flat_map(|path| path.ancestors().skip(1))
        .collect();
    for file in repo.ls_tree(parent)? {
        let located = roots.locate(&file.path);
        let Some(path) = located.path() else { continue };
        if !omitted.iter().any(|omitted| path.starts_with(omitted))
            || !tracked.would_retain(path)?
            || repo.object_at(tree, &file.path)?.is_some()
        {
            continue;
        }
        let Some(entry) = tracked.entry_for(path) else {
            continue;
        };
        if entry.tree_path(path)? != file.path {
            continue;
        }
        if entry.policy.encrypt && !repo.blob_starts_with(&file.oid, b"mise-encrypted-file-v1\n")? {
            eyre::bail!(
                "cannot retain an unreadable plaintext version of newly encrypted {}",
                display_path(path)
            );
        }
        let display = display_path(path);
        modes.remove(&display);
        if let Some(mode) = record.tree.modes.get(&display) {
            modes.insert(display, *mode);
        }
        for parent in mode_ancestors(path, &entry.path, &roots) {
            if !observed_directories.contains(parent) {
                let display = display_path(parent);
                if let Some(mode) = record.tree.modes.get(&display) {
                    modes.insert(display, *mode);
                }
            }
        }
        overlays.push(Overlay {
            path: file.path,
            object: Some((file.mode, file.oid)),
        });
    }
    repo.compose(tree, &overlays)
}

/// The directories whose permissions a captured file carries: every
/// ancestor strictly below the root it is mapped under (home or the
/// configuration directory). A parent that holds only one tracked file still
/// decides who can read it, so a fresh machine must recreate it the same way.
/// The root itself is never recorded: enrolling a file must not capture
/// unrelated metadata about home or a custom configuration root. A path
/// outside every root carries only the explicitly enrolled directory.
fn mode_ancestors<'a>(
    path: &'a Path,
    enrolled: &'a Path,
    roots: &'a super::sync::layout::Roots,
) -> impl Iterator<Item = &'a Path> + 'a {
    let root = roots.root_of(path);
    path.ancestors()
        .skip(1)
        .take_while(move |ancestor| match root {
            Some(root) => *ancestor != root && ancestor.starts_with(root),
            None => ancestor.starts_with(enrolled),
        })
}

/// The permission bits of captured regular files that git cannot record
/// (anything but `0644` and `0755`) and of their non-default (not `0755`)
/// directories, so a restore can put them back.
#[cfg(unix)]
fn file_modes(
    walk: &super::tracked::Walk,
    roots: &super::sync::layout::Roots,
) -> BTreeMap<String, u32> {
    use std::os::unix::fs::PermissionsExt;
    let mut modes = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for (path, (owner, _)) in &walk.files {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if meta.is_file() {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o644 && mode != 0o755 {
                modes.insert(display_path(path), mode);
            }
        }
        let enrolled = &walk.entries[*owner].path;
        for ancestor in mode_ancestors(path, enrolled, roots) {
            dirs.insert(ancestor.to_path_buf());
        }
    }
    for dir in dirs {
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.is_dir() {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o755 {
                modes.insert(display_path(&dir), mode);
            }
        }
    }
    modes
}

#[cfg(not(unix))]
fn file_modes(
    _walk: &super::tracked::Walk,
    _roots: &super::sync::layout::Roots,
) -> BTreeMap<String, u32> {
    BTreeMap::new()
}

fn changes_from(
    repo: &HistoryRepo,
    from: Option<&str>,
    to: &str,
    since: Option<String>,
) -> Result<Changes> {
    let mut changes = Changes {
        since,
        ..Default::default()
    };
    let mut count = 0usize;
    for change in repo.changes(from, to)? {
        if change.path.starts_with(".mise-history/") {
            continue;
        }
        count += 1;
        if count > CHANGES_MAX {
            changes.truncated = true;
            break;
        }
        let path = tree_path_to_display(&change.path);
        match change.status {
            'A' => changes.added.push(path),
            'D' => changes.removed.push(path),
            _ => changes.modified.push(path),
        }
    }
    Ok(changes)
}

/// The computed one-line description of a checkpoint.
pub(crate) fn describe(
    draft: &Draft,
    changes: &Changes,
    has_previous: bool,
    total_files: u64,
) -> String {
    if let Some(operation) = &draft.operation {
        let what = match operation.message.as_deref() {
            Some(message) => format!(": {message}"),
            None if !changes.is_empty() => format!(": {}", describe_changes(changes)),
            None => String::new(),
        };
        return truncate(format!("{}{what}", operation.kind.as_str()));
    }
    if draft.protective {
        return truncate(format!(
            "before {}",
            draft.trigger().as_str().trim_end_matches("-before")
        ));
    }
    if !has_previous {
        return format!("initial checkpoint ({total_files} files)");
    }
    if changes.is_empty() {
        return "no file changes".to_string();
    }
    truncate(describe_changes(changes))
}

pub(crate) fn describe_changes(changes: &Changes) -> String {
    let mut budget = DESCRIPTION_PATHS;
    let mut groups = vec![];
    let mut more = 0usize;
    for (verb, paths) in [
        ("edited", &changes.modified),
        ("added", &changes.added),
        ("removed", &changes.removed),
    ] {
        if paths.is_empty() {
            continue;
        }
        let mut sorted: Vec<&String> = paths.iter().collect();
        sorted.sort();
        let take = budget.min(sorted.len());
        more += sorted.len() - take;
        if take == 0 {
            continue;
        }
        budget -= take;
        let names: Vec<String> = sorted[..take].iter().map(|path| short_path(path)).collect();
        groups.push(format!("{verb} {}", names.join(", ")));
    }
    let mut text = groups.join("; ");
    if more > 0 {
        text.push_str(&format!(" +{more} more"));
    }
    text
}

/// `~/.config/hypr/bindings.lua` -> `hypr/bindings.lua`; other paths as is.
fn short_path(path: &str) -> String {
    path.strip_prefix("~/.config/")
        .map(str::to_string)
        .unwrap_or_else(|| path.to_string())
}

fn truncate(text: String) -> String {
    if text.chars().count() <= DESCRIPTION_MAX {
        return text;
    }
    let mut cut: String = text.chars().take(DESCRIPTION_MAX - 1).collect();
    if let Some(boundary) = cut.rfind(", ") {
        cut.truncate(boundary);
    }
    cut.push('…');
    cut
}

/// A minimal record for repository tests.
#[cfg(test)]
pub(crate) fn test_checkpoint(uuid: &str, snapshot: Option<&str>) -> Checkpoint {
    Checkpoint {
        schema_version: store::SCHEMA_VERSION,
        uuid: uuid.to_string(),
        machine: Machine {
            id: "machine".into(),
            name: "test".into(),
        },
        created_at: store::now_rfc3339(),
        mise_version: "0".into(),
        trigger: Trigger::Save,
        description: "test".into(),
        description_source: DescriptionSource::Computed,
        summary: "test".into(),
        task: None,
        labels: vec![],
        tree: TreeInfo {
            snapshot: snapshot.map(str::to_string),
            available: snapshot.is_some(),
            reason: None,
            roots: vec![],
            coverage: Default::default(),
            modes: Default::default(),
        },
        changes: Changes::default(),
        operation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_notices_survive_a_metadata_cache_failure() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().expect("git is required for checkpoint tests");
        let tree = repo.empty_object("tree")?;
        let checkpoint = test_checkpoint("cache-failure", Some(&tree));
        let cache = store::meta_cache_path_in(temp.path(), &checkpoint.uuid);
        let cache_dir = cache.parent().unwrap();
        if cache_dir.exists() {
            std::fs::remove_dir_all(cache_dir)?;
        }
        std::fs::write(cache_dir, b"not a directory")?;
        let notice = "history: synthetic credential saved in plaintext".to_string();
        assert!(
            store
                .commit_record_locked(
                    checkpoint,
                    Index::default(),
                    None,
                    std::slice::from_ref(&notice),
                    false,
                    false
                )
                .is_err()
        );
        assert!(repo.ref_oid(HistoryRepo::HISTORY_REF)?.is_some());
        let pending = std::fs::read_to_string(store::store_dir_in(temp.path()).join("notices"))?;
        assert!(pending.contains(&notice));
        Ok(())
    }

    #[test]
    fn failed_snapshots_and_failed_commits_do_not_report_capture() -> Result<()> {
        for fail_commit in [false, true] {
            let temp = tempfile::tempdir()?;
            let store = Store::open_in(temp.path())?;
            let repo = store.repo().expect("git is required for checkpoint tests");
            let tree = repo.empty_object("tree")?;
            let checkpoint =
                test_checkpoint("failed-capture", fail_commit.then_some(tree.as_str()));
            if fail_commit {
                let lock = HistoryRepo::path_in(temp.path())
                    .join(format!("{}.lock", HistoryRepo::HISTORY_REF));
                std::fs::create_dir_all(lock.parent().unwrap())?;
                std::fs::write(lock, b"locked")?;
            }
            let result = store.commit_record_locked(
                checkpoint,
                Index::default(),
                None,
                &["history: synthetic credential saved in plaintext".into()],
                false,
                false,
            );
            assert_eq!(result.is_err(), fail_commit);
            assert!(!store::store_dir_in(temp.path()).join("notices").exists());
        }
        Ok(())
    }

    /// The key the drop matches on is the string the rebuilt record will
    /// hold, because both come from the tree path by the same route.
    ///
    /// This is the whole of the Windows case, checked from any host: the
    /// trailer is written with `portable_path`, read back with
    /// `tree_path_to_display`, and the skip is matched on the result of
    /// exactly those two — never against `display_path`'s spelling, which
    /// keeps the host separator and leaves `$HOME` expanded off unix.
    #[test]
    fn a_skip_is_matched_on_the_spelling_the_rebuilt_record_holds() {
        let home = mise_util::dirs::HOME.join(".native");
        let plugin = home.join("plugin");
        let mut checkpoint = test_checkpoint("nested", None);
        // built the way a capture builds it, so a coverage field added
        // later cannot leave this test describing something else
        let mut tracked = TrackedSet::default();
        tracked.push(TrackedEntry::new(
            home.clone(),
            "track",
            crate::files::FilePolicy::for_mode(crate::files::FileMode::Track),
        ));
        checkpoint.tree.coverage = tracked.coverage(&crate::history::tracked::Walk {
            entries: tracked.entries.clone(),
            ..Default::default()
        });
        let skip = store::PathReason {
            path: mise_util::file::display_path(&plugin),
            reason: crate::history::tracked::NESTED_REPOSITORY_REASON.into(),
        };
        checkpoint.tree.coverage.nested.push(skip.clone());

        // what the trailer carries, and what a reader rebuilds from it
        let record = checkpoint.for_commit();
        let rebuilt: Vec<String> = record
            .omitted
            .iter()
            .map(|path| tree_path_to_display(path))
            .collect();
        assert_eq!(rebuilt, vec!["~/.native/plugin".to_string()]);

        // the drop matches those exact strings and nothing else, so the
        // skip is named once wherever the two display spellings differ
        let skipped = skipped_as_rebuilt(&checkpoint, std::slice::from_ref(&skip));
        assert_eq!(
            skipped,
            rebuilt.iter().cloned().collect::<BTreeSet<String>>(),
            "the drop is not matching on what the rebuilt record holds"
        );

        // On Windows this is the whole bug: `display_path` keeps the host
        // separator and leaves `$HOME` expanded, so the walked spelling is
        // not the rebuilt one and matching against it left the skip in
        // both lists. The key is derived from the tree path for that
        // reason, and this asserts the reason rather than assuming it.
        #[cfg(windows)]
        {
            assert_ne!(
                skip.path, rebuilt[0],
                "the two writers agree here, so the derivation is untested"
            );
            assert!(!skipped.contains(&skip.path));
        }

        // and nothing is folded, so a file genuinely named with a
        // backslash is a different path from the one with a separator
        let mut omitted = vec![
            store::PathReason {
                path: "~/.native/plugin".into(),
                reason: "not captured in this commit".into(),
            },
            store::PathReason {
                path: r"~/.native\plugin".into(),
                reason: "not captured in this commit".into(),
            },
        ];
        omitted.retain(|omitted| !skipped.contains(&omitted.path));
        assert_eq!(
            omitted.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(),
            vec![r"~/.native\plugin"],
            "a name containing a backslash was taken for a separated path"
        );
    }

    #[test]
    fn rebuild_reuses_commit_metadata_without_retaining_removed_annotations() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let tree = repo.empty_object("tree")?;
        let mut last = String::new();
        for i in 0..8 {
            let mut checkpoint = test_checkpoint(&format!("checkpoint-{i}"), Some(&tree));
            checkpoint.description = format!("checkpoint {i}");
            checkpoint.summary = checkpoint.description.clone();
            last = repo.write_checkpoint(Some(&tree), &checkpoint)?;
        }

        shadow::reset_read_meta_calls();
        let first = store.rebuild_index()?;
        assert_eq!(first.entries.len(), 8);
        assert_eq!(shadow::read_meta_calls(), 8);

        shadow::reset_read_meta_calls();
        let second = store.rebuild_index()?;
        assert_eq!(second.entries.len(), 8);
        assert_eq!(shadow::read_meta_calls(), 0);

        repo.write_annotation(
            &last,
            &Annotation {
                description: Some("renamed checkpoint".into()),
                description_source: Some(DescriptionSource::User),
                updated_at: store::now_rfc3339(),
                ..Default::default()
            },
        )?;
        let annotation = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        shadow::reset_read_meta_calls();
        store.rebuild_index()?;
        assert_eq!(shadow::read_meta_calls(), 0);
        assert_eq!(
            store.list()?.last().unwrap().checkpoint.description,
            "renamed checkpoint"
        );

        repo.update_history_head(&last, Some(&annotation))?;
        shadow::reset_read_meta_calls();
        store.rebuild_index()?;
        assert_eq!(shadow::read_meta_calls(), 0);
        assert_eq!(
            store.list()?.last().unwrap().checkpoint.description,
            "checkpoint 7"
        );
        Ok(())
    }

    #[test]
    fn automatic_capture_without_enrollment_does_not_create_a_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        assert!(matches!(
            store.attempt(&TrackedSet::default(), Draft::new(Trigger::Edit))?,
            Outcome::Unchanged
        ));
        assert!(
            store
                .repo()
                .unwrap()
                .ref_oid(HistoryRepo::HISTORY_REF)?
                .is_none()
        );
        let mut labeled = Draft::new(Trigger::Agent);
        labeled.description = Some("explicit operation boundary".into());
        assert!(matches!(
            store.attempt(&TrackedSet::default(), labeled)?,
            Outcome::Created(_)
        ));
        Ok(())
    }

    #[test]
    fn unavailable_git_does_not_create_a_parallel_metadata_history() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut store = Store::open_in(temp.path())?;
        store.repo = None;
        store.unavailable = Some("Git is unavailable".into());
        let mut draft = Draft::new(Trigger::Agent);
        draft.description = Some("labeled operation".into());
        assert!(matches!(
            store.attempt(&TrackedSet::default(), draft)?,
            Outcome::Unavailable(_)
        ));
        assert!(store::load_index_in(temp.path())?.entries.is_empty());
        Ok(())
    }

    #[test]
    fn failed_baseline_does_not_commit_metadata() -> Result<()> {
        let state = tempfile::tempdir()?;
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let path = live.path().join("secret");
        std::fs::write(&path, "private")?;
        let mut policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        policy.encrypt = true;
        let mut tracked = TrackedSet::default();
        tracked.push(TrackedEntry::new(path.clone(), "track", policy));
        tracked.manifest.recipients = vec!["invalid-recipient".into()];
        let mut draft = Draft::new(Trigger::Baseline);
        draft.description = Some("tracked encrypted file".into());
        draft.explicit_paths = vec![path];
        let store = Store::open_in(state.path())?;

        assert!(matches!(
            store.attempt(&tracked, draft)?,
            Outcome::Unavailable(_)
        ));
        assert!(store::load_index_in(state.path())?.entries.is_empty());
        assert!(
            store
                .repo()
                .unwrap()
                .ref_oid(HistoryRepo::HISTORY_REF)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn numeric_commit_prefixes_cannot_silently_select_another_checkpoint() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let Outcome::Created(mut first) =
            store.attempt(&TrackedSet::default(), Draft::new(Trigger::Agent))?
        else {
            panic!("expected a checkpoint");
        };
        first.id = 42;
        first.checkpoint.uuid = "123abc".into();
        let mut second = first.clone();
        second.id = 123;
        second.checkpoint.uuid = "abcdef".into();
        let entries = vec![*first, *second];
        assert!(store::resolve_ref("12", &entries).is_err());
        assert_eq!(store::resolve_ref("42", &entries)?, 42);
        assert_eq!(store::resolve_ref("123", &entries)?, 123);
        assert_eq!(store::resolve_ref("commit:12", &entries)?, 42);
        assert_eq!(store::resolve_ref("commit:123", &entries)?, 42);
        assert!(store::resolve_ref("commit:", &entries).is_err());
        assert!(store::resolve_ref("", &entries).is_err());
        assert!(store::resolve_ref("1234567890123456789012345678901234567890", &entries).is_err());
        assert_eq!(store::resolve_ref("123abc", &entries)?, 42);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn permission_capture_stops_at_explicit_enrollment() {
        use super::super::tracked::{TrackedEntry, Walk};
        use crate::files::{FileMode, FilePolicy};
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("private-parent");
        let enrolled = parent.join("enrolled");
        std::fs::create_dir_all(&enrolled).unwrap();
        let path = enrolled.join("config");
        std::fs::write(&path, "config").unwrap();
        for directory in [&parent, &enrolled] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut walk = Walk {
            entries: vec![TrackedEntry::new(enrolled.clone(), "track", policy)],
            files: BTreeMap::from([(path.clone(), (0, policy))]),
            ..Default::default()
        };
        // outside every root, only the explicitly enrolled directory counts
        let roots = super::super::sync::layout::Roots {
            home: temp.path().join("elsewhere"),
            config_dir: temp.path().join("elsewhere/.config/mise"),
        };
        assert_eq!(
            file_modes(&walk, &roots),
            BTreeMap::from([
                (display_path(&enrolled), 0o700),
                (display_path(&path), 0o600),
            ])
        );
        walk.entries[0].path = path.clone();
        assert_eq!(
            file_modes(&walk, &roots),
            BTreeMap::from([(display_path(&path), 0o600)])
        );
    }

    /// A tracked file's parents up to (but excluding) home or the
    /// configuration root are recorded when their mode is not the default,
    /// so a fresh machine recreates a private parent private.
    #[cfg(unix)]
    #[test]
    fn permission_capture_includes_parents_below_the_root() {
        use super::super::sync::layout::Roots;
        use super::super::tracked::{TrackedEntry, Walk};
        use crate::files::{FileMode, FilePolicy};
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let private = home.join(".claude");
        let public = private.join("public");
        std::fs::create_dir_all(&public).unwrap();
        let settings = private.join("settings.json");
        let notes = public.join("notes");
        std::fs::write(&settings, "{}").unwrap();
        std::fs::write(&notes, "notes").unwrap();
        for (directory, mode) in [(&home, 0o700), (&private, 0o700), (&public, 0o755)] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut walk = Walk {
            entries: vec![
                TrackedEntry::new(settings.clone(), "track", policy),
                TrackedEntry::new(notes.clone(), "track", policy),
            ],
            files: BTreeMap::from([
                (settings.clone(), (0, policy)),
                (notes.clone(), (1, policy)),
            ]),
            ..Default::default()
        };
        let roots = Roots {
            home: home.clone(),
            config_dir: home.join(".config/mise"),
        };
        // the private parent is recorded; a default parent and home itself
        // (also 0700) are not
        assert_eq!(
            file_modes(&walk, &roots),
            BTreeMap::from([(display_path(&private), 0o700)])
        );
        assert_eq!(
            mode_ancestors(&notes, &notes, &roots).collect::<Vec<_>>(),
            vec![public.as_path(), private.as_path()]
        );

        // the configuration root is a boundary of its own: a file directly
        // under it carries no directory at all
        let config_dir = home.join(".config/mise");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config = config_dir.join("config.toml");
        std::fs::write(&config, "").unwrap();
        for directory in [home.join(".config"), config_dir.clone()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        walk.entries = vec![TrackedEntry::new(config.clone(), "track", policy)];
        walk.files = BTreeMap::from([(config.clone(), (0, policy))]);
        assert_eq!(file_modes(&walk, &roots), BTreeMap::new());
    }

    /// A checkpoint record carries the modes of containing directories, so a
    /// rollback can recreate them and an unchanged tree is not recorded
    /// again on every automatic capture.
    #[cfg(unix)]
    #[test]
    fn parent_modes_reach_the_record_and_deduplicate() -> Result<()> {
        use super::super::manifest::{Enrollment, Manifest};
        use super::super::sync::layout::Roots;
        use super::super::tracked::normalize;
        use crate::files::{FileMode, FilePolicy};
        use std::os::unix::fs::PermissionsExt;

        let state = tempfile::tempdir()?;
        let store = Store::open_in(state.path())?;
        if store.repo().is_none() {
            return Ok(());
        }
        let parent = tempfile::Builder::new()
            .prefix(".history-record-")
            .tempdir_in(Roots::current().home)?;
        let parent_path = normalize(parent.path());
        let settings = parent_path.join("settings.json");
        std::fs::write(&settings, "{}")?;
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))?;
        let entry = TrackedEntry::new(
            settings.clone(),
            "track",
            FilePolicy::for_mode(FileMode::Track),
        );
        let tracked = TrackedSet {
            manifest: Manifest {
                enrollment: vec![Enrollment {
                    path: entry.tree_path(&settings)?,
                    autosave: true,
                    encrypt: false,
                    allow_plaintext: None,
                    variants: vec![],
                    exclude: None,
                    include: None,
                }],
                ..Default::default()
            },
            entries: vec![entry],
            ..Default::default()
        };
        let Outcome::Created(created) = store.attempt(&tracked, Draft::new(Trigger::Edit))? else {
            panic!("no checkpoint")
        };
        assert_eq!(
            created.checkpoint.tree.modes,
            BTreeMap::from([(display_path(&parent_path), 0o700)])
        );
        assert_eq!(
            store.list()?.pop().unwrap().checkpoint.tree.modes,
            created.checkpoint.tree.modes
        );
        assert!(matches!(
            store.attempt(&tracked, Draft::new(Trigger::Edit))?,
            Outcome::Unchanged
        ));
        Ok(())
    }

    /// A selective save of one child of a manual directory keeps the saved
    /// modes of its unnamed siblings, but a containing directory the live
    /// walk observed takes its live mode: a parent back at the default is
    /// not recorded again at its old private bits.
    #[cfg(unix)]
    #[test]
    fn selective_save_does_not_restore_a_stale_parent_mode() -> Result<()> {
        use super::super::manifest::{Enrollment, Manifest};
        use super::super::sync::layout::Roots;
        use super::super::tracked::normalize;
        use crate::files::{FileMode, FilePolicy};
        use std::os::unix::fs::PermissionsExt;

        let state = tempfile::tempdir()?;
        let store = Store::open_in(state.path())?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let roots = Roots::current();
        let parent = tempfile::Builder::new()
            .prefix(".history-selective-")
            .tempdir_in(&roots.home)?;
        let parent_path = normalize(parent.path());
        let manual = parent_path.join("manual");
        std::fs::create_dir(&manual)?;
        let first = manual.join("first");
        let second = manual.join("second");
        std::fs::write(&first, "saved")?;
        std::fs::write(&second, "saved")?;
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&manual, std::fs::Permissions::from_mode(0o700))?;
        let mut policy = FilePolicy::for_mode(FileMode::Track);
        policy.autosave = false;
        let entry = TrackedEntry::new(manual.clone(), "track", policy);
        let tracked = TrackedSet {
            manifest: Manifest {
                enrollment: vec![Enrollment {
                    path: entry.tree_path(&manual)?,
                    autosave: false,
                    encrypt: false,
                    allow_plaintext: None,
                    variants: vec![],
                    exclude: None,
                    include: None,
                }],
                ..Default::default()
            },
            entries: vec![entry],
            ..Default::default()
        };
        let portable = roots.branch_path(&parent_path, None).unwrap();
        let own = roots.branch_path(&manual, None).unwrap();
        let permissions = || -> Result<BTreeMap<String, u32>> {
            let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
            Ok(Manifest::read(repo, &head)?.unwrap().permissions)
        };

        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths.push(manual.clone());
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no baseline")
        };
        assert_eq!(
            permissions()?,
            BTreeMap::from([(portable.clone(), 0o700), (own.clone(), 0o700)])
        );

        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o755))?;
        std::fs::write(&first, "edited")?;
        std::fs::write(&second, "edited")?;
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths.push(first.clone());
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no selective save")
        };
        // the save was selective: the unnamed sibling keeps its saved version
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let content = |path: &Path| -> Result<Vec<u8>> {
            let (_, oid) = repo
                .object_at(&head, &tracked.entries[0].tree_path(path)?)?
                .unwrap();
            repo.cat_object(&oid)
        };
        assert_eq!(content(&first)?, b"edited");
        assert_eq!(content(&second)?, b"saved");
        // the parent went back to the default and is dropped; the manual
        // directory's own unchanged mode is kept, not stripped as unnamed
        assert_eq!(permissions()?, BTreeMap::from([(own.clone(), 0o700)]));
        let latest = store.list()?.pop().unwrap();
        assert!(
            !latest
                .checkpoint
                .tree
                .modes
                .contains_key(&display_path(&parent_path))
        );
        Ok(())
    }

    fn changes(modified: &[&str], added: &[&str], removed: &[&str]) -> Changes {
        Changes {
            since: None,
            added: added.iter().map(|s| s.to_string()).collect(),
            modified: modified.iter().map(|s| s.to_string()).collect(),
            removed: removed.iter().map(|s| s.to_string()).collect(),
            truncated: false,
        }
    }

    #[test]
    fn descriptions_group_sort_and_cap() {
        let draft = Draft::new(Trigger::Edit);
        assert_eq!(
            describe(&draft, &Changes::default(), false, 12),
            "initial checkpoint (12 files)"
        );
        assert_eq!(
            describe(&draft, &Changes::default(), true, 12),
            "no file changes"
        );
        let c = changes(
            &["~/.config/hypr/monitors.lua", "~/.config/hypr/bindings.lua"],
            &["~/.config/omarchy/hooks/post-theme"],
            &["~/.XCompose"],
        );
        assert_eq!(
            describe(&draft, &c, true, 0),
            "edited hypr/bindings.lua, hypr/monitors.lua; added omarchy/hooks/post-theme; removed ~/.XCompose"
        );
        let many: Vec<String> = (0..10).map(|i| format!("~/.f{i}")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let text = describe(&draft, &changes(&refs, &[], &[]), true, 0);
        assert!(text.ends_with("+4 more"), "{text}");
        assert!(text.chars().count() <= DESCRIPTION_MAX);
    }

    #[test]
    fn operation_descriptions_name_the_kind() {
        let mut draft = Draft::new(Trigger::Bootstrap);
        draft.operation = Some(Operation {
            id: "test-operation".into(),
            kind: store::OperationKind::Bootstrap,
            status: store::OperationStatus::Completed,
            command: "bootstrap".into(),
            argv: vec![],
            cwd: PathBuf::new(),
            user: None,
            finished_at: None,
            error: None,
            before: None,
            to: None,
            undoes: None,
            applied: None,
            affected: vec![],
            sources: vec![],
            directories: vec![],
            directory_modes: Default::default(),
            message: None,
            journal: vec![],
        });
        let c = changes(&["~/.zshrc"], &[], &[]);
        assert_eq!(describe(&draft, &c, true, 0), "bootstrap: edited ~/.zshrc");
        let mut protective = Draft::new(Trigger::BootstrapBefore);
        protective.protective = true;
        assert_eq!(describe(&protective, &c, true, 0), "before bootstrap");
    }

    #[test]
    fn metadata_decides_deduplication() {
        assert!(!Draft::new(Trigger::Edit).has_metadata());
        assert!(!Draft::new(Trigger::Save).has_metadata());
        assert!(Draft::new(Trigger::Agent).has_metadata());
        let mut described = Draft::new(Trigger::Edit);
        described.description = Some("x".into());
        assert!(described.has_metadata());
    }

    /// A directory the OS refuses to read is not a deletion and does not
    /// stop the save of a sibling. The denied path keeps the object the
    /// previous checkpoint stored, and the save reports it until it can be
    /// read again.
    #[cfg(unix)]
    #[test]
    fn snapshot_keeps_last_saved_version_of_unreadable_path() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        struct Restore(PathBuf, u32);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
            }
        }

        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home, so a
        // tracked fixture has to live there
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let readable = live.path().join("readable.toml");
        let denied_dir = live.path().join("denied");
        let denied = denied_dir.join("settings.toml");
        std::fs::write(&readable, "first")?;
        std::fs::create_dir(&denied_dir)?;
        std::fs::write(&denied, "saved-settings")?;
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let readable_entry = TrackedEntry::new(readable.clone(), "track", policy);
        let denied_entry = TrackedEntry::new(denied.clone(), "track", policy);
        let enroll = |entry: &TrackedEntry, path: &Path| -> Result<_> {
            Ok(super::super::manifest::Enrollment {
                path: entry.tree_path(path)?,
                autosave: true,
                encrypt: false,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            })
        };
        let tracked = TrackedSet {
            manifest: super::super::manifest::Manifest {
                enrollment: vec![
                    enroll(&readable_entry, &readable)?,
                    enroll(&denied_entry, &denied)?,
                ],
                ..Default::default()
            },
            entries: vec![readable_entry, denied_entry],
            ..Default::default()
        };
        let store = Store::open_in(state.path())?;
        let Outcome::Created(_) = store.attempt(&tracked, Draft::new(Trigger::Save))? else {
            panic!("the first save recorded nothing");
        };
        let repo = store.repo().expect("git is required");
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let denied_tree = tracked.entry_for(&denied).unwrap().tree_path(&denied)?;
        let (_, saved_oid) = repo
            .object_at(&head, &denied_tree)?
            .expect("denied file saved");

        let restore = Restore(denied_dir.clone(), 0o700);
        std::fs::set_permissions(&denied_dir, std::fs::Permissions::from_mode(0o000))?;
        if nix::unistd::geteuid().is_root() {
            drop(restore);
            return Ok(());
        }
        let probe = std::fs::symlink_metadata(&denied).expect_err("a non-root denial was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::write(&readable, "edited")?;
        let saved = match store.attempt(&tracked, Draft::new(Trigger::Save))? {
            Outcome::Created(saved) => saved,
            outcome => {
                panic!("a readable edit was not saved while a sibling was denied: {outcome:?}")
            }
        };
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let readable_tree = tracked.entry_for(&readable).unwrap().tree_path(&readable)?;
        let (_, readable_oid) = repo
            .object_at(&head, &readable_tree)?
            .expect("readable file saved");
        assert_eq!(repo.cat_object(&readable_oid)?, b"edited");
        let (_, kept_oid) = repo
            .object_at(&head, &denied_tree)?
            .expect("denied file was deleted from the checkpoint");
        assert_eq!(
            kept_oid, saved_oid,
            "the denied file was replaced instead of keeping its last saved object"
        );
        let health = crate::history::health::read(state.path()).expect("health.json");
        let _ = &saved;
        let report = health
            .watcher
            .degraded
            .iter()
            .find(|line| line.contains(&display_path(&denied)))
            .expect("health.json watcher.degraded does not name the denied path");
        assert!(
            report.contains("Operation not permitted") || report.contains("Permission denied"),
            "{report}"
        );
        drop(restore);
        Ok(())
    }

    /// A denied path nothing has saved is reported and stored as absent,
    /// not as an empty file.
    #[cfg(unix)]
    #[test]
    fn a_never_saved_denied_path_is_absent_and_reported() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let path = live.path().join("notes.toml");
        std::fs::write(&path, "new")?;
        let mode = std::fs::symlink_metadata(&path)?.permissions().mode();
        let restore = MoveMode(path.clone(), mode);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        let probe = std::fs::File::open(&path).expect_err("a non-root file was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let entry = TrackedEntry::new(path.clone(), "track", policy);
        let tracked = enrolled(vec![(entry, path.clone())])?;
        let store = Store::open_in(state.path())?;
        let saved = match store.attempt(&tracked, Draft::new(Trigger::Save))? {
            Outcome::Created(saved) => saved,
            outcome => panic!("a never-saved denial stopped the checkpoint: {outcome:?}"),
        };
        let head = store
            .repo()
            .unwrap()
            .ref_oid(HistoryRepo::HISTORY_REF)?
            .unwrap();
        let tree = tracked.entry_for(&path).unwrap().tree_path(&path)?;
        assert!(store.repo().unwrap().object_at(&head, &tree)?.is_none());
        assert!(
            saved
                .checkpoint
                .tree
                .coverage
                .omitted
                .iter()
                .any(|omitted| omitted.path == display_path(&path))
        );
        drop(restore);
        Ok(())
    }

    /// Restoring access captures the live bytes and clears only this path's
    /// denial, leaving an unrelated degraded reason where it was.
    #[cfg(unix)]
    #[test]
    fn a_denied_report_clears_after_the_path_can_be_read() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let path = live.path().join("notes.toml");
        std::fs::write(&path, "saved")?;
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let entry = TrackedEntry::new(path.clone(), "track", policy);
        let tracked = enrolled(vec![(entry, path.clone())])?;
        let store = Store::open_in(state.path())?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let mode = std::fs::symlink_metadata(&path)?.permissions().mode();
        let restore = MoveMode(path.clone(), mode);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let unrelated = "cannot watch ~/notes: limit reached".to_string();
        let mut health = crate::history::health::read(state.path()).unwrap_or_default();
        health.watcher.degraded.push(unrelated.clone());
        crate::history::health::write(state.path(), &mut health)?;
        drop(restore);
        std::fs::write(&path, "readable-again")?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let health = crate::history::health::read(state.path()).unwrap_or_default();
        assert!(
            health
                .watcher
                .degraded
                .iter()
                .all(|line| !line.contains(&display_path(&path)))
        );
        assert!(
            health
                .watcher
                .degraded
                .iter()
                .any(|line| line == &unrelated)
        );
        Ok(())
    }

    /// A denied directory keeps every previously saved descendant, not the
    /// ones a partial walk happened to read.
    #[cfg(unix)]
    #[test]
    fn a_denied_directory_keeps_every_previously_saved_descendant() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let dir = live.path().join("folder");
        std::fs::create_dir(&dir)?;
        let first = dir.join("one.toml");
        let second = dir.join("two.toml");
        std::fs::write(&first, "one")?;
        std::fs::write(&second, "two")?;
        let sibling = live.path().join("sibling.toml");
        std::fs::write(&sibling, "before")?;
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let tracked = enrolled(vec![
            (TrackedEntry::new(dir.clone(), "track", policy), dir.clone()),
            (
                TrackedEntry::new(sibling.clone(), "track", policy),
                sibling.clone(),
            ),
        ])?;
        let store = Store::open_in(state.path())?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let repo = store.repo().unwrap();
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let oid = |path: &Path| -> Result<String> {
            Ok(repo
                .object_at(&head, &tracked.entry_for(path).unwrap().tree_path(path)?)?
                .unwrap()
                .1)
        };
        let first_oid = oid(&first)?;
        let second_oid = oid(&second)?;
        let mode = std::fs::symlink_metadata(&dir)?.permissions().mode();
        let restore = MoveMode(dir.clone(), mode);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))?;
        let probe = std::fs::read_dir(&dir).expect_err("a non-root directory was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::write(&sibling, "after")?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let kept = |path: &Path| -> Result<String> {
            Ok(repo
                .object_at(&head, &tracked.entry_for(path).unwrap().tree_path(path)?)?
                .expect("descendant deleted")
                .1)
        };
        assert_eq!(kept(&first)?, first_oid);
        assert_eq!(kept(&second)?, second_oid);
        drop(restore);
        Ok(())
    }

    /// A file whose metadata is readable but whose contents are refused
    /// keeps its saved object. The open is the denial, not the walk.
    #[cfg(unix)]
    #[test]
    fn a_denied_file_content_read_keeps_its_saved_object() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let denied = live.path().join("notes.toml");
        let readable = live.path().join("other.toml");
        std::fs::write(&denied, "saved-notes")?;
        std::fs::write(&readable, "before")?;
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let tracked = enrolled(vec![
            (
                TrackedEntry::new(denied.clone(), "track", policy),
                denied.clone(),
            ),
            (
                TrackedEntry::new(readable.clone(), "track", policy),
                readable.clone(),
            ),
        ])?;
        let store = Store::open_in(state.path())?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let repo = store.repo().unwrap();
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let tree = tracked.entry_for(&denied).unwrap().tree_path(&denied)?;
        let saved_oid = repo.object_at(&head, &tree)?.unwrap().1;
        let mode = std::fs::symlink_metadata(&denied)?.permissions().mode();
        let restore = MoveMode(denied.clone(), mode);
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000))?;
        assert!(
            std::fs::symlink_metadata(&denied).is_ok(),
            "metadata must stay readable"
        );
        let probe = std::fs::File::open(&denied).expect_err("content was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::write(&readable, "after")?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let kept = repo
            .object_at(&head, &tree)?
            .expect("content denial deleted the file")
            .1;
        assert_eq!(kept, saved_oid);
        drop(restore);
        Ok(())
    }

    #[cfg(unix)]
    struct MoveMode(PathBuf, u32);
    #[cfg(unix)]
    impl Drop for MoveMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
        }
    }

    /// Restoring a denied file without changing its bytes is still a
    /// recovery: the denial report clears even though the checkpoint is
    /// unchanged.
    #[cfg(unix)]
    #[test]
    fn an_unchanged_readable_capture_clears_a_permission_report() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let path = live.path().join("notes.toml");
        std::fs::write(&path, "saved")?;
        let policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let tracked = enrolled(vec![(
            TrackedEntry::new(path.clone(), "track", policy),
            path.clone(),
        )])?;
        let store = Store::open_in(state.path())?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let mode = std::fs::symlink_metadata(&path)?.permissions().mode();
        let restore = MoveMode(path.clone(), mode);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        assert!(
            crate::history::health::read(state.path())
                .expect("denial recorded")
                .watcher
                .degraded
                .iter()
                .any(|line| {
                    crate::history::health::permission_report_path(line)
                        == Some(display_path(&path).as_str())
                })
        );
        drop(restore);
        let outcome = store.attempt(&tracked, Draft::new(Trigger::Save))?;
        assert!(
            matches!(outcome, Outcome::Unchanged),
            "restoring the same bytes created a checkpoint: {outcome:?}"
        );
        let health = crate::history::health::read(state.path()).unwrap_or_default();
        assert!(
            health.watcher.degraded.iter().all(|line| {
                crate::history::health::permission_report_path(line)
                    != Some(display_path(&path).as_str())
            }),
            "an unchanged recovery left the denial: {health:?}"
        );
        Ok(())
    }

    /// An encrypted file the operating system refuses to open keeps its
    /// saved envelope. A readable sibling in the same save is stored, and
    /// the denial is named.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_encrypted_file_keeps_its_saved_envelope() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let state = tempfile::tempdir()?;
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME)?;
        let denied = live.path().join("secret.toml");
        let sibling = live.path().join("settings.toml");
        std::fs::write(&denied, "saved-secret")?;
        std::fs::write(&sibling, "before")?;
        let identity = age::x25519::Identity::generate();
        let mut policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        policy.encrypt = true;
        let plain = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        let mut tracked = enrolled(vec![
            (
                TrackedEntry::new(denied.clone(), "track", policy),
                denied.clone(),
            ),
            (
                TrackedEntry::new(sibling.clone(), "track", plain),
                sibling.clone(),
            ),
        ])?;
        tracked.manifest.enrollment[0].encrypt = true;
        tracked.manifest.recipients = vec![identity.to_public().to_string()];
        let store = Store::open_in(state.path())?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let repo = store.repo().unwrap();
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let denied_tree = tracked.entry_for(&denied).unwrap().tree_path(&denied)?;
        let saved = repo
            .object_at(&head, &denied_tree)?
            .expect("envelope saved");
        let saved_bytes = repo.cat_object(&saved.1)?;
        assert!(
            saved_bytes.starts_with(b"mise-encrypted-file-v1\n"),
            "the baseline did not store an encrypted envelope"
        );
        let mode = std::fs::symlink_metadata(&denied)?.permissions().mode();
        let restore = MoveMode(denied.clone(), mode);
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000))?;
        assert!(std::fs::symlink_metadata(&denied).is_ok());
        let probe = std::fs::File::open(&denied).expect_err("encrypted content was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::write(&sibling, "after")?;
        store.attempt(&tracked, Draft::new(Trigger::Save))?;
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?.unwrap();
        let kept = repo
            .object_at(&head, &denied_tree)?
            .expect("an unreadable encrypted file was deleted");
        assert_eq!(kept.1, saved.1, "the saved envelope was replaced");
        let sibling_tree = tracked.entry_for(&sibling).unwrap().tree_path(&sibling)?;
        let sibling_oid = repo.object_at(&head, &sibling_tree)?.unwrap().1;
        assert_eq!(repo.cat_object(&sibling_oid)?, b"after");
        let health = crate::history::health::read(state.path()).expect("health.json");
        assert!(
            health.watcher.degraded.iter().any(|line| {
                crate::history::health::permission_report_path(line)
                    == Some(display_path(&denied).as_str())
            }),
            "{health:?}"
        );
        drop(restore);
        Ok(())
    }

    fn enrolled(entries: Vec<(TrackedEntry, PathBuf)>) -> Result<TrackedSet> {
        let mut enrollment = vec![];
        let mut tracked_entries = vec![];
        for (entry, path) in entries {
            enrollment.push(super::super::manifest::Enrollment {
                path: entry.tree_path(&path)?,
                autosave: true,
                encrypt: false,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            });
            tracked_entries.push(entry);
        }
        Ok(TrackedSet {
            manifest: super::super::manifest::Manifest {
                enrollment,
                ..Default::default()
            },
            entries: tracked_entries,
            ..Default::default()
        })
    }

    /// A capture after history moved on (a pulled checkpoint, or an
    /// annotation) extends the index with only the new commits: it does not
    /// replay and re-derive every historical checkpoint. The snapshot is still
    /// the whole live tree, the restored path's encrypted preimage is exact,
    /// undo returns it, and no plaintext version is stored.
    #[cfg(unix)]
    #[tokio::test]
    async fn scoped_rollback_refreshes_a_stale_index_without_recapturing_history() -> Result<()> {
        use super::super::manifest::{Enrollment, Manifest};
        use super::super::sync::layout::Roots;
        use super::super::tracked::normalize;
        use crate::files::{FileMode, FilePolicy};

        let (_key, recipient) = encryption_identity();
        let state = tempfile::tempdir()?;
        let store = Store::open_in(state.path())?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let home = tempfile::Builder::new()
            .prefix(".history-stale-index-")
            .tempdir_in(&Roots::current().home)?;
        let base = normalize(home.path());
        let target = base.join("config.yml");
        let unrelated = base.join("other.yml");
        std::fs::write(&target, "target one\n")?;
        std::fs::write(&unrelated, "other one\n")?;
        let enroll = |path: &Path| -> Result<(TrackedEntry, Enrollment)> {
            let mut policy = FilePolicy::for_mode(FileMode::Track);
            policy.encrypt = true;
            let entry = TrackedEntry::new(path.to_path_buf(), "track", policy);
            let enrollment = Enrollment {
                path: entry.tree_path(path)?,
                autosave: true,
                encrypt: true,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            };
            Ok((entry, enrollment))
        };
        let (target_entry, target_enrollment) = enroll(&target)?;
        let (unrelated_entry, unrelated_enrollment) = enroll(&unrelated)?;
        let tracked = TrackedSet {
            manifest: Manifest {
                enrollment: vec![target_enrollment, unrelated_enrollment],
                recipients: vec![recipient],
                ..Default::default()
            },
            entries: vec![target_entry, unrelated_entry],
            ..Default::default()
        };
        let target_path = tracked.entries[0].tree_path(&target)?;

        // two checkpoints the index already covers
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone(), unrelated.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no baseline checkpoint")
        };
        std::fs::write(&target, "target saved\n")?;
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no second checkpoint")
        };
        let before_index = store::load_index_in(state.path())?;
        let before_ids: Vec<u64> = before_index.entries.iter().map(|entry| entry.id).collect();
        assert_eq!(before_ids.len(), 2);
        // a cold historical metadata cache must not be re-derived either:
        // drop every cached commit except the newest baseline
        let commits_dir = ["history/index/commits", "index/commits"]
            .iter()
            .map(|relative| state.path().join(relative))
            .find(|dir| dir.is_dir())
            .expect("commit metadata cache directory");
        let keep = format!("{}.json", before_index.entries[1].commit);
        for entry in std::fs::read_dir(commits_dir)? {
            let entry = entry?;
            if entry.file_name() != keep.as_str() {
                std::fs::remove_file(entry.path())?;
            }
        }

        // history moves on without the index: an annotation at the tip
        let tip = before_index.entries.last().unwrap().commit.clone();
        repo.write_annotation(
            &tip,
            &Annotation {
                description: Some("stale advance".into()),
                description_source: None,
                labels: None,
                updated_at: store::now_rfc3339(),
            },
        )?;
        assert_ne!(
            repo.ref_oid(HistoryRepo::HISTORY_REF)?.as_deref(),
            Some(tip.as_str())
        );

        // a rollback's protective capture: the whole live tree is still
        // recorded, but no historical metadata is re-derived
        std::fs::write(&target, "target live\n")?;
        std::fs::write(&unrelated, "other live\n")?;
        super::super::shadow::reset_read_meta_calls();
        let mut draft = Draft::new(Trigger::RollbackBefore);
        draft.protective = true;
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(before) = store.attempt(&tracked, draft)? else {
            panic!("no protective checkpoint")
        };
        // the missing historical cache would force a full replay; the
        // incremental refresh reads only the checkpoint it appends
        assert_eq!(
            super::super::shadow::read_meta_calls(),
            1,
            "a stale index is extended, not replayed"
        );
        let after_ids: Vec<u64> = store::load_index_in(state.path())?
            .entries
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(&after_ids[..before_ids.len()], before_ids.as_slice());
        assert!(after_ids[before_ids.len()] > before_ids[1]);
        assert_eq!(
            before.checkpoint.changes.modified,
            vec![display_path(&target), display_path(&unrelated)],
            "the protective checkpoint still records the whole live tree"
        );

        // the restored path's preimage is exact and encrypted at rest, and no
        // plaintext version was stored
        let tree = before.checkpoint.tree.snapshot.clone().unwrap();
        let target_object = repo
            .object_at(&tree, &target_path)?
            .expect("the checkpoint holds the restored path");
        assert!(
            repo.cat_object(&target_object.1)?
                .starts_with(b"mise-encrypted-file-v1\n")
        );
        for plaintext in [
            b"target one\n".as_slice(),
            b"target saved\n".as_slice(),
            b"target live\n".as_slice(),
            b"other live\n".as_slice(),
        ] {
            let oid = gix::objs::compute_hash(
                repo.gix()?.object_hash(),
                gix::object::Kind::Blob,
                plaintext,
            )?;
            assert!(
                repo.gix()?.find_header(oid).is_err(),
                "no plaintext version may be stored: {}",
                String::from_utf8_lossy(plaintext)
            );
        }
        let saved = super::super::sync::files::decrypt(repo, &target_path, &target_object, false)?;
        let preimage = repo.cat_object(&saved.1)?;
        assert_eq!(preimage, b"target live\n");

        // the production rollback plans, captures its own protective
        // checkpoint, and restores the saved version
        let entries = store.list()?;
        super::super::replay::rollback_with(
            &store,
            &tracked,
            &entries,
            super::super::replay::RollbackRequest {
                paths: vec![target.clone()],
                to: Some(before_index.entries[0].id.to_string()),
                all: false,
                dry_run: false,
                yes: true,
                force: false,
            },
        )
        .await?;
        assert_eq!(std::fs::read(&target)?, b"target one\n");
        assert_eq!(
            std::fs::read(&unrelated)?,
            b"other live\n",
            "an unrelated live edit survives a path rollback"
        );

        // the operation's protective checkpoint is where undo reads from:
        // its target blob is encrypted and decrypts to the live preimage
        let after_rollback = store.list()?;
        let operation = after_rollback
            .iter()
            .rev()
            .find(|entry| {
                entry.checkpoint.operation.as_ref().is_some_and(|op| {
                    op.undoes.is_none() && op.before.is_some() && !op.affected.is_empty()
                })
            })
            .expect("the rollback recorded an operation");
        let op = operation.checkpoint.operation.clone().unwrap();
        let before_uuid = op.before.clone().unwrap();
        let before = after_rollback
            .iter()
            .find(|entry| entry.checkpoint.uuid == before_uuid)
            .expect("the protective checkpoint is listed");
        let tree = before.checkpoint.tree.snapshot.clone().unwrap();
        let object = repo
            .object_at(&tree, &target_path)?
            .expect("the protective checkpoint holds the restored path");
        assert!(
            repo.cat_object(&object.1)?
                .starts_with(b"mise-encrypted-file-v1\n"),
            "a protective preimage stays encrypted at rest"
        );
        let saved = super::super::sync::files::decrypt(repo, &target_path, &object, false)?;
        assert_eq!(repo.cat_object(&saved.1)?, b"target live\n");

        // production undo restores that exact preimage; the unrelated edit
        // is still untouched and nothing this test wrote stands in for undo
        let entries = store.list()?;
        super::super::replay::undo_with(
            &store,
            &tracked,
            &entries,
            super::super::replay::UndoRequest {
                reference: None,
                dry_run: false,
                yes: true,
            },
        )
        .await?;
        assert_eq!(std::fs::read(&target)?, b"target live\n");
        assert_eq!(std::fs::read(&unrelated)?, b"other live\n");
        Ok(())
    }

    /// A merge in the fresh suffix must never be walked by first parent: its
    /// side ancestry can precede the indexed tip in any topological order, so
    /// an appended index would omit it. The incremental result is compared
    /// against a full rebuild.
    #[cfg(unix)]
    #[test]
    fn scoped_rollback_merge_suffix_matches_a_full_rebuild() -> Result<()> {
        use super::super::sync::layout::Roots;
        use super::super::tracked::normalize;
        use crate::files::{FileMode, FilePolicy};

        let state = tempfile::tempdir()?;
        let store = Store::open_in(state.path())?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let home = tempfile::Builder::new()
            .prefix(".history-merge-index-")
            .tempdir_in(&Roots::current().home)?;
        let (_key, recipient) = encryption_identity();
        let target = normalize(home.path()).join("config.yml");
        std::fs::write(&target, "one\n")?;
        let mut policy = FilePolicy::for_mode(FileMode::Track);
        policy.encrypt = true;
        let entry = TrackedEntry::new(target.clone(), "track", policy);
        let enrollment = super::super::manifest::Enrollment {
            path: entry.tree_path(&target)?,
            autosave: true,
            encrypt: true,
            allow_plaintext: None,
            variants: vec![],
            exclude: None,
            include: None,
        };
        let tracked = TrackedSet {
            manifest: super::super::manifest::Manifest {
                enrollment: vec![enrollment],
                recipients: vec![recipient],
                ..Default::default()
            },
            entries: vec![entry],
            ..Default::default()
        };
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no baseline checkpoint")
        };
        std::fs::write(&target, "two\n")?;
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no second checkpoint")
        };
        let index = store::load_index_in(state.path())?;
        let first = index.entries[0].commit.clone();
        let last = index.entries[1].commit.clone();
        let tree = repo.output_tree_of(&last)?;

        // a side checkpoint branched below the indexed tip; a first-parent
        // walk from the merge reaches `last` without ever seeing it
        repo.update_history_head(&first, Some(&last))?;
        let side = test_checkpoint("side-checkpoint", Some(&tree));
        let side_commit = repo.write_checkpoint(Some(&tree), &side)?;
        let merge = test_checkpoint("merge-checkpoint", Some(&tree));
        let message = format!(
            "{}\n\n{}{}",
            merge.description,
            HistoryRepo::RECORD_TRAILER,
            serde_json::to_string(&merge.for_commit())?
        );
        let merge_commit = repo.commit_tree(&tree, vec![&last, &side_commit], &message)?;
        repo.update_history_head(&merge_commit, Some(&side_commit))?;

        let rows = |index: &store::Index| -> Vec<(u64, String, String, String, String)> {
            index
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.id,
                        entry.uuid.clone(),
                        entry.commit.clone(),
                        entry.created_at.clone(),
                        format!("{:?}", entry.trigger),
                    )
                })
                .collect()
        };
        let incremental = store.rebuild_index_locked()?;
        let incremental = rows(&incremental);
        let existing = store::load_index_in(state.path())?;
        let full = rows(&store.rebuild_full_index_locked(repo, existing)?);
        assert_eq!(
            incremental, full,
            "an incremental index must equal a full rebuild"
        );
        assert!(
            incremental.iter().any(|row| row.2 == side_commit),
            "the merge's side ancestry is not omitted"
        );
        Ok(())
    }

    #[cfg(unix)]
    fn encryption_identity() -> (mise_util::testing::EnvVarGuard, String) {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let mut guard = mise_util::testing::EnvVarGuard::new();
        guard.set("MISE_AGE_KEY", identity.to_string().expose_secret());
        (guard, identity.to_public().to_string())
    }

    /// Two encrypted save checkpoints and the index covering both.
    #[cfg(unix)]
    fn two_checkpoint_fixture(
        recipient: &str,
    ) -> Result<(
        tempfile::TempDir,
        tempfile::TempDir,
        Store,
        TrackedSet,
        PathBuf,
        PathBuf,
        store::Index,
    )> {
        use super::super::manifest::{Enrollment, Manifest};
        use super::super::sync::layout::Roots;
        use super::super::tracked::normalize;
        use crate::files::{FileMode, FilePolicy};

        let state = tempfile::tempdir()?;
        let store = Store::open_in(state.path())?;
        let home = tempfile::Builder::new()
            .prefix(".history-eligibility-")
            .tempdir_in(&Roots::current().home)?;
        let base = normalize(home.path());
        let target = base.join("config.yml");
        let unrelated = base.join("other.yml");
        std::fs::write(&target, "target one\n")?;
        std::fs::write(&unrelated, "other one\n")?;
        let enroll = |path: &Path| -> Result<(TrackedEntry, Enrollment)> {
            let mut policy = FilePolicy::for_mode(FileMode::Track);
            policy.encrypt = true;
            let entry = TrackedEntry::new(path.to_path_buf(), "track", policy);
            let enrollment = Enrollment {
                path: entry.tree_path(path)?,
                autosave: true,
                encrypt: true,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            };
            Ok((entry, enrollment))
        };
        let (target_entry, target_enrollment) = enroll(&target)?;
        let (unrelated_entry, unrelated_enrollment) = enroll(&unrelated)?;
        let tracked = TrackedSet {
            manifest: Manifest {
                enrollment: vec![target_enrollment, unrelated_enrollment],
                recipients: vec![recipient.into()],
                ..Default::default()
            },
            entries: vec![target_entry, unrelated_entry],
            ..Default::default()
        };
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone(), unrelated.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no baseline checkpoint")
        };
        std::fs::write(&target, "target saved\n")?;
        let mut draft = Draft::new(Trigger::Save);
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no second checkpoint")
        };
        let index = store::load_index_in(state.path())?;
        Ok((state, home, store, tracked, target, unrelated, index))
    }

    fn index_rows(index: &store::Index) -> Vec<(u64, String, String)> {
        index
            .entries
            .iter()
            .map(|entry| (entry.id, entry.uuid.clone(), entry.commit.clone()))
            .collect()
    }

    /// A baseline view written under another machine context is not a
    /// baseline: the fast path must replay, as a full rebuild would.
    #[cfg(unix)]
    #[test]
    fn scoped_rollback_fast_path_requires_current_metadata_context() -> Result<()> {
        let (_key, recipient) = encryption_identity();
        let (state, _home, store, tracked, target, _unrelated, index) =
            two_checkpoint_fixture(&recipient)?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let last = &index.entries[1];
        let mut sentinel =
            store::read_meta_cache_in(state.path(), &last.uuid)?.expect("the baseline is cached");
        sentinel.description = "stale-context view".into();
        store::write_meta_cache_in(state.path(), &sentinel)?;
        let context = store::index_context_file_in(state.path());
        let mut stamp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&context)?)?;
        stamp["home"] = serde_json::Value::String("/some/other/home".into());
        std::fs::write(&context, serde_json::to_string(&stamp)?)?;

        std::fs::write(&target, "target live\n")?;
        super::super::shadow::reset_read_meta_calls();
        let mut draft = Draft::new(Trigger::RollbackBefore);
        draft.protective = true;
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no protective checkpoint")
        };
        assert!(
            super::super::shadow::read_meta_calls() > 1,
            "an index from another context is replayed, not trusted"
        );
        assert!(
            store::index_context_matches_in(state.path())?,
            "the replay restamps the index with this context"
        );
        let view =
            store::read_meta_cache_in(state.path(), &last.uuid)?.expect("the view is rebuilt");
        assert_ne!(
            view.description, "stale-context view",
            "the rebuild replaces a view from another context"
        );
        let incremental = index_rows(&store::load_index_in(state.path())?);
        let existing = store::load_index_in(state.path())?;
        let full = index_rows(&store.rebuild_full_index_locked(repo, existing)?);
        assert_eq!(incremental, full, "the result must equal a full rebuild");
        Ok(())
    }

    /// An annotation targeting an indexed commit whose view is gone cannot be
    /// applied in place without its earlier annotations: the rebuild derives
    /// it and applies every annotation in ancestry order.
    #[cfg(unix)]
    #[test]
    fn scoped_rollback_fast_path_derives_missing_annotated_metadata() -> Result<()> {
        let (_key, recipient) = encryption_identity();
        let (state, _home, store, tracked, target, _unrelated, index) =
            two_checkpoint_fixture(&recipient)?;
        let Some(repo) = store.repo() else {
            return Ok(());
        };
        let first = &index.entries[0];
        std::fs::remove_file(store::meta_cache_path_in(state.path(), &first.uuid))?;
        repo.write_annotation(
            &first.commit,
            &Annotation {
                description: Some("side note".into()),
                description_source: None,
                labels: None,
                updated_at: store::now_rfc3339(),
            },
        )?;
        std::fs::write(&target, "target live\n")?;
        super::super::shadow::reset_read_meta_calls();
        let mut draft = Draft::new(Trigger::RollbackBefore);
        draft.protective = true;
        draft.explicit_paths = vec![target.clone()];
        let Outcome::Created(_) = store.attempt(&tracked, draft)? else {
            panic!("no protective checkpoint")
        };
        assert!(
            super::super::shadow::read_meta_calls() > 1,
            "a missing annotated view is derived by the rebuild"
        );
        let view =
            store::read_meta_cache_in(state.path(), &first.uuid)?.expect("the view is derived");
        assert_eq!(view.description, "side note");
        let incremental = index_rows(&store::load_index_in(state.path())?);
        let existing = store::load_index_in(state.path())?;
        let full = index_rows(&store.rebuild_full_index_locked(repo, existing)?);
        assert_eq!(incremental, full, "the result must equal a full rebuild");
        Ok(())
    }
}
