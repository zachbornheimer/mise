//! One synchronization: fetch the ordinary origin branch, reconcile against
//! Git ancestry, and publish without rewriting history (on a rejection, fetch
//! again and retry). Record operational health and derive `sync.json` with
//! incoming changes to apply and conflicts to decide.
//! Captures never wait on the network; this never changes a
//! live file (application is its own operation).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr, bail};
use serde::{Deserialize, Serialize};

use super::SyncMode;
use super::format::{self, RepoState};
use super::layout::{Located, Roots, is_configuration};
use super::network::{PushOutcome, Remote, UPSTREAM_REF};
use super::publish_skip_reason::PublishSkip;
use super::reconcile::{self, Conflict, Object, PathPlan};
use super::{publish, share, state};
use crate::history::checkpoint::Store;
use crate::history::config::OriginTomlConfig;
use crate::history::store as hstore;
use crate::history::tracked::{Asked, ExcludeSet, TrackedSet};
use mise_util::file::display_path;

/// How many times one sync re-plans because the local saved history moved
/// while it planned. The watcher saves every edit, so a busy machine moves it
/// often; a bound keeps a machine that never settles from looping forever.
const REPLAN_LIMIT: usize = 20;

/// How many times one sync may push before a rejection is final. Machines
/// that publish together all lose the race except one; enough attempts let
/// the losers fetch the winner and fast-forward instead of failing together.
const PUSH_ATTEMPTS: usize = 8;

/// Upper bound of the wait before the next fetch, in milliseconds, growing by
/// retry and then capped. The first rejected push waits at most half a second.
const REJECTION_DELAYS_MS: [u64; 3] = [500, 1_000, 2_000];
const REJECTION_DELAY_CAP_MS: u64 = 3_000;

/// How long to wait before fetching again after rejected publication `retry`
/// (the first rejection is 1). `sample` picks a delay from the upper half of
/// that retry's bound: `0` is the lower end and `u32::MAX` is the bound, so
/// two machines that lose the same race do not fetch again together.
fn rejection_delay(retry: u32, sample: u32) -> Duration {
    let bound = REJECTION_DELAYS_MS
        .get(retry.saturating_sub(1) as usize)
        .copied()
        .unwrap_or(REJECTION_DELAY_CAP_MS);
    let lower = bound / 2;
    let span = bound - lower;
    Duration::from_millis(lower + (span * u64::from(sample)) / u64::from(u32::MAX))
}

/// Draws the wait for rejected publication `retry` and hands it to `wait`.
/// Production sleeps; a test records the duration and returns.
fn pause_after_rejection(retry: u32, wait: &mut impl FnMut(Duration)) {
    wait(rejection_delay(retry, rand::random()));
}

/// An incoming change waiting for `mise dot pull` (or automatic
/// application in `sync` mode).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingApplication {
    pub branch_path: String,
    /// `None` deletes the local file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<Object>,
    /// Configuration, whose change may alter declarations.
    pub configuration: bool,
    /// The state to record once the write succeeds.
    pub next: state::SyncRecord,
    /// Saved local version used to compute this application. Absence is
    /// significant: saving a newer version never authorizes overwriting it.
    #[serde(default)]
    pub local: Option<Object>,
}

/// A path sync leaves alone, and why; listed by `mise dot status`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedPath {
    pub branch_path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub local: Option<Object>,
    pub remote: Option<Object>,
    pub live: Option<Object>,
    pub take_remote: bool,
    pub local_mode: Option<u32>,
    pub remote_mode: Option<u32>,
    pub live_mode: Option<u32>,
}

/// Derived from the repository after every sync; rebuilt when it
/// disagrees.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Choices are bound to all three observed versions, not just a path.
    #[serde(default)]
    pub resolutions: BTreeMap<String, Resolution>,
    /// A failed application is not cleared by successful network traffic.
    /// An explicit pull retries the complete batch after inspecting it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_publish: Option<String>,
    /// Why the latest sync did not publish, when something blocked it. A
    /// skip is not an error: `last_error` stays empty. Absent when the
    /// sync published or had nothing to publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_skipped: Option<PublishSkip>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fetch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply: Option<String>,
    #[serde(default)]
    pub conflicts: Vec<Conflict>,
    #[serde(default)]
    pub pending_applications: Vec<PendingApplication>,
    /// Paths neither applied nor removed, with why (nested repositories).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedPath>,
    /// Repository metadata and inactive streams can change without live writes.
    #[serde(default)]
    pub pending_repository: bool,
    /// Directories here whose incoming permissions differ, which a pull
    /// changes even when no file does.
    #[serde(default, skip_serializing_if = "no_directories")]
    pub pending_directories: usize,
    /// Incoming configuration changed declarations: run `mise bootstrap`.
    #[serde(default)]
    pub declarations_changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the current run of failed syncs began; a success clears it. An
    /// origin that has never answered has no last success to measure from,
    /// so `mise doctor` measures the failure from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub consecutive_failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_commit: Option<String>,
    /// The user confirmed adopting an unmarked repository.
    #[serde(default)]
    pub adopted: bool,
    /// The repository this state belongs to; another one starts afresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_branch: Option<String>,
    /// Whether this conflict-paused episode has already been observed.
    #[serde(default)]
    pub conflict_pause_observed: bool,
    /// `origin --remove` was run: the recorded repository no longer stands
    /// in for a declaration.
    #[serde(default)]
    pub disconnected: bool,
}

fn no_directories(count: &usize) -> bool {
    *count == 0
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

pub(crate) fn status_path(state_dir: &Path) -> PathBuf {
    hstore::store_dir_in(state_dir).join("sync.json")
}

pub fn read_status(state_dir: &Path) -> Result<SyncStatus> {
    let path = status_path(state_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(SyncStatus::default()),
        Err(err) => return Err(err).wrap_err_with(|| format!("cannot read sync state {}; repair its permissions or restore it from a backup before syncing", display_path(&path))),
    };
    serde_json::from_str(&text).wrap_err_with(|| format!("invalid sync state {}; restore a valid copy before syncing; the existing state has been preserved", display_path(&path)))
}

pub(crate) fn write_status(state_dir: &Path, status: &SyncStatus) -> Result<()> {
    hstore::write_json(&status_path(state_dir), status)
}

#[cfg(test)]
mod status_read_tests {
    use super::*;

    #[test]
    fn missing_sync_status_is_empty_but_invalid_state_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_status(dir.path()).unwrap().conflicts.is_empty());
        let path = status_path(dir.path());
        mise_util::file::create_dir_all(path.parent().unwrap()).unwrap();
        let invalid = b"{\"resolutions\": broken";
        std::fs::write(&path, invalid).unwrap();
        assert!(
            read_status(dir.path())
                .unwrap_err()
                .to_string()
                .contains("invalid sync state")
        );
        assert_eq!(std::fs::read(&path).unwrap(), invalid);
    }

    #[test]
    fn unreadable_sync_status_is_not_treated_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        mise_util::file::create_dir_all(status_path(dir.path())).unwrap();
        assert!(
            read_status(dir.path())
                .unwrap_err()
                .to_string()
                .contains("cannot read sync state")
        );
    }
}

#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub published: Option<String>,
    /// What blocked publication before anything was built.
    pub publish_skipped: Option<PublishSkip>,
    /// Incoming changes waiting for `mise dot pull`, counting the
    /// repository's own changes as one.
    pub pending: usize,
    /// Of those, the repository changed in a way that writes no file here:
    /// another machine's own versions, or enrollment.
    pub pending_repository: bool,
    /// Directories whose permissions a pull would change here.
    pub pending_directories: usize,
    pub conflicts: usize,
    pub fetched_upstream: Option<String>,
}

pub struct SyncRequest {
    pub fetch_only: bool,
    /// Skip the plaintext ancestry audit for this sync.
    pub allow_plaintext_history: bool,
    /// Save the tracked set first, so what is published is what is on
    /// disk. The watcher passes `false`: it saves on its own schedule, and a
    /// throttled file's held version or a manual-save entry's unsaved edits
    /// must not reach the repository through a sync.
    pub capture: bool,
    /// The repository to use instead of `[history.origin]` (onboarding,
    /// before the configuration that declares it is in place).
    pub origin: Option<OriginTomlConfig>,
    /// No network: reconcile against the branch as last fetched and record
    /// what is pending (after an incoming configuration declared more).
    pub offline: bool,
    /// A preview: nothing is announced (the caller puts the recorded state
    /// back afterwards).
    pub dry_run: bool,
    /// Wait in line behind a running sync or pull (`history.lock_wait`)
    /// instead of failing at once. Commands someone runs queue; the watcher
    /// does not, because it retries a contended sync on its own schedule.
    pub queue: bool,
    /// How long a queued sync waits for the lock before giving up; `None`
    /// uses `history.lock_wait`. This is `--wait`, so a caller can bound a
    /// wait longer or shorter than the setting.
    pub wait: Option<Duration>,
}

impl SyncRequest {
    pub fn new(fetch_only: bool) -> Self {
        Self {
            fetch_only,
            allow_plaintext_history: false,
            capture: true,
            origin: None,
            offline: false,
            dry_run: false,
            queue: false,
            wait: None,
        }
    }
}

/// The connected origin, or why there is none.
pub fn origin() -> Result<OriginTomlConfig> {
    if crate::history::local::active() {
        bail!("local-only history is never shared with a setup repository");
    }
    if let Some((_, origin)) = crate::history::config::origin()? {
        return Ok(origin);
    }
    // recorded when it was connected: a fresh machine's declaration may
    // still be on its way in the configuration being pulled
    let status = read_status(&super::super::local::root())?;
    if let (Some(url), Some(branch), false) =
        (status.origin_url, status.origin_branch, status.disconnected)
    {
        return Ok(OriginTomlConfig::plain(url, branch));
    }
    bail!("no setup repository is connected; `mise dot origin set <url>` connects one")
}

/// Whether the saved history has moved since `shared` was read from it. The
/// watcher saves a checkpoint on every edit, so this is how a sync finds out
/// that the plans built from `shared` no longer describe what would be
/// published.
fn head_moved(
    repo: &crate::history::shadow::HistoryRepo,
    shared: &share::ShareReport,
) -> Result<bool> {
    Ok(repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)? != shared.checkpoint)
}

/// Runs one synchronization.
pub fn sync(store: &Store, tracked: &TrackedSet, request: &SyncRequest) -> Result<SyncOutcome> {
    let asked = chrono::Utc::now();
    let _sync_lock = if request.queue {
        match lock_in(store.state_dir()) {
            Ok(lock) => lock,
            Err(_) => match wait_in_line(store, tracked, request, asked)? {
                Queued::Lock(lock) => lock,
                Queued::Served(outcome) => return Ok(outcome),
            },
        }
    } else {
        lock(store)?
    };
    sync_locked(store, tracked, request)
}

enum Queued {
    Lock(fslock::LockFile),
    Served(SyncOutcome),
}

/// Waits for the sync lock behind a running sync, and stops waiting as soon
/// as a sync that began after this one was asked has published what this
/// machine had saved when it was asked. The lock is not first come, first
/// served: polling waiters race for it, and one could lose to newer syncs
/// until its wait ran out although each of them had already done its work.
/// Checking while waiting needs no lock: `sync.json` is replaced
/// atomically, and a sync writes it once, when it is done.
fn wait_in_line(
    store: &Store,
    tracked: &TrackedSet,
    request: &SyncRequest,
    asked: chrono::DateTime<chrono::Utc>,
) -> Result<Queued> {
    // a dry run, an offline sync and a sync to another origin are not the
    // sync whose result another one reports, so they only wait
    let may_be_covered = !request.dry_run && !request.offline && request.origin.is_none();
    // what this sync must publish is what is saved now, so save the live
    // files first, as the sync itself would (skipped while another write
    // operation holds the files, exactly as the sync would skip it)
    if may_be_covered && request.capture {
        capture_now(store, tracked);
    }
    let pinned = store
        .repo()
        .map(|repo| repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF))
        .transpose()?
        .flatten();
    let publishes = SyncMode::current()?.publishes() && !request.fetch_only;
    let wait = request
        .wait
        .unwrap_or_else(crate::history::scope::operation_lock_wait);
    let deadline = Instant::now() + wait;
    let mut seen_fetch = None;
    loop {
        if let Some(lock) = mise_util::lock_file::LockFile::at(&lock_path(store.state_dir()))
            .with_pid()
            .try_lock()?
        {
            return Ok(Queued::Lock(lock));
        }
        let status = read_status(store.state_dir())?;
        if may_be_covered && status.last_fetch != seen_fetch {
            seen_fetch = status.last_fetch.clone();
            if let Some(outcome) = covered(store, &status, asked, pinned.as_deref(), publishes)? {
                debug!("history sync: a sync that began after this one covered it");
                return Ok(Queued::Served(outcome));
            }
        }
        if Instant::now() >= deadline {
            return Err(contended(store.state_dir(), Some(wait)));
        }
        std::thread::sleep(STATUS_LOCK_POLL);
    }
}

/// Whether the sync that last wrote `status` did this sync's work: it
/// fetched after this sync was asked, succeeded, and (when this sync would
/// publish) the origin holds `pinned`, the newest checkpoint saved when this
/// sync was asked.
fn covered(
    store: &Store,
    status: &SyncStatus,
    asked: chrono::DateTime<chrono::Utc>,
    pinned: Option<&str>,
    publishes: bool,
) -> Result<Option<SyncOutcome>> {
    let fetched_since_asked = status
        .last_fetch
        .as_deref()
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .is_some_and(|at| at >= asked);
    if !fetched_since_asked || status.last_error.is_some() {
        return Ok(None);
    }
    if publishes && let Some(pinned) = pinned {
        let Some(repo) = store.repo() else {
            return Ok(None);
        };
        let Some(upstream) = repo.ref_oid(UPSTREAM_REF)? else {
            return Ok(None);
        };
        if upstream != pinned
            && !repo
                .merge_bases(pinned, &upstream)?
                .iter()
                .any(|base| base == pinned)
        {
            return Ok(None);
        }
    }
    // Nothing was published and nothing was skipped by this sync: those
    // fields, and any the mirror adds to the outcome, keep their defaults.
    Ok(Some(SyncOutcome {
        pending: status.pending_applications.len() + usize::from(status.pending_repository),
        pending_repository: status.pending_repository,
        pending_directories: status.pending_directories,
        conflicts: status.conflicts.len(),
        fetched_upstream: status.upstream_commit.clone(),
        ..Default::default()
    }))
}

/// Runs one synchronization while the caller holds the sync lock.
pub(crate) fn sync_locked(
    store: &Store,
    tracked: &TrackedSet,
    request: &SyncRequest,
) -> Result<SyncOutcome> {
    sync_locked_waiting(
        store,
        tracked,
        request,
        &mut std::thread::sleep,
        &mut |_| {},
    )
}

/// [`sync_locked`], with the wait a rejected publication takes before it
/// fetches again and the hook that runs after each fetch. Production sleeps
/// and does nothing after a fetch; a caller may record the wait and move the
/// origin between the fetch and the push. The publication and the re-plan are
/// unchanged.
fn sync_locked_waiting(
    store: &Store,
    tracked: &TrackedSet,
    request: &SyncRequest,
    wait: &mut impl FnMut(Duration),
    after_fetch: &mut impl FnMut(&str),
) -> Result<SyncOutcome> {
    // Synchronizing publishes and applies, so it does not run on a rule
    // set that could not be fully built: the missing rules are exactly
    // the paths that would then look selected here.
    tracked.refuse_unusable_exclusions()?;
    let origin = match &request.origin {
        Some(origin) => origin.clone(),
        None => origin()?,
    };
    let repo = store
        .repo()
        .ok_or_else(|| eyre::eyre!("synchronizing requires git"))?;
    let mode = SyncMode::current()?;
    let allow_plaintext_history = request.allow_plaintext_history
        || mise_settings::Settings::get()
            .history
            .allow_plaintext_history;
    let state_dir = store.state_dir();
    let mut status = read_status(state_dir)?;
    let remote = Remote::new(repo, &origin.url);
    let mut outcome = SyncOutcome::default();

    let result = (|| -> Result<()> {
        if !request.offline {
            // a branch that vanished from a repository this machine had
            // synced with is not an empty upstream: reading it as one would
            // queue the deletion of every file it held
            let found = remote.fetch(&origin.branch)?;
            after_fetch(&origin.url);
            if !found && status.upstream_commit.is_some() {
                bail!(
                    "the setup branch `{}` is not at {} any more (renamed, or deleted?); nothing was changed. `mise dot origin set {} --branch <name>` follows a renamed branch",
                    origin.branch,
                    origin.url,
                    origin.url
                );
            }
            // a machine that has never synced has no vanished-branch signal,
            // so a branch this repository does not have (a declaration that
            // named the wrong one, or omitted it and took the default) must
            // not read as an empty upstream either
            if !found {
                super::origin::refuse_missing_branch(&remote, &origin.branch, &origin.url)?;
            }
            if !found && repo.ref_oid(UPSTREAM_REF)?.is_some() {
                repo.delete_ref(UPSTREAM_REF)?;
            }
            status.last_fetch = Some(hstore::now_rfc3339());
        }
        let mut upstream_commit = repo.ref_oid(UPSTREAM_REF)?;
        outcome.fetched_upstream = upstream_commit.clone();
        let repo_state = format::detect(repo, upstream_commit.as_deref())?;
        repo_state.check()?;
        if repo_state == RepoState::Unmarked && !status.adopted {
            bail!(
                "{} is an existing repository without the mise marker; `mise dot origin set {}` previews how it would be adopted",
                origin.url,
                origin.url
            );
        }
        // ours is the saved version: save what is live first, so a fresh
        // machine's existing files take part in adoption
        if request.capture
            && !(repo
                .ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?
                .is_none()
                && upstream_commit.is_some()
                && tracked.manifest.enrollment.is_empty())
        {
            capture_now(store, tracked);
            // a baseline of paths that do not exist yet holds no file: the
            // origin's history replaces it rather than read as unrelated
            super::origin::discard_contentless_history(repo)?;
        }
        let publish = mode.publishes() && !request.fetch_only && !request.offline;
        // Before the saved history is read for planning, so the plans describe
        // the history that is published.
        if publish && !allow_plaintext_history {
            rerecord_unpublished(store, tracked, upstream_commit.as_deref())?;
        }
        let mut shared = share::current(repo, tracked)?;
        let mut unsaved = unsaved_paths(repo, tracked, &shared)?;
        if publish
            && !allow_plaintext_history
            && let Some(head) = repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?
        {
            audit_publication(repo, &head, tracked)?;
        }
        let mut plans;
        let mut attempts = 0;
        let mut replans = 0;
        loop {
            attempts += 1;
            // The plans below are built from `shared`, the saved history as it
            // was when it was read. A checkpoint saved since then (autosave
            // keeps saving while a sync runs) was never examined by them, so
            // publishing past it is unsafe and failing wastes the whole sync.
            // Read the history again and plan again instead. Re-planning is not
            // a rejected push, so it does not spend the push retries.
            if head_moved(repo, &shared)?
                && !shared.checkpoint.as_deref().is_some_and(|pinned| {
                    publish::fast_forwards(
                        repo,
                        pinned,
                        repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)
                            .ok()
                            .flatten()
                            .as_deref(),
                        upstream_commit.as_deref(),
                    )
                    .unwrap_or(false)
                })
            {
                replans += 1;
                if replans > REPLAN_LIMIT {
                    bail!(
                        "local saved history kept changing while planning ({REPLAN_LIMIT} re-plans); retry shortly"
                    );
                }
                debug!("history sync: saved history moved while planning, planning again");
                attempts -= 1;
                if publish && !allow_plaintext_history {
                    rerecord_unpublished(store, tracked, upstream_commit.as_deref())?;
                }
                shared = share::current(repo, tracked)?;
                unsaved = unsaved_paths(repo, tracked, &shared)?;
                if publish
                    && !allow_plaintext_history
                    && let Some(head) =
                        repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?
                {
                    audit_publication(repo, &head, tracked)?;
                }
                continue;
            }
            let upstream = reconcile::upstream_with_interaction(
                repo,
                upstream_commit.as_deref(),
                request.capture && console::user_attended_stderr(),
            )?;
            let sync_state = state::load(repo)?;
            plans = prepare(
                repo,
                state_dir,
                tracked,
                &shared,
                &upstream,
                &unsaved,
                &mut status,
            )?;
            // Observing identical versions establishes a baseline even when
            // there is no publication (including fetch-only connections).
            let mut observed = sync_state.clone();
            for plan in &plans {
                if plan.is_noop() {
                    observed.insert(plan.branch_path.clone(), plan.next.clone());
                }
            }
            if observed != sync_state {
                state::save(repo, &observed, "observed identical versions")?;
            }
            let gate = if request.offline {
                Some(PublishSkip::Offline)
            } else if !publish {
                Some(PublishSkip::FetchOnly)
            } else {
                None
            };
            // Publication must wait for the entire incoming setup, not
            // just configuration or encrypted paths. A merge cannot be
            // acknowledged while its live application is still pending.
            if let Some(skip) = PublishSkip::detect(gate, &status, &plans) {
                outcome.publish_skipped = Some(skip);
                break;
            }
            let accepted = plans
                .iter()
                .filter(|plan| plan.conflict.is_none() && plan.apply.is_none())
                .map(|plan| plan.branch_path.clone())
                .collect();
            let Some(commit) = publish::build(
                repo,
                upstream_commit.as_deref(),
                shared.checkpoint.as_deref(),
                &accepted,
                allow_plaintext_history,
            )?
            else {
                break;
            };
            // The candidate may be our own new merge commit. A rejected
            // push must retry from it, without treating it as another
            // writer's change or dropping either parent history.
            shared.checkpoint = Some(commit.clone());
            match publish::push(&remote, &origin.branch, &commit, upstream_commit.as_deref())? {
                PushOutcome::Done => {
                    outcome.published = Some(commit.clone());
                    status.last_publish = Some(hstore::now_rfc3339());
                    repo.update_ref(UPSTREAM_REF, &commit, upstream_commit.as_deref())?;
                    upstream_commit = Some(commit);
                    // the published plans are acknowledged now
                    let mut next_state = sync_state.clone();
                    for plan in &plans {
                        if plan.publish.is_some() {
                            next_state.insert(plan.branch_path.clone(), plan.next.clone());
                        }
                    }
                    for plan in &plans {
                        if plan.publish.is_none() && plan.apply.is_none() && plan.conflict.is_none()
                        {
                            next_state.insert(plan.branch_path.clone(), plan.next.clone());
                        }
                    }
                    state::save(repo, &next_state, "published")?;
                    // the applications and conflicts are relative to the new head
                    let upstream = reconcile::upstream_with_interaction(
                        repo,
                        upstream_commit.as_deref(),
                        request.capture && console::user_attended_stderr(),
                    )?;
                    plans = prepare(
                        repo,
                        state_dir,
                        tracked,
                        &shared,
                        &upstream,
                        &unsaved,
                        &mut status,
                    )?;
                    break;
                }
                PushOutcome::Rejected(reason) if attempts < PUSH_ATTEMPTS => {
                    debug!(
                        "history sync: publication rejected, waiting before fetching again: {reason}"
                    );
                    pause_after_rejection(attempts as u32, wait);
                    remote.fetch(&origin.branch)?;
                    after_fetch(&origin.url);
                    upstream_commit = repo.ref_oid(UPSTREAM_REF)?;
                }
                PushOutcome::Rejected(reason) => {
                    bail!("publication kept being rejected after {attempts} attempts: {reason}")
                }
            }
        }
        status.upstream_commit = upstream_commit.clone();
        status.publish_skipped = outcome.publish_skipped.clone();
        record_pending(&mut status, &plans, &Roots::current(), &shared.objects());
        outcome.pending =
            status.pending_applications.len() + usize::from(status.pending_repository);
        outcome.pending_repository = status.pending_repository;
        outcome.pending_directories = status.pending_directories;
        outcome.conflicts = status.conflicts.len();
        status.last_error = None;
        status.failing_since = None;
        status.consecutive_failures = 0;
        status.backoff_until = None;
        if !request.dry_run {
            notify_new_conflicts(&mut status);
        }
        Ok(())
    })();
    if let Err(err) = &result {
        status.pending_applications.clear();
        status.last_error = Some(format!("{err:#}"));
        status.failing_since.get_or_insert_with(hstore::now_rfc3339);
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        if !request.dry_run {
            notify_new_conflicts(&mut status);
        }
    }
    if let Err(write_error) = write_status(state_dir, &status) {
        return match result {
            Err(error) => Err(error.wrap_err(format!(
                "also failed to record sync health: {write_error:#}"
            ))),
            Ok(()) => Err(write_error),
        };
    }
    result.map(|()| outcome)
}

/// How long a status update waits for a running sync or pull to finish.
pub(crate) const STATUS_LOCK_WAIT: Duration = Duration::from_secs(5);
const STATUS_LOCK_POLL: Duration = Duration::from_millis(100);

fn audit_publication(
    repo: &crate::history::shadow::HistoryRepo,
    head: &str,
    tracked: &TrackedSet,
) -> Result<()> {
    super::files::audit_history(repo, head, &publication_protected(repo, head, tracked)?)
}

/// The encrypted paths the publish audit covers: the live tracked set plus
/// every enrollment the proposed ancestry itself recorded. A path encrypted
/// only in an unpublished checkpoint is still protected.
fn publication_protected(
    repo: &crate::history::shadow::HistoryRepo,
    head: &str,
    tracked: &TrackedSet,
) -> Result<BTreeSet<String>> {
    let mut protected = tracked
        .entries
        .iter()
        .filter(|entry| entry.policy.encrypt)
        .map(|entry| entry.tree_path(&entry.path))
        .collect::<Result<BTreeSet<_>>>()?;
    let objects = repo.gix()?;
    let commits = repo.rev_list(head, usize::MAX)?;
    super::files::enrolled_paths(&objects, &commits, &mut protected)?;
    Ok(protected)
}

/// Re-records unpublished work the publish audit refuses.
///
/// A checkpoint saved before its path was marked for encryption holds that
/// path in plaintext, and the audit refuses every publish while any such
/// commit is in the local ancestry. When every refused version lives only in
/// commits the origin does not have, and the local tip's own tree passes the
/// audit, the unpublished checkpoints are replaced by one new checkpoint: the
/// tip's tree on the merge base with the origin, the commit a normal sync
/// merges from. The old tip stays reachable under `refs/mise/unpublishable/`,
/// which is never pushed.
///
/// The new commit is audited before the branch moves, so nothing here lets
/// plaintext through: a refused version the origin already has, a tip that
/// itself fails, or histories with no single merge base all leave the branch
/// alone for the audit to refuse.
fn rerecord_unpublished(
    store: &Store,
    tracked: &TrackedSet,
    upstream: Option<&str>,
) -> Result<bool> {
    use crate::history::shadow::HistoryRepo;

    let (Some(repo), Some(upstream)) = (store.repo(), upstream) else {
        return Ok(false);
    };
    let Some(head) = repo.ref_oid(HistoryRepo::HISTORY_REF)? else {
        return Ok(false);
    };
    let protected = publication_protected(repo, &head, tracked)?;
    if super::files::plaintext_versions(repo, &head, &protected)?.is_empty() {
        return Ok(false);
    }
    let bases = repo.merge_bases(&head, upstream)?;
    let [base] = bases.as_slice() else {
        return Ok(false);
    };
    let replaced = repo.rev_list_after(&head, base)?.len();
    let tree = repo
        .gix()?
        .find_commit(gix::ObjectId::from_hex(head.as_bytes())?)
        .wrap_err_with(|| format!("reading {head}"))?
        .tree_id()?
        .to_string();
    let backup_name = unpublishable_ref(repo)?;
    let message = format!(
        "re-recorded {replaced} unpublished checkpoint(s)\n\n\
         The audit refused a saved version of an encrypted path in those checkpoints, \
         which were never published. They are replaced by this checkpoint, which holds \
         the same files. The previous tip is kept at {backup_name}."
    );
    let new = repo.commit_tree(&tree, vec![base.as_str()], &message)?;
    // Audited before anything moves. A commit the origin already has that is
    // refused, or a tip that fails itself, fails here too and is left as it is.
    let after = publication_protected(repo, &new, tracked)?;
    if !super::files::plaintext_versions(repo, &new, &after)?.is_empty() {
        return Ok(false);
    }
    repo.update_ref(&backup_name, &head, None)?;
    repo.update_history_head(&new, Some(&head))?;
    store.rebuild_index()?;
    info!(
        "history: re-recorded {replaced} unpublished checkpoint(s) that held plaintext of an encrypted path; the previous tip is kept at {backup_name}"
    );
    Ok(true)
}

/// A fresh `refs/mise/unpublishable/<utc timestamp>` name.
fn unpublishable_ref(repo: &crate::history::shadow::HistoryRepo) -> Result<String> {
    let stamp = hstore::now_rfc3339().replace(':', "-");
    let mut name = format!("refs/mise/unpublishable/{stamp}");
    let mut attempt = 1;
    while repo.ref_oid(&name)?.is_some() {
        attempt += 1;
        name = format!("refs/mise/unpublishable/{stamp}-{attempt}");
    }
    Ok(name)
}

fn lock_path(state_dir: &Path) -> PathBuf {
    hstore::store_dir_in(state_dir).join("sync.lock")
}

/// Who holds the sync lock, for a refusal to name: the pid the holder
/// recorded, the command that pid runs, and how long it has held the lock.
/// "Another sync is running" and "a watcher is parked on the lock" read the
/// same without this, and only one of them is worth waiting for.
fn describe_holder(state_dir: &Path) -> String {
    let path = lock_path(state_dir);
    let Some(pid) = mise_util::lock_file::read_holder_pid(&path) else {
        return "the holder recorded no pid (a mise older than this one, or it released the lock as this was read)".to_string();
    };
    let command = process_command(pid)
        .map(|command| format!(" running `{command}`"))
        .unwrap_or_default();
    let held = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|written| written.elapsed().ok())
        .map(|held| format!(", holding the lock for {}", human_duration(held)))
        .unwrap_or_default();
    let liveness = if process_alive(pid) {
        ""
    } else {
        ", and that process has exited (an older holder took the lock without recording a pid)"
    };
    format!("pid {pid}{command}{held}{liveness}")
}

/// The command line of `pid`, best effort. Another user's process, a process
/// that exited, or a platform without the source of truth yields nothing and
/// the refusal names the pid alone.
#[cfg(target_os = "linux")]
fn process_command(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = raw
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    (!command.is_empty()).then_some(command)
}

#[cfg(not(target_os = "linux"))]
fn process_command(pid: u32) -> Option<String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let command = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!command.is_empty()).then_some(command)
}

/// Whether `pid` is still running. Unanswerable counts as running: a refusal
/// that wrongly says the holder is gone would invite concurrent syncs.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// A lock age in the units someone reads at a glance: seconds under a
/// minute, then minutes, then hours and minutes.
fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m", seconds / 60),
        _ => format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60),
    }
}

/// The sync lock: every reader-then-writer of `sync.json` holds it. A sync
/// or pull takes it for its whole duration and fails at once when another
/// holds it.
pub fn lock(store: &Store) -> Result<fslock::LockFile> {
    lock_in(store.state_dir())
}

/// The sync lock for a command someone ran: it waits its turn behind a
/// running sync or pull for `history.lock_wait`, as a save waits behind a
/// running save, so syncs started together run one after another instead of
/// all but one failing. The watcher keeps [`lock`]: waiting would stall its
/// event loop, and it retries a contended sync on its own schedule.
pub fn lock_queued(store: &Store, wait: Option<Duration>) -> Result<fslock::LockFile> {
    lock_wait(
        store.state_dir(),
        wait.unwrap_or_else(crate::history::scope::operation_lock_wait),
    )
}

/// The sync lock was already held. The text is the refusal a command prints;
/// the type is how the watcher tells a held lock from a sync that failed.
#[derive(Debug)]
pub(crate) struct SyncLockHeld {
    pub holder: String,
    waited: Option<Duration>,
}

impl std::fmt::Display for SyncLockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.waited {
            None => write!(
                f,
                "another setup sync or pull is running: {}; pass `--wait <duration>` to queue behind it, or stop the holder",
                self.holder
            ),
            Some(waited) => write!(
                f,
                "another setup sync or pull is running: {}; waited {} and gave up, so raise `history.lock_wait`, pass a longer `--wait`, or stop the holder",
                self.holder,
                human_duration(waited)
            ),
        }
    }
}

impl std::error::Error for SyncLockHeld {}

/// The refusal for a sync that could not take the lock: who holds it, and
/// what to do instead of retrying into the same wall. A command someone ran
/// can pick a wait; the watcher can only be stopped or waited out.
pub(crate) fn contended(state_dir: &Path, waited: Option<Duration>) -> eyre::Report {
    eyre::Report::new(SyncLockHeld {
        holder: describe_holder(state_dir),
        waited,
    })
}

/// Whether a sync or pull holds the sync lock right now. A reader that only
/// looks at `sync.json` and the fetched objects takes no lock: the record is
/// replaced atomically and the objects are immutable, so the worst a running
/// sync does is make what the reader shows out of date. This lets the reader
/// say so instead of queueing behind a network round trip.
pub fn sync_running(store: &Store) -> bool {
    matches!(
        mise_util::lock_file::LockFile::at(&lock_path(store.state_dir())).try_lock(),
        Ok(None)
    )
}
pub(crate) fn lock_in(state_dir: &Path) -> Result<fslock::LockFile> {
    mise_util::lock_file::LockFile::at(&lock_path(state_dir))
        .with_pid()
        .try_lock()?
        .ok_or_else(|| contended(state_dir, None))
}

/// Changes one thing in `sync.json` under the sync lock, reading the record
/// again first, so a sync or pull that finished meanwhile is not written
/// over with an older copy. Waits up to `wait` for a running one;
/// `Duration::ZERO` tries once.
pub(crate) fn update_status(
    state_dir: &Path,
    wait: Duration,
    mutate: impl FnOnce(&mut SyncStatus),
) -> Result<()> {
    let _lock = lock_wait(state_dir, wait)?;
    let mut status = read_status(state_dir)?;
    mutate(&mut status);
    write_status(state_dir, &status)
}

pub(crate) fn lock_wait(state_dir: &Path, wait: Duration) -> Result<fslock::LockFile> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(lock) = mise_util::lock_file::LockFile::at(&lock_path(state_dir))
            .with_pid()
            .try_lock()?
        {
            return Ok(lock);
        }
        if Instant::now() >= deadline {
            return Err(contended(state_dir, Some(wait)));
        }
        std::thread::sleep(STATUS_LOCK_POLL);
    }
}

/// A desktop notification for conflicts that newly need a decision, when
/// `history.notify` is on. Notify once per whole-setup pause, not per path.
/// Never blocks; a failure is only logged.
fn notify_new_conflicts(status: &mut SyncStatus) {
    notify_conflicts_with(
        status,
        mise_settings::Settings::get().history.notify,
        crate::history::notify::send,
    );
}

fn notify_conflicts_with(status: &mut SyncStatus, enabled: bool, send: impl FnOnce(&str, &str)) {
    let current: BTreeSet<String> = status
        .conflicts
        .iter()
        .map(|conflict| conflict.branch_path.clone())
        .collect();
    if !current.is_empty() && !status.conflict_pause_observed && enabled {
        let roots = Roots::current();
        let lines: Vec<String> = status
            .conflicts
            .iter()
            .take(1)
            .map(|conflict| {
                let path = roots
                    .locate(&conflict.branch_path)
                    .path()
                    .map(display_path)
                    .unwrap_or_else(|| conflict.branch_path.clone());
                let mut chars = path.chars().filter(|ch| !ch.is_control());
                let mut path: String = chars.by_ref().take(80).collect();
                if chars.next().is_some() {
                    path.push('…');
                }
                path
            })
            .collect();
        let more = current.len().saturating_sub(1);
        let body = if more > 0 {
            let noun = if more == 1 { "file" } else { "files" };
            format!("{} and {more} other {noun}", lines.join(""))
        } else {
            lines.join("\n")
        };
        send(
            "mise: dotfile sync paused",
            &format!(
                "Conflicting changes in {body}.\nLocal saves still work. For resolution steps, run:\nmise dot status"
            ),
        );
    }
    status.conflict_pause_observed = !current.is_empty();
}

/// Saves the tracked set now (deduplicated against the newest checkpoint),
/// so the versions this sync publishes are what is on disk.
pub(crate) fn capture_now(store: &Store, tracked: &TrackedSet) {
    use crate::history::checkpoint::Draft;
    use crate::history::store::Trigger;
    let capture = || -> Result<()> {
        let Some(_operation) = crate::history::scope::try_operation_lock(store, tracked)? else {
            debug!("history sync: a write operation is active; keeping the existing saved commits");
            return Ok(());
        };
        store.attempt(tracked, Draft::new(Trigger::Edit))?;
        Ok(())
    };
    match capture() {
        Ok(_) => {}
        Err(err) => warn!("history sync: could not save the current state first: {err:#}"),
    }
}

/// Records what is left to apply or decide, keeping the newest upstream
/// version for a path whose application was already pending.
fn record_pending(
    status: &mut SyncStatus,
    plans: &[PathPlan],
    roots: &Roots,
    shared: &BTreeMap<String, Object>,
) {
    status.conflicts = plans
        .iter()
        .filter_map(|plan| plan.conflict.clone())
        .collect();
    status.skipped = plans
        .iter()
        .filter_map(|plan| {
            Some(SkippedPath {
                branch_path: plan.branch_path.clone(),
                reason: plan.skipped.clone()?,
            })
        })
        .collect();
    status.pending_applications = plans
        .iter()
        .filter(|plan| plan.conflict.is_none())
        .filter_map(|plan| {
            let object = plan.apply.clone()?;
            roots.locate(&plan.branch_path).path()?;
            Some(PendingApplication {
                branch_path: plan.branch_path.clone(),
                object,
                configuration: is_configuration(&plan.branch_path),
                next: plan.next.clone(),
                local: shared.get(&plan.branch_path).cloned(),
            })
        })
        .collect();
    // said until `mise bootstrap` ran, even once the configuration is written
    status.declarations_changed = status.declarations_changed
        || status
            .pending_applications
            .iter()
            .any(|pending| pending.configuration);
}

/// Rebuild the incoming plan against current saved files and the latest
/// fetched branch. Pull never trusts an old pending plan after a save.
pub(crate) fn refresh(store: &Store, tracked: &TrackedSet, status: &mut SyncStatus) -> Result<()> {
    refresh_with_interaction(store, tracked, status, false)
}

pub fn refresh_with_interaction(
    store: &Store,
    tracked: &TrackedSet,
    status: &mut SyncStatus,
    interactive: bool,
) -> Result<()> {
    let repo = store
        .repo()
        .ok_or_else(|| eyre::eyre!("planning requires git"))?;
    let shared = share::current(repo, tracked)?;
    let upstream = reconcile::upstream_with_interaction(
        repo,
        repo.ref_oid(UPSTREAM_REF)?.as_deref(),
        interactive,
    )?;
    let plans = prepare(
        repo,
        store.state_dir(),
        tracked,
        &shared,
        &upstream,
        &unsaved_paths(repo, tracked, &shared)?,
        status,
    )?;
    status.upstream_commit = upstream.commit;
    record_pending(status, &plans, &Roots::current(), &shared.objects());
    // a refresh that finds nothing left to wait for clears a reason recorded
    // by an earlier sync; the next sync records a new one if it is blocked
    if let Some(skip) = &status.publish_skipped {
        let still_blocked = match skip {
            PublishSkip::PendingApplications { .. } => !status.pending_applications.is_empty(),
            PublishSkip::PendingRepository => status.pending_repository,
            PublishSkip::Conflicts { .. } => !status.conflicts.is_empty(),
            _ => true,
        };
        if !still_blocked {
            status.publish_skipped = None;
        }
    }
    Ok(())
}

/// First resolve configuration, then discover its complete incoming write
/// set in memory. Publication never gets ahead of this second preflight.
fn prepare(
    repo: &crate::history::shadow::HistoryRepo,
    state_dir: &Path,
    tracked: &TrackedSet,
    report: &share::ShareReport,
    upstream: &reconcile::Upstream,
    unsaved: &BTreeSet<String>,
    status: &mut SyncStatus,
) -> Result<Vec<PathPlan>> {
    let shared = &report.objects();
    // One observation of the heads, and one virtual base when there are
    // several. Tracking and the file baseline both use it; neither recomputes it.
    let heads = super::graph::Heads::read(repo)?;
    // A base conflict is a repository conflict. Computing it inside the
    // match would return before status records it, and a later caller
    // would see an empty conflict list for a pause that already happened.
    let base = enrollment_manifest(repo, &heads).inspect_err(|error| {
        if heads.local.is_some() && heads.remote.is_some() {
            repository_conflict(status, error);
        }
    })?;
    let incoming = incoming_tracking_with(repo, tracked, &heads, base.as_ref())
        .inspect_err(|error| repository_conflict(status, error))?;
    let tracked = &incoming;
    let roots = Roots::current();
    // **A live file that already holds the incoming version has no edit
    // for the incoming write to overwrite.** An apply interrupted after its
    // write leaves exactly that: the file is the incoming version, its
    // checkpoint was never recorded, and holding it as an unsaved edit
    // paused sharing over a change nobody made.
    let unsaved: BTreeSet<String> = unsaved
        .iter()
        .filter(|branch_path| !holds_incoming(repo, &roots, upstream, branch_path))
        .cloned()
        .collect();
    let unsaved = &unsaved;
    // Git ancestry, not a machine's replaceable acknowledgement cache,
    // determines the shared baseline. Losing local bookkeeping must not
    // turn an ordinary incoming edit into an unrelated adoption conflict.
    status.upstream_commit = heads.remote.clone();
    status.pending_repository = match &heads.local {
        Some(local) => {
            crate::history::manifest::Manifest::read(repo, local)?.as_ref()
                != Some(&tracked.manifest)
        }
        None => heads.remote.is_some(),
    };
    let repository_tree = incoming_repository_tree_with(repo, tracked, &heads)
        .inspect_err(|error| repository_conflict(status, error))?;
    status.pending_repository |= repository_tree.is_some();
    status.pending_directories = 0;
    if let Some(tree) = repository_tree.as_deref().or(heads.remote.as_deref()) {
        status.pending_directories = super::directories::plan(repo, tracked, tree)
            .inspect_err(|error| repository_conflict(status, error))?
            .len();
    }
    if heads.remote != upstream.commit {
        bail!("origin changed while planning; reconcile again");
    }
    // File ancestry is a real commit when there is one. Several merge
    // bases have no single commit, and a tree that holds only the virtual
    // enrollment is not their file history: reading it as a baseline would
    // invent an empty file set. Keep the conservative absence instead.
    let baseline = reconcile::upstream(repo, heads.base.as_deref())?;
    let local_manifest = heads
        .local
        .as_deref()
        .map(|head| crate::history::manifest::Manifest::read(repo, head))
        .transpose()?
        .flatten()
        .unwrap_or_default();
    let record = |object: Object| state::SyncRecord {
        acknowledged: Some(object.clone()),
        reconciled: Some(object.clone()),
        applied: Some(object),
        upstream_commit: heads.base.clone(),
    };
    let mut sync_state: state::SyncState = baseline
        .files
        .into_iter()
        .map(|(path, object)| (path, record(object)))
        .collect();
    // a stream this machine does not hold shares no baseline with upstream:
    // its baseline is the version it last held, and without one,
    // reconciling it is adopting it
    for (path, base) in &report.unheld {
        match base {
            Some(base) => sync_state.insert(path.clone(), record(base.clone())),
            None => sync_state.remove(path),
        };
    }
    let reconcile_set = |set: &TrackedSet| {
        // one compiled exclude set for the whole pass: the question is
        // asked once per upstream path and the patterns do not change
        let exclude = set.exclude_set()?;
        let selected = reconcile::Upstream {
            commit: upstream.commit.clone(),
            files: upstream
                .files
                .iter()
                .filter(|(path, object)| {
                    eligible(&roots, set, &exclude, path)
                        || (reconcile::is_gitlink(Some(object)) && owns_stream(&roots, set, path))
                })
                .map(|(path, object)| (path.clone(), object.clone()))
                .collect(),
            // never filtered: an origin plaintext version of an encrypted
            // path is reported for every such path the incoming config
            // declares, whether or not this machine selects it
            plaintext: upstream.plaintext.clone(),
        };
        let mut plans = reconcile::reconcile(repo, shared, &selected, &sync_state, unsaved)?;
        // Old acknowledgements are not authority to delete a path this
        // machine no longer declares or selects.
        plans.retain(|plan| {
            eligible(&roots, set, &exclude, &plan.branch_path)
                || (plan.skipped.is_some() && owns_stream(&roots, set, &plan.branch_path))
        });
        for (path, object) in shared {
            if reconcile::is_gitlink(Some(object))
                || !eligible(&roots, set, &exclude, path)
                || local_manifest.file_permissions(path, Some(object))
                    == set.manifest.file_permissions(path, Some(object))
            {
                continue;
            }
            if let Some(plan) = plans.iter_mut().find(|plan| plan.branch_path == *path) {
                if plan.conflict.is_none() && plan.apply.is_none() {
                    plan.apply = Some(Some(object.clone()));
                }
            } else {
                plans.push(PathPlan {
                    branch_path: path.clone(),
                    apply: Some(Some(object.clone())),
                    next: state::SyncRecord {
                        acknowledged: Some(object.clone()),
                        reconciled: Some(object.clone()),
                        applied: Some(object.clone()),
                        upstream_commit: upstream.commit.clone(),
                    },
                    ..Default::default()
                });
            }
        }
        Ok::<_, eyre::Report>(plans)
    };
    let mut plans = reconcile_set(tracked)?;
    apply_resolutions(repo, status, shared, upstream, &mut plans)?;
    reconcile::skip_pointer_applications(&mut plans, shared);
    status.validation_error = None;
    // Source deletion and invalid source types matter even when the bootstrap
    // configuration itself is unchanged or deliberately not tracked.
    if plans.iter().any(|plan| plan.apply.is_some()) {
        let validation = (|| -> Result<()> {
            let prospective = super::preflight::prospective(repo, state_dir, tracked, &plans)?;
            plans = reconcile_set(&prospective)?;
            apply_resolutions(repo, status, shared, upstream, &mut plans)?;
            reconcile::skip_pointer_applications(&mut plans, shared);
            super::preflight::sources(repo, &prospective, &plans)
        })();
        if let Err(error) = validation {
            status.validation_error = Some(format!("{error:#}"));
            for plan in &mut plans {
                if plan.apply.is_some() {
                    plan.conflict = Some(Conflict {
                        branch_path: plan.branch_path.clone(),
                        kind: reconcile::ConflictKind::InvalidIncoming,
                        local: shared.get(&plan.branch_path).cloned(),
                        remote: upstream.files.get(&plan.branch_path).cloned(),
                        base: plan.next.acknowledged.clone(),
                        detail: None,
                    });
                    plan.publish = None;
                }
            }
        }
    }
    Ok(plans)
}

/// Whether the live file at `branch_path` already is its incoming version.
fn holds_incoming(
    repo: &crate::history::shadow::HistoryRepo,
    roots: &Roots,
    upstream: &reconcile::Upstream,
    branch_path: &str,
) -> bool {
    let located = roots.locate(branch_path);
    let (Some(path), Some(incoming)) = (located.path(), upstream.files.get(branch_path)) else {
        return false;
    };
    super::apply::live_object(repo, path).is_ok_and(|live| live.as_ref() == Some(incoming))
}

fn repository_conflict(status: &mut SyncStatus, error: &eyre::Report) {
    status.pending_repository = true;
    status.validation_error = Some(format!("{error:#}"));
    status.conflicts = vec![Conflict {
        branch_path: crate::history::manifest::PATH.into(),
        kind: reconcile::ConflictKind::Repository,
        local: None,
        remote: None,
        base: None,
        detail: None,
    }];
}

fn apply_resolutions(
    repo: &crate::history::shadow::HistoryRepo,
    status: &mut SyncStatus,
    shared: &BTreeMap<String, Object>,
    upstream: &reconcile::Upstream,
    plans: &mut [PathPlan],
) -> Result<()> {
    let roots = Roots::current();
    let local_head = repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?;
    let saved_manifest = local_head
        .as_deref()
        .map(|head| crate::history::manifest::Manifest::read(repo, head))
        .transpose()?
        .flatten()
        .unwrap_or_default();
    let remote_manifest = upstream
        .commit
        .as_deref()
        .map(|head| crate::history::manifest::Manifest::read(repo, head))
        .transpose()?
        .flatten()
        .unwrap_or_default();
    let mut invalid = vec![];
    for (path, choice) in &status.resolutions {
        let live = match roots.locate(path).path() {
            Some(local) => match super::apply::live_object(repo, local) {
                Ok(live) => live,
                Err(_) => {
                    invalid.push(path.clone());
                    continue;
                }
            },
            None => {
                invalid.push(path.clone());
                continue;
            }
        };
        if shared.get(path) != choice.local.as_ref()
            || upstream.files.get(path) != choice.remote.as_ref()
            || live != choice.live
            || saved_manifest.file_permissions(path, shared.get(path)) != choice.local_mode
            || remote_manifest.file_permissions(path, upstream.files.get(path))
                != choice.remote_mode
            || roots
                .locate(path)
                .path()
                .map(super::apply::live_permissions)
                .transpose()?
                .flatten()
                != choice.live_mode
        {
            invalid.push(path.clone());
            continue;
        }
        if let Some(plan) = plans.iter_mut().find(|plan| plan.branch_path == *path) {
            plan.conflict = None;
            if choice.take_remote {
                plan.publish = None;
                plan.apply = Some(choice.remote.clone());
                plan.next.reconciled = choice.remote.clone();
            } else {
                plan.apply = None;
                plan.publish = Some(choice.local.clone());
                let oid = choice.local.clone();
                plan.next.acknowledged = oid.clone();
                plan.next.reconciled = oid.clone();
                plan.next.applied = oid;
            }
        }
    }
    for path in invalid {
        status.resolutions.remove(&path);
    }
    // A clean text merge is not sufficient: inspect every incoming live
    // path before any publication, so unsaved or staged edits pause the
    // whole setup instead of being discovered after other files shipped.
    let fresh = repo
        .ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?
        .is_none();
    let incoming_paths: Vec<_> = plans
        .iter()
        .filter(|plan| plan.apply.is_some())
        .filter_map(|plan| {
            roots
                .locate(&plan.branch_path)
                .path()
                .map(Path::to_path_buf)
        })
        .collect();
    let staged = super::apply::staged_paths(incoming_paths.iter().map(PathBuf::as_path))?;
    for plan in plans {
        let Some(incoming) = &plan.apply else {
            continue;
        };
        let located = roots.locate(&plan.branch_path);
        let Some(path) = located.path() else {
            continue;
        };
        let mut kind = None;
        if let Some((_, oid)) = incoming
            && is_configuration(&plan.branch_path)
            && path.extension().is_some_and(|ext| ext == "toml")
            && toml::from_str::<toml::Value>(&String::from_utf8_lossy(&repo.cat_object(oid)?))
                .is_err()
        {
            kind = Some(reconcile::ConflictKind::InvalidIncoming);
        }
        let live = super::apply::live_object(repo, path);
        let live_is_incoming = live.as_ref().is_ok_and(|live| live == incoming);
        match live {
            // a live file that already is the incoming version loses
            // nothing to its write: a machine adopting files it already
            // has, or an apply interrupted before it was recorded
            Ok(live)
                if live.as_ref() != shared.get(&plan.branch_path)
                    && !live_is_incoming
                    && !status
                        .resolutions
                        .get(&plan.branch_path)
                        .is_some_and(|r| r.take_remote) =>
            {
                kind = kind.or(Some(reconcile::ConflictKind::UnsavedEdits));
            }
            // Only the live path's own fault is a conflict: neither side of
            // the repository changed type, so say what is really there. A
            // repository or process failure is nobody's to fix by hand, so it
            // stops the pass with its own error instead of posing as one.
            Err(err) if err.downcast_ref::<super::apply::UnusableLive>().is_some() => {
                kind = kind.or(Some(reconcile::ConflictKind::UnusableLive));
            }
            Err(err) => return Err(err),
            _ => {}
        }
        // and the same for its mode: one the incoming write would set
        // anyway is not an edit, while a mode matching neither side is
        let mode_edited = || -> Result<bool> {
            let live_mode = super::apply::live_permissions(path)?;
            if live_mode
                == saved_manifest.file_permissions(&plan.branch_path, shared.get(&plan.branch_path))
            {
                return Ok(false);
            }
            let incoming_mode = super::apply::permissions_at(
                repo,
                upstream.commit.as_deref(),
                &plan.branch_path,
                incoming.as_ref(),
            )?;
            Ok(!(live_is_incoming && live_mode == incoming_mode))
        };
        if !fresh
            && mode_edited()?
            && !status
                .resolutions
                .get(&plan.branch_path)
                .is_some_and(|r| r.take_remote)
        {
            kind = kind.or(Some(reconcile::ConflictKind::UnsavedEdits));
        }
        if super::apply::has_staged_changes(&staged, path) {
            kind = kind.or(Some(reconcile::ConflictKind::StagedEdits));
        }
        if let Some(kind) = kind {
            plan.conflict = Some(Conflict {
                branch_path: plan.branch_path.clone(),
                kind,
                local: shared.get(&plan.branch_path).cloned(),
                remote: upstream.files.get(&plan.branch_path).cloned(),
                base: plan.next.acknowledged.clone(),
                detail: None,
            });
            plan.publish = None;
        }
    }
    Ok(())
}

/// Whether an upstream path belongs on this machine: configuration and
/// sources always; a tracked entry's stream only when it is the one this
/// machine selects (its variant, or the base stream when it has none), so
/// another platform's version is never applied here and never read as a
/// change. Undeclared paths wait for prospective incoming configuration;
/// their absence from this machine is not a publication of a deletion.
fn owns_stream(roots: &Roots, tracked: &TrackedSet, branch_path: &str) -> bool {
    match roots.locate(branch_path) {
        Located::Tracked { path, variant } => tracked
            .entry_for(&path)
            .is_some_and(|entry| entry.variant == variant),
        Located::Config(path) => tracked
            .entry_for(&path)
            .is_some_and(|entry| entry.variant.is_none()),
        Located::Marker | Located::Unmapped => false,
    }
}

// Legacy pointers produce only skip diagnostics, so their owning stream
// remains reportable even when live nested content is ineligible for apply.
///
/// **Declared is not the same as selected, and only a selected path can
/// be deleted.** A path the exclude lists drop is still covered by its
/// entry, so ownership alone says "managed here" about a file the
/// setup deliberately stopped capturing. Reconciliation then reads its
/// absence from the incoming snapshot as a deletion and removes the
/// local copy — narrowing on one machine deleting files on every other
/// one. `exclude` is asked here, against the same incoming set whose
/// snapshot the absence is being read from, so the two agree: a path
/// missing because selection no longer covers it is unmanaged, while a
/// path missing although selection still covers it was deleted, and
/// that deletion is propagated as before.
pub(super) fn eligible(
    roots: &Roots,
    tracked: &TrackedSet,
    exclude: &ExcludeSet,
    branch_path: &str,
) -> bool {
    match roots.locate(branch_path) {
        Located::Tracked { path, variant } => match tracked.entry_for(&path) {
            Some(entry) => {
                entry.variant == variant
                    && !tracked.excluded_by_lists(exclude, &path, Asked::Exactly)
            }
            None => false,
        },
        Located::Config(path) => {
            tracked
                .entry_for(&path)
                .is_some_and(|entry| entry.variant.is_none())
                && !tracked.excluded_by_lists(exclude, &path, Asked::Exactly)
        }
        Located::Marker => false,
        Located::Unmapped => false,
    }
}

/// The enrollment both tips descend from, so [`Manifest::merge`] can tell a
/// change from an addition.
///
/// One merge base is that commit's manifest. Several are one virtual
/// manifest: each pair is merged against the ancestry they share, and that
/// result is the base the tips are merged against. Nothing is dropped to
/// make the bases agree, and a pair that cannot be merged is a conflict
/// naming its path. A pair with no shared ancestry cannot be constructed;
/// that fails closed and names `mise dot status`, which prints the manual
/// reconciliation. The result is a manifest. When the merge needs a parent
/// for the next pair, that parent is an unreferenced commit whose only job
/// is to keep the accumulated ancestry; it is not a history ref and not a
/// file baseline.
pub(super) fn enrollment_base(
    repo: &crate::history::shadow::HistoryRepo,
    local: &str,
    remote: &str,
) -> Result<crate::history::manifest::Manifest> {
    enrollment_against(repo, local, remote, &mut EnrollmentCache::default()).wrap_err(
        "a virtual enrollment base could not be constructed; run `mise dot status` and reconcile the histories it names before syncing",
    )
}

fn enrollment_manifest(
    repo: &crate::history::shadow::HistoryRepo,
    heads: &super::graph::Heads,
) -> Result<Option<crate::history::manifest::Manifest>> {
    match (&heads.local, &heads.remote) {
        (Some(local), Some(remote)) => Ok(Some(enrollment_base(repo, local, remote)?)),
        _ => Ok(None),
    }
}

/// Pair, base, and manifest reads for one enrollment computation. A nested
/// criss-cross asks the same question of commits already answered.
#[derive(Default)]
struct EnrollmentCache {
    bases: std::collections::HashMap<(String, String), Vec<String>>,
    manifests: std::collections::HashMap<String, Option<crate::history::manifest::Manifest>>,
}

fn enrollment_against(
    repo: &crate::history::shadow::HistoryRepo,
    local: &str,
    remote: &str,
    cache: &mut EnrollmentCache,
) -> Result<crate::history::manifest::Manifest> {
    let bases = cached_bases(repo, local, remote, cache)?;
    if bases.is_empty() {
        // Heads::read already refuses unrelated tips before a sync plans.
        // Reaching here means two merge bases themselves share nothing, which
        // a user reconciles by hand. `mise dot conflicts` plans through this
        // same function, so it cannot be the recovery.
        bail!(
            "merge bases share no ancestry, so a virtual base cannot be constructed; \
             run `mise dot status` and reconcile the histories it names before syncing"
        );
    }
    if bases.len() == 1 {
        return Ok(cached_manifest(repo, &bases[0], cache)?.unwrap_or_default());
    }
    let mut paired = Vec::with_capacity(bases.len());
    for base in &bases {
        let manifest = cached_manifest(repo, base, cache)?.ok_or_else(|| {
            eyre::eyre!(
                "a merge base has no enrollment metadata, so a virtual base cannot be constructed; \
                 run `mise dot status` and reconcile the histories it names before syncing"
            )
        })?;
        paired.push((base.clone(), manifest));
    }
    virtual_enrollment(repo, &paired, cache)
}

fn cached_bases(
    repo: &crate::history::shadow::HistoryRepo,
    local: &str,
    remote: &str,
    cache: &mut EnrollmentCache,
) -> Result<Vec<String>> {
    let key = if local <= remote {
        (local.to_string(), remote.to_string())
    } else {
        (remote.to_string(), local.to_string())
    };
    if let Some(bases) = cache.bases.get(&key) {
        return Ok(bases.clone());
    }
    let bases = repo.merge_bases(local, remote)?;
    cache.bases.insert(key, bases.clone());
    Ok(bases)
}

fn cached_manifest(
    repo: &crate::history::shadow::HistoryRepo,
    commit: &str,
    cache: &mut EnrollmentCache,
) -> Result<Option<crate::history::manifest::Manifest>> {
    if let Some(manifest) = cache.manifests.get(commit) {
        return Ok(manifest.clone());
    }
    let manifest = crate::history::manifest::Manifest::read(repo, commit)?;
    cache.manifests.insert(commit.to_string(), manifest.clone());
    Ok(manifest)
}

/// Merge base manifests pairwise against the ancestry each pair shares.
///
/// Reducing left to right is safe because [`Manifest::merge`] is the only
/// rule, and it does not depend on which side is asked first when the two
/// sides differ: that is a conflict, not a choice. An accumulated result is
/// written as an unreferenced commit with both parents, so the next pair's
/// merge-base sees that ancestry instead of an empty id. A pair whose own
/// bases are several is the same function again.
fn virtual_enrollment(
    repo: &crate::history::shadow::HistoryRepo,
    bases: &[(String, crate::history::manifest::Manifest)],
    cache: &mut EnrollmentCache,
) -> Result<crate::history::manifest::Manifest> {
    use crate::history::manifest::Manifest;
    let mut reduced: Option<(String, Manifest)> = None;
    for (index, (commit, manifest)) in bases.iter().enumerate() {
        let last = index + 1 == bases.len();
        reduced = Some(match reduced {
            None => (commit.clone(), manifest.clone()),
            Some((previous, previous_manifest)) => {
                let shared = enrollment_against(repo, &previous, commit, cache)?;
                let merged = Manifest::merge(&shared, &previous_manifest, manifest)?;
                // The last pair has no later merge-base to answer, so its
                // parent commit would be written and never read.
                let accumulated = if last {
                    String::new()
                } else {
                    accumulated_parent(repo, &merged, &previous, commit, cache)?
                };
                (accumulated, merged)
            }
        });
    }
    reduced
        .map(|(_, manifest)| manifest)
        .ok_or_else(|| eyre::eyre!("a virtual base needs at least one merge base"))
}

/// An unreferenced commit whose parents are the two enrollments just merged.
/// Later pairs ask merge-base against it; nothing stores it as history or
/// reads its tree as a file baseline.
fn accumulated_parent(
    repo: &crate::history::shadow::HistoryRepo,
    merged: &crate::history::manifest::Manifest,
    left: &str,
    right: &str,
    cache: &mut EnrollmentCache,
) -> Result<String> {
    let empty = repo.empty_object("tree")?;
    let tree = merged.write(repo, &empty)?;
    let commit = repo.commit_tree(&tree, vec![left, right], "virtual enrollment base")?;
    cache.manifests.insert(commit.clone(), Some(merged.clone()));
    Ok(commit)
}

/// A fresh store gets its explicit inventory from the fetched ordinary branch.
/// Do not create an unrelated local root just to discover incoming files.
pub(super) fn incoming_tracking(
    repo: &crate::history::shadow::HistoryRepo,
    tracked: &TrackedSet,
) -> Result<TrackedSet> {
    let heads = super::graph::Heads::read(repo)?;
    let base = enrollment_manifest(repo, &heads)?;
    incoming_tracking_with(repo, tracked, &heads, base.as_ref())
}

fn incoming_tracking_with(
    repo: &crate::history::shadow::HistoryRepo,
    tracked: &TrackedSet,
    heads: &super::graph::Heads,
    base: Option<&crate::history::manifest::Manifest>,
) -> Result<TrackedSet> {
    use crate::history::manifest::Manifest;
    let Some(remote) = &heads.remote else {
        return Ok(tracked.clone());
    };
    let remote = Manifest::read(repo, remote)?
        .ok_or_else(|| eyre::eyre!("setup repository has no enrollment metadata"))?;
    let manifest = match &heads.local {
        None => remote,
        Some(local) => Manifest::merge(
            base.ok_or_else(|| {
                eyre::eyre!(
                "enrollment base was not computed; run `mise dot status` and reconcile the histories it names before syncing"
                )
            })?,
            &Manifest::read(repo, local)?.unwrap_or_default(),
            &remote,
        )?,
    };
    let mut incoming = manifest.tracking()?;
    incoming.required_sources = tracked.required_sources.clone();
    incoming.invalid = tracked.invalid.clone();
    // a path kept local here is never written from the repository, even
    // when another machine shares it
    incoming.local = tracked.local.clone();
    incoming.keep_local_out();
    Ok(incoming)
}

/// Complete-tree changes outside active native files still need adoption:
/// enrollment, inactive variants, and ordinary repository documentation.
pub(super) fn incoming_repository_tree(
    repo: &crate::history::shadow::HistoryRepo,
    tracked: &TrackedSet,
) -> Result<Option<String>> {
    incoming_repository_tree_with(repo, tracked, &super::graph::Heads::read(repo)?)
}

fn incoming_repository_tree_with(
    repo: &crate::history::shadow::HistoryRepo,
    tracked: &TrackedSet,
    heads: &super::graph::Heads,
) -> Result<Option<String>> {
    let (Some(local), Some(remote)) = (&heads.local, &heads.remote) else {
        return Ok(None);
    };
    if heads.base.as_ref() == Some(remote) {
        return Ok(None);
    }
    let (merged, conflicts) = repo.merge_tree(local, remote)?;
    // Settling replaces Git's version of a conflicted path, so the merged tree
    // can equal the saved one; the merge still happened, and its tree is the
    // one to adopt.
    let merged_conflicts = !conflicts.is_empty();
    let (merged, conflicts) = settle_conflicts(
        repo,
        heads.base.as_deref(),
        local,
        remote,
        &merged,
        conflicts,
    )?;
    let tree = tracked.manifest.write(repo, &merged)?;
    let roots = Roots::current();
    let exclude = tracked.exclude_set()?;
    if repo.output_tree_of(local)? == tree && conflicts.is_empty() && !merged_conflicts {
        return Ok(None);
    }
    // An eligible tracked file is decided per file, so its ordinary text
    // conflict is not a repository conflict. An encrypted envelope is not
    // text: dropping its conflict here is how a text-merged ciphertext was
    // committed as "merge origin dotfiles". It stays a conflict the user resolves.
    let encrypted = super::files::encrypted_paths(repo, Some(local))?
        .union(&super::files::encrypted_paths(repo, Some(remote))?)
        .cloned()
        .collect::<BTreeSet<_>>();
    let unresolved: Vec<_> = conflicts
        .into_iter()
        .filter(|path| {
            path != crate::history::manifest::PATH
                && (!eligible(&roots, tracked, &exclude, path) || encrypted.contains(path))
        })
        .collect();
    if !unresolved.is_empty() {
        bail!(
            "repository application paused: reconcile repository conflicts first: {}",
            unresolved.join(", ")
        );
    }
    Ok(Some(tree))
}

/// Git merged the saved envelopes as text. Whatever it wrote for a conflicted
/// path is not a saved version: when the decrypted content is equal, the local
/// saved envelope stands, and every other path is replaced by the per-file
/// plan before anything is adopted. A marker blob is never carried forward.
pub(super) fn settle_conflicts(
    repo: &crate::history::shadow::HistoryRepo,
    base: Option<&str>,
    local: &str,
    remote: &str,
    merged: &str,
    conflicts: Vec<String>,
) -> Result<(String, Vec<String>)> {
    let mut overlays = vec![];
    let mut settled = std::collections::BTreeSet::new();
    // The manifest that lists an encrypted path's recipients lives in the local
    // tree, and a re-seal reads them from there.
    let local_tree = repo.output_tree_of(local)?;
    for path in &conflicts {
        if path == crate::history::manifest::PATH {
            continue;
        }
        let Some(saved) = repo.object_at(local, path)? else {
            continue;
        };
        let Some(merged_object) = repo.object_at(merged, path)? else {
            continue;
        };
        // A record Git merged as text is repaired here: when its two sides
        // hold the same content, one clean envelope replaces it.
        let repaired = match super::files::repair(repo, path, &merged_object, false)? {
            super::files::Repair::Same { envelope, .. } => {
                Some(("100644".to_string(), repo.store_blob(&envelope)?))
            }
            _ => match super::files::repair(repo, path, &saved, false)? {
                super::files::Repair::Same { envelope, .. } => {
                    Some(("100644".to_string(), repo.store_blob(&envelope)?))
                }
                _ => None,
            },
        };
        if let Some(object) = repaired {
            settled.insert(path.clone());
            overlays.push(crate::history::shadow::Overlay {
                path: path.clone(),
                object: Some(object),
            });
            continue;
        }
        // Compare the two saved sides, not the blob Git kept. With -merge
        // that blob is one parent, so comparing it with the local side
        // would settle a real difference.
        let Some(theirs) = repo.object_at(remote, path)? else {
            continue;
        };
        if super::files::normalized_equal(repo, path, &saved, &theirs, false)? {
            settled.insert(path.clone());
            overlays.push(crate::history::shadow::Overlay {
                path: path.clone(),
                object: Some(saved),
            });
            continue;
        }
        // The origin still holds the base's content: only this machine changed
        // the file. A machine that re-encrypts a file it did not edit writes a
        // new envelope, and a new envelope is not a change to merge. A base that
        // cannot be read proves nothing, so the path stays a conflict.
        if let Some(base) = base
            && let Some(base_object) = repo.object_at(base, path)?
            && matches!(
                super::files::normalized_equal(repo, path, &base_object, &theirs, false),
                Ok(true)
            )
        {
            settled.insert(path.clone());
            overlays.push(crate::history::shadow::Overlay {
                path: path.clone(),
                object: Some(saved),
            });
            continue;
        }
        // A structured file is merged by key before any line merge. A
        // parsed clash must stay a conflict: a clean line merge would hide it.
        if let Some(base) = base
            && let Some(base_object) = repo.object_at(base, path)?
        {
            match super::files::merge_by_key(repo, path, &base_object, &saved, &theirs, false)? {
                super::files::KeyMerge::KeepLocal => {
                    settled.insert(path.clone());
                    overlays.push(crate::history::shadow::Overlay {
                        path: path.clone(),
                        object: Some(saved),
                    });
                    continue;
                }
                super::files::KeyMerge::Merged { mode, text } => {
                    let local_encrypted = repo.blob_starts_with(&saved.1, super::files::MAGIC)?;
                    let remote_encrypted = repo.blob_starts_with(&theirs.1, super::files::MAGIC)?;
                    let base_encrypted =
                        repo.blob_starts_with(&base_object.1, super::files::MAGIC)?;
                    if local_encrypted != remote_encrypted || local_encrypted != base_encrypted {
                        continue;
                    }
                    let object = if local_encrypted {
                        let recipients =
                            super::files::recipients_of(repo, &local_tree, path, &saved)?;
                        let scheme = super::files::scheme_of(repo, &saved)?;
                        super::files::seal(repo, path, &mode, &text, &scheme, &recipients)?
                    } else {
                        (mode, repo.store_blob(&text)?)
                    };
                    settled.insert(path.clone());
                    overlays.push(crate::history::shadow::Overlay {
                        path: path.clone(),
                        object: Some(object),
                    });
                    continue;
                }
                super::files::KeyMerge::Clash => {
                    continue;
                }
                super::files::KeyMerge::Inapplicable => {}
            }
        }
        // A symlink, a binary file, and a mode change are not text to merge.
        // A regular file whose sides changed different lines is merged here
        // exactly as Git used to, before -merge kept one side instead. An
        // envelope is decrypted first and sealed again: this is the merge for
        // every text path, and a structured path has already merged by key.
        if let Some(base) = base
            && let Some(base_object) = repo.object_at(base, path)?
            && let Some(object) = super::files::merge_lines(
                repo,
                path,
                &base_object,
                &saved,
                &theirs,
                false,
                &local_tree,
            )?
        {
            settled.insert(path.clone());
            overlays.push(crate::history::shadow::Overlay {
                path: path.clone(),
                object: Some(object),
            });
        }
    }
    let remaining = conflicts
        .into_iter()
        .filter(|path| !settled.contains(path))
        .collect();
    if overlays.is_empty() {
        return Ok((merged.to_string(), remaining));
    }
    Ok((repo.compose(merged, &overlays)?, remaining))
}

/// A bootstrap finished: the declarations that arrived through sync are
/// applied now, so `status` stops asking for one.
pub fn bootstrap_completed() {
    let state_dir: &Path = &super::super::local::root();
    let status = match read_status(state_dir) {
        Ok(status) => status,
        Err(err) => {
            warn!("history: could not record that the bootstrap ran: {err:#}");
            return;
        }
    };
    if !status.declarations_changed {
        return;
    }
    // under the sync lock, changing only this: a sync that finished during
    // the bootstrap keeps its conflicts, pending changes, and uploads
    if let Err(err) = update_status(state_dir, STATUS_LOCK_WAIT, |status| {
        status.declarations_changed = false;
    }) {
        debug!("history: could not record that the bootstrap ran: {err}");
    }
}

/// Manual-save entries whose live file differs from the saved version:
/// an incoming change there is held instead of applied.
fn unsaved_paths(
    repo: &crate::history::shadow::HistoryRepo,
    tracked: &TrackedSet,
    shared: &share::ShareReport,
) -> Result<BTreeSet<String>> {
    let Some(checkpoint) = shared.checkpoint.as_deref() else {
        return Ok(BTreeSet::new());
    };
    let walk = tracked.walk()?;
    let mut unsaved = BTreeSet::new();
    for (branch_path, file) in &shared.files {
        let Some((_, policy)) = walk.files.get(&file.local) else {
            continue;
        };
        if policy.autosave {
            continue;
        }
        let live = match super::apply::live_object(repo, &file.local) {
            Ok(live) => live,
            Err(_) => {
                // A changed type or unreadable live file must hold incoming
                // application, not abort fetching.
                unsaved.insert(branch_path.clone());
                continue;
            }
        };
        if live != Some((file.mode.clone(), file.oid.clone())) {
            debug!(
                "history sync: {} has unsaved edits (checkpoint {})",
                display_path(&file.local),
                checkpoint
            );
            unsaved.insert(branch_path.clone());
        }
    }
    Ok(unsaved)
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use crate::history::shadow::HistoryRepo;
    use crate::history::tracked::TrackedEntry;

    #[test]
    fn publication_checks_live_variant_encryption_even_without_a_new_capture() -> Result<()> {
        use crate::history::tracked::TrackedEntry;
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().unwrap();
        let mut policy = crate::files::FilePolicy::for_mode(crate::files::FileMode::Track);
        policy.encrypt = true;
        let mut entry = TrackedEntry::new(
            Roots::current().home.join("variant-secret"),
            "track",
            policy,
        );
        entry.variant = Some("macos".into());
        let path = entry.tree_path(&entry.path)?;
        assert_eq!(path, "home@macos/variant-secret");
        let tree = repo.write_tree(&[("100644".into(), repo.hash_blob(b"plaintext")?, path)])?;
        // No encrypted manifest was captured yet: the live policy alone must
        // protect the stream when capture was skipped or failed.
        let head = repo.commit_tree(&tree, vec![], "previous plaintext version")?;
        let tracked = TrackedSet {
            entries: vec![entry],
            ..Default::default()
        };
        assert!(audit_publication(repo, &head, &tracked).is_err());
        Ok(())
    }

    struct Replay {
        _temp: tempfile::TempDir,
        repo: HistoryRepo,
        regions: String,
        other: String,
        tree: String,
        held: Vec<String>,
    }

    /// Two commits from one base, then the repository merge the sync adopts.
    fn replay(base: &str, local: &str, remote: &str, other_remote: &str) -> Replay {
        let temp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(temp.path()).unwrap().unwrap();
        let roots = Roots::current();
        let regions = roots
            .branch_path(&roots.home.join(".agents/sync-probe/4b-regions.txt"), None)
            .unwrap();
        let other = roots
            .branch_path(&roots.home.join(".agents/sync-probe/other.txt"), None)
            .unwrap();
        let tree_of = |regions_text: &str, other_text: &str| {
            repo.write_tree(&[
                (
                    "100644".into(),
                    repo.hash_blob(regions_text.as_bytes()).unwrap(),
                    regions.clone(),
                ),
                (
                    "100644".into(),
                    repo.hash_blob(other_text.as_bytes()).unwrap(),
                    other.clone(),
                ),
            ])
            .unwrap()
        };
        let base_commit = repo
            .commit_tree(&tree_of(base, "shared\n"), vec![], "base")
            .unwrap();
        let local_commit = repo
            .commit_tree(&tree_of(local, "shared\n"), vec![&base_commit], "local")
            .unwrap();
        let remote_commit = repo
            .commit_tree(&tree_of(remote, other_remote), vec![&base_commit], "remote")
            .unwrap();
        repo.update_ref(HistoryRepo::HISTORY_REF, &local_commit, None)
            .unwrap();
        repo.update_ref(UPSTREAM_REF, &remote_commit, None).unwrap();
        let tracked = TrackedSet {
            entries: vec![TrackedEntry::new(
                roots.home.join(".agents/sync-probe"),
                "track",
                crate::files::FilePolicy::for_mode(crate::files::FileMode::Track),
            )],
            ..Default::default()
        };
        let heads = crate::history::sync::graph::Heads::read(&repo).unwrap();
        let (git_tree, conflicts) = repo
            .merge_tree(
                heads.local.as_deref().unwrap(),
                heads.remote.as_deref().unwrap(),
            )
            .unwrap();
        let (settled, held) = settle_conflicts(
            &repo,
            heads.base.as_deref(),
            heads.local.as_deref().unwrap(),
            heads.remote.as_deref().unwrap(),
            &git_tree,
            conflicts,
        )
        .unwrap();
        let tree = incoming_repository_tree(&repo, &tracked)
            .expect("a plaintext replay must not pause the repository")
            .unwrap_or(settled);
        Replay {
            _temp: temp,
            repo,
            regions,
            other,
            tree,
            held,
        }
    }

    impl Replay {
        fn text(&self, path: &str) -> String {
            let object = self.repo.object_at(&self.tree, path).unwrap().unwrap();
            String::from_utf8(self.repo.cat_object(&object.1).unwrap()).unwrap()
        }
    }

    /// Two machines edit different regions of one plaintext file from a known
    /// base. Both edits land, and the other path keeps syncing.
    #[test]
    fn non_overlapping_edits_to_one_plaintext_file_merge() {
        let base = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n";
        let seen = replay(
            base,
            "MAC-LINE\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n",
            "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nVPS-LINE\n",
            "remote-only\n",
        );
        assert_eq!(
            seen.text(&seen.regions),
            "MAC-LINE\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nVPS-LINE\n"
        );
        assert_eq!(seen.text(&seen.other), "remote-only\n");
        assert!(!seen.text(&seen.regions).contains("<<<<<<<"));
    }
    /// The same edit on both machines converges without a conflict.
    #[test]
    fn identical_edits_to_one_plaintext_file_converge() {
        let same = "SAME\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n";
        let seen = replay(
            "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n",
            same,
            same,
            "shared\n",
        );
        assert_eq!(seen.text(&seen.regions), same);
        assert!(!seen.held.iter().any(|path| path == &seen.regions));
    }

    /// An edit of the same line stays a conflict, and only that path is held.
    #[test]
    fn same_line_edits_conflict_only_that_path() {
        let seen = replay(
            "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n",
            "MAC-VERSION\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n",
            "VPS-VERSION\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\n",
            "remote-only\n",
        );
        assert_eq!(seen.held, vec![seen.regions.clone()]);
        assert_eq!(seen.text(&seen.other), "remote-only\n");
        assert!(!seen.text(&seen.regions).contains("<<<<<<<"));
    }
    /// An encrypted path is not text-merged, even when its plaintext edits
    /// would not overlap.
    #[test]
    fn an_encrypted_path_is_not_text_merged() {
        let temp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(temp.path()).unwrap().unwrap();
        let roots = Roots::current();
        let path = roots
            .branch_path(&roots.home.join(".agents/sync-probe/secret.txt"), None)
            .unwrap();
        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let seal = |text: &str| {
            crate::history::sync::files::encode(
                &path,
                "100644",
                text.as_bytes(),
                "test",
                &recipients,
            )
            .unwrap()
        };
        let tree_of = |text: &str| {
            repo.write_tree(&[(
                "100644".into(),
                repo.hash_blob(&seal(text)).unwrap(),
                path.clone(),
            )])
            .unwrap()
        };
        let base = repo
            .commit_tree(&tree_of("base\n"), vec![], "base")
            .unwrap();
        let local = repo
            .commit_tree(&tree_of("local line\n"), vec![&base], "local")
            .unwrap();
        let remote = repo
            .commit_tree(&tree_of("remote line\n"), vec![&base], "remote")
            .unwrap();
        repo.update_ref(HistoryRepo::HISTORY_REF, &local, None)
            .unwrap();
        repo.update_ref(UPSTREAM_REF, &remote, None).unwrap();
        let (merged, conflicts) = repo.merge_tree(&local, &remote).unwrap();
        assert!(
            conflicts.iter().any(|conflict| conflict == &path),
            "{conflicts:?}"
        );
        let object = repo.object_at(&merged, &path).unwrap().unwrap();
        let bytes = repo.cat_object(&object.1).unwrap();
        assert!(!bytes.windows(7).any(|window| window == b"<<<<<<<"));
        assert_eq!(object.1, repo.object_at(&local, &path).unwrap().unwrap().1);
    }

    /// The decision a sync makes before it publishes: has a checkpoint been
    /// saved since the plans were built? A sync that publishes past one would
    /// publish history its plans never examined; a sync that fails on it
    /// never finishes while the watcher keeps saving.
    #[test]
    fn a_checkpoint_saved_after_the_snapshot_moves_the_head() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().ok_or_else(|| eyre::eyre!("git required"))?;
        let tree = repo.empty_object("tree")?;
        let first = repo.commit_tree(&tree, vec![], "first")?;
        repo.update_ref(
            crate::history::shadow::HistoryRepo::HISTORY_REF,
            &first,
            None,
        )?;
        let snapshot = share::current(repo, &TrackedSet::default())?;
        assert!(
            !head_moved(repo, &snapshot)?,
            "nothing was saved since the snapshot"
        );

        let second = repo.commit_tree(&tree, vec![first.as_str()], "second")?;
        repo.update_ref(
            crate::history::shadow::HistoryRepo::HISTORY_REF,
            &second,
            Some(&first),
        )?;
        assert!(
            head_moved(repo, &snapshot)?,
            "a checkpoint saved after the snapshot must be noticed"
        );

        let fresh = share::current(repo, &TrackedSet::default())?;
        assert!(
            !head_moved(repo, &fresh)?,
            "planning again from the new head settles it"
        );
        Ok(())
    }

    #[test]
    fn unsaved_observation_only_conflicts_when_there_is_an_incoming_write() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().ok_or_else(|| eyre::eyre!("git required"))?;
        let path = format!("home/.mise-test-{}", crate::history::store::new_uuid());
        let saved = ("100644".into(), repo.hash_blob(b"saved")?);
        let incoming = ("100644".into(), repo.hash_blob(b"incoming")?);
        let shared = BTreeMap::from([(path.clone(), saved.clone())]);
        let upstream = reconcile::Upstream::default();
        let mut status = SyncStatus::default();
        let mut plans = vec![PathPlan {
            branch_path: path,
            publish: Some(Some(saved)),
            ..Default::default()
        }];
        // The missing live file differs from its saved object, just as an
        // autosave edit still waiting in the debounce queue does. Publishing
        // saved commits must not inspect it when no incoming write is planned.
        apply_resolutions(repo, &mut status, &shared, &upstream, &mut plans)?;
        assert!(plans[0].conflict.is_none());
        assert!(plans[0].publish.is_some());

        // Conversely, exempting autosave entries from the check would lose
        // their pending edits when there really is an incoming write.
        plans[0].apply = Some(Some(incoming));
        apply_resolutions(repo, &mut status, &shared, &upstream, &mut plans)?;
        assert_eq!(
            plans[0].conflict.as_ref().map(|c| c.kind),
            Some(reconcile::ConflictKind::UnsavedEdits)
        );
        Ok(())
    }

    #[test]
    fn a_directory_in_the_way_is_not_reported_as_a_type_change() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().ok_or_else(|| eyre::eyre!("git required"))?;
        let roots = Roots::current();
        // The live side is a directory: nothing changed type on either side
        // of the repository, so neither resolution applies until it is gone.
        let live = tempfile::Builder::new()
            .prefix(".mise-unusable-test-")
            .tempdir_in(&roots.home)?;
        let branch_path = roots
            .branch_path(live.path(), None)
            .ok_or_else(|| eyre::eyre!("path is not under a root"))?;
        let saved = ("100644".into(), repo.hash_blob(b"saved")?);
        let incoming = ("100644".into(), repo.hash_blob(b"incoming")?);
        let shared = BTreeMap::from([(branch_path.clone(), saved.clone())]);
        let upstream = reconcile::Upstream::default();
        let mut status = SyncStatus::default();
        let mut plans = vec![PathPlan {
            branch_path,
            apply: Some(Some(incoming)),
            ..Default::default()
        }];
        apply_resolutions(repo, &mut status, &shared, &upstream, &mut plans)?;
        assert_eq!(
            plans[0].conflict.as_ref().map(|c| c.kind),
            Some(reconcile::ConflictKind::UnusableLive)
        );
        Ok(())
    }

    #[test]
    fn sync_capture_does_not_observe_an_active_write_operation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open_in(temp.path())?;
        let repo = store.repo().ok_or_else(|| eyre::eyre!("git required"))?;
        let roots = Roots::current();
        let live = tempfile::Builder::new()
            .prefix(".mise-lock-test-")
            .tempdir_in(&roots.home)?;
        let path = live.path().join("config");
        std::fs::write(&path, "explicitly enrolled")?;
        let tracked = crate::history::manifest::Manifest {
            enrollment: vec![crate::history::manifest::Enrollment {
                path: roots.branch_path(&path, None).unwrap(),
                autosave: true,
                encrypt: false,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            }],
            ..Default::default()
        }
        .tracking()?;
        let operation = crate::history::scope::take_operation_lock(&store, &tracked)?;
        capture_now(&store, &tracked);
        assert_eq!(
            repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?,
            None
        );
        drop(operation);
        capture_now(&store, &tracked);
        assert!(
            repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)?
                .is_some()
        );
        Ok(())
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;

    fn conflict(path: &str) -> Conflict {
        Conflict {
            branch_path: path.into(),
            kind: reconcile::ConflictKind::SameHunk,
            local: None,
            remote: None,
            base: None,
            detail: None,
        }
    }

    #[test]
    fn one_notification_per_pause_and_another_after_recovery() {
        let mut status = SyncStatus {
            conflicts: vec![conflict("tracked/home/.zshrc")],
            ..Default::default()
        };
        let mut calls = 0;
        notify_conflicts_with(&mut status, true, |title, body| {
            assert!(title.contains("dotfile sync paused"));
            assert!(body.contains(".zshrc"));
            calls += 1;
        });
        status.conflicts.push(conflict("tracked/home/.gitconfig"));
        notify_conflicts_with(&mut status, true, |_, _| calls += 1);
        status.conflicts.remove(0);
        notify_conflicts_with(&mut status, true, |_, _| calls += 1);
        assert_eq!(calls, 1);
        status.conflicts.clear();
        notify_conflicts_with(&mut status, true, |_, _| calls += 1);
        assert!(!status.conflict_pause_observed);
        status.conflicts.push(conflict("tracked/home/.gitconfig"));
        notify_conflicts_with(&mut status, true, |_, _| calls += 1);
        assert_eq!(calls, 2);
    }

    #[test]
    fn notification_keeps_the_action_visible_for_long_or_unusual_paths() {
        let mut status = SyncStatus {
            conflicts: vec![
                conflict(&format!("tracked/home/\n{}", "x".repeat(200))),
                conflict("tracked/home/.gitconfig"),
            ],
            ..Default::default()
        };
        notify_conflicts_with(&mut status, true, |_, body| {
            assert!(body.contains("… and 1 other file"));
            assert!(body.contains("Local saves still work."));
            assert!(body.ends_with("mise dot status"));
            assert_eq!(body.lines().count(), 3);
            assert!(body.chars().count() < 250);
        });
    }

    #[test]
    fn explicit_opt_out_is_preserved() {
        let mut status = SyncStatus {
            conflicts: vec![conflict("tracked/home/.zshrc")],
            ..Default::default()
        };
        notify_conflicts_with(&mut status, false, |_, _| panic!("notifications disabled"));
        assert!(status.conflict_pause_observed);
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    fn conflict() -> Conflict {
        Conflict {
            branch_path: "tracked/home/.zshrc".to_string(),
            kind: reconcile::ConflictKind::SameHunk,
            local: None,
            remote: None,
            base: None,
            detail: None,
        }
    }

    #[test]
    fn omitted_failure_fields_default_to_no_failures() {
        let status: SyncStatus = serde_json::from_str("{}").unwrap();
        assert_eq!(status.failing_since, None);
        assert_eq!(status.consecutive_failures, 0);
        let text = serde_json::to_string(&status).unwrap();
        assert!(!text.contains("consecutive_failures"));
    }

    #[test]
    fn an_update_changes_only_its_field_in_the_current_record() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let mut status = SyncStatus {
            declarations_changed: true,
            last_error: Some("unreachable".to_string()),
            ..Default::default()
        };
        write_status(state_dir, &status).unwrap();
        // a sync finishes meanwhile and records a conflict: the update reads
        // that record, not the one it started from
        status.conflicts.push(conflict());
        write_status(state_dir, &status).unwrap();
        update_status(state_dir, Duration::ZERO, |status| {
            status.declarations_changed = false;
        })
        .unwrap();
        let current = read_status(state_dir).unwrap();
        assert!(!current.declarations_changed);
        assert_eq!(current.conflicts.len(), 1);
        assert_eq!(current.last_error.as_deref(), Some("unreachable"));
    }

    #[test]
    fn an_update_gives_way_to_a_running_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        std::fs::create_dir_all(hstore::store_dir_in(state_dir)).unwrap();
        let held = lock_in(state_dir).unwrap();
        let err = update_status(state_dir, Duration::ZERO, |status| {
            status.declarations_changed = false;
        })
        .unwrap_err();
        assert!(err.to_string().contains("another setup sync or pull"));
        drop(held);
        update_status(state_dir, Duration::ZERO, |status| {
            status.declarations_changed = false;
        })
        .unwrap();
    }

    /// A sync someone ran queues behind a running one instead of failing, and
    /// the watcher's no-wait lock still fails at once on the same contention.
    #[test]
    fn a_queued_sync_waits_for_a_running_one_and_a_plain_one_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(hstore::store_dir_in(&state_dir)).unwrap();
        let held = lock_in(&state_dir).unwrap();
        assert!(
            lock_in(&state_dir)
                .unwrap_err()
                .to_string()
                .contains("another setup sync or pull")
        );
        let waiter = {
            let state_dir = state_dir.clone();
            std::thread::spawn(move || lock_wait(&state_dir, Duration::from_secs(10)).is_ok())
        };
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        assert!(
            waiter.join().unwrap(),
            "the queued sync should take the lock once it is free"
        );
    }

    /// A refusal names who holds the lock, so a permanent holder is visible
    /// without `lsof`: waiting out `mise dot watch` is wasted time, and the
    /// refusal is what an agent reads.
    #[test]
    fn a_refused_lock_names_the_holder_pid_and_age() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(hstore::store_dir_in(&state_dir)).unwrap();
        let held = lock_in(&state_dir).unwrap();
        let err = lock_in(&state_dir).unwrap_err().to_string();
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "the refusal must name the holder: {err}"
        );
        assert!(
            err.contains("holding the lock for"),
            "the refusal must say how long it has been held: {err}"
        );
        assert!(
            err.contains("--wait"),
            "the refusal must point at the bounded wait: {err}"
        );
        drop(held);
    }

    /// A bounded wait that runs out says who it was waiting for and how long
    /// it waited, rather than "retry shortly" about a process that may never
    /// release the lock.
    #[test]
    fn an_expired_wait_names_the_holder_and_the_wait() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(hstore::store_dir_in(&state_dir)).unwrap();
        let held = lock_in(&state_dir).unwrap();
        let err = lock_wait(&state_dir, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "the timeout must name the holder: {err}"
        );
        assert!(
            err.contains("waited 0s and gave up"),
            "the timeout must say how long it waited: {err}"
        );
        drop(held);
    }

    /// A holder from a mise that did not record a pid is a fact, not a panic:
    /// the refusal says so instead of inventing a holder.
    #[test]
    fn a_holder_that_recorded_no_pid_is_reported_as_such() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(hstore::store_dir_in(&state_dir)).unwrap();
        let path = lock_path(&state_dir);
        let mut older = fslock::LockFile::open(&path).unwrap();
        assert!(older.try_lock().unwrap());
        let err = lock_in(&state_dir).unwrap_err().to_string();
        assert!(
            err.contains("recorded no pid"),
            "an unrecorded holder must be named as such: {err}"
        );
        drop(older);
    }

    #[test]
    fn lock_ages_read_in_seconds_minutes_and_hours() {
        assert_eq!(human_duration(Duration::ZERO), "0s");
        assert_eq!(human_duration(Duration::from_secs(59)), "59s");
        assert_eq!(human_duration(Duration::from_secs(90)), "1m");
        assert_eq!(human_duration(Duration::from_secs(3600 + 840)), "1h 14m");
    }
}

#[cfg(test)]
mod nested_repository_tests {
    use super::*;
    use crate::files::{FileMode, FilePolicy};
    use crate::history::tracked::{TrackedEntry, normalize};

    #[test]
    fn incoming_files_leave_live_nested_repositories_alone() {
        let temp = tempfile::tempdir().unwrap();
        let home = normalize(temp.path());
        let roots = Roots {
            home: home.clone(),
            config_dir: home.join(".config/mise"),
        };
        for (parent, prefix) in [
            (home.join("plugins"), "home/plugins"),
            (roots.config_dir.join("plugins"), "config/plugins"),
        ] {
            let nested = parent.join("checkout");
            std::fs::create_dir_all(nested.join(".git")).unwrap();
            std::fs::write(nested.join("local.txt"), "local").unwrap();
            let policy = FilePolicy::for_mode(FileMode::Track);
            let mut tracked = TrackedSet::default();
            tracked.push(TrackedEntry::new(parent, "track", policy));
            let exclude = tracked.exclude_set().unwrap();
            for suffix in ["checkout", "checkout/local.txt", "checkout/incoming.txt"] {
                let path = format!("{prefix}/{suffix}");
                assert!(!eligible(&roots, &tracked, &exclude, &path), "{path}");
            }
            assert!(eligible(
                &roots,
                &tracked,
                &exclude,
                &format!("{prefix}/ordinary.txt")
            ));
            tracked.push(TrackedEntry::new(nested, "track", policy));
            assert!(eligible(
                &roots,
                &tracked,
                &exclude,
                &format!("{prefix}/checkout/incoming.txt")
            ));
        }
    }
}

#[cfg(all(test, unix))]
mod rejection_backoff_tests {
    use super::*;
    use crate::files::{FileMode, FilePolicy};
    use crate::history::manifest::Manifest;
    use crate::history::shadow::HistoryRepo;
    use crate::history::tracked::TrackedEntry;

    /// A marked history whose saved manifest matches an empty tracked set, so
    /// publication is not held for an incoming repository change.
    fn marked(repo: &HistoryRepo, parent: Option<&str>, message: &str) -> String {
        let tree = Manifest::default()
            .write(repo, &repo.empty_object("tree").unwrap())
            .unwrap();
        let parents = parent.into_iter().collect::<Vec<_>>();
        let commit = repo.commit_tree(&tree, parents, message).unwrap();
        repo.update_history_head(&commit, parent).unwrap();
        commit
    }

    /// A bare origin and a local store one commit ahead of the fetched base.
    fn ahead(name: &str) -> (tempfile::TempDir, Store, std::path::PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        let origin = root.path().join(format!("{name}.git"));
        std::fs::create_dir_all(&origin).unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "--bare", "-b", "mise"])
            .current_dir(&origin)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let store = Store::open_in(&root.path().join("state")).unwrap();
        let repo = store.repo().unwrap();
        let base = marked(repo, None, "base");
        let seeded = std::process::Command::new("git")
            .args([
                "push",
                "--quiet",
                &origin.to_string_lossy(),
                &format!("{base}:refs/heads/mise"),
            ])
            .current_dir(repo.dir())
            .output()
            .unwrap();
        assert!(
            seeded.status.success(),
            "{}",
            String::from_utf8_lossy(&seeded.stderr)
        );
        repo.update_ref(UPSTREAM_REF, &base, None).unwrap();
        let local = marked(repo, Some(&base), name);
        (root, store, origin, local)
    }

    /// Moves the origin branch on after a fetch, the race a rejected push
    /// retries. The move happens inside the fetch the sync just made, so the
    /// lease check sees a branch the fetch did not, and the next fetch sees
    /// the move. `moves` bounds how many fetches lose the race.
    fn race_after_fetch<'a>(
        branch: &str,
        remaining: &'a mut usize,
        raced: &'a mut Vec<String>,
    ) -> impl FnMut(&str) + 'a {
        let branch = branch.to_string();
        move |url: &str| {
            if *remaining == 0 {
                return;
            }
            *remaining -= 1;
            // the commit is born in the origin, so the next fetch can read it
            let moved = std::process::Command::new("git")
                .args([
                    "commit-tree",
                    &format!("refs/heads/{branch}^{{tree}}"),
                    "-p",
                    &format!("refs/heads/{branch}"),
                    "-m",
                    "raced",
                ])
                .current_dir(url)
                .env("GIT_AUTHOR_NAME", "mise")
                .env("GIT_AUTHOR_EMAIL", "mise@localhost")
                .env("GIT_COMMITTER_NAME", "mise")
                .env("GIT_COMMITTER_EMAIL", "mise@localhost")
                .output()
                .unwrap();
            assert!(
                moved.status.success(),
                "{}",
                String::from_utf8_lossy(&moved.stderr)
            );
            let commit = String::from_utf8(moved.stdout).unwrap().trim().to_string();
            raced.push(commit.clone());
            let advanced = std::process::Command::new("git")
                .args(["update-ref", &format!("refs/heads/{branch}"), &commit])
                .current_dir(url)
                .output()
                .unwrap();
            assert!(
                advanced.status.success(),
                "{}",
                String::from_utf8_lossy(&advanced.stderr)
            );
        }
    }
    fn publishing(origin: &std::path::Path) -> SyncRequest {
        let mut request = SyncRequest::new(false);
        request.capture = false;
        request.allow_plaintext_history = true;
        request.origin = Some(OriginTomlConfig::plain(
            origin.to_string_lossy().into_owned(),
            "mise".into(),
        ));
        request
    }

    fn sync_recording(
        store: &Store,
        request: &SyncRequest,
        after_fetch: &mut impl FnMut(&str),
    ) -> (Result<SyncOutcome>, Vec<Duration>) {
        let mut delays = Vec::new();
        let result = sync_locked_waiting(
            store,
            &TrackedSet::default(),
            request,
            &mut |delay| delays.push(delay),
            after_fetch,
        );
        (result, delays)
    }

    /// The origin rejects the first pushes of this sync, after the fetch. Each
    /// rejection waits, the waits grow, and their worst case stays under 16
    /// seconds. The later push is accepted and this machine's commit is kept.
    #[test]
    fn rejected_push_backs_off() {
        let (_root, store, origin, local) = ahead("rejected");
        let mut moves = 1;
        let mut raced = Vec::new();
        let (result, delays) = sync_recording(
            &store,
            &publishing(&origin),
            &mut race_after_fetch("mise", &mut moves, &mut raced),
        );
        assert_eq!(
            moves, 0,
            "the origin moved after the fetch, so the push was rejected"
        );
        assert_eq!(raced.len(), 1);
        assert!(
            result.is_ok(),
            "the retry publishes once the race ends: {result:?}"
        );
        assert_eq!(
            delays.len(),
            1,
            "one rejection waits once before fetching again"
        );
        assert!(
            (Duration::from_millis(250)..=Duration::from_millis(500)).contains(&delays[0]),
            "the first wait is the upper half of half a second: {:?}",
            delays[0]
        );
        let published = result
            .unwrap()
            .published
            .expect("the retried publication is accepted");
        let history = store
            .repo()
            .unwrap()
            .rev_list(&published, usize::MAX)
            .unwrap();
        assert!(
            history.contains(&local),
            "this machine's commit is what the retry publishes"
        );
        assert!(
            history.contains(&raced[0]),
            "the competing commit is reconciled in"
        );
    }

    /// The first push is accepted: nothing was rejected, so nothing waits.
    #[test]
    fn an_accepted_push_does_not_wait() {
        let (_root, store, origin, local) = ahead("accepted");
        let (result, delays) = sync_recording(&store, &publishing(&origin), &mut |_| {});
        assert!(
            delays.is_empty(),
            "an accepted push waits for nothing: {delays:?}"
        );
        assert_eq!(result.unwrap().published.as_deref(), Some(local.as_str()));
    }

    /// Every push is rejected. The failure names how many were tried and the
    /// reason the origin gave.
    #[test]
    fn an_exhausted_rejection_names_the_attempts_and_the_reason() {
        let (_root, store, origin, _local) = ahead("exhausted");
        let mut moves = PUSH_ATTEMPTS;
        let mut raced = Vec::new();
        let (result, delays) = sync_recording(
            &store,
            &publishing(&origin),
            &mut race_after_fetch("mise", &mut moves, &mut raced),
        );
        assert_eq!(raced.len(), PUSH_ATTEMPTS, "every attempt lost the race");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains(&format!("after {PUSH_ATTEMPTS} attempts")),
            "{err}"
        );
        assert!(err.contains("the origin branch changed"), "{err}");
        assert_eq!(delays.len(), PUSH_ATTEMPTS - 1);
    }

    /// Publishing a store whose saved file cannot be read does not publish
    /// that unreadability as a deletion. The origin keeps the saved object,
    /// and a readable sibling edit is published beside it.
    #[test]
    fn publishing_keeps_a_denied_saved_object_and_publishes_the_sibling_edit() {
        use crate::history::checkpoint::{Draft, Outcome};
        use crate::history::manifest::Enrollment;
        use crate::history::store::Trigger;
        use std::os::unix::fs::PermissionsExt;
        struct Restore(std::path::PathBuf, u32);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
            }
        }
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let (_root, store, origin, _local) = ahead("denied-publish");
        // portable-home-ok: history maps paths under the real home
        let live = tempfile::tempdir_in(*mise_util::dirs::HOME).unwrap();
        let denied = live.path().join("notes.toml");
        let sibling = live.path().join("settings.toml");
        std::fs::write(&denied, "saved-notes").unwrap();
        std::fs::write(&sibling, "before").unwrap();
        let policy = FilePolicy::for_mode(FileMode::Track);
        let denied_entry = TrackedEntry::new(denied.clone(), "track", policy);
        let sibling_entry = TrackedEntry::new(sibling.clone(), "track", policy);
        let enroll = |entry: &TrackedEntry, path: &std::path::Path| Enrollment {
            path: entry.tree_path(path).unwrap(),
            autosave: true,
            encrypt: false,
            allow_plaintext: None,
            variants: vec![],
            exclude: None,
            include: None,
        };
        let tracked = TrackedSet {
            manifest: Manifest {
                enrollment: vec![
                    enroll(&denied_entry, &denied),
                    enroll(&sibling_entry, &sibling),
                ],
                ..Default::default()
            },
            entries: vec![denied_entry, sibling_entry],
            ..Default::default()
        };
        let Outcome::Created(_) = store.attempt(&tracked, Draft::new(Trigger::Save)).unwrap()
        else {
            panic!("the baseline recorded nothing");
        };
        let repo = store.repo().unwrap();
        let head = repo.ref_oid(HistoryRepo::HISTORY_REF).unwrap().unwrap();
        let denied_tree = tracked
            .entry_for(&denied)
            .unwrap()
            .tree_path(&denied)
            .unwrap();
        let (_, saved_oid) = repo.object_at(&head, &denied_tree).unwrap().unwrap();

        let mode = std::fs::symlink_metadata(&denied)
            .unwrap()
            .permissions()
            .mode();
        let _restore = Restore(denied.clone(), mode);
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
        let probe = std::fs::File::open(&denied).expect_err("a non-root denial was readable");
        assert_eq!(probe.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::write(&sibling, "after").unwrap();
        // The watcher's save stores the sibling edit; the denied path keeps
        // its saved object. Sync then publishes that saved history.
        let Outcome::Created(_) = store.attempt(&tracked, Draft::new(Trigger::Save)).unwrap()
        else {
            panic!("the sibling edit was not saved");
        };

        let published = sync_locked(&store, &tracked, &publishing(&origin))
            .unwrap()
            .published
            .expect("the saved history was not published");
        let (_, kept_oid) = repo
            .object_at(&published, &denied_tree)
            .unwrap()
            .expect("unreadability was published as a deletion");
        assert_eq!(kept_oid, saved_oid, "the denied path lost its saved object");
        let sibling_tree = tracked
            .entry_for(&sibling)
            .unwrap()
            .tree_path(&sibling)
            .unwrap();
        let (_, sibling_oid) = repo
            .object_at(&published, &sibling_tree)
            .unwrap()
            .expect("the sibling edit was not published");
        assert_eq!(repo.cat_object(&sibling_oid).unwrap(), b"after");
    }

    /// An encrypted path saved in plaintext by an earlier checkpoint, then
    /// marked for encryption and saved again, on top of the fetched base.
    struct PlaintextHistory {
        _root: tempfile::TempDir,
        store: Store,
        origin: std::path::PathBuf,
        tracked: TrackedSet,
        base: String,
        plaintext_commit: String,
        tip: String,
        _environment: mise_util::testing::EnvVarGuard,
    }

    /// A repository path, not a machine path: no home directory is read.
    const PLAINTEXT_PATH: &str = "home/x"; // portable-home-ok

    /// `on_origin` puts the plaintext checkpoint on the origin as well, so the
    /// refused version is already published.
    fn plaintext_history(name: &str, on_origin: bool) -> PlaintextHistory {
        use age::secrecy::ExposeSecret;
        let (root, store, origin, local) = ahead(name);
        let repo = store.repo().unwrap();
        let base = repo.ref_oid(UPSTREAM_REF).unwrap().unwrap();
        let marker_path = crate::history::sync::layout::MARKER_PATH;
        let marker = repo.object_at(&base, marker_path).unwrap().unwrap();
        let plain = repo.hash_blob(b"saved in the clear").unwrap();
        let plain_tree = repo
            .write_tree(&[
                (marker.0.clone(), marker.1.clone(), marker_path.into()),
                ("100644".into(), plain, PLAINTEXT_PATH.into()),
            ])
            .unwrap();
        let plaintext_commit = repo
            .commit_tree(&plain_tree, vec![&base], "plaintext checkpoint")
            .unwrap();

        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let cipher = repo
            .hash_blob(
                &super::super::files::encode(
                    PLAINTEXT_PATH,
                    "100644",
                    b"now encrypted",
                    "test",
                    &recipients,
                )
                .unwrap(),
            )
            .unwrap();
        let mut manifest = Manifest::default();
        manifest
            .enrollment
            .push(crate::history::manifest::Enrollment {
                path: PLAINTEXT_PATH.into(),
                autosave: true,
                encrypt: true,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            });
        let encrypted_tree = repo
            .write_tree(&[
                (marker.0, marker.1, marker_path.into()),
                ("100644".into(), cipher, PLAINTEXT_PATH.into()),
            ])
            .unwrap();
        let encrypted_tree = manifest.write(repo, &encrypted_tree).unwrap();
        let tip = repo
            .commit_tree(&encrypted_tree, vec![&plaintext_commit], "encrypt now")
            .unwrap();
        if on_origin {
            let pushed = std::process::Command::new("git")
                .args([
                    "push",
                    "--quiet",
                    &origin.to_string_lossy(),
                    &format!("{plaintext_commit}:refs/heads/mise"),
                ])
                .current_dir(repo.dir())
                .output()
                .unwrap();
            assert!(
                pushed.status.success(),
                "{}",
                String::from_utf8_lossy(&pushed.stderr)
            );
        }
        // `ahead` left the branch at `local`; the new history replaces it.
        repo.update_history_head(&tip, Some(&local)).unwrap();

        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
        PlaintextHistory {
            _root: root,
            store,
            origin,
            // The path is enrolled in the saved history, not as a live entry:
            // a live entry needs a path under the real home.
            tracked: TrackedSet {
                manifest,
                ..Default::default()
            },
            base,
            plaintext_commit,
            tip,
            _environment: environment,
        }
    }

    /// Every version of the path in every commit of the origin branch.
    fn origin_versions(origin: &std::path::Path) -> Vec<Vec<u8>> {
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(origin)
                .output()
                .unwrap()
        };
        let commits = git(&["rev-list", "refs/heads/mise"]);
        assert!(commits.status.success());
        String::from_utf8(commits.stdout)
            .unwrap()
            .lines()
            .filter_map(|commit| {
                let shown = git(&["show", &format!("{commit}:{PLAINTEXT_PATH}")]);
                shown.status.success().then_some(shown.stdout)
            })
            .collect()
    }

    /// A plaintext checkpoint only this machine has is replaced by one
    /// checkpoint before the audit, so the sync publishes instead of failing
    /// every time. The audit is not skipped, and nothing pushed holds plaintext.
    #[test]
    fn unpublished_plaintext_checkpoints_are_rerecorded() {
        let fixture = plaintext_history("unpublished-plaintext", false);
        let repo = fixture.store.repo().unwrap();
        let published = sync_locked(
            &fixture.store,
            &fixture.tracked,
            &publishing_strict(&fixture.origin),
        )
        .expect(
            "an unpublished plaintext checkpoint must be re-recorded, not fail the sync forever",
        )
        .published
        .expect("the re-recorded history was not published");

        let origin_head = std::process::Command::new("git")
            .args(["rev-parse", "refs/heads/mise"])
            .current_dir(&fixture.origin)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(origin_head.stdout).unwrap().trim(),
            published
        );
        let ancestry = repo.rev_list(&published, usize::MAX).unwrap();
        assert!(ancestry.contains(&fixture.base));
        assert!(!ancestry.contains(&fixture.plaintext_commit));
        assert_eq!(
            repo.parents_of(&published).unwrap(),
            vec![fixture.base.clone()],
            "the checkpoints are replaced by one on the merge base"
        );
        let versions = origin_versions(&fixture.origin);
        assert!(!versions.is_empty(), "the encrypted path was dropped");
        for version in versions {
            assert!(
                version.starts_with(super::super::files::MAGIC),
                "the origin holds a version of the path that is not an envelope"
            );
        }
        let backups = repo.list_refs("refs/mise/unpublishable/").unwrap();
        assert_eq!(backups.len(), 1, "the old tip is kept under one local ref");
        assert_eq!(backups[0].1, fixture.tip);
    }

    /// A refused version the origin already has is published history: it is
    /// never rewritten, so the audit keeps refusing it as before.
    #[test]
    fn published_plaintext_is_still_refused() {
        let fixture = plaintext_history("published-plaintext", true);
        let repo = fixture.store.repo().unwrap();
        let error = sync_locked(
            &fixture.store,
            &fixture.tracked,
            &publishing_strict(&fixture.origin),
        )
        .expect_err("plaintext the origin already holds must still be refused");
        assert!(format!("{error:#}").contains("cannot publish"), "{error:#}");
        assert_eq!(
            repo.ref_oid(crate::history::shadow::HistoryRepo::HISTORY_REF)
                .unwrap()
                .as_deref(),
            Some(fixture.tip.as_str()),
            "a refused history is left as it was"
        );
        assert!(
            repo.list_refs("refs/mise/unpublishable/")
                .unwrap()
                .is_empty()
        );
    }

    /// [`publishing`] with the plaintext override off, so the audit runs.
    fn publishing_strict(origin: &std::path::Path) -> SyncRequest {
        let mut request = publishing(origin);
        request.allow_plaintext_history = false;
        request
    }

    #[test]
    fn a_rejection_delay_grows_then_caps_and_two_samples_differ_by_half() {
        let bounds = [500, 1_000, 2_000, 3_000, 3_000, 3_000, 3_000];
        for (index, bound) in bounds.into_iter().enumerate() {
            let retry = index as u32 + 1;
            assert_eq!(rejection_delay(retry, 0), Duration::from_millis(bound / 2));
            assert_eq!(
                rejection_delay(retry, u32::MAX),
                Duration::from_millis(bound)
            );
        }
        let worst: Duration = (1..PUSH_ATTEMPTS)
            .map(|retry| rejection_delay(retry as u32, u32::MAX))
            .sum();
        assert_eq!(worst, Duration::from_millis(15_500));
        assert!(worst <= Duration::from_secs(16));
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::files::{FileMode, FilePolicy};
    use crate::history::tracked::TrackedEntry;

    /// Declared is not selected. A path the exclude lists drop is not
    /// managed here, so its absence from an incoming snapshot is the
    /// setup having stopped capturing it — never a deletion to replay.
    #[test]
    fn an_excluded_path_is_not_eligible_for_deletion() {
        let roots = Roots {
            home: "/home/u".into(),
            config_dir: "/config/mise".into(),
        };
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut entry = TrackedEntry::new("/home/u/.sample".into(), "track", policy);
        entry.exclude = Some(vec!["leave".into()]);
        let tracked = TrackedSet {
            entries: vec![entry],
            exclude: vec!["*.log".into()],
            ..Default::default()
        };
        let exclude = tracked.exclude_set().unwrap();
        assert!(eligible(&roots, &tracked, &exclude, "home/.sample/keep"));
        assert!(!eligible(&roots, &tracked, &exclude, "home/.sample/leave"));
        // the global list answers the same question
        assert!(!eligible(
            &roots,
            &tracked,
            &exclude,
            "home/.sample/app.log"
        ));
        // and a path no entry covers is still not eligible
        assert!(!eligible(&roots, &tracked, &exclude, "home/.elsewhere"));
    }

    /// Synchronization asks the strict question, the same one retention
    /// asks. A local copy whose kind cannot be read — it is gone, or it
    /// sits under a directory this machine cannot search — is not
    /// managed here unless the lists actually select it. Answered
    /// permissively, a name-only `include` pattern prunes nothing, the
    /// path looks managed, and a narrowing made on another machine
    /// deletes it here.
    #[test]
    fn a_path_with_no_readable_kind_is_not_eligible_for_deletion() {
        let roots = Roots {
            home: "/home/u".into(),
            config_dir: "/config/mise".into(),
        };
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut entry = TrackedEntry::new("/home/u/.sample".into(), "track", policy);
        entry.include = Some(vec!["keep".into()]);
        let tracked = TrackedSet {
            entries: vec![entry],
            ..Default::default()
        };
        let exclude = tracked.exclude_set().unwrap();
        // nothing of this test exists on disk, so every path below has
        // no kind to read
        assert!(eligible(&roots, &tracked, &exclude, "home/.sample/keep"));
        assert!(!eligible(
            &roots,
            &tracked,
            &exclude,
            "home/.sample/nested/leave"
        ));
    }
}

#[cfg(test)]
mod enrollment_base_tests {
    use super::*;
    use crate::history::manifest::{Enrollment, Manifest, PATH};
    use crate::history::shadow::HistoryRepo;

    fn enrollment(path: &str, autosave: bool) -> Enrollment {
        Enrollment {
            path: path.into(),
            autosave,
            encrypt: false,
            allow_plaintext: None,
            variants: vec![],
            exclude: None,
            include: None,
        }
    }

    fn manifest(entries: Vec<Enrollment>) -> Manifest {
        Manifest {
            enrollment: entries,
            ..Default::default()
        }
    }

    /// A commit whose only content is enrollment metadata.
    fn commit(repo: &HistoryRepo, parents: &[&str], manifest: &Manifest) -> Result<String> {
        let empty = repo.empty_object("tree")?;
        let tree = manifest.write(repo, &empty)?;
        repo.commit_tree(&tree, parents.to_vec(), "enrollment")
    }

    /// Criss-cross: root, then A and B, then each side merges the other.
    /// The two merges are the only merge bases of the resulting tips.
    fn criss_cross(
        repo: &HistoryRepo,
        root: &Manifest,
        left: &Manifest,
        right: &Manifest,
        local_tip: &Manifest,
        remote_tip: &Manifest,
    ) -> Result<()> {
        let root = commit(repo, &[], root)?;
        let left = commit(repo, &[&root], left)?;
        let right = commit(repo, &[&root], right)?;
        let local = commit(repo, &[&left, &right], local_tip)?;
        let remote = commit(repo, &[&right, &left], remote_tip)?;
        repo.update_ref(HistoryRepo::HISTORY_REF, &local, None)?;
        repo.update_ref(UPSTREAM_REF, &remote, None)?;
        let bases = repo.merge_bases(&local, &remote)?;
        eyre::ensure!(
            bases.len() == 2 && bases.contains(&left) && bases.contains(&right),
            "fixture is not a criss-cross: {bases:?}"
        );
        Ok(())
    }

    #[test]
    fn enrollment_with_several_merge_bases() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = HistoryRepo::open_or_init_in(temp.path())?.unwrap();
        criss_cross(
            &repo,
            &manifest(vec![enrollment("home/.shared", true)]),
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-left", true),
            ]),
            &manifest(vec![
                enrollment("home/.shared", false),
                enrollment("home/.from-right", true),
            ]),
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-left", true),
                enrollment("home/.from-right", true),
                enrollment("home/.local-only", true),
            ]),
            &manifest(vec![
                enrollment("home/.shared", false),
                enrollment("home/.from-left", true),
                enrollment("home/.from-right", true),
                enrollment("home/.remote-only", true),
            ]),
        )?;

        let incoming = incoming_tracking(&repo, &TrackedSet::default())?;
        let paths = incoming
            .manifest
            .enrollment
            .iter()
            .map(|entry| (entry.path.as_str(), entry.autosave))
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                ("home/.from-left", true),
                ("home/.from-right", true),
                ("home/.local-only", true),
                ("home/.remote-only", true),
                ("home/.shared", true),
            ],
            "independent additions survive; the base is false, the local tip changed it to true, and the remote tip left the base value, so the result is true"
        );
        assert!(
            incoming_repository_tree(&repo, &incoming)?.is_some(),
            "several bases are not a fast-forward, so the repository tree is still merged"
        );
        assert!(
            repo.ref_oid(HistoryRepo::HISTORY_REF)?.is_some(),
            "computing the base writes no history"
        );
        Ok(())
    }

    #[test]
    fn enrollment_conflict_across_two_bases_names_the_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = HistoryRepo::open_or_init_in(temp.path())?.unwrap();
        // Each base changed `.shared` a different way, and neither tip
        // restates it, so the conflict is between the bases themselves.
        criss_cross(
            &repo,
            &manifest(vec![enrollment("home/.shared", true)]),
            &manifest(vec![enrollment("home/.shared", false)]),
            &manifest(vec![]),
            &manifest(vec![enrollment("home/.local-only", true)]),
            &manifest(vec![enrollment("home/.remote-only", true)]),
        )?;

        let error = incoming_tracking(&repo, &TrackedSet::default()).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("home/.shared"),
            "a real enrollment conflict names its path, got {message}"
        );
        assert!(
            !message.contains("home/.local-only") && !message.contains("home/.remote-only"),
            "an independent addition is not reported as the conflict, got {message}"
        );
        let mut status = SyncStatus::default();
        repository_conflict(&mut status, &error);
        assert_eq!(
            status.conflicts[0].branch_path, PATH,
            "the conflict is reported through the repository conflict, not dropped"
        );
        assert!(
            status
                .validation_error
                .as_deref()
                .is_some_and(|text| text.contains("home/.shared")),
            "status keeps the path the merge named"
        );
        Ok(())
    }

    /// Each of the two merge bases is itself a criss-cross, so the pair
    /// has two common bases. Recursion has to merge that inner pair; a
    /// walk that only descends one side never asks.
    #[test]
    fn a_nested_criss_cross_merges_bases_that_themselves_have_two_bases() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = HistoryRepo::open_or_init_in(temp.path())?.unwrap();
        let root = commit(
            &repo,
            &[],
            &manifest(vec![enrollment("home/.shared", true)]),
        )?;
        let west = commit(
            &repo,
            &[&root],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-west", true),
            ]),
        )?;
        let east = commit(
            &repo,
            &[&root],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-east", true),
            ]),
        )?;
        let left = commit(
            &repo,
            &[&west, &east],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-west", true),
                enrollment("home/.from-east", true),
            ]),
        )?;
        let right = commit(
            &repo,
            &[&east, &west],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-west", true),
                enrollment("home/.from-east", true),
                enrollment("home/.from-right", true),
            ]),
        )?;
        let local = commit(
            &repo,
            &[&left, &right],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-west", true),
                enrollment("home/.from-east", true),
                enrollment("home/.from-right", true),
                enrollment("home/.local-only", true),
            ]),
        )?;
        let remote = commit(
            &repo,
            &[&right, &left],
            &manifest(vec![
                enrollment("home/.shared", true),
                enrollment("home/.from-west", true),
                enrollment("home/.from-east", true),
                enrollment("home/.from-right", true),
                enrollment("home/.remote-only", true),
            ]),
        )?;
        repo.update_ref(HistoryRepo::HISTORY_REF, &local, None)?;
        repo.update_ref(UPSTREAM_REF, &remote, None)?;
        let bases = repo.merge_bases(&local, &remote)?;
        assert_eq!(bases.len(), 2, "tips have two merge bases: {bases:?}");
        for base in &bases {
            let other = bases.iter().find(|candidate| *candidate != base).unwrap();
            let inner = repo.merge_bases(base, other)?;
            assert_eq!(
                inner.len(),
                2,
                "merge bases {base} and {other} themselves have two bases: {inner:?}"
            );
            assert!(inner.contains(&west) && inner.contains(&east));
        }

        let incoming = incoming_tracking(&repo, &TrackedSet::default())?;
        let paths: Vec<_> = incoming
            .manifest
            .enrollment
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "home/.from-east",
                "home/.from-right",
                "home/.from-west",
                "home/.local-only",
                "home/.remote-only",
                "home/.shared",
            ],
            "additions from both inner bases survive the recursive merge"
        );
        Ok(())
    }

    /// Three merge bases. The accumulated parent of the first pair must
    /// stay a real commit, or the third base is asked against an empty id.
    #[test]
    fn enrollment_with_three_merge_bases_keeps_each_independent_addition() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = HistoryRepo::open_or_init_in(temp.path())?.unwrap();
        let root = commit(
            &repo,
            &[],
            &manifest(vec![enrollment("home/.shared", true)]),
        )?;
        let added = |name: &str| {
            manifest(vec![
                enrollment("home/.shared", true),
                enrollment(name, true),
            ])
        };
        let first = commit(&repo, &[&root], &added("home/.from-first"))?;
        let second = commit(&repo, &[&root], &added("home/.from-second"))?;
        let third = commit(&repo, &[&root], &added("home/.from-third"))?;
        let combined = manifest(vec![
            enrollment("home/.shared", true),
            enrollment("home/.from-first", true),
            enrollment("home/.from-second", true),
            enrollment("home/.from-third", true),
        ]);
        let mut local_entries = combined.enrollment.clone();
        local_entries.push(enrollment("home/.local-only", true));
        let mut remote_entries = combined.enrollment.clone();
        remote_entries.push(enrollment("home/.remote-only", true));
        let local = commit(&repo, &[&first, &second, &third], &manifest(local_entries))?;
        let remote = commit(&repo, &[&third, &first, &second], &manifest(remote_entries))?;
        repo.update_ref(HistoryRepo::HISTORY_REF, &local, None)?;
        repo.update_ref(UPSTREAM_REF, &remote, None)?;
        assert_eq!(repo.merge_bases(&local, &remote)?.len(), 3);

        let incoming = incoming_tracking(&repo, &TrackedSet::default())?;
        let paths: Vec<_> = incoming
            .manifest
            .enrollment
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "home/.from-first",
                "home/.from-second",
                "home/.from-third",
                "home/.local-only",
                "home/.remote-only",
                "home/.shared",
            ],
            "each of the three bases contributes its addition"
        );
        assert_eq!(
            repo.ref_oid(HistoryRepo::HISTORY_REF)?.as_deref(),
            Some(local.as_str()),
            "the accumulated parent is unreferenced and does not move history"
        );
        Ok(())
    }

    #[test]
    fn merge_bases_without_shared_ancestry_fail_closed_and_name_status() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = HistoryRepo::open_or_init_in(temp.path())?.unwrap();
        let left_root = commit(&repo, &[], &manifest(vec![enrollment("home/.left", true)]))?;
        let right_root = commit(&repo, &[], &manifest(vec![enrollment("home/.right", true)]))?;
        let left = commit(
            &repo,
            &[&left_root],
            &manifest(vec![enrollment("home/.left", true)]),
        )?;
        let right = commit(
            &repo,
            &[&right_root],
            &manifest(vec![enrollment("home/.right", true)]),
        )?;
        let local = commit(
            &repo,
            &[&left, &right],
            &manifest(vec![enrollment("home/.left", true)]),
        )?;
        let remote = commit(
            &repo,
            &[&right, &left],
            &manifest(vec![enrollment("home/.right", true)]),
        )?;
        repo.update_ref(HistoryRepo::HISTORY_REF, &local, None)?;
        repo.update_ref(UPSTREAM_REF, &remote, None)?;
        assert_eq!(repo.merge_bases(&local, &remote)?.len(), 2);
        assert!(
            repo.merge_bases(&left, &right)?.is_empty(),
            "the two bases must share no ancestry"
        );

        let error = incoming_tracking(&repo, &TrackedSet::default()).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("mise dot status"),
            "recovery names status, which can print the reconciliation, got {message}"
        );
        assert!(
            !message.contains("mise dot conflicts"),
            "conflicts plans through the same failing code, got {message}"
        );
        assert!(
            message.contains("no ancestry"),
            "the failure says why a virtual base cannot be built, got {message}"
        );
        Ok(())
    }

    #[test]
    fn refresh_records_a_base_conflict_before_returning() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = crate::history::checkpoint::Store::open_in(temp.path())?;
        let repo = store.repo().unwrap();
        criss_cross(
            repo,
            &manifest(vec![enrollment("home/.shared", true)]),
            &manifest(vec![enrollment("home/.shared", false)]),
            &manifest(vec![]),
            &manifest(vec![enrollment("home/.local-only", true)]),
            &manifest(vec![enrollment("home/.remote-only", true)]),
        )?;
        let mut status = SyncStatus::default();
        let error = refresh(&store, &TrackedSet::default(), &mut status).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("home/.shared"),
            "refresh returns the named path conflict, got {message}"
        );
        assert!(
            status.pending_repository,
            "a base conflict is a repository conflict, not an empty plan"
        );
        assert_eq!(status.conflicts[0].branch_path, PATH);
        assert!(
            status
                .validation_error
                .as_deref()
                .is_some_and(|text| text.contains("home/.shared")),
            "status was filled before planning returned, got {:?}",
            status.validation_error
        );
        Ok(())
    }
}
