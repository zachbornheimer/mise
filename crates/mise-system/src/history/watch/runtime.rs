//! The foreground watcher process behind `mise dot watch` and
//! the `history-watch` built-in service: installs filesystem watches for the
//! tracked set, schedules each changed path on its own (a constantly
//! rewritten file is saved ever more rarely, never floods the history, and
//! never delays an ordinary edit), saves checkpoints, and persists its
//! health for `mise doctor` and `mise dot status`. Captures
//! never wait on the network and never run while another history operation
//! holds the operation lock; they are deferred and retried.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eyre::{Result, bail};
use notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, NoCache, new_debouncer_opt};
use serde_json::json;
use tokio::sync::mpsc;

use super::noise::{self, NoisyPath, NoisyRecord};
use super::plan::{Anchor, Mode, PathKind, WatchPlan};
use super::schedule::{self, Adjustment, Limits, PersistedSchedule, Schedule};
use crate::history::checkpoint::{Draft, Outcome, Store};
use crate::history::describe_command;
use crate::history::health::{self, Health, ThrottledPath};
use crate::history::store::{self, Trigger};
use crate::history::sync::apply::{self, ApplyRequest};
use crate::history::sync::run::{self as sync_run, SyncOutcome, SyncRequest};
use crate::history::sync::{Automatic, SyncMode};
use crate::history::tracked::{
    self, ExcludeSet, TrackedSet, hard_exclusions, normalize, normalize_target,
};
use mise_settings::Settings;
use mise_util::file::display_path;
use mise_util::lock_file::LockFile;

/// How long the debouncer coalesces raw filesystem events before they reach
/// the scheduler, which applies the configured quiet period on top.
const COALESCE: Duration = Duration::from_millis(500);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);
/// What a final capture does with throttled files: everything live when
/// the watcher stops for good, the schedule respected when the service is
/// about to restart it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Restart {
    Final,
    Held,
}

/// How often a start retries the watch lock a status probe may be holding
/// for a moment.
const WATCH_LOCK_TRIES: u32 = 5;
const WATCH_LOCK_RETRY: Duration = Duration::from_millis(200);

/// How often the watcher checks that the executable it started from has
/// not been replaced by an upgrade.
const BINARY_CHECK_EVERY: Duration = Duration::from_secs(60);
/// How long a synchronization in flight may delay the restart an upgrade
/// asks for; a stalled origin must not keep the old watcher running.
const UPGRADE_SYNC_GRACE: Duration = Duration::from_secs(30);

/// How many checkpoints may wait for `history.describe_command` before the
/// oldest keeps its computed description.
const DESCRIBE_QUEUE: usize = 8;

/// How often, and how many times, the shutdown capture waits for a running
/// history operation to finish before giving up.
const SHUTDOWN_RETRY_EVERY: Duration = Duration::from_secs(1);
const SHUTDOWN_RETRIES: usize = 10;
/// Automatic synchronization: the first fetch after a start, the follow-up
/// after an incoming configuration changed the tracked set, and the
/// backoff after a failed sync (local saves continue meanwhile).
const SYNC_FIRST_FETCH: Duration = Duration::from_secs(15);
const SYNC_FOLLOW_UP: Duration = Duration::from_secs(5);
const SYNC_BACKOFF_MIN: Duration = Duration::from_secs(60);
const SYNC_BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// What became of a capture attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
    /// It ran (a checkpoint was written, or nothing had changed).
    Done,
    /// Another history operation holds the lock; retried later.
    Deferred,
    /// It failed; retried after the backoff.
    Failed,
}

pub struct WatchOptions {
    /// Reconcile once and exit.
    pub once: bool,
    /// One JSON object per line instead of log lines.
    pub json: bool,
}

/// Runs the watcher; returns the process exit code.
pub async fn run(opts: WatchOptions) -> Result<i32> {
    // the baseline is taken before anything slow, so an upgrade landing
    // during startup is still seen as one
    let mut binary = BinaryWatch::new();
    let out = Output { json: opts.json };
    if !Settings::get().history.enabled {
        out.emit(
            "disabled",
            "history is disabled (history.enabled = false)",
            json!({}),
        );
        return Ok(0);
    }
    let store = Store::open()?;
    if let Some(reason) = store.unavailable() {
        out.emit("unavailable", &format!("cannot watch: {reason}"), json!({}));
        return Ok(1);
    }
    // a status probe (`doctor`, `status`, `track`) takes the lock for a
    // moment to see whether a watcher holds it: a start that lands on that
    // moment tries again rather than concluding another watcher runs
    let mut watch_lock = None;
    for attempt in 0..WATCH_LOCK_TRIES {
        if let Some(lock) = LockFile::at(&watch_lock_in(store.state_dir())).try_lock()? {
            watch_lock = Some(lock);
            break;
        }
        if attempt + 1 < WATCH_LOCK_TRIES {
            tokio::time::sleep(WATCH_LOCK_RETRY).await;
        }
    }
    let Some(_watch_lock) = watch_lock else {
        out.emit(
            "already-running",
            "another watcher is running for this store",
            json!({}),
        );
        return Ok(0);
    };
    let settings = Settings::get();
    let mut intervals = Intervals::from_settings(&settings);
    let mut state = State::load().await?;
    let mut capture = Capture::new(store, out, intervals.limits.clone());
    prune_schedule(&mut capture, &state);
    capture.health.watcher.started_at = Some(store::now_rfc3339());
    // a previous watcher's finding says nothing about this process
    capture.health.watcher.executable_gone = false;
    if opts.once {
        // A one-shot capture has no installed filesystem watches. Failures
        // from a previous watch installation do not describe this run.
        capture
            .health
            .watcher
            .degraded
            .retain(|line| line.starts_with(crate::history::health::PERMISSION_DEGRADED_PREFIX));
        // the restored schedule applies to this capture too: a throttled
        // file whose save is not due is held, not read live
        let outcome = capture.reconcile(&state.tracked, "startup reconcile");
        capture.write_health();
        let synced = once_sync(&mut capture, &state).await;
        if let Some(task) = start_describe(&mut capture)
            && let Ok((id, result)) = task.await
        {
            match result {
                Ok(Some(description)) => capture.out.emit(
                    "described",
                    &format!("checkpoint {id} described by history.describe_command: {description}"),
                    json!({ "id": id, "description": description }),
                ),
                Ok(None) => {}
                Err(err) => capture.out.emit(
                    "describe-error",
                    &format!("history.describe_command failed for checkpoint {id}: {err:#}; keeping the computed description"),
                    json!({ "id": id, "message": format!("{err:#}") }),
                ),
            }
        }
        return Ok(match outcome {
            Attempt::Done if synced => 0,
            Attempt::Done => 1,
            Attempt::Deferred => {
                capture.out.emit(
                    "unsaved",
                    "nothing was saved: another history operation is running; run again once it finished",
                    json!({ "reason": "deferred" }),
                );
                1
            }
            Attempt::Failed => {
                capture.out.emit(
                    "unsaved",
                    &format!(
                        "nothing was saved: {}",
                        capture
                            .health
                            .watcher
                            .last_error
                            .as_deref()
                            .unwrap_or("the capture failed")
                    ),
                    json!({ "reason": "failed" }),
                );
                1
            }
        });
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<DebounceEventResult>();
    let mut debouncer = new_debouncer_opt::<_, RecommendedWatcher, NoCache>(
        COALESCE,
        None,
        move |result| {
            let _ = tx.send(result);
        },
        NoCache,
        notify::Config::default(),
    )?;
    let mut installed = match install(&mut debouncer, &[], &state.plan.anchors, &mut capture) {
        Ok(installed) if !installed.is_empty() => installed,
        outcome => {
            // what changed while the watcher was down is saved before it
            // gives up on watching (waiting a moment for a running
            // operation), and why it gave up, and whether that final save
            // happened, is on record for `doctor` and `status`
            let err = match outcome {
                Ok(_) => eyre::eyre!("no watch could be installed for the tracked set"),
                Err(err) => err,
            };
            stop_after_install_failure(&mut capture, &state.tracked, &err, "installed").await;
            debouncer.stop();
            return Ok(1);
        }
    };
    // the first capture comes after the watches are in place, so an edit
    // landing between the two reaches the scheduler instead of waiting for
    // the next reconcile
    capture.reconcile(&state.tracked, "startup reconcile");
    // Readiness must mean a service manager can immediately stop us cleanly.
    // Install signal handlers before publishing the started event.
    let mut shutdown = Shutdown::new()?;
    capture.out.emit(
        "started",
        &format!(
            "watching {} anchor(s) for {} tracked entr{}",
            installed.len(),
            state.tracked.entries.len(),
            if state.tracked.entries.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ),
        json!({ "anchors": installed.len(), "pending": state.plan.pending.len() }),
    );
    capture.write_health();

    let mut next_reconcile = intervals
        .reconcile
        .map(|every| tokio::time::Instant::now() + every);
    let mut binary_check = tokio::time::interval_at(
        tokio::time::Instant::now() + BINARY_CHECK_EVERY,
        BINARY_CHECK_EVERY,
    );
    // the network runs on a blocking task of its own: a slow origin never
    // delays a capture
    let mut sync_task: Option<tokio::task::JoinHandle<Result<SyncOutcome>>> = None;
    // the description command runs one checkpoint at a time, off the loop
    let mut describe_task: Option<tokio::task::JoinHandle<(u64, Result<Option<String>>)>> = None;
    loop {
        if describe_task.is_none() {
            describe_task = start_describe(&mut capture);
        }
        // the next save, or the retry of a deferred or failed capture,
        // whichever comes first
        let flush_at = match (
            capture.schedule.deadline().map(|at| capture.not_before(at)),
            capture.retry_due(),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let flush = async {
            match flush_at {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        let reconcile = async {
            match next_reconcile {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        let sync_at = if sync_task.is_none() {
            capture.sync.as_ref().and_then(SyncPlan::deadline)
        } else {
            None
        };
        let sync_tick = async {
            match sync_at {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        let sync_done = async {
            match &mut sync_task {
                Some(task) => task.await,
                None => std::future::pending().await,
            }
        };
        let describe_done = async {
            match &mut describe_task {
                Some(task) => task.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            received = rx.recv() => {
                let Some(result) = received else {
                    capture.out.emit(
                        "error",
                        "the filesystem watch stopped delivering events; stopping so the service restarts it",
                        json!({ "message": "watch channel closed" }),
                    );
                    // the service restarts the watcher: throttled files
                    // stay held, so a failure that persists does not save
                    // them on every restart
                    finish(&mut capture, &state.tracked, Restart::Held).await;
                    // Transport failure is not a capture failure: finish may
                    // have saved successfully. Preserve its actual outcome.
                    capture.health.watcher.degraded.push("the filesystem watch stopped".into());
                    capture.write_health();
                    debouncer.stop();
                    return Ok(1);
                };
                let now = Instant::now();
                let mut config_changed = false;
                let mut rescan = false;
                let mut pending_appeared = false;
                // a watched directory itself changed (replaced, recreated,
                // renamed): its watch may be dead
                let mut anchor_changed = false;
                let mut throttled_changed = false;
                match result {
                    Ok(events) => {
                        for event in events {
                            trace!("history watch: {:?} {:?}", event.kind, event.paths);
                            if event.kind.is_access() {
                                continue;
                            }
                            if event.need_rescan() {
                                rescan = true;
                            }
                            for path in &event.paths {
                                // the parent resolved, the final link kept:
                                // a tracked link is scheduled as the link
                                let path = normalize_target(path);
                                if state.is_config_file(&path) {
                                    config_changed = true;
                                }
                                // a tracked path that did not exist is watched
                                // through an ancestor: something appearing on
                                // the way to it means the plan can move closer
                                if state.plan.pending.iter().any(|pending| pending.starts_with(&path)) {
                                    pending_appeared = true;
                                }
                                if anchor_replaced(&capture.anchor_ids, &path) {
                                    anchor_changed = true;
                                }
                                // a link that appeared or changed may point
                                // somewhere new: the derived entries follow
                                if path.is_symlink() && state.relevant(&path) {
                                    pending_appeared = true;
                                }
                                if !state.relevant(&path) {
                                    debug!("history watch: ignoring {}", path.display());
                                    continue;
                                }
                                // files are scheduled, never directories: a
                                // held directory would hold everything in it
                                if path.is_dir() && !path.is_symlink() {
                                    continue;
                                }
                                capture.schedule.note(path.clone(), now);
                                if capture.schedule.is_throttled(&path) {
                                    throttled_changed = true;
                                }
                            }
                        }
                    }
                    Err(errors) => {
                        for err in errors {
                            capture.out.emit("error", &format!("watch error: {err}"), json!({ "message": err.to_string() }));
                        }
                    }
                }
                // a throttled file's unsaved changes are visible to status
                // and doctor as they happen, not only after its next save
                if throttled_changed {
                    capture.persist_schedule();
                    capture.write_health();
                }
                if config_changed {
                    match state.reload().await {
                        Ok(true) => {
                            // Config and root replacement events can share a
                            // batch. Recreate watches even for retained paths,
                            // whose old inode may no longer exist.
                            installed = match reinstall(&mut debouncer, &installed, &state.plan.anchors, &mut capture) {
                        Ok(installed) => installed,
                        Err(err) => {
                            stop_after_install_failure(&mut capture, &state.tracked, &err, "re-installed").await;
                            debouncer.stop();
                            return Ok(1);
                        }
                    };
                            // the timing settings may have changed with it
                            apply_intervals(&mut capture, &mut intervals, &mut next_reconcile);
                            // the origin or the mode may have changed with it
                            refresh_sync_plan(&mut capture, now);
                            capture.out.emit(
                                "replan",
                                &format!("configuration changed; watching {} anchor(s)", installed.len()),
                                json!({ "anchors": installed.len() }),
                            );
                            // a path the new configuration no longer
                            // autosaves (excluded, untracked, switched to
                            // manual saving) leaves the schedule: no capture
                            // from now on holds it or carries its old
                            // version forward as if it were still eligible.
                            // A path that is missing right now (a symlink
                            // target between two versions, say) keeps its
                            // throttling while something still declares it;
                            // one nothing declares any more leaves like any
                            // other
                            prune_schedule(&mut capture, &state);
                            // the configuration that changed is what this
                            // capture is for: never held back
                            let config_dir = state.config_dir.clone();
                            let held: Vec<PathBuf> = capture
                                .schedule
                                .held_paths(now)
                                .into_iter()
                                .filter(|path| !path.starts_with(&config_dir))
                                .collect();
                            if capture.attempt(&state.tracked, "configuration changed", &held) == Attempt::Done {
                                capture.health.watcher.last_reconcile = Some(store::now_rfc3339());
                                for path in capture.schedule.due_paths(now).into_iter().chain(
                                    capture
                                        .schedule
                                        .held_paths(now)
                                        .into_iter()
                                        .filter(|path| path.starts_with(&config_dir)),
                                ) {
                                    capture.schedule.saved(&path, now);
                                }
                                capture.schedule.prune(now);
                                capture.persist_schedule();
                            }
                            capture.write_health();
                        }
                        Ok(false) => {
                            stop_disabled(&mut capture, &state.tracked).await;
                            debouncer.stop();
                            return Ok(0);
                        }
                        Err(err) => capture.out.emit(
                            "error",
                            &format!("configuration could not be reloaded; keeping the previous tracked set: {err:#}"),
                            json!({ "message": format!("{err:#}") }),
                        ),
                    }
                } else if rescan {
                    // the backend lost track: every watch is made anew
                    match state.reload().await {
                        Ok(true) => {
                            installed = match reinstall(&mut debouncer, &installed, &state.plan.anchors, &mut capture) {
                                Ok(installed) => installed,
                                Err(err) => {
                                    stop_after_install_failure(&mut capture, &state.tracked, &err, "re-installed").await;
                                    debouncer.stop();
                                    return Ok(1);
                                }
                            };
                            apply_intervals(&mut capture, &mut intervals, &mut next_reconcile);
                            refresh_sync_plan(&mut capture, Instant::now());
                            prune_schedule(&mut capture, &state);
                        }
                        Ok(false) => {
                            stop_disabled(&mut capture, &state.tracked).await;
                            debouncer.stop();
                            return Ok(0);
                        }
                        Err(err) => capture.out.emit(
                            "error",
                            &format!("configuration could not be reloaded; keeping the previous tracked set: {err:#}"),
                            json!({ "message": format!("{err:#}") }),
                        ),
                    }
                    capture.reconcile(&state.tracked, "rescan");
                    capture.write_health();
                } else if pending_appeared || anchor_changed {
                    match state.reload().await {
                        Ok(true) => {}
                        Ok(false) => {
                            stop_disabled(&mut capture, &state.tracked).await;
                            debouncer.stop();
                            return Ok(0);
                        }
                        Err(err) => {
                            capture.out.emit(
                                "error",
                                &format!("configuration could not be reloaded; keeping the previous tracked set: {err:#}"),
                                json!({ "message": format!("{err:#}") }),
                            );
                            continue;
                        }
                    }
                    apply_intervals(&mut capture, &mut intervals, &mut next_reconcile);
                    refresh_sync_plan(&mut capture, Instant::now());
                    // a replaced directory keeps its path but not its
                    // watch: an anchor that changed is watched anew
                    installed = match if anchor_changed {
                        reinstall(&mut debouncer, &installed, &state.plan.anchors, &mut capture)
                    } else {
                        install(&mut debouncer, &installed, &state.plan.anchors, &mut capture)
                    } {
                        Ok(installed) => installed,
                        Err(err) => {
                            stop_after_install_failure(&mut capture, &state.tracked, &err, "re-installed").await;
                            debouncer.stop();
                            return Ok(1);
                        }
                    };
                    // what the new set no longer covers (a link's old
                    // target, say) leaves the schedule
                    prune_schedule(&mut capture, &state);
                    // Newly appeared trees may already contain files before
                    // their watches are installed. Capture those and any edits
                    // during reinstallation even if periodic reconciliation is
                    // disabled, while preserving the noisy-file schedule.
                    capture.reconcile(&state.tracked, "watches updated");
                    capture.out.emit(
                        "replan",
                        &format!("a tracked path appeared; watching {} anchor(s)", installed.len()),
                        json!({ "anchors": installed.len(), "pending": state.plan.pending.len() }),
                    );
                    capture.write_health();
                }
            }
            _ = flush => {
                let now = Instant::now();
                let due = capture.schedule.due_paths(now);
                let retrying = capture.retry_due().is_some_and(|at| at <= now);
                if !due.is_empty() || retrying {
                    let held = capture.schedule.held_paths(now);
                    let reason = if due.is_empty() {
                        "retry".to_string()
                    } else {
                        describe(&due)
                    };
                    let done = capture.attempt(&state.tracked, &reason, &held) == Attempt::Done;
                    if done {
                        for path in &due {
                            match capture.schedule.saved(path, now) {
                                Adjustment::Stretched => {
                                    let interval = capture.schedule.get(path).map(|s| s.interval).unwrap_or_default();
                                    capture.out.emit(
                                        "throttled",
                                        &format!(
                                            "{} keeps changing; saving it every {} now (up to {}). Exclude it with `mise dot exclude '{}'` if it is a log, cache, or database, or track it with `--no-autosave` and save it explicitly",
                                            display_path(path),
                                            humantime(interval),
                                            humantime(capture.schedule.limits().max),
                                            display_path(path)
                                        ),
                                        json!({ "path": display_path(path), "interval_secs": interval.as_secs() }),
                                    );
                                }
                                Adjustment::Reset => capture.out.emit(
                                    "settled",
                                    &format!("{} settled; saving it promptly again", display_path(path)),
                                    json!({ "path": display_path(path) }),
                                ),
                                Adjustment::Unchanged => {}
                            }
                        }
                        capture.schedule.prune(now);
                        capture.persist_schedule();
                        capture.write_health();
                    }
                }
            }
            _ = reconcile => {
                if let Some(every) = intervals.reconcile {
                    next_reconcile = Some(tokio::time::Instant::now() + every);
                }
                // the tracked set and every watch are made anew: a pending
                // path that appeared is watched, a replaced directory's dead
                // watch is replaced, and what the set no longer covers
                // leaves the schedule
                match state.reload().await {
                    Ok(true) => {
                        installed = match reinstall(&mut debouncer, &installed, &state.plan.anchors, &mut capture) {
                            Ok(installed) => installed,
                            Err(err) => {
                                stop_after_install_failure(&mut capture, &state.tracked, &err, "re-installed").await;
                                debouncer.stop();
                                return Ok(1);
                            }
                        };
                        apply_intervals(&mut capture, &mut intervals, &mut next_reconcile);
                        refresh_sync_plan(&mut capture, Instant::now());
                        prune_schedule(&mut capture, &state);
                    }
                    Ok(false) => {
                        stop_disabled(&mut capture, &state.tracked).await;
                        debouncer.stop();
                        return Ok(0);
                    }
                    Err(err) => capture.out.emit(
                        "error",
                        &format!("configuration could not be reloaded; keeping the previous tracked set: {err:#}"),
                        json!({ "message": format!("{err:#}") }),
                    ),
                }
                capture.reconcile(&state.tracked, "reconcile");
                capture.write_health();
            }
            _ = binary_check.tick() => {
                let executable = binary.check();
                let gone = match executable {
                    Executable::Gone => true,
                    Executable::Current => false,
                    _ => capture.health.watcher.executable_gone,
                };
                if gone != capture.health.watcher.executable_gone {
                    capture.health.watcher.executable_gone = gone;
                    if gone {
                        capture.out.emit(
                            "outdated",
                            health::EXECUTABLE_GONE_ADVICE,
                            json!({ "reason": "executable-removed" }),
                        );
                    }
                    capture.write_health();
                }
                if executable == Executable::Replaced {
                    capture.out.emit(
                        "restarting",
                        "the mise executable was replaced; stopping so the service restarts the watcher on the new version",
                        json!({ "reason": "upgraded" }),
                    );
                    if let Some(task) = sync_task.take()
                        && let Ok(joined) = tokio::time::timeout(UPGRADE_SYNC_GRACE, task).await
                    {
                        let outcome = joined.unwrap_or_else(|err| Err(eyre::eyre!("the sync task stopped unexpectedly: {err}")));
                        finish_sync(&mut capture, &state.tracked, outcome).await;
                    }
                    // an upgrade happens once, and a watcher started by hand
                    // has no service to bring it back: everything pending is
                    // saved now
                    finish(&mut capture, &state.tracked, Restart::Final).await;
                    debouncer.stop();
                    return Ok(1);
                }
            }
            _ = sync_tick => {
                sync_task = start_sync(&mut capture, &state.tracked);
            }
            joined = describe_done => {
                describe_task = None;
                match joined {
                    Ok((id, Ok(Some(description)))) => capture.out.emit(
                        "described",
                        &format!("checkpoint {id} described by history.describe_command: {description}"),
                        json!({ "id": id, "description": description }),
                    ),
                    Ok((id, Ok(None))) => capture.out.emit(
                        "described",
                        &format!("history.describe_command printed nothing for checkpoint {id}; keeping the computed description"),
                        json!({ "id": id, "description": null }),
                    ),
                    Ok((id, Err(err))) => capture.out.emit(
                        "describe-error",
                        &format!("history.describe_command failed for checkpoint {id}: {err:#}; keeping the computed description"),
                        json!({ "id": id, "message": format!("{err:#}") }),
                    ),
                    Err(err) => capture.out.emit(
                        "describe-error",
                        &format!("history.describe_command stopped unexpectedly: {err}"),
                        json!({ "message": err.to_string() }),
                    ),
                }
            }
            joined = sync_done => {
                sync_task = None;
                let outcome = match joined {
                    Ok(outcome) => outcome,
                    Err(err) => Err(eyre::eyre!("the sync task stopped unexpectedly: {err}")),
                };
                if finish_sync(&mut capture, &state.tracked, outcome).await == Some(true) {
                    // the configuration that arrived may declare more:
                    // replan, and fetch again soon for what it declares
                    match state.reload().await {
                        Ok(true) => {
                            installed = match install(&mut debouncer, &installed, &state.plan.anchors, &mut capture) {
                                Ok(installed) => installed,
                                Err(err) => {
                                    stop_after_install_failure(&mut capture, &state.tracked, &err, "re-installed").await;
                                    debouncer.stop();
                                    return Ok(1);
                                }
                            };
                            capture.out.emit(
                                "replan",
                                &format!("incoming configuration applied; watching {} anchor(s)", installed.len()),
                                json!({ "anchors": installed.len() }),
                            );
                            if let Some(plan) = &mut capture.sync {
                                plan.follow_up(Instant::now());
                            }
                        }
                        Ok(false) => {
                            stop_disabled(&mut capture, &state.tracked).await;
                            debouncer.stop();
                            return Ok(0);
                        }
                        Err(err) => capture.out.emit(
                            "error",
                            &format!("configuration could not be reloaded; keeping the previous tracked set: {err:#}"),
                            json!({ "message": format!("{err:#}") }),
                        ),
                    }
                }
            }
            _ = shutdown.wait() => {
                if let Some(task) = sync_task.take() {
                    // a publication in flight finishes; nothing is started after
                    let outcome = task.await.unwrap_or_else(|err| Err(eyre::eyre!("the sync task stopped unexpectedly: {err}")));
                    finish_sync(&mut capture, &state.tracked, outcome).await;
                }
                finish(&mut capture, &state.tracked, Restart::Final).await;
                break;
            }
        }
    }
    debouncer.stop();
    Ok(0)
}

/// Starts the description command for the newest checkpoint waiting for
/// one, on a blocking task of its own. The checkpoint is saved already;
/// whatever the command does, history is not held up.
fn start_describe(
    capture: &mut Capture,
) -> Option<tokio::task::JoinHandle<(u64, Result<Option<String>>)>> {
    let entry = capture.describe_next.pop_front()?;
    let command = describe_command::configured()?;
    let state_dir = capture.store.state_dir().to_path_buf();
    Some(tokio::task::spawn_blocking(move || {
        let id = entry.id;
        let result = Store::open_in(&state_dir)
            .and_then(|store| describe_command::run(&store, &entry, &command));
        (id, result)
    }))
}

/// Starts one synchronization on a blocking task, per the mode: the
/// watcher's own captures decide what is saved, so the sync never captures
/// (a throttled file's held version and a manual-save entry's unsaved edits
/// stay on this machine).
fn start_sync(
    capture: &mut Capture,
    tracked: &TrackedSet,
) -> Option<tokio::task::JoinHandle<Result<SyncOutcome>>> {
    let plan = capture.sync.as_mut()?;
    let fetch_only = !plan.config.automatic.publish;
    plan.next_publish = None;
    plan.next_fetch = None;
    capture.out.emit(
        "sync",
        if fetch_only {
            "fetching the setup repository"
        } else {
            "publishing to and fetching the setup repository"
        },
        json!({ "fetch_only": fetch_only }),
    );
    let tracked = tracked.clone();
    let state_dir = capture.store.state_dir().to_path_buf();
    Some(tokio::task::spawn_blocking(move || {
        let store = Store::open_in(&state_dir)?;
        let mut request = SyncRequest::new(fetch_only);
        request.capture = false;
        sync_run::sync(&store, &tracked, &request)
    }))
}

/// Records a sync's outcome and, in `sync` mode, applies what it recorded
/// as pending. `None` after a failure (retried after the backoff). A held
/// lock is `Some(false)`: nothing was applied, and it is not a failure.
/// Otherwise, whether a configuration file was written.
async fn finish_sync(
    capture: &mut Capture,
    tracked: &TrackedSet,
    outcome: Result<SyncOutcome>,
) -> Option<bool> {
    let now = Instant::now();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            // a held lock is the other sync doing this work, not a failure:
            // the recorded run of failures stays as the last real sync left it
            if let Some(held) = err.downcast_ref::<sync_run::SyncLockHeld>() {
                if let Some(plan) = &mut capture.sync {
                    plan.skipped(now);
                }
                capture.out.emit(
                    "sync-skipped",
                    &format!(
                        "synchronization skipped: {}; retrying in {}",
                        held.holder,
                        humantime(SYNC_FOLLOW_UP)
                    ),
                    json!({
                        "holder": held.holder,
                        "retry_in_secs": SYNC_FOLLOW_UP.as_secs(),
                    }),
                );
                return Some(false);
            }
            let retry_in = capture.sync_failed(now);
            capture.out.emit(
                "sync-error",
                &format!(
                    "could not synchronize: {err:#}; retrying in {} (saving continues meanwhile)",
                    humantime(retry_in)
                ),
                json!({ "message": format!("{err:#}"), "retry_in_secs": retry_in.as_secs() }),
            );
            return None;
        }
    };
    capture.sync_succeeded(now);
    capture.out.emit(
        "synced",
        &format!(
            "synchronized: {}, {} incoming change(s) pending, {} conflict(s)",
            match &outcome.published {
                Some(commit) => format!("published {}", crate::history::short(commit)),
                None => match &outcome.publish_skipped {
                    Some(skip) => skip.sentence(),
                    None => "nothing new to publish".to_string(),
                },
            },
            outcome.pending,
            outcome.conflicts
        ),
        json!({
            "published": outcome.published,
            "publish_skipped": outcome.publish_skipped,
            "pending": outcome.pending,
            "conflicts": outcome.conflicts,
        }),
    );
    let applies = capture
        .sync
        .as_ref()
        .is_some_and(|plan| plan.config.automatic.apply);
    if !applies || outcome.pending == 0 {
        return Some(false);
    }
    match apply::apply(&capture.store, tracked, &ApplyRequest::automatic()).await {
        Ok(applied) => {
            capture.out.emit(
                "applied",
                &format!(
                    "applied {} incoming change(s); {} path(s) held for a decision{}",
                    applied.written,
                    applied.held,
                    if applied.configuration {
                        "; configuration changed: run `mise bootstrap` when its declarations should take effect"
                    } else {
                        ""
                    }
                ),
                json!({ "written": applied.written, "held": applied.held, "configuration": applied.configuration }),
            );
            Some(applied.configuration)
        }
        Err(err) => {
            let retry_in = capture.sync_failed(now);
            capture.out.emit(
                "error",
                &format!(
                    "could not apply incoming changes: {err:#}; retrying in {}",
                    humantime(retry_in)
                ),
                json!({ "message": format!("{err:#}"), "retry_in_secs": retry_in.as_secs() }),
            );
            Some(false)
        }
    }
}

/// `--once`: one synchronization per the mode, waited for. Whether it (and
/// the application it may include) succeeded; `true` when nothing is due.
async fn once_sync(capture: &mut Capture, state: &State) -> bool {
    let Some(task) = start_sync(capture, &state.tracked) else {
        return true;
    };
    let outcome = task
        .await
        .unwrap_or_else(|err| Err(eyre::eyre!("the sync task stopped unexpectedly: {err}")));
    finish_sync(capture, &state.tracked, outcome)
        .await
        .is_some()
}

/// What the watcher does with the setup repository on its own, per
/// `settings.history.sync`: when the next publication (at most
/// `sync_interval` after a save) and the next fetch (every
/// `fetch_interval`) are due, and the backoff after a failure.
struct SyncPlan {
    config: SyncConfig,
    next_publish: Option<Instant>,
    next_fetch: Option<Instant>,
    backoff: Duration,
}

/// What `settings.history.sync` and `[history.origin]` say. Compared after a
/// reload of the configuration, so a pending deadline survives an edit to
/// something else.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SyncConfig {
    automatic: Automatic,
    publish_after: Duration,
    fetch_every: Duration,
    /// The repository's url and branch: another one starts afresh.
    origin: (String, String),
}

impl SyncConfig {
    /// `None` without a connected origin, or in `manual` mode.
    fn from_settings(settings: &Settings) -> Option<Self> {
        let (_, origin) = crate::history::config::origin().ok().flatten()?;
        let automatic = SyncMode::parse(&settings.history.sync).ok()?.automatic();
        if !automatic.publish && !automatic.fetch {
            return None;
        }
        let parse = |name: &str, value: &str, default: Duration| {
            mise_util::duration::parse_duration(value).unwrap_or_else(|err| {
                warn!("history.{name}: {err}; using {default:?}");
                default
            })
        };
        Some(Self {
            automatic,
            publish_after: parse(
                "sync_interval",
                &settings.history.sync_interval,
                Duration::from_secs(300),
            ),
            fetch_every: parse(
                "fetch_interval",
                &settings.history.fetch_interval,
                Duration::from_secs(900),
            ),
            origin: (origin.url, origin.branch),
        })
    }
}

impl SyncPlan {
    /// `None` without a connected origin, or in `manual` mode.
    fn from_settings(settings: &Settings, now: Instant) -> Option<Self> {
        SyncConfig::from_settings(settings).map(|config| Self::new(config, now))
    }

    /// A fresh plan: the first fetch soon, no publication pending.
    fn new(mut config: SyncConfig, now: Instant) -> Self {
        config.fetch_every = config.fetch_every.max(Duration::from_secs(1));
        Self {
            next_publish: None,
            next_fetch: config
                .automatic
                .fetch
                .then(|| now + SYNC_FIRST_FETCH.min(config.fetch_every)),
            backoff: SYNC_BACKOFF_MIN.min(config.fetch_every),
            config,
        }
    }

    /// The configuration was reloaded. Another origin starts afresh;
    /// otherwise what is pending stays, moved only by what changed: a
    /// disabled activity loses its deadline, a newly enabled fetch gets its
    /// first one, and a shorter interval brings a deadline forward, never
    /// back. A reload that changes nothing changes nothing here, so a
    /// reconcile tick or an edit elsewhere never postpones what is due.
    fn reconfigure(&mut self, mut fresh: SyncConfig, now: Instant) {
        fresh.fetch_every = fresh.fetch_every.max(Duration::from_secs(1));
        if fresh == self.config {
            return;
        }
        if fresh.origin != self.config.origin {
            *self = Self::new(fresh, now);
            return;
        }
        let previous = std::mem::replace(&mut self.config, fresh);
        let config = &self.config;
        if !config.automatic.publish {
            self.next_publish = None;
        } else if config.publish_after != previous.publish_after {
            // nothing saved, nothing to bring forward
            let at = now + config.publish_after;
            self.next_publish = self.next_publish.map(|due| due.min(at));
        }
        if !config.automatic.fetch {
            self.next_fetch = None;
        } else if !previous.automatic.fetch {
            self.next_fetch = Some(now + SYNC_FIRST_FETCH.min(config.fetch_every));
        } else if config.fetch_every != previous.fetch_every {
            let at = now + config.fetch_every;
            self.next_fetch = Some(self.next_fetch.map_or(at, |due| due.min(at)));
        }
        self.backoff = self.backoff.min(SYNC_BACKOFF_MAX).max(self.backoff_floor());
    }

    /// The shortest backoff: a minute, or the fetch interval when that is
    /// shorter (a test's, say).
    fn backoff_floor(&self) -> Duration {
        SYNC_BACKOFF_MIN.min(self.config.fetch_every)
    }

    fn deadline(&self) -> Option<Instant> {
        match (self.next_publish, self.next_fetch) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// A checkpoint was saved: publish it soon, unless a publication is
    /// already due sooner.
    fn saved(&mut self, now: Instant) {
        if !self.config.automatic.publish {
            return;
        }
        let at = now + self.config.publish_after;
        self.next_publish = Some(self.next_publish.map_or(at, |due| due.min(at)));
    }

    /// An incoming configuration changed the tracked set: fetch again soon.
    fn follow_up(&mut self, now: Instant) {
        let at = now + SYNC_FOLLOW_UP;
        self.next_fetch = Some(self.next_fetch.map_or(at, |due| due.min(at)));
    }

    fn failed(&mut self, now: Instant) -> Duration {
        let retry_in = jittered(self.backoff);
        self.next_publish = None;
        self.next_fetch = Some(now + retry_in);
        self.backoff = (self.backoff * 2).min(SYNC_BACKOFF_MAX);
        retry_in
    }

    /// The lock was held. The failure base stays where it is. The attempt
    /// that just ended consumed its deadline, so the next one is exactly the
    /// follow-up from now: a deadline already due would start again at once,
    /// and a publication saved while this sync ran keeps its deadline unless
    /// that deadline is already past.
    fn skipped(&mut self, now: Instant) {
        let at = now + SYNC_FOLLOW_UP;
        self.next_fetch = Some(at);
        self.next_publish = self.next_publish.map(|due| due.max(at));
    }

    fn succeeded(&mut self, now: Instant) {
        self.backoff = self.backoff_floor();
        // start_sync consumed the old deadline. A new one belongs to a
        // checkpoint saved while that synchronization was in flight.
        self.next_fetch = self
            .config
            .automatic
            .fetch
            .then(|| now + jittered_around(self.config.fetch_every));
    }
}

/// A base this short stays exact: the one-second floor and the two-second
/// retry that follows it.
const EXACT_BACKOFF: Duration = Duration::from_secs(2);
/// A fetch interval this short stays exact, so the one-second floor cannot spin.
const EXACT_FETCH: Duration = Duration::from_secs(10);

/// A delay in `[full / 2, full]`, never above the backoff cap. At or below
/// [`EXACT_BACKOFF`] the delay stays exact.
fn jittered(full: Duration) -> Duration {
    let capped = full.min(SYNC_BACKOFF_MAX);
    if capped <= EXACT_BACKOFF {
        return capped;
    }
    within(capped / 2, capped)
}

/// `every`, moved by at most a tenth either way. Below [`EXACT_FETCH`] it
/// stays exact.
fn jittered_around(every: Duration) -> Duration {
    if every < EXACT_FETCH {
        return every;
    }
    within(every - every / 10, every + every / 10)
}

/// A duration in `[low, high]`. The factor is half-open; the clamp closes it.
fn within(low: Duration, high: Duration) -> Duration {
    let factor = rand::random::<f64>();
    let span = high.saturating_sub(low);
    low + Duration::from_secs_f64(span.as_secs_f64() * factor).min(span)
}

/// The final capture before the process ends: a full capture, not only the
/// due paths (a change still inside the coalescing window has not reached
/// the scheduler yet, and a throttled file's final state is saved now). The
/// backoff does not apply, and a running operation is given a moment.
/// The watches could not be re-installed after a replan: what is pending is
/// saved and the failure recorded before the process exits, so the service
/// restarts it and status says why.
/// Stops after the watches could not be `installed` (at startup) or
/// `re-installed` (a replan): a final capture first, then the reason on
/// record, including a final capture that could not run.
async fn stop_after_install_failure(
    capture: &mut Capture,
    tracked: &TrackedSet,
    err: &eyre::Report,
    phase: &str,
) {
    capture.out.emit(
        "error",
        &format!("the watches could not be {phase}; stopping so the service restarts it: {err:#}"),
        json!({ "message": format!("{err:#}") }),
    );
    let saved = finish(capture, tracked, Restart::Held).await;
    // recorded after the final capture, which would clear it
    let unsaved = match saved {
        Attempt::Done => String::new(),
        Attempt::Deferred => {
            "; the final capture did not run: another history operation held the lock".to_string()
        }
        Attempt::Failed => "; the final capture failed".to_string(),
    };
    capture.health.watcher.last_error = Some(format!(
        "the watches could not be {phase}: {err:#}{unsaved}"
    ));
    capture.health.watcher.last_error_at = Some(store::now_rfc3339());
    capture.health.watcher.consecutive_failures += 1;
    capture.write_health();
}

/// Returns how the final capture went.
/// The final capture before the process ends. A stop for good (a signal,
/// history switched off) saves everything live, a throttled file's final
/// state included. A stop the service will undo by restarting the watcher
/// (`Restart::Held`, the watches could not be installed) keeps holding
/// throttled files: a failure that persists would otherwise save them on
/// every restart.
async fn finish(capture: &mut Capture, tracked: &TrackedSet, restart: Restart) -> Attempt {
    // a full capture, not only the due paths: a change still
    // inside the coalescing window has not reached the scheduler
    // yet. The backoff does not apply, and a running operation is
    // given a moment to finish
    let now = Instant::now();
    let held = match restart {
        Restart::Held => capture.schedule.held_paths(now),
        Restart::Final => vec![],
    };
    capture.retry_at = None;
    let mut outcome = capture.attempt(tracked, "shutdown", &held);
    for _ in 0..SHUTDOWN_RETRIES {
        if outcome != Attempt::Deferred {
            break;
        }
        tokio::time::sleep(SHUTDOWN_RETRY_EVERY).await;
        capture.retry_at = None;
        outcome = capture.attempt(tracked, "shutdown", &held);
    }
    if outcome == Attempt::Done {
        match restart {
            Restart::Final => capture.schedule.clear_pending(now),
            Restart::Held => {
                for path in capture.schedule.due_paths(now) {
                    capture.schedule.saved(&path, now);
                }
                capture.schedule.prune(now);
            }
        }
    } else {
        let pending =
            capture.schedule.held_paths(now).len() + capture.schedule.due_paths(now).len();
        capture.out.emit(
            "unsaved",
            &format!("stopping with {pending} pending path(s) unsaved; the next start saves them"),
            json!({ "pending": pending }),
        );
    }
    capture.persist_schedule();
    // a description command still running is not waited for: its
    // checkpoint keeps the computed description
    describe_command::abort_running();
    capture.out.emit("stopped", "stopping", json!({}));
    capture.write_health();
    outcome
}

fn describe(paths: &[PathBuf]) -> String {
    let mut names: Vec<String> = paths.iter().map(display_path).collect();
    names.sort();
    let extra = names.len().saturating_sub(3);
    names.truncate(3);
    if extra > 0 {
        format!("{} +{extra} more changed", names.join(", "))
    } else {
        format!("{} changed", names.join(", "))
    }
}

pub fn humantime(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Intervals {
    limits: Limits,
    reconcile: Option<Duration>,
}

impl Intervals {
    fn from_settings(settings: &Settings) -> Self {
        let parse = |name: &str, value: &str, default: Duration| {
            mise_util::duration::parse_duration(value).unwrap_or_else(|err| {
                warn!("history.watch.{name}: {err}; using {default:?}");
                default
            })
        };
        let reconcile = parse(
            "reconcile",
            &settings.history.watch.reconcile,
            Duration::from_secs(600),
        );
        Self {
            limits: Limits {
                base: parse(
                    "debounce",
                    &settings.history.watch.debounce,
                    Duration::from_secs(2),
                ),
                max: parse(
                    "max_interval",
                    &settings.history.watch.max_interval,
                    Duration::from_secs(24 * 3600),
                ),
            },
            reconcile: (!reconcile.is_zero()).then_some(reconcile),
        }
    }
}

/// The tracked set, its watch plan, and the filters applied to events.
struct State {
    /// The declared set, what captures walk.
    tracked: TrackedSet,
    /// The declared set plus derived entries, what is watched.
    watched: TrackedSet,
    /// Links inside tracked directories seen by a walk (a link whose target
    /// is missing now derives nothing, but still declares where it points,
    /// wherever that is by now).
    tracked_links: Vec<PathBuf>,
    plan: WatchPlan,
    exclude: ExcludeSet,
    hard: Vec<PathBuf>,
    config_dir: PathBuf,
}

impl State {
    async fn load() -> Result<Self> {
        let tracked = TrackedSet::effective().await?;
        Self::from_tracked(tracked)
    }

    fn from_tracked(tracked: TrackedSet) -> Result<Self> {
        let exclude = tracked.exclude_set()?;
        let (watched, tracked_links) = watched_set(&tracked)?;
        let plan = build_plan(&watched);
        Ok(Self {
            tracked,
            watched,
            tracked_links,
            plan,
            exclude,
            hard: hard_exclusions(),
            config_dir: normalize(&tracked::global_config_dir()),
        })
    }

    /// Reloads the configuration; `Ok(false)` when history was disabled.
    async fn reload(&mut self) -> Result<bool> {
        crate::host::reload_config().await?;
        if !Settings::get().history.enabled {
            return Ok(false);
        }
        let tracked = TrackedSet::effective().await?;
        let mut fresh = Self::from_tracked(tracked)?;
        // a link whose target is between two versions derives nothing
        // right now; the link is remembered while it is one, and consulted
        // for where it points now (it may have been retargeted meanwhile)
        for link in self.tracked_links.drain(..) {
            if link.is_symlink() && !fresh.tracked_links.contains(&link) {
                fresh.tracked_links.push(link);
            }
        }
        *self = fresh;
        Ok(true)
    }

    /// A change to a mise configuration file: the tracked set and the
    /// settings may differ now.
    fn is_config_file(&self, path: &Path) -> bool {
        path.starts_with(&self.config_dir)
            && (path.extension().is_some_and(|ext| ext == "toml")
                || path
                    .components()
                    .any(|component| component.as_os_str() == "conf.d"))
    }

    /// Whether a change to `path` is one the watcher saves: under a
    /// declared or derived entry (a symlink target inside the home
    /// directory), autosaved, and not excluded.
    fn relevant(&self, path: &Path) -> bool {
        if self.hard.iter().any(|dir| path.starts_with(dir)) {
            return false;
        }
        if path
            .components()
            .any(|component| component.as_os_str() == ".git")
        {
            return false;
        }
        // exclusion is read relative to the entry that owns the path, so
        // the owner is found first
        self.watched
            .entry_for(path)
            .is_some_and(|entry| entry.policy.autosave)
            && !self
                .watched
                .excluded_by_lists(&self.exclude, path, tracked::Asked::Possibly)
    }

    /// Whether a path that does not exist right now may still be one the
    /// watcher saves once it is back: under a declared autosave entry, or
    /// where a tracked symlink (through any links on the way) points, its
    /// target between two versions, say. A path nothing declares for
    /// automatic saving any more is not kept for being missing.
    fn may_cover_missing(&self, path: &Path) -> bool {
        if self.hard.iter().any(|dir| path.starts_with(dir)) {
            return false;
        }
        (self
            .watched
            .entry_for(path)
            .is_some_and(|entry| entry.policy.autosave)
            && !self
                .watched
                .excluded_by_lists(&self.exclude, path, tracked::Asked::Possibly))
            || (self.tracked.entry_for(path).is_some_and(|entry| {
                entry.policy.autosave
                    && !tracked::is_refused_root(&entry.path, &normalize(&mise_util::dirs::HOME))
            }) && !self.tracked.excluded_by_lists(
                &self.exclude,
                path,
                tracked::Asked::Possibly,
            ))
    }
}

/// The declared entries the watcher plans and filters by, plus the tracked
/// links themselves so dangling links remain observable. Targets are not enrolled.
fn watched_set(tracked: &TrackedSet) -> Result<(TrackedSet, Vec<PathBuf>)> {
    let walk = tracked.walk()?;
    // Keep scan diagnostics from detached startup and reload walks.
    // Capture warnings belong to the save path, after the snapshot is durable.
    for warning in &walk.warnings {
        let message = format!("history: {warning}");
        if let Err(err) = crate::history::notices::record(&message) {
            warn!("{message}");
            debug!("history: could not keep the notice: {err}");
        }
    }
    // Rediscover dangling links on startup without enrolling their targets.
    let links = walk
        .files
        .keys()
        .filter(|path| path.is_symlink())
        .cloned()
        .collect();
    let mut watched = tracked.clone();
    // an entry the walker refuses (the home directory or above) captures
    // nothing, so it is not watched either: a watch there would schedule
    // the whole tree for captures that cannot store it
    let home = normalize(&mise_util::dirs::HOME);
    watched.entries = walk
        .entries
        .into_iter()
        .filter(|entry| !tracked::is_refused_root(&entry.path, &home))
        .collect();
    Ok((watched, links))
}

fn build_plan(tracked: &TrackedSet) -> WatchPlan {
    let paths = tracked
        .entries
        .iter()
        .filter(|entry| entry.policy.autosave)
        .map(|entry| {
            let kind = match std::fs::symlink_metadata(&entry.path) {
                Ok(meta) if meta.is_dir() => PathKind::Directory,
                Ok(_) => PathKind::File,
                Err(_) => PathKind::Missing,
            };
            (entry.path.clone(), kind)
        });
    // Observe configuration changes even when configuration is not enrolled.
    // This anchor only reloads policy; capture still uses the explicit set.
    let config_dir = normalize(&tracked::global_config_dir());
    let config_kind = if config_dir.is_dir() {
        PathKind::Directory
    } else {
        PathKind::Missing
    };
    WatchPlan::build(paths.chain([(config_dir, config_kind)]), |path| {
        path.ancestors()
            .skip(1)
            .find(|ancestor| ancestor.is_dir())
            .map(Path::to_path_buf)
    })
}

/// Installs the plan's anchors, removing the ones no longer wanted.
/// Returns the anchors now installed.
/// History was switched off while the watcher ran: what is still pending
/// is saved under the set that was in force, like any stop.
async fn stop_disabled(capture: &mut Capture, tracked: &TrackedSet) {
    capture
        .out
        .emit("disabled", "history was disabled; stopping", json!({}));
    finish(capture, tracked, Restart::Final).await;
}

/// The timing settings as they are now, after a reload of the
/// configuration: the schedule's limits and the reconciliation timer follow
/// an edit to `history.watch.*` without a restart.
fn apply_intervals(
    capture: &mut Capture,
    intervals: &mut Intervals,
    next_reconcile: &mut Option<tokio::time::Instant>,
) {
    let fresh = Intervals::from_settings(&Settings::get());
    if fresh.limits != *capture.schedule.limits() {
        capture.schedule.set_limits(fresh.limits.clone());
    }
    if fresh.reconcile != intervals.reconcile {
        *next_reconcile = fresh
            .reconcile
            .map(|every| tokio::time::Instant::now() + every);
    }
    *intervals = fresh;
}

/// The synchronization plan as the configuration says now (the origin or
/// the mode may have changed), adjusted rather than rebuilt: a pending
/// publication or fetch keeps its deadline unless what it depends on changed.
fn refresh_sync_plan(capture: &mut Capture, now: Instant) {
    let fresh = SyncConfig::from_settings(&Settings::get());
    capture.sync = match (capture.sync.take(), fresh) {
        (Some(mut plan), Some(fresh)) => {
            plan.reconfigure(fresh, now);
            Some(plan)
        }
        (_, fresh) => fresh.map(|config| SyncPlan::new(config, now)),
    };
}

/// Drops from the schedule what the tracked set no longer covers (excluded,
/// untracked, switched to manual saving, a link's old target): no capture
/// from now on holds it or carries its old version forward. A path that is
/// missing right now keeps its throttling while something still declares
/// it.
fn prune_schedule(capture: &mut Capture, state: &State) {
    capture
        .schedule
        .retain(|path| state.relevant(path) || (!path.exists() && state.may_cover_missing(path)));
    capture.persist_schedule();
}

/// Every watch anew: the one on a directory that was replaced or recreated
/// keeps its path but is dead, and only a fresh watch on the new inode
/// delivers events again.
fn reinstall(
    debouncer: &mut Debouncer<RecommendedWatcher, NoCache>,
    installed: &[Anchor],
    wanted: &[Anchor],
    capture: &mut Capture,
) -> Result<Vec<Anchor>> {
    for anchor in installed {
        if let Err(err) = debouncer.unwatch(&anchor.path) {
            debug!("history watch: unwatch {}: {err}", anchor.path.display());
        }
    }
    install(debouncer, &[], wanted, capture)
}

fn install(
    debouncer: &mut Debouncer<RecommendedWatcher, NoCache>,
    installed: &[Anchor],
    wanted: &[Anchor],
    capture: &mut Capture,
) -> Result<Vec<Anchor>> {
    let mut current: Vec<Anchor> = vec![];
    capture
        .health
        .watcher
        .degraded
        .retain(|line| line.starts_with(crate::history::health::PERMISSION_DEGRADED_PREFIX));
    for anchor in installed {
        if wanted.contains(anchor) {
            current.push(anchor.clone());
        } else if let Err(err) = debouncer.unwatch(&anchor.path) {
            debug!("history watch: unwatch {}: {err}", anchor.path.display());
        }
    }
    for anchor in wanted {
        if current.contains(anchor) {
            continue;
        }
        let mode = match anchor.mode {
            Mode::Recursive => RecursiveMode::Recursive,
            Mode::Flat => RecursiveMode::NonRecursive,
        };
        match debouncer.watch(&anchor.path, mode) {
            Ok(()) => current.push(anchor.clone()),
            Err(err) if matches!(err.kind, notify::ErrorKind::MaxFilesWatch) => {
                if current.is_empty() {
                    bail!(
                        "cannot watch {}: the system's watch limit is reached (on Linux raise fs.inotify.max_user_watches)",
                        display_path(&anchor.path)
                    );
                }
                let message = format!(
                    "cannot watch {}: the system's watch limit is reached; reconciliation still saves it (on Linux raise fs.inotify.max_user_watches)",
                    display_path(&anchor.path)
                );
                capture.health.watcher.degraded.push(message.clone());
                capture.out.emit(
                    "degraded",
                    &message,
                    json!({ "path": display_path(&anchor.path) }),
                );
            }
            Err(err) => {
                let message = format!(
                    "cannot watch {}: {err}; reconciliation still saves it",
                    display_path(&anchor.path)
                );
                capture.health.watcher.degraded.push(message.clone());
                capture.out.emit(
                    "degraded",
                    &message,
                    json!({ "path": display_path(&anchor.path), "message": err.to_string() }),
                );
            }
        }
    }
    // nothing watched while something should be: no event would ever
    // arrive, so the caller stops (and the service restarts it) instead of
    // running blind until a reconciliation that may be disabled
    if current.is_empty() && !wanted.is_empty() {
        bail!("no watch could be installed for the tracked set");
    }
    capture.anchor_ids = current
        .iter()
        .filter_map(|anchor| {
            file_id::get_file_id(&anchor.path)
                .ok()
                .map(|id| (anchor.path.clone(), id))
        })
        .collect();
    Ok(current)
}

fn anchor_replaced(
    ids: &std::collections::BTreeMap<PathBuf, file_id::FileId>,
    path: &Path,
) -> bool {
    ids.get(path)
        .is_some_and(|before| file_id::get_file_id(path).ok().as_ref() != Some(before))
}

/// Captures with the operation lock respected, failures backed off, the
/// per-path schedule applied, and health persisted.
struct Capture {
    store: Store,
    out: Output,
    schedule: Schedule,
    health: Health,
    /// Automatic synchronization, when an origin is connected and the mode
    /// allows any.
    sync: Option<SyncPlan>,
    /// Checkpoints waiting for `history.describe_command`, oldest first;
    /// past the bound the oldest is skipped, and said so.
    describe_next: std::collections::VecDeque<store::Entry>,
    backoff: Duration,
    retry_at: Option<Instant>,
    /// Why the last attempt did not run, while a retry is pending.
    retry_kind: Option<Attempt>,
    anchor_ids: std::collections::BTreeMap<PathBuf, file_id::FileId>,
}

impl Capture {
    fn new(store: Store, out: Output, limits: Limits) -> Self {
        let mut schedule = Schedule::new(limits);
        let persisted: PersistedSchedule =
            std::fs::read_to_string(schedule_path_in(store.state_dir()))
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default();
        let now = Instant::now();
        let now_epoch = epoch_secs();
        schedule.restore(&persisted, now, now_epoch);
        // a throttled file rewritten while the watcher was down has a change
        // pending: held until its next save is due, like any other
        for (path, record) in &persisted.paths {
            let path = PathBuf::from(path);
            let Some(saved) = record.saved_epoch_secs else {
                continue;
            };
            let changed_since = std::fs::symlink_metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                // not strictly after: both are whole seconds, and a change
                // in the same second as the save must count as pending (a
                // false positive only holds the file until its save is due)
                .is_some_and(|modified| modified.as_secs() >= saved);
            if changed_since && schedule.get(&path).is_some_and(|s| !s.pending()) {
                schedule.mark_pending(path, now);
            }
        }
        let health = health::read(store.state_dir()).unwrap_or_default();
        Self {
            store,
            out,
            schedule,
            health,
            backoff: BACKOFF_MIN,
            retry_at: None,
            retry_kind: None,
            anchor_ids: Default::default(),
            sync: SyncPlan::from_settings(&Settings::get(), Instant::now()),
            describe_next: std::collections::VecDeque::new(),
        }
    }

    /// When a deferred or failed capture is retried, if one is pending.
    fn retry_due(&self) -> Option<Instant> {
        self.retry_kind.and(self.retry_at)
    }

    /// A whole-set capture (a reconcile or rescan) that respects the
    /// schedule: held paths are carried forward, and the paths that were due
    /// count as saved so they are not saved again at their own deadline.
    fn reconcile(&mut self, tracked: &TrackedSet, reason: &str) -> Attempt {
        let now = Instant::now();
        let held = self.schedule.held_paths(now);
        let due = self.schedule.due_paths(now);
        let outcome = self.attempt(tracked, reason, &held);
        if outcome == Attempt::Done {
            self.health.watcher.last_reconcile = Some(store::now_rfc3339());
            for path in &due {
                self.schedule.saved(path, now);
            }
            self.schedule.prune(now);
            self.persist_schedule();
        }
        outcome
    }

    /// A flush deadline no earlier than the current backoff allows.
    fn not_before(&self, at: Instant) -> Instant {
        match self.retry_at {
            Some(retry) if retry > at => retry,
            _ => at,
        }
    }

    /// Saves a checkpoint of the tracked set, with `held` paths carried
    /// forward from the newest checkpoint instead of read live. Returns
    /// whether the attempt ran (a deferred or failed attempt leaves its
    /// paths pending).
    fn attempt(&mut self, tracked: &TrackedSet, reason: &str, held: &[PathBuf]) -> Attempt {
        if let Some(retry) = self.retry_at
            && Instant::now() < retry
        {
            return self.retry_kind.unwrap_or(Attempt::Failed);
        }
        let operation =
            match LockFile::at(&store::operation_lock_in(self.store.state_dir())).try_lock() {
                Ok(Some(lock)) => lock,
                Ok(None) => {
                    self.out.emit(
                        "deferred",
                        "another history operation is running; saving afterwards",
                        json!({ "reason": reason }),
                    );
                    self.retry_at = Some(Instant::now() + BACKOFF_MIN);
                    self.retry_kind = Some(Attempt::Deferred);
                    return Attempt::Deferred;
                }
                Err(err) => {
                    self.fail(reason, &format!("{err:#}"));
                    return Attempt::Failed;
                }
            };
        let mut draft = Draft::new(Trigger::Edit);
        draft.held = held.to_vec();
        let result = self.store.attempt(tracked, draft);
        drop(operation);
        match result {
            Ok(Outcome::Created(entry)) => {
                self.recovered();
                if let Some(plan) = &mut self.sync {
                    plan.saved(Instant::now());
                }
                if describe_command::configured().is_some() {
                    self.describe_next.push_back((*entry).clone());
                    if self.describe_next.len() > DESCRIBE_QUEUE
                        && let Some(skipped) = self.describe_next.pop_front()
                    {
                        self.out.emit(
                            "describe-skipped",
                            &format!(
                                "history.describe_command is behind; checkpoint {} keeps its computed description",
                                skipped.id
                            ),
                            json!({ "id": skipped.id }),
                        );
                    }
                }
                self.health.watcher.last_capture = Some(store::now_rfc3339());
                self.out.emit(
                    "captured",
                    &format!(
                        "saved checkpoint {} ({reason}): {}",
                        entry.id, entry.checkpoint.description
                    ),
                    json!({ "id": entry.id, "uuid": entry.checkpoint.uuid, "description": entry.checkpoint.description, "reason": reason }),
                );
                self.retry_kind = None;
                Attempt::Done
            }
            Ok(Outcome::Unchanged) => {
                self.recovered();
                self.health.watcher.last_capture = Some(store::now_rfc3339());
                self.out.emit(
                    "unchanged",
                    &format!("nothing to save ({reason})"),
                    json!({ "reason": reason }),
                );
                self.retry_kind = None;
                Attempt::Done
            }
            Ok(Outcome::Unavailable(message)) => {
                self.fail(reason, &message);
                Attempt::Failed
            }
            Err(err) => {
                self.fail(reason, &format!("{err:#}"));
                Attempt::Failed
            }
        }
    }

    /// A sync failed: the next attempt after the backoff, recorded for
    /// `mise doctor` and `mise dot status`.
    fn sync_failed(&mut self, now: Instant) -> Duration {
        let Some(plan) = &mut self.sync else {
            return SYNC_BACKOFF_MIN;
        };
        let retry_in = plan.failed(now);
        // under the sync lock, changing only this; no wait: this is the event
        // loop, and an explicit sync or pull holding the lock writes its own
        // fresh record
        let until = rfc3339_in(retry_in);
        if let Err(err) =
            sync_run::update_status(self.store.state_dir(), Duration::ZERO, |status| {
                status.backoff_until = Some(until);
            })
        {
            debug!("history watch: could not record the sync backoff: {err}");
        }
        retry_in
    }

    fn sync_succeeded(&mut self, now: Instant) {
        if let Some(plan) = &mut self.sync {
            plan.succeeded(now);
        }
    }

    fn fail(&mut self, reason: &str, message: &str) {
        self.out.emit(
            "error",
            &format!(
                "could not save ({reason}): {message}; retrying in {:?}",
                self.backoff
            ),
            json!({ "reason": reason, "message": message, "retry_in_secs": self.backoff.as_secs() }),
        );
        self.retry_at = Some(Instant::now() + self.backoff);
        self.retry_kind = Some(Attempt::Failed);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        self.health.watcher.last_error = Some(message.to_string());
        self.health.watcher.last_error_at = Some(store::now_rfc3339());
        self.health.watcher.consecutive_failures += 1;
        self.write_health();
    }

    fn recovered(&mut self) {
        self.backoff = BACKOFF_MIN;
        self.retry_at = None;
        self.retry_kind = None;
        self.health.watcher.last_error = None;
        self.health.watcher.last_error_at = None;
        self.health.watcher.consecutive_failures = 0;
    }

    fn persist_schedule(&self) {
        let persisted = self.schedule.persist(Instant::now(), epoch_secs());
        let path = schedule_path_in(self.store.state_dir());
        if let Err(err) = store::write_json(&path, &persisted) {
            debug!("history watch: could not write {}: {err}", path.display());
        }
        // what `paths --noisy` lists
        let mut record = NoisyRecord::default();
        for (path, schedule) in self.schedule.throttled() {
            record.paths.insert(
                display_path(&path),
                NoisyPath {
                    interval_secs: schedule.interval.as_secs(),
                    pending_changes: schedule.changes,
                    last_seen: schedule
                        .last_seen
                        .map(|seen| rfc3339_ago(Instant::now().saturating_duration_since(seen)))
                        .unwrap_or_else(|| "unknown".into()),
                },
            );
        }
        let noisy = noisy_path_in(self.store.state_dir());
        if let Err(err) = noise::write(&noisy, &record) {
            debug!("history watch: could not write {}: {err}", noisy.display());
        }
    }

    fn write_health(&mut self) {
        // The store's capture is the authority on which paths are denied:
        // its permission subset replaces the one in memory, so a denial it
        // recorded after this watcher loaded appears and one it cleared does
        // not return. Every other degraded reason stays as it is in memory.
        if let Some(stored) = health::read(self.store.state_dir()) {
            let stored: Vec<String> = stored
                .watcher
                .degraded
                .into_iter()
                .filter(|line| health::permission_report_path(line).is_some())
                .collect();
            health::replace_permission_denials(&mut self.health.watcher.degraded, &stored);
        }
        let now = Instant::now();
        self.health.throttled = self
            .schedule
            .throttled()
            .into_iter()
            .map(|(path, schedule)| ThrottledPath {
                path: display_path(&path),
                interval_secs: schedule.interval.as_secs(),
                last_saved: schedule
                    .last_saved
                    .map(|saved| rfc3339_ago(now.saturating_duration_since(saved))),
                pending_changes: schedule.changes,
                heavy: schedule.interval >= schedule::HEAVY_INTERVAL,
            })
            .collect();
        if let Err(err) = health::write(self.store.state_dir(), &mut self.health) {
            debug!("history watch: could not write health: {err}");
        }
    }
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339_in(from_now: Duration) -> String {
    let at = chrono::Utc::now() + chrono::Duration::from_std(from_now).unwrap_or_default();
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn rfc3339_ago(ago: Duration) -> String {
    let at = chrono::Utc::now() - chrono::Duration::from_std(ago).unwrap_or_default();
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// JSON lines `Output` emitted on this thread, so a test reads the event a
// caller of `mise dot watch --json` reads without sharing process stdout.
#[cfg(test)]
thread_local! {
    static JSON_LINES: std::cell::RefCell<Vec<serde_json::Value>> =
        std::cell::RefCell::new(Vec::new());
}

#[derive(Clone, Copy)]
struct Output {
    json: bool,
}

impl Output {
    fn emit(&self, event: &str, message: &str, mut fields: serde_json::Value) {
        if self.json {
            if let Some(object) = fields.as_object_mut() {
                object.insert("event".into(), json!(event));
                object.insert("message".into(), json!(message));
                object.insert("at".into(), json!(store::now_rfc3339()));
            }
            use std::io::Write;
            #[cfg(test)]
            JSON_LINES.with(|lines| lines.borrow_mut().push(fields.clone()));
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{fields}");
            let _ = stdout.flush();
        } else {
            match event {
                "error" | "degraded" => warn!("history watch: {message}"),
                "unchanged" | "deferred" => debug!("history watch: {message}"),
                _ => info!("history watch: {message}"),
            }
        }
    }
}

/// Notices that the executable this watcher runs from was replaced, which
/// is what an upgrade does. The process keeps running the old code, and a
/// newer mise may write history state it cannot read, so every capture would
/// fail until someone restarted the service by hand.
struct BinaryWatch {
    path: Option<PathBuf>,
    started: Option<BinaryIdentity>,
    /// A changed identity seen on the previous check: an upgrade still
    /// writing the file is not acted on until it holds still.
    seen: Option<Option<BinaryIdentity>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Executable {
    /// The file is the one this process started from.
    Current,
    /// It differs or is missing, but has not held for two checks yet.
    Pending,
    /// A different file is there now; the service starts the new version.
    Replaced,
    /// Nothing is there. The service would start the same missing path, so
    /// the watcher keeps running and says so instead of stopping.
    Gone,
}

type BinaryIdentity = (u64, Option<std::time::SystemTime>, u64);

impl BinaryWatch {
    fn new() -> Self {
        // the path the service was started by can be a link an upgrade
        // retargets, which the resolved `current_exe` on Linux would miss
        let path = std::env::args_os()
            .next()
            .and_then(|arg0| {
                let arg0 = PathBuf::from(arg0);
                if arg0.is_absolute() {
                    arg0.is_file().then_some(arg0)
                } else {
                    which::which(&arg0).ok()
                }
            })
            .or_else(|| std::env::current_exe().ok());
        Self::at(path)
    }

    fn at(path: Option<PathBuf>) -> Self {
        let started = path.as_deref().and_then(Self::identity);
        Self {
            path,
            started,
            seen: None,
        }
    }

    fn identity(path: &Path) -> Option<BinaryIdentity> {
        let meta = std::fs::metadata(path).ok()?;
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(&meta);
        #[cfg(not(unix))]
        let inode = 0;
        Some((meta.len(), meta.modified().ok(), inode))
    }

    /// What became of the executable since this process started, once it
    /// has held for two checks in a row: an upgrade in flight leaves no file
    /// for a moment, or a half-written one.
    fn check(&mut self) -> Executable {
        let (Some(path), Some(started)) = (self.path.as_deref(), self.started) else {
            return Executable::Pending;
        };
        let now = Self::identity(path);
        if now == Some(started) {
            self.seen = None;
            return Executable::Current;
        }
        let settled = self.seen == Some(now);
        self.seen = Some(now);
        match (settled, now) {
            (false, _) => Executable::Pending,
            (true, Some(_)) => Executable::Replaced,
            (true, None) => Executable::Gone,
        }
    }
}

/// The lock a running watcher holds; `mise dot status` reads it.
pub(crate) fn watch_lock_in(state_dir: &Path) -> PathBuf {
    store::store_dir_in(state_dir).join("watch.lock")
}

pub fn noisy_path_in(state_dir: &Path) -> PathBuf {
    store::store_dir_in(state_dir).join("noisy.json")
}

pub(crate) fn schedule_path_in(state_dir: &Path) -> PathBuf {
    store::store_dir_in(state_dir).join("watch-schedule.json")
}

/// Whether a watcher currently holds the lock for this store.
pub fn is_running(state_dir: &Path) -> bool {
    matches!(LockFile::at(&watch_lock_in(state_dir)).try_lock(), Ok(None))
}

struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
}

impl Shutdown {
    fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            #[cfg(unix)]
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
            #[cfg(windows)]
            ctrl_break: tokio::signal::windows::ctrl_break()?,
        })
    }

    async fn wait(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = self.terminate.recv() => {}
                _ = self.hangup.recv() => {}
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = self.ctrl_break.recv() => {}
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::files::{FileMode, FilePolicy};
    use crate::history::tracked::TrackedEntry;

    #[test]
    fn a_replaced_executable_is_noticed_once_it_holds_still() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("mise");
        std::fs::write(&exe, "old").unwrap();
        let mut watch = BinaryWatch::at(Some(exe.clone()));
        assert_eq!(watch.check(), Executable::Current);
        // an upgrade replaces the file by renaming a new one over it
        let staged = dir.path().join("mise.new");
        std::fs::write(&staged, "a newer version").unwrap();
        std::fs::rename(&staged, &exe).unwrap();
        assert_eq!(
            watch.check(),
            Executable::Pending,
            "the first sighting is not acted on"
        );
        assert_eq!(watch.check(), Executable::Replaced);
    }

    #[test]
    fn a_missing_executable_is_reported_gone_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("mise");
        std::fs::write(&exe, "old").unwrap();
        let mut watch = BinaryWatch::at(Some(exe.clone()));
        std::fs::remove_file(&exe).unwrap();
        assert_eq!(
            watch.check(),
            Executable::Pending,
            "an upgrade in flight leaves none for a moment"
        );
        assert_eq!(watch.check(), Executable::Gone);
        assert_eq!(BinaryWatch::at(None).check(), Executable::Pending);
    }

    #[test]
    fn a_new_nested_repository_stops_watcher_capture_and_holds() {
        let temp = tempfile::tempdir().unwrap();
        let parent = normalize(temp.path());
        let nested = parent.join("checkout");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("config.txt");
        std::fs::write(&file, "local").unwrap();
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut tracked = TrackedSet::default();
        tracked.push(TrackedEntry::new(parent, "track", policy));
        let state = State::from_tracked(tracked.clone()).unwrap();
        assert!(state.relevant(&file));
        std::fs::create_dir(nested.join(".git")).unwrap();
        assert!(!state.relevant(&file));
        assert!(!state.relevant(&nested));
        std::fs::remove_file(&file).unwrap();
        assert!(!state.may_cover_missing(&file));
        tracked.push(TrackedEntry::new(nested, "track", policy));
        let explicit = State::from_tracked(tracked).unwrap();
        assert!(explicit.may_cover_missing(&file));
    }

    #[test]
    fn unfinished_reconciliation_preserves_success_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        let mut capture = Capture::new(
            store,
            Output { json: false },
            Limits {
                base: Duration::from_secs(2),
                max: Duration::from_secs(86400),
            },
        );
        let tracked = TrackedSet {
            entries: vec![],
            manifest: Default::default(),
            declarations: None,
            disabled: vec![],
            required_sources: vec![],
            exclude: vec![],
            invalid: vec![],
            invalid_local: vec![],
            local: vec![],
            private_exclude: vec![],
            unselected: Default::default(),
        };
        capture.health.watcher.last_reconcile = Some("previous success".into());
        capture.retry_at = Some(Instant::now() + Duration::from_secs(60));
        for outcome in [Attempt::Deferred, Attempt::Failed] {
            capture.retry_kind = Some(outcome);
            assert_eq!(capture.reconcile(&tracked, "watches updated"), outcome);
            assert_eq!(
                capture.health.watcher.last_reconcile.as_deref(),
                Some("previous success")
            );
        }
    }

    #[test]
    fn parent_activity_is_not_an_anchor_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = dir.path().join("anchor");
        std::fs::create_dir(&anchor).unwrap();
        let ids = [(anchor.clone(), file_id::get_file_id(&anchor).unwrap())]
            .into_iter()
            .collect();
        std::fs::write(anchor.join("unrelated"), "activity").unwrap();
        assert!(!anchor_replaced(&ids, &anchor));
        std::fs::rename(&anchor, dir.path().join("old")).unwrap();
        assert!(anchor_replaced(&ids, &anchor));
        std::fs::create_dir(&anchor).unwrap();
        assert!(anchor_replaced(&ids, &anchor));
    }

    #[test]
    fn dangling_links_do_not_enroll_their_missing_targets() {
        let dir = tempfile::tempdir().unwrap();
        let root = normalize(dir.path());
        let tracked_dir = root.join("tracked");
        std::fs::create_dir(&tracked_dir).unwrap();
        let link = tracked_dir.join("link");
        let target = root.join("missing");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let tracked = TrackedSet {
            required_sources: vec![],
            manifest: Default::default(),
            declarations: None,
            disabled: vec![],
            entries: vec![TrackedEntry::new(
                tracked_dir,
                "track",
                FilePolicy::for_mode(FileMode::Track),
            )],
            exclude: vec![],
            invalid: vec![],
            invalid_local: vec![],
            local: vec![],
            private_exclude: vec![],
            unselected: Default::default(),
        };
        let state = State::from_tracked(tracked.clone()).unwrap();
        assert!(state.tracked_links.contains(&link));
        assert!(!state.may_cover_missing(&target));
        let mut excluded = tracked;
        excluded.exclude.push(link.to_string_lossy().into_owned());
        assert!(
            !State::from_tracked(excluded)
                .unwrap()
                .may_cover_missing(&target)
        );
    }

    fn state_of(tracked: TrackedSet, config_dir: PathBuf) -> State {
        State {
            watched: tracked.clone(),
            tracked_links: vec![],
            plan: build_plan(&tracked),
            exclude: tracked.exclude_set().unwrap(),
            hard: vec![],
            config_dir,
            tracked,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_path_keeps_its_schedule_only_while_something_declares_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = normalize(dir.path());
        let hypr = root.join("hypr");
        std::fs::create_dir_all(&hypr).unwrap();
        // a tracked link whose target, through another link, is between
        // two versions
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("hop"), &link).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/target"), root.join("hop")).unwrap();
        let policy = FilePolicy::for_mode(FileMode::Track);
        let mut tracked = TrackedSet {
            required_sources: vec![],
            manifest: Default::default(),
            declarations: None,
            disabled: vec![],
            entries: vec![
                TrackedEntry::new(hypr.clone(), "track", policy),
                TrackedEntry::new(link.clone(), "track", policy),
            ],
            exclude: vec![format!("{}/hypr/plugins/**", root.display())],
            invalid: vec![],
            invalid_local: vec![],
            local: vec![],
            private_exclude: vec![],
            unselected: Default::default(),
        };
        let state = state_of(tracked.clone(), root.join("mise"));
        assert!(state.may_cover_missing(&hypr.join("bindings.lua")));
        assert!(!state.may_cover_missing(&root.join("elsewhere/target")));
        assert!(!state.may_cover_missing(&hypr.join("plugins/state.json")));
        assert!(!state.may_cover_missing(&root.join("untracked/state.json")));

        // a link inside the tracked directory whose target went missing:
        // remembered from the last walk while the link still points there
        let inner = hypr.join("inner-link");
        std::os::unix::fs::symlink(root.join("elsewhere/inner"), &inner).unwrap();
        let mut remembered = state_of(tracked.clone(), root.join("mise"));
        remembered.tracked_links = vec![inner.clone()];
        assert!(!remembered.may_cover_missing(&root.join("elsewhere/inner")));
        // retargeted while its new target is missing: the new target is
        // what it declares now, the old one no longer
        std::fs::remove_file(&inner).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/moved"), &inner).unwrap();
        assert!(!remembered.may_cover_missing(&root.join("elsewhere/moved")));
        assert!(!remembered.may_cover_missing(&root.join("elsewhere/inner")));
        std::fs::remove_file(&inner).unwrap();
        assert!(!remembered.may_cover_missing(&root.join("elsewhere/moved")));

        // untracked, or switched to manual saving: nothing keeps it
        tracked.entries[0].policy.autosave = false;
        tracked.entries.pop();
        let state = state_of(tracked, root.join("mise"));
        assert!(!state.may_cover_missing(&hypr.join("bindings.lua")));
        assert!(!state.may_cover_missing(&root.join("elsewhere/target")));
    }
}

#[cfg(test)]
mod sync_plan_tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn config(mode: SyncMode, publish_after: u64, fetch_every: u64) -> SyncConfig {
        SyncConfig {
            automatic: mode.automatic(),
            publish_after: secs(publish_after),
            fetch_every: secs(fetch_every),
            origin: ("file:///setup.git".to_string(), "main".to_string()),
        }
    }

    #[test]
    fn a_reload_that_changes_nothing_keeps_the_deadlines() {
        let start = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.saved(start);
        let retry = plan.failed(start + secs(1));
        let (publish, fetch, backoff) = (plan.next_publish, plan.next_fetch, plan.backoff);
        assert_eq!(fetch, Some(start + secs(1) + retry));
        plan.reconfigure(config(SyncMode::Sync, 300, 900), start + secs(5));
        assert_eq!(plan.next_publish, publish);
        assert_eq!(plan.next_fetch, fetch);
        assert_eq!(plan.backoff, backoff);
    }

    #[test]
    fn zero_fetch_interval_cannot_spin_or_disable_failure_backoff() {
        let now = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 0), now);
        assert_eq!(plan.next_fetch, Some(now + secs(1)));
        assert_eq!(plan.failed(now), secs(1));
        assert_eq!(plan.failed(now + secs(1)), secs(2));
        plan.reconfigure(config(SyncMode::Sync, 300, 0), now);
        plan.succeeded(now);
        assert_eq!(plan.next_fetch, Some(now + secs(1)));
    }

    #[test]
    fn sync_completion_preserves_saves_made_in_flight() {
        let now = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), now);
        plan.next_publish = None; // consumed by start_sync
        plan.saved(now + secs(1));
        plan.succeeded(now + secs(2));
        assert_eq!(plan.next_publish, Some(now + secs(301)));
    }

    #[test]
    fn fetch_only_drops_the_pending_publication() {
        let start = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.saved(start);
        let fetch = plan.next_fetch;
        plan.reconfigure(config(SyncMode::FetchOnly, 300, 900), start + secs(5));
        assert_eq!(plan.next_publish, None);
        assert_eq!(plan.next_fetch, fetch);
        // and a save in fetch-only mode schedules nothing
        plan.saved(start + secs(6));
        assert_eq!(plan.next_publish, None);
    }

    #[test]
    fn a_shorter_fetch_interval_brings_the_next_fetch_forward_a_longer_one_does_not_delay_it() {
        let start = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.succeeded(start);
        let due = plan.next_fetch.expect("a successful sync arms a fetch");
        let wait = due.saturating_duration_since(start);
        assert!(
            wait >= secs(810) && wait <= secs(990),
            "fetch wait {wait:?} outside \u{00b1}10% of 900s"
        );
        plan.reconfigure(config(SyncMode::Sync, 300, 2), start + secs(5));
        assert_eq!(plan.next_fetch, Some(start + secs(7)));
        plan.reconfigure(config(SyncMode::Sync, 300, 900), start + secs(6));
        assert_eq!(plan.next_fetch, Some(start + secs(7)));
    }

    #[test]
    fn a_shorter_publish_delay_brings_a_pending_publication_forward() {
        let start = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.reconfigure(config(SyncMode::Sync, 1, 900), start + secs(1));
        // nothing saved: a new delay arms nothing
        assert_eq!(plan.next_publish, None);
        plan.saved(start + secs(2));
        assert_eq!(plan.next_publish, Some(start + secs(3)));
        plan.reconfigure(config(SyncMode::Sync, 300, 900), start + secs(2));
        assert_eq!(plan.next_publish, Some(start + secs(3)));
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.saved(start);
        plan.reconfigure(config(SyncMode::Sync, 1, 900), start + secs(2));
        assert_eq!(plan.next_publish, Some(start + secs(3)));
    }

    #[test]
    fn enabling_fetch_arms_the_first_fetch() {
        let start = Instant::now();
        let mut publish_only = config(SyncMode::Sync, 300, 900);
        publish_only.automatic.fetch = false;
        let mut plan = SyncPlan::new(publish_only, start);
        assert_eq!(plan.next_fetch, None);
        plan.reconfigure(config(SyncMode::Sync, 300, 900), start + secs(5));
        assert_eq!(plan.next_fetch, Some(start + secs(5) + SYNC_FIRST_FETCH));
    }

    #[test]
    fn another_origin_starts_afresh() {
        let start = Instant::now();
        let mut plan = SyncPlan::new(config(SyncMode::Sync, 300, 900), start);
        plan.saved(start);
        plan.failed(start);
        plan.failed(start + secs(60));
        assert!(plan.backoff > plan.backoff_floor());
        let mut moved = config(SyncMode::Sync, 300, 900);
        moved.origin.1 = "work".to_string();
        plan.reconfigure(moved, start + secs(100));
        assert_eq!(plan.backoff, plan.backoff_floor());
        assert_eq!(plan.next_publish, None);
        assert_eq!(plan.next_fetch, Some(start + secs(100) + SYNC_FIRST_FETCH));
    }
}

/// The JSON events `Output` wrote on this thread since the last read.
#[cfg(test)]
fn take_json_events() -> Vec<serde_json::Value> {
    JSON_LINES.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
}

/// Watcher pacing under contention and failure. These tests name the contract
/// the production path must meet; they fail against a watcher that treats a
/// held sync lock as a failure or retries on an exact shared delay.
#[cfg(test)]
mod sync_pacing {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn config(fetch_every: u64) -> SyncConfig {
        SyncConfig {
            automatic: SyncMode::Sync.automatic(),
            publish_after: secs(300),
            fetch_every: secs(fetch_every),
            origin: ("file:///setup.git".to_string(), "main".to_string()),
        }
    }

    fn plan_at(fetch_every: u64, now: Instant) -> SyncPlan {
        SyncPlan::new(config(fetch_every), now)
    }

    fn plan(fetch_every: u64) -> SyncPlan {
        plan_at(fetch_every, Instant::now())
    }

    /// Half of `full` through `full`, never above the backoff cap.
    fn within_jitter(sampled: Duration, full: Duration) {
        let capped = full.min(SYNC_BACKOFF_MAX);
        let low = capped / 2;
        assert!(
            sampled >= low && sampled <= capped,
            "sampled {sampled:?} outside [{low:?}, {capped:?}]"
        );
    }

    fn event_named<'a>(
        events: &'a [serde_json::Value],
        name: &str,
    ) -> Option<&'a serde_json::Value> {
        events
            .iter()
            .find(|event| event.get("event").and_then(|value| value.as_str()) == Some(name))
    }

    fn message_of(event: &serde_json::Value) -> &str {
        event
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
    }

    #[test]
    fn a_failure_delay_is_jittered_inside_half_of_its_exponential_value() {
        let now = Instant::now();
        let mut plan = plan(900);
        let mut full = plan.backoff;
        for step in 0..8 {
            let before = plan.backoff;
            let sampled = plan.failed(now + secs(step));
            within_jitter(sampled, full);
            // the sample is drawn from the base; it does not become the base
            assert_eq!(plan.backoff, (before * 2).min(SYNC_BACKOFF_MAX));
            assert_eq!(plan.next_fetch, Some(now + secs(step) + sampled));
            full = plan.backoff;
        }
        let capped = plan.failed(now + secs(8));
        within_jitter(capped, SYNC_BACKOFF_MAX);
        assert_eq!(plan.backoff, SYNC_BACKOFF_MAX);
    }

    #[test]
    fn the_same_failure_base_does_not_always_sample_the_same_delay() {
        let now = Instant::now();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..24 {
            let mut plan = plan(900);
            seen.insert(plan.failed(now));
        }
        assert!(
            seen.len() > 1,
            "twenty-four samples of a 60s base were identical: {seen:?}"
        );
        for sampled in &seen {
            within_jitter(*sampled, SYNC_BACKOFF_MIN);
        }
    }

    #[test]
    fn a_periodic_fetch_deadline_stays_within_ten_percent_of_fetch_every() {
        let every = secs(900);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..24 {
            let now = Instant::now();
            let mut plan = plan(900);
            plan.succeeded(now);
            let due = plan.next_fetch.expect("a successful sync arms a fetch");
            let wait = due.saturating_duration_since(now);
            assert!(
                wait >= every * 9 / 10 && wait <= every * 11 / 10,
                "fetch wait {wait:?} outside \u{00b1}10% of {every:?}"
            );
            seen.insert(wait);
        }
        assert!(
            seen.len() > 1,
            "twenty-four fetch deadlines were identical: {seen:?}"
        );
    }

    #[test]
    fn zero_fetch_interval_stays_exact_when_jitter_has_no_room() {
        let now = Instant::now();
        let mut plan = plan_at(0, now);
        assert_eq!(plan.next_fetch, Some(now + secs(1)));
        assert_eq!(plan.failed(now), secs(1));
        assert_eq!(plan.backoff, secs(2));
        assert_eq!(plan.failed(now + secs(1)), secs(2));
        assert_eq!(plan.backoff, secs(4));
        plan.reconfigure(config(0), now);
        plan.succeeded(now);
        assert_eq!(plan.next_fetch, Some(now + secs(1)));
        assert_eq!(plan.backoff, secs(1));
    }

    #[test]
    fn a_fractional_backoff_stays_inside_half_of_itself() {
        let full = Duration::from_millis(3000);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let sampled = jittered(full);
            assert!(
                sampled >= full / 2 && sampled <= full,
                "sampled {sampled:?} outside [{:?}, {full:?}]",
                full / 2
            );
            seen.insert(sampled);
        }
        assert!(seen.len() > 1, "sixty-four samples of 3s were identical");
    }

    #[test]
    fn a_fractional_fetch_interval_stays_within_ten_percent() {
        let every = Duration::from_millis(10_990);
        let low = every - every / 10;
        let high = every + every / 10;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let sampled = jittered_around(every);
            assert!(
                sampled >= low && sampled <= high,
                "sampled {sampled:?} outside [{low:?}, {high:?}]"
            );
            seen.insert(sampled);
        }
        assert!(
            seen.len() > 1,
            "sixty-four samples of 10.99s were identical"
        );
    }

    #[test]
    fn a_skip_retries_in_exactly_five_seconds_and_keeps_a_later_publication() {
        let now = Instant::now();
        let mut plan = plan_at(900, now);
        let base = plan.backoff;
        // the first fetch is fifteen seconds out, and this attempt has not
        // consumed it: a skip must not keep that later deadline
        plan.skipped(now);
        assert_eq!(plan.next_fetch, Some(now + SYNC_FOLLOW_UP));
        assert_eq!(plan.next_publish, None);
        assert_eq!(plan.backoff, base);

        // a save made while the sync ran, still in the future, keeps its deadline
        let mut plan = plan_at(900, now);
        plan.saved(now);
        plan.skipped(now + secs(1));
        assert_eq!(plan.next_fetch, Some(now + secs(1) + SYNC_FOLLOW_UP));
        assert_eq!(plan.next_publish, Some(now + secs(300)));

        // a publication already due must not start again the moment the skip ends
        let mut plan = plan_at(900, now);
        plan.next_publish = Some(now);
        plan.skipped(now + secs(1));
        assert_eq!(plan.next_publish, Some(now + secs(1) + SYNC_FOLLOW_UP));
        assert_eq!(plan.next_fetch, Some(now + secs(1) + SYNC_FOLLOW_UP));
    }

    #[test]
    fn reconfiguration_still_keeps_a_deadline_that_nothing_changed() {
        let start = Instant::now();
        let mut plan = plan(900);
        plan.saved(start);
        let retry = plan.failed(start + secs(1));
        let (publish, fetch, base) = (plan.next_publish, plan.next_fetch, plan.backoff);
        assert_eq!(fetch, Some(start + secs(1) + retry));
        plan.reconfigure(config(900), start + secs(5));
        assert_eq!(plan.next_publish, publish);
        assert_eq!(plan.next_fetch, fetch);
        assert_eq!(plan.backoff, base);
    }

    struct Fixture {
        capture: Capture,
        _dir: tempfile::TempDir,
    }

    fn capture(fetch_every: u64) -> Fixture {
        let _ = take_json_events();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in(dir.path()).unwrap();
        let mut capture = Capture::new(
            store,
            Output { json: true },
            Limits {
                base: Duration::from_secs(2),
                max: Duration::from_secs(86400),
            },
        );
        capture.sync = Some(plan(fetch_every));
        Fixture { capture, _dir: dir }
    }

    fn health_of(state_dir: &std::path::Path) -> crate::history::sync::run::SyncStatus {
        sync_run::read_status(state_dir).unwrap_or_default()
    }

    #[tokio::test]
    async fn a_held_sync_lock_is_skipped_without_touching_failure_health() {
        let mut fixture = capture(900);
        let capture = &mut fixture.capture;
        let state_dir = capture.store.state_dir().to_path_buf();
        let held = sync_run::lock_in(&state_dir).unwrap();
        sync_run::write_status(
            &state_dir,
            &crate::history::sync::run::SyncStatus {
                consecutive_failures: 2,
                failing_since: Some("2026-11-17T00:00:00Z".to_string()),
                last_error: Some("origin refused the push".to_string()),
                backoff_until: Some("2026-11-17T00:01:00Z".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let before = health_of(&state_dir);
        let base = capture.sync.as_ref().unwrap().backoff;
        let started = Instant::now();

        let applied = finish_sync(
            capture,
            &TrackedSet::default(),
            Err(sync_run::contended(&state_dir, None)),
        )
        .await;

        assert_eq!(
            applied,
            Some(false),
            "a held lock applies nothing and is not a failed sync"
        );
        let after = health_of(&state_dir);
        assert_eq!(after.consecutive_failures, before.consecutive_failures);
        assert_eq!(after.failing_since, before.failing_since);
        assert_eq!(after.last_error, before.last_error);
        assert_eq!(
            after.backoff_until, before.backoff_until,
            "a skip must not record a new backoff"
        );
        assert_eq!(capture.sync.as_ref().unwrap().backoff, base);
        let finished = Instant::now();
        let due = capture.sync.as_ref().unwrap().next_fetch.unwrap();
        let earliest = started + SYNC_FOLLOW_UP;
        let latest = finished + SYNC_FOLLOW_UP;
        assert!(
            due >= earliest && due <= latest,
            "retry {due:?} outside [{earliest:?}, {latest:?}]"
        );
        let events = take_json_events();
        let skipped =
            event_named(&events, "sync-skipped").expect("a contended sync emits sync-skipped");
        let holder = sync_run::contended(&state_dir, None).to_string();
        let pid = holder
            .split("pid ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ', ';']).next())
            .expect("the refusal names a pid");
        assert!(
            message_of(skipped).contains(pid),
            "the skip names the holder {pid}, got {skipped}"
        );
        assert!(
            event_named(&events, "sync-error").is_none(),
            "a held lock is not a sync-error: {events:?}"
        );
        drop(held);
    }

    #[tokio::test]
    async fn an_ordinary_sync_error_still_counts_as_a_failure() {
        let mut fixture = capture(900);
        let capture = &mut fixture.capture;
        let state_dir = capture.store.state_dir().to_path_buf();
        let seeded = crate::history::sync::run::SyncStatus {
            consecutive_failures: 2,
            failing_since: Some("2026-11-17T00:00:00Z".to_string()),
            last_error: Some("origin refused the push".to_string()),
            backoff_until: Some("2026-11-17T00:01:00Z".to_string()),
            ..Default::default()
        };
        sync_run::write_status(&state_dir, &seeded).unwrap();
        let before = Instant::now();

        let applied = finish_sync(
            capture,
            &TrackedSet::default(),
            Err(eyre::eyre!("origin refused the push")),
        )
        .await;

        assert_eq!(applied, None);
        // sync_locked records the failure; finish_sync only arms the retry
        // and must not invent a second counter
        let health = health_of(&state_dir);
        assert_eq!(health.consecutive_failures, seeded.consecutive_failures);
        assert_eq!(health.failing_since, seeded.failing_since);
        assert_eq!(health.last_error, seeded.last_error);
        assert_ne!(
            health.backoff_until, seeded.backoff_until,
            "an ordinary failure records when the retry is due"
        );
        let due = capture.sync.as_ref().unwrap().next_fetch.unwrap();
        let after = Instant::now();
        assert!(
            due >= before + SYNC_BACKOFF_MIN / 2 && due <= after + SYNC_BACKOFF_MIN,
            "retry {due:?} outside [{:?}, {:?}]",
            before + SYNC_BACKOFF_MIN / 2,
            after + SYNC_BACKOFF_MIN
        );
        assert_eq!(capture.sync.as_ref().unwrap().backoff, secs(120));
        let events = take_json_events();
        let error =
            event_named(&events, "sync-error").expect("an ordinary failure emits sync-error");
        assert!(
            message_of(error).contains("origin refused the push"),
            "{error}"
        );
    }

    #[test]
    fn write_health_takes_the_stores_denials_and_keeps_in_memory_watch_failures() {
        let mut fixture = capture(900);
        let capture = &mut fixture.capture;
        let state_dir = capture.store.state_dir().to_path_buf();
        let watch_failure = "cannot watch ~/other: limit reached".to_string();
        let denial =
            crate::history::health::permission_report("~/notes.toml", "Operation not permitted");
        capture.health.watcher.degraded = vec![watch_failure.clone()];

        // a capture recorded a denial after this watcher loaded its health
        let mut stored = crate::history::health::Health::default();
        stored.watcher.degraded = vec![denial.clone()];
        crate::history::health::write(&state_dir, &mut stored).unwrap();
        capture.write_health();
        let written = crate::history::health::read(&state_dir).unwrap();
        assert!(
            written.watcher.degraded.contains(&denial),
            "a denial recorded after the load was dropped: {written:?}"
        );
        assert!(
            written.watcher.degraded.contains(&watch_failure),
            "an in-memory watch failure was replaced: {written:?}"
        );

        // a later capture cleared it: the stale in-memory copy must not return
        let mut cleared = crate::history::health::Health::default();
        cleared.watcher.degraded = vec![];
        crate::history::health::write(&state_dir, &mut cleared).unwrap();
        capture.write_health();
        let after = crate::history::health::read(&state_dir).unwrap();
        assert!(
            after
                .watcher
                .degraded
                .iter()
                .all(|line| crate::history::health::permission_report_path(line).is_none()),
            "a cleared denial returned from memory: {after:?}"
        );
        assert!(
            after.watcher.degraded.contains(&watch_failure),
            "an in-memory watch failure was lost: {after:?}"
        );
    }

    #[test]
    fn a_refused_wait_keeps_its_text() {
        let temp = tempfile::tempdir().unwrap();
        let text = sync_run::contended(temp.path(), Some(Duration::from_secs(30))).to_string();
        assert!(
            text.contains("waited 30s and gave up"),
            "the waited refusal changed: {text}"
        );
        assert!(
            !text.contains("pass `--wait <duration>`"),
            "a waited refusal must not offer the immediate command: {text}"
        );
    }

    #[test]
    fn the_immediate_refusal_text_is_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let text = sync_run::contended(temp.path(), None).to_string();
        assert!(
            text.starts_with("another setup sync or pull is running: "),
            "{text}"
        );
        assert!(
            text.ends_with("; pass `--wait <duration>` to queue behind it, or stop the holder"),
            "{text}"
        );
    }
}
