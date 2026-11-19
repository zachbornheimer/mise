//! Background health, persisted under `$MISE_STATE_DIR/history/health.json`
//! by the watcher and read by `mise doctor` and `mise dot
//! status`. This is pull-based visibility: nothing here gets the user's
//! attention on its own. Readers distinguish stale information (the last
//! update is older than the watcher's reconcile period while a watcher
//! still holds the lock) from confirmed current health.

use std::path::{Path, PathBuf};

use eyre::Result;
use serde::{Deserialize, Serialize};

use super::store;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Health {
    /// When this record was written (RFC 3339).
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub watcher: WatcherHealth,
    /// Paths whose autosave interval is stretched by sustained churn.
    #[serde(default)]
    pub throttled: Vec<ThrottledPath>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WatcherHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_capture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<String>,
    /// The last capture failure, with when it happened; cleared by the
    /// next successful capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<String>,
    /// Consecutive capture failures.
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub degraded: Vec<String>,
    /// The mise executable this watcher started from is gone, so the
    /// process runs old code that only a service restart replaces. Not a
    /// degraded watch: captures still run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable_gone: bool,
}

/// What to tell the user when `WatcherHealth::executable_gone` is set.
pub const EXECUTABLE_GONE_ADVICE: &str = "the mise executable this watcher runs from is gone, so it keeps running the old version; run `mise bootstrap services apply` to restart it on the installed one";

/// What to tell the user when a watcher predates the executable replacement
/// check and cannot read a newer enrollment record.
pub const STALE_WATCHER_SCHEMA_ADVICE: &str = "the history watcher is running an older mise that cannot read current dotfile tracking metadata; run `mise bootstrap services apply` to restart it on the installed version";

/// What to tell the user when macOS denies a tracked folder to this binary.
/// Every release installs to a new path, so a previous grant does not cover it.
pub const MACOS_PRIVACY_HINT: &str = "on macOS, grant this mise binary access to that folder in System Settings > Privacy & Security";

/// The marker a denial report starts with, so a later readable capture can
/// clear these lines without touching an unrelated degraded reason.
pub const PERMISSION_DEGRADED_PREFIX: &str = "unreadable: ";

/// Whether `error` is the operating system refusing a read. Only `EPERM`
/// and `EACCES` are a partial capture; every other failure stays as it is.
pub fn is_permission_denied(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(nix::libc::EPERM | nix::libc::EACCES)
        )
    }
    #[cfg(not(unix))]
    {
        error.kind() == std::io::ErrorKind::PermissionDenied
    }
}

/// One denial, named once: the path, the operating-system error, and the
/// grant the binary needs before the next capture can read it.
pub fn permission_denial(path: &str, error: &std::io::Error) -> String {
    permission_report(path, &error.to_string())
}

/// What follows the hint, up to the path that ends every denial report.
const PERMISSION_PATH_MARKER: &str = "; path: ";

/// The same report from a denial a walk or a content read already recorded:
/// the operating-system error, the grant that fixes it, then the path last.
/// The path is last because it is the one part with no fixed shape: an error
/// text and a file name can both contain parentheses, and a fixed hint
/// followed by a fixed marker is the only boundary neither can imitate. The
/// path is matched whole, so `~/notes` does not hide `~/notes-other`.
pub fn permission_report(path: &str, reason: &str) -> String {
    format!(
        "{PERMISSION_DEGRADED_PREFIX}{reason}; {MACOS_PRIVACY_HINT}{PERMISSION_PATH_MARKER}{path}"
    )
}

/// The display path a denial report names, or nothing when `line` is another
/// degraded reason. The path is what follows the first hint and marker, so a
/// path or an error text that contains parentheses is read whole.
pub fn permission_report_path(line: &str) -> Option<&str> {
    let rest = line.strip_prefix(PERMISSION_DEGRADED_PREFIX)?;
    let after_hint = &rest[rest.find(MACOS_PRIVACY_HINT)? + MACOS_PRIVACY_HINT.len()..];
    after_hint.strip_prefix(PERMISSION_PATH_MARKER)
}

/// Replaces denial reports with `denied` and leaves every other degraded
/// reason where it was. An empty `denied` clears only the denial reports.
/// A path already named is kept once, compared as a path rather than a prefix.
pub fn replace_permission_denials(degraded: &mut Vec<String>, denied: &[String]) {
    degraded.retain(|line| permission_report_path(line).is_none());
    let mut seen = std::collections::BTreeSet::new();
    for line in denied {
        let Some(path) = permission_report_path(line) else {
            continue;
        };
        if seen.insert(path) {
            degraded.push(line.clone());
        }
    }
}

/// Whether a capture error came from a watcher whose enrollment schema
/// predates tracked-entry exclusions, includes, and plaintext selection.
///
/// This is deliberately narrower than every serde unknown-field error: a
/// future manifest must remain a capture failure, not an invitation to restart
/// a healthy current watcher. The old enrollment record had exactly these four
/// fields, so its error is enough to identify the recovery path.
pub fn is_stale_watcher_schema_error(error: &str) -> bool {
    let legacy_enrollment = ["path", "autosave", "encrypt", "variants"];
    let newer_field = ["exclude", "include", "allow_plaintext"];
    let unknown_field = |field: &str| {
        [
            format!("unknown field `{field}`"),
            format!("unknown field '{field}'"),
            format!("unknown field \"{field}\""),
        ]
        .iter()
        .any(|prefix| error.contains(prefix))
    };
    error.contains("unknown field")
        && error.contains("expected one of")
        && legacy_enrollment.iter().all(|field| error.contains(field))
        && newer_field.iter().any(|field| unknown_field(field))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThrottledPath {
    pub path: String,
    pub interval_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_saved: Option<String>,
    /// Changes seen since the last save.
    /// Changes seen since the last save (events, not verified content
    /// differences).
    pub pending_changes: u32,
    /// The interval reached the heavy-throttling mark.
    pub heavy: bool,
}

impl Health {
    /// The last capture failure of the watcher that wrote this record, if the
    /// capture after it has not succeeded. A watcher starts from the previous
    /// one's record, so an error from before this run started is inherited,
    /// not this watcher's failure.
    pub fn failing_capture(&self) -> Option<&str> {
        let watcher = &self.watcher;
        let error = watcher.last_error.as_deref()?;
        let parse = |at: &Option<String>| {
            at.as_deref()
                .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        };
        match (parse(&watcher.last_error_at), parse(&watcher.started_at)) {
            (Some(failed), Some(started)) if failed < started => None,
            _ => Some(error),
        }
    }
}

pub(crate) fn path_in(state_dir: &Path) -> PathBuf {
    store::store_dir_in(state_dir).join("health.json")
}

pub fn read(state_dir: &Path) -> Option<Health> {
    let text = std::fs::read_to_string(path_in(state_dir)).ok()?;
    serde_json::from_str(&text).ok()
}

pub(crate) fn write(state_dir: &Path, health: &mut Health) -> Result<()> {
    health.updated_at = store::now_rfc3339();
    store::write_json(&path_in(state_dir), health)
}

/// How old a record is, in seconds, if its timestamp parses.
pub fn age_secs(health: &Health) -> Option<u64> {
    let updated = chrono::DateTime::parse_from_rfc3339(&health.updated_at).ok()?;
    let age = chrono::Utc::now().signed_duration_since(updated);
    u64::try_from(age.num_seconds()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(started: Option<&str>, failed: Option<&str>) -> Health {
        Health {
            watcher: WatcherHealth {
                started_at: started.map(str::to_string),
                last_error: failed.map(|_| "boom".to_string()),
                last_error_at: failed.map(str::to_string),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_error_from_before_this_watcher_started_is_not_its_failure() {
        let started = "2026-09-29T22:10:00+00:00";
        let earlier = "2026-09-29T22:05:00+00:00";
        let later = "2026-09-29T22:15:00+00:00";
        assert_eq!(health(Some(started), Some(earlier)).failing_capture(), None);
        assert_eq!(
            health(Some(started), Some(later)).failing_capture(),
            Some("boom")
        );
        // without a start time to compare to, the error is reported
        assert_eq!(health(None, Some(earlier)).failing_capture(), Some("boom"));
        assert_eq!(health(Some(started), None).failing_capture(), None);
    }

    #[test]
    fn replacing_permission_denials_keeps_an_unrelated_reason() {
        let first = permission_report("~/Desktop/a", "Operation not permitted");
        let second = permission_report("~/Desktop/b", "Permission denied");
        let unrelated = "cannot watch ~/notes: limit reached".to_string();
        let mut degraded = vec![first, unrelated.clone()];
        replace_permission_denials(&mut degraded, std::slice::from_ref(&second));
        assert_eq!(degraded, vec![unrelated.clone(), second]);
        replace_permission_denials(&mut degraded, &[]);
        assert_eq!(degraded, vec![unrelated]);
    }

    #[test]
    fn a_report_names_its_path_whatever_parentheses_the_error_and_path_hold() {
        // a real operating-system error text carries its own parentheses
        let reason = std::io::Error::from_raw_os_error(13).to_string();
        assert!(reason.contains(" (os error 13)"), "{reason}");
        let path = "~/notes (work)/a (draft); path: b.toml";
        let line = permission_report(path, &reason);
        assert_eq!(permission_report_path(&line), Some(path));
        assert!(line.contains(MACOS_PRIVACY_HINT), "{line}");
        assert!(line.contains(&reason), "{line}");
        assert_eq!(permission_report_path("cannot watch ~/notes: limit"), None);
    }

    #[test]
    fn replacing_permission_denials_keeps_a_path_that_starts_with_another() {
        let shorter = permission_report("~/notes", "Permission denied");
        let longer = permission_report("~/notes-other", "Permission denied");
        let mut degraded = vec!["cannot watch ~/notes: limit reached".into()];
        replace_permission_denials(&mut degraded, &[shorter.clone(), longer.clone()]);
        assert!(degraded.iter().any(|line| line == &shorter));
        assert!(degraded.iter().any(|line| line == &longer));
        assert_eq!(
            degraded
                .iter()
                .filter(|line| permission_report_path(line).is_some())
                .count(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_eperm_and_eacces_are_a_permission_denial() {
        let denied = |code| std::io::Error::from_raw_os_error(code);
        assert!(is_permission_denied(&denied(nix::libc::EPERM)));
        assert!(is_permission_denied(&denied(nix::libc::EACCES)));
        assert!(!is_permission_denied(&denied(nix::libc::EIO)));
        assert!(!is_permission_denied(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "gone"
        )));
    }

    #[test]
    fn identifies_a_watcher_that_cannot_read_newer_enrollment_fields() {
        for field in ["exclude", "include", "allow_plaintext"] {
            let error = format!(
                "unknown field `{field}`, expected one of `path`, `autosave`, `encrypt`, `variants` at line 79 column 15"
            );
            assert!(is_stale_watcher_schema_error(&error), "{error}");
        }
        assert!(is_stale_watcher_schema_error(
            "unknown field \"exclude\", expected one of `path`, `autosave`, `encrypt`, `variants`"
        ));

        assert!(!is_stale_watcher_schema_error(
            "unknown field `future_field`, expected one of `path`, `autosave`, `encrypt`, `variants` at line 79 column 15"
        ));
        assert!(!is_stale_watcher_schema_error(
            "unknown field `future_field`, expected one of `path`, `autosave`, `encrypt`, `variants`; an include list was configured"
        ));
        assert!(!is_stale_watcher_schema_error(
            "unknown field `exclude`, expected one of `format`, `enrollment`, `recipients` at line 1 column 1"
        ));
    }
}
