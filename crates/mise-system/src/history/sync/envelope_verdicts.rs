//! Remembered publish-audit verdicts.
//!
//! Whether a blob is an acceptable envelope for a path depends only on the
//! blob's bytes, the path and the mode, and an object id is the hash of its
//! bytes. A verdict therefore never goes stale, so an audit that already
//! decided a (blob, path, mode) does not read that blob again, in this process
//! or a later one. A verdict holds no plaintext and no ciphertext.
//!
//! The file lives beside the history repository and is the user's own, like
//! the repository: it spares an audit work, it is not a defence against the
//! user editing their own history store.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::history::shadow::HistoryRepo;

/// The verdict file's entry cap: a file with more entries is not one this code
/// wrote, so it is treated as no verdicts.
const MAX_VERDICTS: usize = 1_048_576;
const FILE: &str = "index/envelope-verdicts.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Verdict {
    path: String,
    mode: String,
    accepted: bool,
}

/// The verdicts known to one audit, keyed by object id.
pub(super) struct EnvelopeVerdicts {
    file: Option<PathBuf>,
    known: BTreeMap<String, Verdict>,
    unsaved: bool,
}

impl EnvelopeVerdicts {
    /// The verdicts an earlier audit recorded for `repo`. A missing,
    /// unreadable, oversized or corrupt file is no verdicts, and an entry that
    /// does not parse is dropped.
    pub(super) fn load(repo: &HistoryRepo) -> Self {
        let file = repo.dir().parent().map(|parent| parent.join(FILE));
        let known = file.as_deref().and_then(read).unwrap_or_default();
        Self {
            file,
            known,
            unsaved: false,
        }
    }

    /// Whether the audit accepts `oid` as `path` in `mode`: the remembered
    /// verdict when it was recorded for this very path and mode, otherwise
    /// `decide`, whose answer is remembered.
    pub(super) fn accepted(
        &mut self,
        path: &str,
        mode: &str,
        oid: &str,
        decide: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        if let Some(known) = self
            .known
            .get(oid)
            .filter(|known| known.path == path && known.mode == mode)
        {
            return Ok(known.accepted);
        }
        let accepted = decide()?;
        if self.known.len() < MAX_VERDICTS || self.known.contains_key(oid) {
            self.known.insert(
                oid.to_string(),
                Verdict {
                    path: path.to_string(),
                    mode: mode.to_string(),
                    accepted,
                },
            );
            self.unsaved = true;
        }
        Ok(accepted)
    }

    /// Keep what this audit decided. A failed write is ignored: the next audit
    /// decides again, which is what it did before verdicts were remembered.
    pub(super) fn save(&mut self) {
        if self.unsaved && self.write().is_ok() {
            self.unsaved = false;
        }
    }

    fn write(&self) -> Result<()> {
        let Some(file) = &self.file else {
            return Ok(());
        };
        let dir = file.parent().expect("the verdict file has a directory");
        crate::history::store::create_private_dir(dir)?;
        let mut temporary = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer(temporary.as_file_mut(), &self.known)?;
        temporary.as_file().sync_all()?;
        mise_util::file::persist_atomic(temporary, file)?;
        Ok(())
    }
}

fn read(file: &std::path::Path) -> Option<BTreeMap<String, Verdict>> {
    let bytes = std::fs::read(file).ok()?;
    let raw: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
    if raw.len() > MAX_VERDICTS {
        return None;
    }
    Some(
        raw.into_iter()
            .filter_map(|(oid, value)| Some((oid, serde_json::from_value(value).ok()?)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(dir: &std::path::Path) -> HistoryRepo {
        HistoryRepo::open_or_init_in(dir).unwrap().unwrap()
    }

    /// Asks for one verdict and reports how many times `decide` ran.
    fn ask(verdicts: &mut EnvelopeVerdicts, path: &str, oid: &str, answer: bool) -> (bool, usize) {
        let mut decided = 0;
        let accepted = verdicts
            .accepted(path, "100644", oid, || {
                decided += 1;
                Ok(answer)
            })
            .unwrap();
        (accepted, decided)
    }

    #[test]
    fn a_verdict_recorded_by_an_earlier_audit_answers_without_deciding_again() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut first = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut first, "home/a", "oid1", true), (true, 1));
        first.save();
        let mut later = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut later, "home/a", "oid1", false), (true, 0));
    }

    #[test]
    fn a_refusal_is_remembered_too() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut first = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut first, "home/a", "oid1", false), (false, 1));
        first.save();
        let mut later = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut later, "home/a", "oid1", true), (false, 0));
    }

    #[test]
    fn a_verdict_recorded_for_another_path_or_mode_is_a_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut first = EnvelopeVerdicts::load(&repo);
        ask(&mut first, "home/a", "oid1", true);
        assert_eq!(ask(&mut first, "home/b", "oid1", false), (false, 1));
        let wrong_mode = first
            .accepted("home/b", "100755", "oid1", || Ok(true))
            .unwrap();
        assert!(wrong_mode);
    }

    #[test]
    fn a_corrupt_verdict_file_is_no_verdicts_not_a_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut first = EnvelopeVerdicts::load(&repo);
        ask(&mut first, "home/a", "oid1", true);
        first.save();
        let file = first.file.clone().unwrap();
        std::fs::write(&file, b"not json").unwrap();
        let mut later = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut later, "home/a", "oid1", true), (true, 1));
    }

    #[test]
    fn an_entry_that_does_not_parse_is_dropped_and_the_rest_stand() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut first = EnvelopeVerdicts::load(&repo);
        ask(&mut first, "home/a", "oid1", true);
        first.save();
        let file = first.file.clone().unwrap();
        std::fs::write(
            &file,
            br#"{"oid1":{"path":"home/a","mode":"100644","accepted":true},"oid2":"junk"}"#,
        )
        .unwrap();
        let mut later = EnvelopeVerdicts::load(&repo);
        assert_eq!(ask(&mut later, "home/a", "oid1", false), (true, 0));
        assert_eq!(ask(&mut later, "home/c", "oid2", true), (true, 1));
    }

    #[test]
    fn a_failed_decision_records_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = repo(tmp.path());
        let mut verdicts = EnvelopeVerdicts::load(&repo);
        let failed = verdicts.accepted("home/a", "100644", "oid1", || eyre::bail!("unreadable"));
        assert!(failed.is_err());
        assert_eq!(ask(&mut verdicts, "home/a", "oid1", true), (true, 1));
    }
}
