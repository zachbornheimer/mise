//! Why a sync that could have published did not. A skip is not an error:
//! it is recorded beside the sync status so a person or tool can tell a
//! blocked publication from one that had nothing to publish.

use serde::{Deserialize, Serialize};

use super::reconcile::PathPlan;
use super::run::SyncStatus;

/// The condition that stopped publication before anything was built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum PublishSkip {
    /// `--fetch-only`, or the `fetch-only` mode.
    FetchOnly,
    /// No network: nothing was fetched or pushed.
    Offline,
    /// Incoming application is still pending; publication must sit on top
    /// of the whole incoming setup.
    PendingApplications { count: usize },
    /// Incoming history changes no files here, but must be recorded first.
    PendingRepository,
    /// Paths whose local and incoming versions need a decision.
    Conflicts { count: usize },
    /// An earlier application failed and sharing is paused.
    ApplicationFailure,
    /// The incoming setup failed validation.
    ValidationError,
}

impl PublishSkip {
    /// The first condition that blocks publication, if any. `gate` is a
    /// reason the request itself rules publication out.
    pub(crate) fn detect(
        gate: Option<Self>,
        status: &SyncStatus,
        plans: &[PathPlan],
    ) -> Option<Self> {
        if gate.is_some() {
            return gate;
        }
        let conflicts = plans.iter().filter(|plan| plan.conflict.is_some()).count();
        let applying = plans.iter().filter(|plan| plan.apply.is_some()).count();
        if status.application_failure.is_some() {
            Some(Self::ApplicationFailure)
        } else if status.validation_error.is_some() {
            Some(Self::ValidationError)
        } else if conflicts > 0 {
            Some(Self::Conflicts { count: conflicts })
        } else if applying > 0 {
            Some(Self::PendingApplications { count: applying })
        } else if status.pending_repository {
            Some(Self::PendingRepository)
        } else {
            None
        }
    }

    /// The sentence `mise dot sync` prints after `history: `.
    pub fn sentence(&self) -> String {
        match self {
            Self::FetchOnly => "publish skipped: fetch-only, nothing is pushed".into(),
            Self::Offline => "publish skipped: offline, nothing is pushed".into(),
            Self::PendingApplications { count } => format!(
                "publish skipped: {count} incoming change(s) pending, run `mise dot pull`"
            ),
            Self::PendingRepository => {
                "publish skipped: incoming history not yet recorded here, run `mise dot pull`"
                    .into()
            }
            Self::Conflicts { count } => format!(
                "publish skipped: {count} conflict(s) need a decision, see `mise dot status`"
            ),
            Self::ApplicationFailure => {
                "publish skipped: an earlier application failed, see `mise dot status`".into()
            }
            Self::ValidationError => {
                "publish skipped: the incoming setup failed validation, see `mise dot status`"
                    .into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_blocked_publication_names_its_condition() {
        let applying = PathPlan {
            apply: Some(None),
            ..Default::default()
        };
        let none = SyncStatus::default();
        assert_eq!(PublishSkip::detect(None, &none, &[]), None);
        assert_eq!(
            PublishSkip::detect(None, &none, &[applying.clone(), applying.clone()]),
            Some(PublishSkip::PendingApplications { count: 2 })
        );
        assert_eq!(
            PublishSkip::detect(Some(PublishSkip::FetchOnly), &none, &[applying]),
            Some(PublishSkip::FetchOnly)
        );
        let repository = SyncStatus {
            pending_repository: true,
            ..Default::default()
        };
        assert_eq!(
            PublishSkip::detect(None, &repository, &[]),
            Some(PublishSkip::PendingRepository)
        );
        let failed = SyncStatus {
            application_failure: Some("x".into()),
            ..Default::default()
        };
        assert_eq!(
            PublishSkip::detect(None, &failed, &[]),
            Some(PublishSkip::ApplicationFailure)
        );
        let invalid = SyncStatus {
            validation_error: Some("x".into()),
            ..Default::default()
        };
        assert_eq!(
            PublishSkip::detect(None, &invalid, &[]),
            Some(PublishSkip::ValidationError)
        );
        let conflicting = PathPlan {
            conflict: Some(crate::history::sync::reconcile::Conflict {
                branch_path: "tracked/home/.zshrc".into(),
                kind: crate::history::sync::reconcile::ConflictKind::SameHunk,
                local: None,
                remote: None,
                base: None,
            }),
            ..Default::default()
        };
        assert_eq!(
            PublishSkip::detect(None, &none, &[conflicting]),
            Some(PublishSkip::Conflicts { count: 1 })
        );
        for skip in [
            PublishSkip::FetchOnly,
            PublishSkip::Offline,
            PublishSkip::PendingApplications { count: 6 },
            PublishSkip::PendingRepository,
            PublishSkip::Conflicts { count: 1 },
            PublishSkip::ApplicationFailure,
            PublishSkip::ValidationError,
        ] {
            let sentence = skip.sentence();
            assert!(sentence.starts_with("publish skipped: "), "{sentence}");
            assert!(!sentence.contains("nothing new to publish"));
        }
        assert_eq!(
            PublishSkip::PendingApplications { count: 6 }.sentence(),
            "publish skipped: 6 incoming change(s) pending, run `mise dot pull`"
        );
        let json = serde_json::to_value(PublishSkip::PendingApplications { count: 6 }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"reason": "pending_applications", "count": 6})
        );
    }
}
