//! Publish the ordinary local branch, never a filtered publication history.

use eyre::{Result, bail};
use std::collections::BTreeSet;

use super::graph::Heads;
use super::network::{PushOutcome, Remote};
use crate::history::shadow::HistoryRepo;

/// Reconciliation and complete live application must precede publication.
/// A merge that still changes this machine's saved tree needs another pull.
pub(crate) fn build(
    repo: &HistoryRepo,
    upstream: Option<&str>,
    expected_local: Option<&str>,
    accepted: &BTreeSet<String>,
    allow_plaintext_history: bool,
) -> Result<Option<String>> {
    let heads = Heads::read(repo)?;
    if heads.local.as_deref() != expected_local {
        // A save landed after planning. The planned checkpoint is still in
        // the history; when it fast-forwards the origin it is published as
        // planned, and the newer saves wait for the next sync. Only a merge,
        // which would have to move the head, must be planned again.
        let Some(pinned) = expected_local else {
            bail!("local saved history changed while planning; reconcile again");
        };
        if heads.remote.as_deref() != upstream
            || !fast_forwards(repo, pinned, heads.local.as_deref(), upstream)?
        {
            bail!("local saved history changed while planning; reconcile again");
        }
        if upstream == Some(pinned) {
            return Ok(None);
        }
        if !allow_plaintext_history {
            super::files::audit_history(repo, pinned, upstream, &Default::default())?;
            super::secrets::audit_unpublished(
                repo,
                pinned,
                upstream,
                &mise_settings::Settings::get().history.allow_secret_values,
            )?;
        }
        return Ok(Some(pinned.to_string()));
    }
    if heads.remote.as_deref() != upstream {
        bail!("origin changed while preparing publication; reconcile again");
    }
    let Some(local) = &heads.local else {
        return Ok(None);
    };
    if heads.remote.as_ref() == Some(local) {
        return Ok(None);
    }
    let tree = repo.output_tree_of(local)?;
    if let Some(remote) = &heads.remote
        && heads.base.as_ref() != Some(remote)
    {
        let (mut merged, mut conflicts) = repo.merge_tree(local, remote)?;
        // Enrollment is a keyed inventory, not arbitrary JSON text. Git's
        // line merge can conflict on independent additions or combine policy
        // changes into invalid metadata. Validate its structured merge first.
        // Several merge bases have no commit to read. Their enrollment is
        // one virtual manifest, the same one sync applies; file conflicts
        // still settle against a real commit, never that manifest.
        let base = super::run::enrollment_base(repo, local, remote)?;
        use crate::history::manifest::Manifest;
        if let (Some(ours), Some(theirs)) =
            (Manifest::read(repo, local)?, Manifest::read(repo, remote)?)
        {
            merged = Manifest::merge(&base, &ours, &theirs)?.write(repo, &merged)?;
            conflicts.retain(|path| path != crate::history::manifest::PATH);
            // A conflicted encrypted path whose decrypted content is equal is not a
            // conflict to resolve: the local saved envelope stands, and Git's
            // version of that path is never published.
            let settled = super::run::settle_conflicts(
                repo,
                heads.base.as_deref(),
                local,
                remote,
                &merged,
                conflicts,
            )?;
            merged = settled.0;
            conflicts = settled.1;
        }
        let unresolved: Vec<_> = conflicts
            .iter()
            .filter(|path| !accepted.contains(*path))
            .collect();
        if !unresolved.is_empty() {
            bail!(
                "sync paused: resolve conflicts across the complete repository before publication: {}",
                unresolved
                    .into_iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        // Accepted choices were validated against saved, live, and remote
        // versions. Carry their already-encrypted saved objects, not a new
        // plaintext publication representation.
        let overlays = conflicts
            .into_iter()
            .map(|path| {
                Ok(crate::history::shadow::Overlay {
                    object: repo.object_at(local, &path)?,
                    path,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let merged = repo.compose(&merged, &overlays)?;
        if merged != tree {
            bail!(
                "incoming setup has not been completely applied; run `mise dot pull` before publishing"
            );
        }
    }
    let Some(candidate) = heads.candidate(repo, &tree)? else {
        return Ok(None);
    };
    if !allow_plaintext_history {
        super::files::audit_history(repo, &candidate.commit, upstream, &Default::default())?;
        super::secrets::audit_unpublished(
            repo,
            &candidate.commit,
            upstream,
            &mise_settings::Settings::get().history.allow_secret_values,
        )?;
    }
    candidate.adopt(repo)?;
    Ok(Some(candidate.commit))
}

/// Whether publishing `pinned` is a plain fast-forward: it is still part of
/// the saved history (`head` descends from it) and the origin is behind it.
pub(crate) fn fast_forwards(
    repo: &HistoryRepo,
    pinned: &str,
    head: Option<&str>,
    upstream: Option<&str>,
) -> Result<bool> {
    let contains = |descendant: &str, ancestor: &str| -> Result<bool> {
        Ok(descendant == ancestor
            || repo
                .merge_bases(descendant, ancestor)?
                .iter()
                .any(|base| base == ancestor))
    };
    let Some(head) = head else { return Ok(false) };
    Ok(contains(head, pinned)?
        && match upstream {
            None => true,
            Some(upstream) => contains(pinned, upstream)?,
        })
}
pub(crate) fn push(
    remote: &Remote<'_>,
    branch: &str,
    commit: &str,
    upstream_commit: Option<&str>,
) -> Result<PushOutcome> {
    remote.push(
        &[format!("{commit}:refs/heads/{branch}")],
        Some((branch, upstream_commit)),
    )
}

#[cfg(test)]
mod tests {
    use super::super::network::UPSTREAM_REF;
    use super::*;
    use crate::history::shadow::Overlay;

    #[test]
    fn publication_reuses_the_whole_local_history() {
        let temporary = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(temporary.path())
            .unwrap()
            .unwrap();
        let tree = repo
            .compose(
                &repo.empty_object("tree").unwrap(),
                &[Overlay {
                    path: "README.md".into(),
                    object: Some((
                        "100644".into(),
                        repo.hash_blob(b"manually maintained").unwrap(),
                    )),
                }],
            )
            .unwrap();
        let before = repo.commit_tree(&tree, vec![], "before").unwrap();
        let after = repo.commit_tree(&tree, vec![&before], "after").unwrap();
        repo.update_history_head(&after, None).unwrap();
        assert_eq!(
            build(&repo, None, Some(&after), &Default::default(), false).unwrap(),
            Some(after.clone())
        );
        assert_eq!(
            repo.rev_list(&after, usize::MAX).unwrap(),
            vec![after.clone(), before]
        );
        assert!(repo.list_refs("refs/setup/").unwrap().is_empty());
        repo.update_ref(UPSTREAM_REF, &after, None).unwrap();
        assert_eq!(
            build(
                &repo,
                Some(&after),
                Some(&after),
                &Default::default(),
                false
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn complete_tree_merge_blocks_unapplied_repository_files() {
        let temporary = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(temporary.path())
            .unwrap()
            .unwrap();
        let tree = repo.empty_object("tree").unwrap();
        let base = repo.commit_tree(&tree, vec![], "base").unwrap();
        let local = repo
            .commit_tree(&tree, vec![&base], "local boundary")
            .unwrap();
        let incoming = repo
            .compose(
                &tree,
                &[Overlay {
                    path: "README.md".into(),
                    object: Some(("100644".into(), repo.hash_blob(b"incoming").unwrap())),
                }],
            )
            .unwrap();
        let remote = repo.commit_tree(&incoming, vec![&base], "remote").unwrap();
        repo.update_history_head(&local, None).unwrap();
        repo.update_ref(UPSTREAM_REF, &remote, None).unwrap();
        for allow_plaintext_history in [false, true] {
            assert!(
                build(
                    &repo,
                    Some(&remote),
                    Some(&local),
                    &Default::default(),
                    allow_plaintext_history,
                )
                .unwrap_err()
                .to_string()
                .contains("completely applied")
            );
        }
        assert_eq!(repo.ref_oid(HistoryRepo::HISTORY_REF).unwrap(), Some(local));
        assert_eq!(repo.ref_oid(UPSTREAM_REF).unwrap(), Some(remote));
    }
}
