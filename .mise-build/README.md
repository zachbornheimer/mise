# mise-build: the carry on `main`

`zachbornheimer/mise` is a fork of `jdx/mise`. Its `main` is upstream `main`
plus **one carry commit**: the build machinery, and nothing else. Everything
the carry adds lives under `.mise-build/`, a directory upstream does not have,
so syncing from upstream never conflicts there. The one unavoidable exception is
`.github/workflows/mise-build.yml`, which GitHub requires in that directory
(and on the default branch, for `schedule`).

The `forking-projects` skill has the design.

| Path                               | What it is                                            |
| ---------------------------------- | ----------------------------------------------------- |
| `.github/workflows/mise-build.yml` | The build: assemble, build both targets, publish.     |
| `.mise-build/resolve-branches.ts`  | Reads `branches/` and prints the ordered branch list. |
| `.mise-build/branches/**/*.toml`   | The manifest: one file per carried branch.            |
| `.mise-build/README.md`            | This file.                                            |

## How a build works

`mise-build` runs on every push to `main`, every 12 hours (to pick up pushes to
carried branches, which cannot trigger it), and on `workflow_dispatch`. It:

1. checks out the triggering commit as the **base**;
2. runs `bun .mise-build/resolve-branches.ts` to get the ordered branch list;
3. fetches each branch from the fork and merges it onto the base with
   `git merge --no-ff`, in order;
4. skips build and publish when the assembled tree equals the tree of the
   latest release's recorded `build_commit`;
5. otherwise pushes the result to the throwaway `mise-build` branch, builds
   `darwin-arm64` on a macOS runner and `linux-x64` on Ubuntu through
   `zysys/github-workflows` `rust-release.yml`, and publishes release
   `build-<timestamp>-<upstream7>-<build7>` as Latest, with
   `mise-darwin-arm64.tar.gz`, `mise-linux-x64.tar.gz` and `SHA256SUMS` — the
   same targets and asset shape as the `oh-my-pi` `omp-build` release.

It fails, and the previous release stays Latest, when a listed branch is missing
from the fork or conflicts with the base or an earlier branch. A branch already
contained in `jdx/mise:main` only warns: delete its file.

A `workflow_dispatch` with a non-empty `branches_override` publishes a
**prerelease**, never Latest.

## Install

`~/.config/mise/config.toml` installs the build like every other fork:

```toml
"github:zachbornheimer/mise" = { version = "latest", matching = "mise-", minimum_release_age = "0" }
```

## Branch files

The path under `branches/`, minus `.toml`, is the branch name:
`branches/fix/performant-dotfiles.toml` is branch `fix/performant-dotfiles`.

```toml
reason = "what the branch does for the person running the build"
upstream = "no" # no | candidate | submitted | merged
pr = "" # required when upstream = "submitted"
layer = 50 # merge order, lower first; default 50
```

jdx/mise takes no outside pull requests, so `upstream` stays `no` or
`candidate` until its maintainers invite one.

### Add a branch

1. Push the branch to the fork (`git push fork <branch>`). A listed branch that
   is not on the fork fails the whole assembly.
2. Create `.mise-build/branches/<branch>.toml` with at least `reason`.
3. Dry-run: `bun .mise-build/resolve-branches.ts "" schedule` prints the resolved
   list, one branch per line.

### Remove a branch

Delete its file, when upstream merges it or it is abandoned.

## Keeping `main` current

To take new upstream commits, merge `jdx/mise:main` into `main`. The carry lives
only under `.mise-build/` and the one workflow file, so it does not conflict.
Never force-push `main` or any branch listed here. Upstream's own workflows in
`.github/workflows/` come back with every sync: disable them in the fork's
Actions settings, so only `mise-build` runs.
