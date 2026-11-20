use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::file::display_path;
use crate::system::history::shadow::HistoryRepo;
use crate::system::history::sync::files;
use crate::system::history::sync::layout::Roots;
use crate::system::history::sync::reconcile::{Conflict, ConflictKind, Object};
use crate::system::history::sync::run;
use crate::system::history::tracked::normalize_target;

/// Compare both sides of a sync conflict
///
/// Prints a unified diff from this machine's saved version to the version
/// fetched from the origin. `--difftool` opens the comparison in Git's
/// configured diff tool; when `diff.tool` is unset, Git falls back to
/// `merge.tool`. `--json` prints one record per conflict, with the commands
/// that resolve it, and writes nothing. `--sides` writes each side's
/// plaintext into a private directory and reports those paths. Encrypted
/// sides are decrypted before a diff, a diff tool, or a side file sees them.
/// This command changes neither saved side. Resolve a conflict with
/// `mise dot pull --take-remote` or `--keep-local`.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("mise dot conflicts", help = "Show every conflict"),
    example("mise dot conflicts ~/.zshrc", help = "Show one conflicted file"),
    example(
        "mise dot conflicts --difftool ~/.zshrc",
        help = "Open the comparison in Git's diff tool"
    ),
    example(
        "mise dot conflicts --difftool --tool meld ~/.zshrc",
        help = "Use a specific diff tool"
    ),
    example(
        "mise dot conflicts --json",
        help = "Print each conflict and the commands that resolve it"
    ),
    example(
        "mise dot conflicts --json --sides /tmp/sides",
        help = "Write each side's plaintext beside the JSON handoff"
    )
)]
pub(crate) struct DotfilesConflicts {
    /// Only inspect these conflicted paths
    #[usage(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Open the comparison in Git's configured diff or merge tool
    #[usage(long)]
    difftool: bool,

    /// Use this Git diff tool instead of the configured default
    #[usage(long, value_name = "TOOL", requires = "difftool")]
    tool: Option<String>,

    /// Print one JSON record per conflict, with the commands that resolve it
    ///
    /// Writes nothing on its own. Each record names the live path, the
    /// history path, the kind, any detail, whether the saved object is
    /// encrypted, and each side's mode. It never includes file content.
    #[usage(long)]
    json: bool,

    /// Write each side's plaintext into a new directory and report the paths
    ///
    /// `DIR` must not exist. mise creates it at mode 0700 and each side file
    /// at mode 0600. An existing path, including a directory or symlink, is
    /// refused. Requires `--json`.
    #[usage(long, value_name = "DIR", requires = "json")]
    sides: Option<PathBuf>,
}

impl DotfilesConflicts {
    pub(crate) async fn run(self) -> Result<()> {
        if !crate::config::Settings::get().history.enabled {
            bail!("history is disabled (history.enabled = false)");
        }
        let (store, tracked) = super::history::open_store().await?;
        let Some(repo) = store.repo() else {
            bail!("inspecting conflicts requires git");
        };
        // read-only against history: no sync lock, so this never waits behind a running sync
        if run::sync_running(&store) {
            warn!("a sync or pull is running; these conflicts may change when it finishes");
        }
        let observation = observe(repo, &store, &tracked, &self.paths)?;
        let plan = decide(&self);
        execute(repo, &observation, &plan)
    }
}

struct Observation {
    encrypted: std::collections::BTreeSet<String>,
    selected: Vec<(PathBuf, Conflict)>,
}

struct Plan {
    json: bool,
    difftool: bool,
    tool: Option<String>,
    sides: Option<PathBuf>,
}

fn observe(
    repo: &HistoryRepo,
    store: &crate::system::history::checkpoint::Store,
    tracked: &crate::system::history::tracked::TrackedSet,
    paths: &[PathBuf],
) -> Result<Observation> {
    let mut status = run::read_status(store.state_dir())?;
    run::refresh_with_interaction(store, tracked, &mut status, console::user_attended_stderr())?;
    let head = repo.ref_oid(HistoryRepo::HISTORY_REF)?;
    Ok(Observation {
        encrypted: files::encrypted_paths(repo, head.as_deref())?,
        selected: select(&status.conflicts, paths)?,
    })
}

fn decide(command: &DotfilesConflicts) -> Plan {
    Plan {
        json: command.json,
        difftool: command.difftool,
        tool: command.tool.clone(),
        sides: command.sides.clone(),
    }
}

fn execute(repo: &HistoryRepo, observation: &Observation, plan: &Plan) -> Result<()> {
    if observation.selected.is_empty() {
        if plan.json {
            miseprintln!("[]");
        } else {
            info!("no sharing conflicts");
        }
        return Ok(());
    }
    if plan.json {
        return print_handoff(repo, observation, plan);
    }
    for (path, conflict) in &observation.selected {
        miseprintln!(
            "Conflict: {} ({})",
            display_path(path),
            conflict.kind.describe()
        );
        if let Some(detail) = &conflict.detail {
            miseprintln!("{detail}");
        }
        if plan.difftool {
            run_difftool(repo, observation, conflict, path, plan.tool.as_deref())?;
        } else {
            print_diff(repo, observation, conflict, path)?;
        }
    }
    Ok(())
}

fn select(conflicts: &[Conflict], paths: &[PathBuf]) -> Result<Vec<(PathBuf, Conflict)>> {
    let roots = Roots::current();
    let requested = paths
        .iter()
        .map(|path| normalize_target(path))
        .collect::<Vec<_>>();
    let mut selected = vec![];
    for conflict in conflicts {
        let Some(path) = roots
            .locate(&conflict.branch_path)
            .path()
            .map(Path::to_path_buf)
        else {
            continue;
        };
        if requested.is_empty() || requested.contains(&path) {
            selected.push((path, conflict.clone()));
        }
    }
    for path in requested {
        if !selected.iter().any(|(selected, _)| selected == &path) {
            bail!("{} is not a sharing conflict", display_path(&path));
        }
    }
    Ok(selected)
}

fn print_handoff(repo: &HistoryRepo, observation: &Observation, plan: &Plan) -> Result<()> {
    if let Some(dir) = &plan.sides {
        prepare_sides_dir(dir)?;
    }
    let mut records = vec![];
    for (index, (path, conflict)) in observation.selected.iter().enumerate() {
        let mut record = record(repo, observation, path, conflict)?;
        if let Some(dir) = &plan.sides {
            let opened = opened_sides(repo, observation, conflict, path)?;
            record["sides"] = write_sides(dir, index, conflict, &opened)?;
        }
        records.push(record);
    }
    miseprintln!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

fn record(
    repo: &HistoryRepo,
    observation: &Observation,
    path: &Path,
    conflict: &Conflict,
) -> Result<Value> {
    let quoted = shell_quote(&path.to_string_lossy());
    let encrypted = path_encrypted(repo, observation, conflict);
    let mut record = json!({
        "path": path,
        "branch_path": conflict.branch_path,
        "kind": conflict.kind,
        "encrypted": encrypted,
        "local": side_meta(repo, conflict.local.as_ref(), encrypted)?,
        "remote": side_meta(repo, conflict.remote.as_ref(), encrypted)?,
        "base": side_meta(repo, conflict.base.as_ref(), encrypted)?,
        "resolve": resolve_commands(&quoted),
    });
    if let Some(detail) = &conflict.detail {
        record["detail"] = json!(detail);
    }
    if !resolution_applies(conflict.kind) {
        record["resolve"] = json!(Value::Null);
    }
    Ok(record)
}

fn resolve_commands(quoted: &str) -> Value {
    json!({
        "take_remote": format!("mise dot pull --take-remote {quoted} --yes"),
        "keep_local": format!("mise dot pull --keep-local {quoted} --yes"),
        "merged": format!(
            "mise dot save {quoted} && mise dot pull --keep-local {quoted} --yes && mise dot sync"
        ),
    })
}

fn resolution_applies(kind: ConflictKind) -> bool {
    !matches!(
        kind,
        ConflictKind::Repository | ConflictKind::UnusableLive | ConflictKind::InvalidIncoming
    )
}

fn side_meta(repo: &HistoryRepo, object: Option<&Object>, encrypted_path: bool) -> Result<Value> {
    let Some(object) = object else {
        return Ok(json!({
            "present": false,
            "mode": "absent",
        }));
    };
    let mode = if needs_decrypt(repo, object, encrypted_path)? {
        files::plaintext_mode(repo, object)?.unwrap_or_else(|| object.0.clone())
    } else {
        object.0.clone()
    };
    Ok(json!({
        "present": true,
        "mode": mode,
    }))
}

fn path_encrypted(repo: &HistoryRepo, observation: &Observation, conflict: &Conflict) -> bool {
    observation.encrypted.contains(&conflict.branch_path)
        || side_is_envelope(repo, conflict.local.as_ref())
        || side_is_envelope(repo, conflict.remote.as_ref())
        || side_is_envelope(repo, conflict.base.as_ref())
}

fn side_is_envelope(repo: &HistoryRepo, object: Option<&Object>) -> bool {
    object.is_some_and(|object| {
        repo.blob_starts_with(&object.1, files::MAGIC)
            .unwrap_or(false)
    })
}

fn needs_decrypt(repo: &HistoryRepo, object: &Object, encrypted_path: bool) -> Result<bool> {
    if !encrypted_path || matches!(object.0.as_str(), "040000" | "160000") {
        return Ok(false);
    }
    // A reconciled local or base may already be a plaintext transient object.
    // Decrypt only a saved envelope or a marker record Git merged as text.
    Ok(repo.blob_starts_with(&object.1, files::MAGIC)?)
}

struct OpenedSides {
    local: OpenedSide,
    remote: OpenedSide,
    base: OpenedSide,
}

struct OpenedSide {
    present: bool,
    mode: String,
    bytes: Vec<u8>,
    label: String,
}

fn opened_sides(
    repo: &HistoryRepo,
    observation: &Observation,
    conflict: &Conflict,
    path: &Path,
) -> Result<OpenedSides> {
    let encrypted = path_encrypted(repo, observation, conflict);
    Ok(OpenedSides {
        local: open_side(
            repo,
            conflict.local.as_ref(),
            &conflict.branch_path,
            path,
            "local",
            encrypted,
        )?,
        remote: open_side(
            repo,
            conflict.remote.as_ref(),
            &conflict.branch_path,
            path,
            "remote",
            encrypted,
        )?,
        base: open_side(
            repo,
            conflict.base.as_ref(),
            &conflict.branch_path,
            path,
            "base",
            encrypted,
        )?,
    })
}

fn open_side(
    repo: &HistoryRepo,
    object: Option<&Object>,
    branch_path: &str,
    path: &Path,
    side: &str,
    encrypted_path: bool,
) -> Result<OpenedSide> {
    let label = format!("{} ({side})", display_path(path));
    let Some(object) = object else {
        return Ok(OpenedSide {
            present: false,
            mode: "absent".into(),
            bytes: vec![],
            label,
        });
    };
    let restored = if needs_decrypt(repo, object, encrypted_path)? {
        files::decrypt(repo, branch_path, object, console::user_attended_stderr())?
    } else {
        object.clone()
    };
    Ok(OpenedSide {
        present: true,
        mode: restored.0.clone(),
        bytes: side_bytes(repo, &restored)?,
        label,
    })
}

fn side_bytes(repo: &HistoryRepo, object: &Object) -> Result<Vec<u8>> {
    match object.0.as_str() {
        "040000" => Ok(format!("tree {}\n", object.1).into_bytes()),
        "160000" => Ok(format!("gitlink {}\n", object.1).into_bytes()),
        _ => repo.cat_object(&object.1),
    }
}

fn print_diff(
    repo: &HistoryRepo,
    observation: &Observation,
    conflict: &Conflict,
    path: &Path,
) -> Result<()> {
    let opened = opened_sides(repo, observation, conflict, path)?;
    let local = materialize(&opened.local, "local", path)?;
    let remote = materialize(&opened.remote, "remote", path)?;
    let output = git_diff(repo, &local, &remote, path, console::colors_enabled())?;
    if !output.stdout.is_empty() {
        miseprint!("{}", String::from_utf8_lossy(&output.stdout))?;
    }
    if local.mode != remote.mode {
        miseprintln!("mode: {} -> {}", local.mode, remote.mode);
    }
    Ok(())
}

fn run_difftool(
    repo: &HistoryRepo,
    observation: &Observation,
    conflict: &Conflict,
    path: &Path,
    tool: Option<&str>,
) -> Result<()> {
    let opened = opened_sides(repo, observation, conflict, path)?;
    let local = materialize(&opened.local, "local", path)?;
    let remote = materialize(&opened.remote, "remote", path)?;
    let git = crate::git::plumbing_binary().ok_or_else(|| eyre::eyre!("git is unavailable"))?;
    let mut command = Command::new(git);
    crate::git::sanitize_git_command(&mut command);
    command
        .current_dir(repo.dir().parent().unwrap_or(repo.dir()))
        .args(["difftool", "--no-prompt"]);
    if let Some(tool) = tool {
        command.arg("--tool").arg(tool);
    }
    command
        .arg("--no-index")
        .arg("--")
        .arg(local.file.path())
        .arg(remote.file.path());
    let status = command
        .status()
        .wrap_err_with(|| format!("running Git conflict difftool for {}", display_path(path)))?;
    if !matches!(status.code(), Some(0 | 1)) {
        bail!("Git difftool failed ({status})");
    }
    if local.mode != remote.mode {
        miseprintln!("mode: {} -> {}", local.mode, remote.mode);
    }
    Ok(())
}

struct SideFile {
    file: tempfile::NamedTempFile,
    mode: String,
    label: String,
}

fn materialize(side: &OpenedSide, name: &str, path: &Path) -> Result<SideFile> {
    let suffix = path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()))
        .unwrap_or_default();
    let mut file = tempfile::Builder::new()
        .prefix(&format!("mise-{name}-"))
        .suffix(&suffix)
        .tempfile()?;
    file.write_all(&side.bytes)?;
    Ok(SideFile {
        file,
        mode: side.mode.clone(),
        label: side.label.clone(),
    })
}

fn git_diff(
    repo: &HistoryRepo,
    local: &SideFile,
    remote: &SideFile,
    path: &Path,
    color: bool,
) -> Result<std::process::Output> {
    let git = crate::git::plumbing_binary().ok_or_else(|| eyre::eyre!("git is unavailable"))?;
    let mut command = Command::new(git);
    crate::git::sanitize_git_command(&mut command);
    command.current_dir(repo.dir().parent().unwrap_or(repo.dir()));
    command.args([
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--patch",
        if color {
            "--color=always"
        } else {
            "--color=never"
        },
        "--no-index",
        "--",
    ]);
    command.arg(local.file.path()).arg(remote.file.path());
    let mut output = command
        .output()
        .wrap_err_with(|| format!("running Git conflict comparison for {}", display_path(path)))?;
    if !matches!(output.status.code(), Some(0 | 1)) {
        bail!(
            "Git diff failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let local_name = local.file.path().to_string_lossy();
    let remote_name = remote.file.path().to_string_lossy();
    output.stdout = String::from_utf8_lossy(&output.stdout)
        .replace(local_name.as_ref(), &local.label)
        .replace(local_name.trim_start_matches('/'), &local.label)
        .replace(remote_name.as_ref(), &remote.label)
        .replace(remote_name.trim_start_matches('/'), &remote.label)
        .into_bytes();
    Ok(output)
}

fn prepare_sides_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "{} is a symlink; refusing to write plaintext sides through it",
                display_path(dir)
            );
        }
        Ok(_) => bail!(
            "{} already exists; --sides requires a new directory",
            display_path(dir)
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_private_dir(dir),
        Err(err) => Err(err).wrap_err_with(|| format!("reading {}", display_path(dir))),
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .wrap_err_with(|| format!("creating {}", display_path(dir)))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir).wrap_err_with(|| format!("creating {}", display_path(dir)))?;
    }
    Ok(())
}

fn write_sides(
    dir: &Path,
    index: usize,
    conflict: &Conflict,
    opened: &OpenedSides,
) -> Result<Value> {
    if !crate::system::history::sync::layout::is_safe_branch_path(&conflict.branch_path) {
        bail!(
            "refusing to write a side file for unsafe history path {}",
            conflict.branch_path
        );
    }
    let mut sides = json!({});
    for (name, side) in [
        ("local", &opened.local),
        ("remote", &opened.remote),
        ("base", &opened.base),
    ] {
        if !side.present {
            continue;
        }
        // The index keeps `a/b` distinct from `a__b`. The label is display only.
        let path = dir.join(format!("conflict-{index:04}-{name}.txt"));
        write_private(&path, &side.bytes)?;
        sides[name] = json!(path);
    }
    Ok(sides)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        bail!(
            "{} already exists; refusing to overwrite a side file",
            display_path(path)
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .wrap_err_with(|| format!("creating {}", display_path(path)))?;
        file.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .wrap_err_with(|| format!("creating {}", display_path(path)))?;
        file.write_all(bytes)?;
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    shell_escape::unix::escape(value.into()).to_string()
}
