//! Encryption before Git capture and process-local decryption for live files.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use eyre::{Result, WrapErr, bail};
use serde::{Deserialize, Serialize};

use super::{layout, reconcile::Object};
use crate::history::shadow::HistoryRepo;
use mise_util::agecrypt;

pub const MAGIC: &[u8] = b"mise-encrypted-file-v1\n";

/// Git's text-merge markers. A record that holds them is damage from a merge
/// that treated two envelopes as text: it holds one complete envelope from
/// each side and nothing else.
const OURS: &[u8] = b"<<<<<<< ";
const BASE: &[u8] = b"||||||| ";
const SEP: &[u8] = b"=======";
const THEIRS: &[u8] = b">>>>>>> ";

/// A record Git merged as text: an envelope whose body starts with a marker.
pub(crate) fn is_marker_record(bytes: &[u8]) -> bool {
    bytes
        .strip_prefix(MAGIC)
        .is_some_and(|body| body.starts_with(OURS))
}

#[derive(Clone)]
struct VerifiedAncestry {
    head: String,
    protected: BTreeSet<String>,
}

// The process remembers a proof it has already checked. The file beside the
// repository carries that proof to the next process, but only when a secret
// that never leaves this repository authenticates it. A copied proof, a
// forged head, or a forged protected set fails that check and is ignored.
static AUDITS: LazyLock<Mutex<BTreeMap<PathBuf, VerifiedAncestry>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The audit rules this proof was written under. A different version is not
/// proof: the history is audited again.
const AUDIT_RULES_VERSION: u32 = 1;
const PROOF_DIR: &str = "mise-audit";
const PROOF_FILE: &str = "verified-ancestry";
const PROOF_SECRET: &str = "secret";

/// Raw bytes serialized as a MessagePack `bin`, whatever the serializer's
/// default for `Vec<u8>` is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
        }
        deserializer.deserialize_byte_buf(Visitor)
    }
}

/// Audit the complete proposed ancestry, not just the latest tree. A newly
/// encrypted path cannot make its previously committed plaintext safe to push.
pub(crate) fn audit_history(
    repo: &HistoryRepo,
    head: &str,
    protected: &BTreeSet<String>,
) -> Result<()> {
    audit_history_cached(repo, head, protected).map(|_| ())
}

fn audit_history_cached(
    repo: &HistoryRepo,
    head: &str,
    protected: &BTreeSet<String>,
) -> Result<usize> {
    let cached = remembered_ancestry(repo, head);
    if cached
        .as_ref()
        .is_some_and(|cached| cached.head == head && protected.is_subset(&cached.protected))
    {
        return Ok(0);
    }
    // Opened once for the whole audit: opening it scans every pack index, so
    // doing it per blob is most of a long audit's cost.
    let objects = repo.gix()?;
    let mut commits = match &cached {
        Some(cached) => repo.rev_list_after(head, &cached.head)?,
        None => repo.rev_list(head, usize::MAX)?,
    };
    let mut protected = protected.clone();
    if let Some(cached) = &cached {
        protected.extend(cached.protected.iter().cloned());
    }
    // Policy changes cannot hide older plaintext, including on a merge
    // parent or a platform that this machine never activates.
    enrolled_paths(&objects, &commits, &mut protected)?;
    // A newly protected path invalidates the old proof for that policy: its
    // plaintext may live anywhere in old ancestry, including a merge parent.
    if cached
        .as_ref()
        .is_some_and(|cached| cached.protected != protected)
    {
        commits = repo.rev_list(head, usize::MAX)?;
        enrolled_paths(&objects, &commits, &mut protected)?;
    }
    let inspected = commits.len();
    let mut checked = BTreeSet::new();
    if !protected.is_empty() {
        repo.visit_paths_in_open(&objects, &commits, &protected, |commit, entry| {
            if !checked.insert((entry.path.clone(), entry.mode.clone(), entry.oid.clone())) {
                return Ok(());
            }
            let path = entry.path;
            let object = (entry.mode, entry.oid);
            let valid = envelope_in(repo, &objects, &object, agecrypt::MAX_ENCRYPTED_BYTES)?
                .is_some_and(|outer| {
                    outer.path == path
                        && matches!(outer.mode.as_str(), "100644" | "100755" | "120000")
                        && outer.ciphertext.0.starts_with(b"age-encryption.org/v1\n")
                })
                // A record Git merged as text still holds only envelopes, so
                // no plaintext enters history through it; its sides are
                // resolved from decrypted content when it is read.
                || record_of_envelopes_in(repo, &objects, &object, &path)?;
            if !valid {
                bail!(
                    "cannot publish: encrypted path {path} has an unencrypted or invalid version in commit {commit}; encrypting the latest version does not erase earlier plaintext. Remove that history before pushing, or use `mise dot sync --allow-plaintext-history` to publish it anyway",
                );
            }
            Ok(())
        })?;
    }
    remember_ancestry(repo, head, protected);
    Ok(inspected)
}

/// The proof this process already checked, or the one the repository's own
/// secret authenticates. A missing, unreadable, corrupt, copied, or
/// wrong-version proof is no proof. A verified head that is not an ancestor
/// of `head` is no proof either.
fn remembered_ancestry(repo: &HistoryRepo, head: &str) -> Option<VerifiedAncestry> {
    let remembered = AUDITS
        .lock()
        .ok()
        .and_then(|cache| cache.get(repo.dir()).cloned());
    let proof = remembered.or_else(|| durable_ancestry(repo));
    proof.filter(|cached| {
        cached.head == head
            || repo
                .merge_bases(&cached.head, head)
                .is_ok_and(|bases| bases.len() == 1 && bases[0] == cached.head)
    })
}

fn durable_ancestry(repo: &HistoryRepo) -> Option<VerifiedAncestry> {
    let secret = std::fs::read(proof_secret(repo.dir())).ok()?;
    if secret.len() != 32 {
        return None;
    }
    let bytes = std::fs::read(proof_file(repo.dir())).ok()?;
    let proof = serde_json::from_slice::<DurableProof>(&bytes).ok()?;
    let repository = repository_identity(repo.dir()).ok()?;
    if proof.rules != AUDIT_RULES_VERSION
        || proof.repository != repository
        || !proof_authentic(&secret, &repository, &proof)
    {
        return None;
    }
    Some(VerifiedAncestry {
        head: proof.head,
        protected: proof.protected,
    })
}

fn remember_ancestry(repo: &HistoryRepo, head: &str, protected: BTreeSet<String>) {
    let ancestry = VerifiedAncestry {
        head: head.into(),
        protected,
    };
    if let Ok(mut cache) = AUDITS.lock() {
        // One watcher normally uses one repository. Bound temporary onboarding
        // probes without adding another durable history or state file.
        if cache.len() >= 64 && !cache.contains_key(repo.dir()) {
            cache.pop_first();
        }
        cache.insert(repo.dir().to_path_buf(), ancestry.clone());
    }
    // A proof this process could not record does not undo the audit. The next
    // process audits again.
    let _ = record_durable_ancestry(repo, &ancestry);
}

fn record_durable_ancestry(repo: &HistoryRepo, ancestry: &VerifiedAncestry) -> Result<()> {
    let dir = proof_dir(repo.dir());
    crate::history::store::create_private_dir(&dir)?;
    // The secret and the proof are one record. Two audits finishing together
    // must not leave a proof signed by a secret the file no longer holds.
    let _record = PROOF_RECORD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let secret = proof_secret_bytes(&dir)?;
    let proof = signed_proof(
        &secret,
        &repository_identity(repo.dir())?,
        &ancestry.head,
        &ancestry.protected,
    );
    let mut temporary = tempfile::NamedTempFile::new_in(&dir)?;
    serde_json::to_writer(temporary.as_file_mut(), &proof)?;
    temporary.as_file().sync_all()?;
    mise_util::file::persist_atomic(temporary, &proof_file(repo.dir()))?;
    Ok(())
}

static PROOF_RECORD: Mutex<()> = Mutex::new(());

/// The secret that makes a proof belong to this repository. Created once,
/// private to the user, and never copied with the proof: a proof moved beside
/// another repository has no matching secret there.
fn proof_secret_bytes(dir: &std::path::Path) -> Result<Vec<u8>> {
    let path = dir.join(PROOF_SECRET);
    if let Ok(secret) = std::fs::read(&path)
        && secret.len() == 32
    {
        return Ok(secret);
    }
    let mut secret = [0u8; 32];
    rand::fill(&mut secret);
    let mut temporary = tempfile::NamedTempFile::new_in(dir)?;
    use std::io::Write;
    temporary.write_all(&secret)?;
    temporary.as_file().sync_all()?;
    mise_util::file::persist_atomic(temporary, &path)?;
    Ok(secret.to_vec())
}

fn proof_dir(repo: &std::path::Path) -> std::path::PathBuf {
    repo.parent().unwrap_or(repo).join(PROOF_DIR)
}

fn proof_file(repo: &std::path::Path) -> std::path::PathBuf {
    proof_dir(repo).join(PROOF_FILE)
}

fn proof_secret(repo: &std::path::Path) -> std::path::PathBuf {
    proof_dir(repo).join(PROOF_SECRET)
}

#[derive(Serialize, Deserialize)]
struct DurableProof {
    rules: u32,
    /// The repository directory's own file identity when the proof was
    /// written. A directory copy gets a new identity, so the copied secret
    /// and proof together still do not vouch for the copy.
    repository: String,
    head: String,
    protected: BTreeSet<String>,
    mac: String,
}

fn signed_proof(
    secret: &[u8],
    repository: &str,
    head: &str,
    protected: &BTreeSet<String>,
) -> DurableProof {
    let key = <[u8; 32]>::try_from(secret).expect("the proof secret is 32 bytes");
    DurableProof {
        rules: AUDIT_RULES_VERSION,
        repository: repository.into(),
        head: head.into(),
        protected: protected.clone(),
        mac: proof_mac(&key, repository, head, protected),
    }
}

/// The repository directory's file identity, not its path. Two directories
/// with the same path at different times, and a copied directory, are not
/// the same repository.
fn repository_identity(repo: &std::path::Path) -> Result<String> {
    let id = file_id::get_file_id(repo).wrap_err("reading the history repository identity")?;
    Ok(format!("{id:?}"))
}

fn proof_authentic(secret: &[u8], repository: &str, proof: &DurableProof) -> bool {
    let Ok(secret) = <[u8; 32]>::try_from(secret) else {
        return false;
    };
    let expected = proof_mac(&secret, repository, &proof.head, &proof.protected);
    // Compare the whole digest. A shorter prefix would accept a truncated mac.
    expected.len() == proof.mac.len()
        && expected
            .bytes()
            .zip(proof.mac.bytes())
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn proof_mac(
    secret: &[u8; 32],
    repository: &str,
    head: &str,
    protected: &BTreeSet<String>,
) -> String {
    let claims = serde_json::to_vec(&(AUDIT_RULES_VERSION, repository, head, protected))
        .expect("the audit proof claims are JSON");
    hex::encode(blake3::keyed_hash(secret, &claims).as_bytes())
}

fn enrolled_paths(
    objects: &gix::Repository,
    commits: &[String],
    protected: &mut BTreeSet<String>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for commit in commits {
        let tree = objects
            .find_commit(gix::ObjectId::from_hex(commit.as_bytes())?)?
            .tree()?;
        let Some(entry) = tree.lookup_entry_by_path(crate::history::manifest::PATH)? else {
            continue;
        };
        // One manifest blob is one enrollment, however many commits name it.
        if !seen.insert(entry.object_id()) {
            continue;
        }
        let manifest = crate::history::manifest::Manifest::read_gix_entry(&entry)?;
        protected.extend(manifest.encrypted_paths());
    }
    Ok(())
}

/// Resolve encrypted files from the same committed enrollment metadata.
pub fn encrypted_paths(repo: &HistoryRepo, commit: Option<&str>) -> Result<BTreeSet<String>> {
    let Some(commit) = commit else {
        return Ok(BTreeSet::new());
    };
    let Some(manifest) = crate::history::manifest::Manifest::read(repo, commit)? else {
        return Ok(BTreeSet::new());
    };
    let protected = manifest.encrypted_paths();
    Ok(repo
        .ls_tree(commit)?
        .into_iter()
        .filter(|entry| {
            protected.iter().any(|prefix| {
                entry.path == *prefix
                    || entry
                        .path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        })
        .map(|entry| entry.path)
        .collect())
}

/// The newest commit in `head`'s ancestry whose tree holds `path` as a blob
/// that is not an encrypted envelope, so a plaintext origin version names the
/// commit that introduced it rather than only the branch head.
pub(crate) fn plaintext_commit(
    repo: &HistoryRepo,
    head: &str,
    path: &str,
) -> Result<Option<String>> {
    for commit in repo.rev_list(head, usize::MAX)? {
        let Some((_mode, oid)) = repo.object_at(&commit, path)? else {
            continue;
        };
        if !repo.blob_starts_with(&oid, MAGIC)? {
            return Ok(Some(commit));
        }
    }
    Ok(None)
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    path: String,
    mode: String,
    scheme: String,
    ciphertext: Bytes,
}

#[derive(Serialize, Deserialize)]
struct Plaintext {
    path: String,
    mode: String,
    scheme: String,
    content: Bytes,
}

fn control_file(path: &str) -> bool {
    if path.starts_with(".mise-history/") {
        return true;
    }
    let Some((root, path)) = path.split_once('/') else {
        return false;
    };
    if root.split('@').next() != Some("config") {
        return false;
    }
    (path.starts_with("conf.d/") && path.ends_with(".toml"))
        || (!path.contains('/')
            && path.ends_with(".toml")
            && (path.starts_with("config.") || path.starts_with("mise.")))
}

fn envelope(repo: &HistoryRepo, object: &Object, limit: u64) -> Result<Option<Envelope>> {
    envelope_in(repo, &repo.gix()?, object, limit)
}

/// [`envelope`] through one open repository, so an audit of many blobs does
/// not scan every pack index once per blob.
fn envelope_in(
    repo: &HistoryRepo,
    objects: &gix::Repository,
    object: &Object,
    limit: u64,
) -> Result<Option<Envelope>> {
    // A gitlink names a commit in another repository, not a readable blob.
    if object.0 == "160000" {
        return Ok(None);
    }
    if !repo.blob_starts_with_in(objects, &object.1, MAGIC)? {
        return Ok(None);
    }
    // Only encrypted envelopes have this limit; do not change plaintext sync.
    let bytes = repo.cat_object_bounded_in(objects, &object.1, limit)?;
    let Some(body) = bytes.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    match rmp_serde::from_slice(body) {
        Ok(outer) => Ok(Some(outer)),
        // two envelopes with markers between them are not one envelope
        Err(_) if body.starts_with(OURS) => Ok(None),
        Err(err) => Err(err).wrap_err("invalid encrypted file envelope"),
    }
}

/// One envelope, parsed from bytes that may instead hold two.
fn parse_envelope(bytes: &[u8]) -> Option<Envelope> {
    let body = bytes.strip_prefix(MAGIC)?;
    let mut cursor = std::io::Cursor::new(body);
    let outer: Envelope = rmp_serde::from_read(&mut cursor).ok()?;
    let used = cursor.position() as usize;
    // Git terminates a side it had to cut with a newline
    let trailing = &body[used..];
    if !trailing.is_empty() && trailing != b"\n" {
        return None;
    }
    if !outer.ciphertext.0.starts_with(b"age-encryption.org/v1\n") {
        return None;
    }
    Some(outer)
}

/// Both sides of the outermost markers, with any markers inside a side kept as
/// that side's text.
fn conflict_sides(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    #[derive(Clone, Copy)]
    enum Side {
        Common,
        Ours,
        Base,
        Theirs,
    }
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    let mut side = Side::Common;
    let mut depth = 0usize;
    let mut seen = false;
    let mut rest = bytes;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|byte| *byte == b'\n') {
            Some(end) => (&rest[..=end], &rest[end + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        let emit = |ours: &mut Vec<u8>, theirs: &mut Vec<u8>, side: Side| match side {
            Side::Common => {
                ours.extend_from_slice(line);
                theirs.extend_from_slice(line);
            }
            Side::Ours => ours.extend_from_slice(line),
            Side::Theirs => theirs.extend_from_slice(line),
            Side::Base => {}
        };
        if line.starts_with(OURS) {
            depth += 1;
            if depth == 1 {
                seen = true;
                side = Side::Ours;
            } else {
                emit(&mut ours, &mut theirs, side);
            }
        } else if line.starts_with(BASE) && depth == 1 {
            side = Side::Base;
        } else if line.strip_suffix(b"\n").unwrap_or(line) == SEP && depth == 1 {
            side = Side::Theirs;
        } else if line.starts_with(THEIRS) {
            if depth == 1 {
                side = Side::Common;
            } else {
                emit(&mut ours, &mut theirs, side);
            }
            depth = depth.saturating_sub(1);
        } else {
            emit(&mut ours, &mut theirs, side);
        }
        rest = next;
    }
    (seen && depth == 0).then_some((ours, theirs))
}

/// Every complete envelope a record holds, one per side, however many merges
/// nested markers in it.
fn record_envelopes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut found = vec![];
    let mut pending = vec![bytes.to_vec()];
    while let Some(candidate) = pending.pop() {
        if parse_envelope(&candidate).is_some() {
            found.push(candidate);
            continue;
        }
        match conflict_sides(&candidate) {
            Some((ours, theirs)) => {
                pending.push(theirs);
                pending.push(ours);
            }
            None => found.push(candidate),
        }
    }
    found
}

/// What a damaged record holds: two envelopes Git merged as text.
#[derive(Debug)]
pub(crate) enum Repair {
    /// Every side decrypts to the same content: one side's envelope is the record.
    Same { envelope: Vec<u8>, object: Object },
    /// The sides hold different content: a real conflict between two versions.
    Conflict { sides: Vec<Object> },
    /// Not a record Git merged as text.
    Intact,
}

/// Decrypt both embedded envelopes. Equal content takes one side; different
/// content is a real conflict, not a record to adopt.
pub(crate) fn repair(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    interactive: bool,
) -> Result<Repair> {
    // Ordinary paths, and files too large to be an envelope, are not records
    // Git merged as text: check the cheap prefix before reading any body.
    if !repo.blob_starts_with(&object.1, MAGIC)?
        || !is_marker_record(&repo.cat_object_bounded(&object.1, agecrypt::MAX_ENCRYPTED_BYTES)?)
    {
        return Ok(Repair::Intact);
    }
    let bytes = repo.cat_object_bounded(&object.1, agecrypt::MAX_ENCRYPTED_BYTES)?;
    let mut found = vec![];
    for candidate in record_envelopes(&bytes) {
        let Some(outer) = parse_envelope(&candidate) else {
            continue;
        };
        if outer.path != path || !matches!(outer.mode.as_str(), "100644" | "100755" | "120000") {
            continue;
        }
        found.push((candidate, open(repo, path, &outer, interactive)?));
    }
    if found.is_empty() {
        bail!("{path} holds merge markers but no complete encrypted file");
    }
    if found.iter().all(|(_, object)| *object == found[0].1) {
        let (envelope, object) = found.swap_remove(0);
        return Ok(Repair::Same { envelope, object });
    }
    Ok(Repair::Conflict {
        sides: found.into_iter().map(|(_, object)| object).collect(),
    })
}

/// Whether two saved sides are the same file once line endings and trailing
/// ASCII whitespace are set aside. An encrypted path is decrypted first.
///
/// Equal means the same mode and, for a regular UTF-8 file, the same text
/// after CRLF becomes LF, spaces and tabs at the end of each line are
/// dropped, and one missing or extra final newline is ignored. Leading
/// whitespace, a lone CR, and any other byte stay significant. A symlink,
/// a file with a NUL, and invalid UTF-8 are equal only byte for byte.
/// A read or decryption failure is returned, never treated as equality.
pub(crate) fn normalized_equal(
    repo: &HistoryRepo,
    path: &str,
    left: &Object,
    right: &Object,
    interactive: bool,
) -> Result<bool> {
    if left == right {
        return Ok(true);
    }
    let (left_mode, left_bytes) = body(repo, path, left, interactive)?;
    let (right_mode, right_bytes) = body(repo, path, right, interactive)?;
    // An envelope is always stored as a regular file. The mode that matters
    // is the one recovered from it, so two encrypted executables compare as
    // executables even though both outer objects are 100644.
    if left_mode != right_mode {
        return Ok(false);
    }
    if left_bytes == right_bytes {
        return Ok(true);
    }
    // Only a regular file has a line ending to normalize. A symlink target
    // and a binary file are equal only byte for byte, decided above.
    if !matches!(left_mode.as_str(), "100644" | "100755")
        || !utf8_text(&left_bytes)
        || !utf8_text(&right_bytes)
    {
        return Ok(false);
    }
    Ok(normalized_lines(&left_bytes).eq(normalized_lines(&right_bytes)))
}

/// The mode the file was saved with, and its bytes. An envelope yields the
/// mode inside it; anything else yields the object's own mode.
fn body(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    interactive: bool,
) -> Result<(String, Vec<u8>)> {
    if repo.blob_starts_with(&object.1, MAGIC)? {
        let decrypted = decrypt(repo, path, object, interactive)?;
        return Ok((decrypted.0, repo.cat_object(&decrypted.1)?));
    }
    Ok((object.0.clone(), repo.cat_object(&object.1)?))
}

pub(crate) fn utf8_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}
/// A structured three-way merge, or the reason one was not made.
#[derive(Debug)]
pub(crate) enum KeyMerge {
    /// Local and remote parse to the same value: keep the local object.
    KeepLocal,
    /// The merged text, in the mode the file was saved with.
    Merged { mode: String, text: Vec<u8> },
    /// The three sides parse, and a key was changed differently on both.
    Clash,
    /// Not a structured path, or a side that this tier must not parse.
    Inapplicable,
}

const STRUCTURED_LIMIT: u64 = 1024 * 1024;

/// Merge a `.json`, `.toml`, `.yaml`, or `.yml` conflict by key.
///
/// Called only for a path the cheaper tiers left unsettled. A side that is
/// not a regular file, is larger than 1 MiB, or does not parse leaves the
/// path to those tiers. Equal parsed values keep the local object. A key
/// changed differently on both sides, including a deletion against an edit,
/// is a clash: the caller must not hide it with a line merge.
pub(crate) fn merge_by_key(
    repo: &HistoryRepo,
    path: &str,
    base: &Object,
    local: &Object,
    remote: &Object,
    interactive: bool,
) -> Result<KeyMerge> {
    let Some(format) = structured_format(path) else {
        return Ok(KeyMerge::Inapplicable);
    };
    let (base_mode, base_bytes) = bounded_body(repo, path, base, interactive)?;
    let (local_mode, local_bytes) = bounded_body(repo, path, local, interactive)?;
    let (remote_mode, remote_bytes) = bounded_body(repo, path, remote, interactive)?;
    let (Some(base_bytes), Some(local_bytes), Some(remote_bytes)) =
        (base_bytes, local_bytes, remote_bytes)
    else {
        return Ok(KeyMerge::Inapplicable);
    };
    if base_mode != local_mode || local_mode != remote_mode {
        return Ok(KeyMerge::Inapplicable);
    }
    if !matches!(local_mode.as_str(), "100644" | "100755") {
        return Ok(KeyMerge::Inapplicable);
    }
    let (Some(base_text), Some(local_text), Some(remote_text)) = (
        std::str::from_utf8(&base_bytes).ok(),
        std::str::from_utf8(&local_bytes).ok(),
        std::str::from_utf8(&remote_bytes).ok(),
    ) else {
        return Ok(KeyMerge::Inapplicable);
    };
    super::key_merge::merge(format, local_mode, base_text, local_text, remote_text)
        .map(|merged| merged.unwrap_or(KeyMerge::Inapplicable))
}

fn structured_format(path: &str) -> Option<super::key_merge::Format> {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let extension = name.rsplit_once('.')?.1;
    match extension {
        "json" => Some(super::key_merge::Format::Json),
        "toml" => Some(super::key_merge::Format::Toml),
        "yaml" | "yml" => Some(super::key_merge::Format::Yaml),
        _ => None,
    }
}

/// The saved mode and bytes, or `None` when the object is not a readable
/// blob within the structured-file limit. An envelope is decrypted first.
fn bounded_body(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    interactive: bool,
) -> Result<(String, Option<Vec<u8>>)> {
    if repo.blob_starts_with(&object.1, MAGIC)? {
        let decrypted = decrypt(repo, path, object, interactive)?;
        let bytes = bounded_blob(repo, &decrypted.1)?;
        return Ok((decrypted.0, bytes));
    }
    Ok((object.0.clone(), bounded_blob(repo, &object.1)?))
}

fn bounded_blob(repo: &HistoryRepo, oid: &str) -> Result<Option<Vec<u8>>> {
    match repo.cat_object_bounded(oid, STRUCTURED_LIMIT) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.to_string().contains("exceeds") => Ok(None),
        Err(err) => Err(err),
    }
}

/// Lines with CRLF reduced to LF, trailing ASCII spaces and tabs removed,
/// and one missing final newline supplied. No allocation when the line
/// already has that shape.
fn normalized_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split_inclusive(|byte| *byte == b'\n').map(|line| {
        // A CR counts as a line ending only when LF follows it. A line that
        // has no LF, including the last line, keeps a trailing CR.
        let line = match line.strip_suffix(b"\n") {
            Some(ended) => ended.strip_suffix(b"\r").unwrap_or(ended),
            None => line,
        };
        let end = line
            .iter()
            .rposition(|byte| *byte != b' ' && *byte != b'\t')
            .map_or(0, |index| index + 1);
        &line[..end]
    })
}

/// Whether a record merged as text still holds only envelopes of this path.
fn record_of_envelopes_in(
    repo: &HistoryRepo,
    objects: &gix::Repository,
    object: &Object,
    path: &str,
) -> Result<bool> {
    if !repo.blob_starts_with_in(objects, &object.1, MAGIC)? {
        return Ok(false);
    }
    let bytes = repo.cat_object_bounded_in(objects, &object.1, agecrypt::MAX_ENCRYPTED_BYTES)?;
    if !is_marker_record(&bytes) {
        return Ok(false);
    }
    let envelopes = record_envelopes(&bytes);
    Ok(!envelopes.is_empty()
        && envelopes.iter().all(|candidate| {
            parse_envelope(candidate).is_some_and(|outer| {
                outer.path == path && matches!(outer.mode.as_str(), "100644" | "100755" | "120000")
            })
        }))
}

fn open(repo: &HistoryRepo, path: &str, outer: &Envelope, interactive: bool) -> Result<Object> {
    let bytes = agecrypt::decrypt_sync(&outer.ciphertext.0, interactive).map_err(|err| {
        // a damaged file is not one another key would unlock, so it is not
        // collected with the locked ones: it fails as itself
        if matches!(
            err.downcast_ref::<agecrypt::DecryptError>(),
            Some(agecrypt::DecryptError::Corrupt(_))
        ) {
            err.wrap_err(format!("{path} is not a readable encrypted file"))
        } else {
            err.wrap_err(Locked(path.to_string()))
        }
    })?;
    let inner: Plaintext =
        rmp_serde::from_slice(&bytes).wrap_err("invalid encrypted file payload")?;
    validate(path, outer, &inner)?;
    let oid = repo.transient_blob_id(&inner.content.0)?;
    Ok((inner.mode, oid))
}

fn validate(path: &str, outer: &Envelope, inner: &Plaintext) -> Result<()> {
    if outer.path != path
        || inner.path != path
        || inner.mode != outer.mode
        || inner.scheme != outer.scheme
        || !layout::is_safe_branch_path(path)
        || !matches!(inner.mode.as_str(), "100644" | "100755" | "120000")
    {
        bail!("encrypted file does not match its path or mode: {path}");
    }
    Ok(())
}

/// The context of a decryption that failed because no identity this machine
/// holds unlocks the file, so a caller can tell it from a damaged envelope.
#[derive(Debug)]
pub(crate) struct Locked(pub String);

impl std::fmt::Display for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot unlock {}; run mise dot pull interactively with a matching age identity",
            self.0
        )
    }
}

/// An encrypt-declared path whose origin version is not an encrypted
/// envelope. It is a per-path condition, not a broken repository: the
/// version can be taken as it is, or replaced by the encrypted version this
/// machine publishes, without touching any other path.
#[derive(Debug)]
pub(crate) struct PlaintextInEncryptedPath(pub String);

impl std::fmt::Display for PlaintextInEncryptedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing encrypted file envelope: {}", self.0)
    }
}

impl std::error::Error for PlaintextInEncryptedPath {}

/// The plaintext mode recorded in an encrypted envelope, without decrypting it.
/// `None` when the object is not an envelope, including a marker record Git
/// merged as text.
pub fn plaintext_mode(repo: &HistoryRepo, object: &Object) -> Result<Option<String>> {
    Ok(envelope(repo, object, agecrypt::MAX_ENCRYPTED_BYTES)?.map(|outer| outer.mode))
}

pub fn decrypt(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    interactive: bool,
) -> Result<Object> {
    let envelope = envelope(repo, object, agecrypt::MAX_ENCRYPTED_BYTES)?;
    if control_file(path) {
        bail!("setup configuration itself cannot be encrypted: {path}");
    }
    // An envelope is bound to one path: a cached decryption of the same blob
    // must not stand in for another path.
    if envelope.as_ref().is_some_and(|outer| outer.path != path) {
        bail!("encrypted file does not match its path: {path}");
    }
    if let Some(decrypted) = repo.decrypted_object(&object.1) {
        return Ok(decrypted);
    }
    let Some(outer) = envelope else {
        // the only other thing mise saves at an encrypted path is a record
        // Git merged as text, which holds the two sides' envelopes
        return match repair(repo, path, object, interactive)? {
            Repair::Same {
                object: decrypted, ..
            } => {
                repo.remember_decrypted(&object.1, decrypted.clone());
                Ok(decrypted)
            }
            Repair::Conflict { sides } => bail!(
                "{path} holds two different saved versions Git merged as text; resolve which one stands: {}",
                sides
                    .iter()
                    .map(|(mode, oid)| format!("{mode} {oid}"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
            // not a record and not an envelope: a plaintext version of an
            // encrypted path, which the reconcile step turns into one path's
            // conflict instead of failing every sync
            Repair::Intact => Err(eyre::Report::new(PlaintextInEncryptedPath(
                path.to_string(),
            ))),
        };
    };
    let decrypted = open(repo, path, &outer, interactive)?;
    repo.remember_decrypted(&object.1, decrypted.clone());
    Ok(decrypted)
}

/// Whether `object` already holds `content` at `path` for the recipients
/// `scheme` names, so a save can keep that ciphertext. Encryption is
/// randomized: without this, a machine with no encryption cache, such as one
/// that just adopted the setup, rewrites every encrypted file it saves, and
/// that rewrite conflicts with the next real edit from another machine.
pub(crate) fn holds(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    mode: &str,
    content: &[u8],
    scheme: &str,
) -> bool {
    // a record Git merged as text is rewritten by this save, not kept: its
    // sides hold the same content, and one clean envelope replaces it
    if repo
        .cat_object_bounded(&object.1, agecrypt::MAX_ENCRYPTED_BYTES)
        .is_ok_and(|bytes| is_marker_record(&bytes))
    {
        return false;
    }
    let Ok(Some(outer)) = envelope(repo, object, agecrypt::MAX_ENCRYPTED_BYTES) else {
        return false;
    };
    if outer.scheme != scheme || outer.mode != mode {
        return false;
    }
    let Ok(decrypted) = decrypt(repo, path, object, false) else {
        return false;
    };
    decrypted.0 == mode
        && repo
            .transient_blob_id(content)
            .is_ok_and(|oid| oid == decrypted.1)
}

fn encrypt(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    scheme: &str,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<Object> {
    let content = repo.cat_object_bounded(&object.1, agecrypt::MAX_PLAINTEXT_BYTES)?;
    let encoded = encode(path, &object.0, &content, scheme, recipients)?;
    let encrypted = ("100644".into(), repo.hash_blob(&encoded)?);
    repo.remember_decrypted(&encrypted.1, object.clone());
    Ok(encrypted)
}

pub(crate) fn seal(
    repo: &HistoryRepo,
    path: &str,
    mode: &str,
    content: &[u8],
    scheme: &str,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<Object> {
    let plain = (mode.to_string(), repo.hash_blob(content)?);
    encrypt(repo, path, &plain, scheme, recipients)
}

pub(crate) fn scheme_of(repo: &HistoryRepo, object: &Object) -> Result<String> {
    envelope(repo, object, agecrypt::MAX_ENCRYPTED_BYTES)?
        .map(|outer| outer.scheme)
        .ok_or_else(|| eyre::eyre!("saved object is not an encrypted envelope"))
}

pub(crate) fn recipients_of(
    repo: &HistoryRepo,
    tree: &str,
    path: &str,
    object: &Object,
) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    let _ = envelope(repo, object, agecrypt::MAX_ENCRYPTED_BYTES)?
        .ok_or_else(|| eyre::eyre!("{path} is not an encrypted envelope"))?;
    let manifest = crate::history::manifest::Manifest::read(repo, tree)?
        .ok_or_else(|| eyre::eyre!("{path} has no encryption recipients"))?;
    let (strings, _) = scheme(&manifest.recipients);
    parse_recipients(&strings, false)
}

/// Turn a reconciled process-local object into its committed representation.
/// Reuse an unchanged envelope; a merged plaintext is encrypted before hashing.
pub(super) fn commit_object(
    repo: &HistoryRepo,
    path: &str,
    object: &Object,
    manifest: &crate::history::manifest::Manifest,
    parents: &[&str],
    interactive: bool,
) -> Result<Object> {
    if !manifest.encrypted_paths().iter().any(|prefix| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }) {
        return Ok(object.clone());
    }
    let (strings, scheme) = scheme(&manifest.recipients);
    for parent in parents {
        if let Some(raw) = repo.object_at(parent, path)?
            && envelope(repo, &raw, agecrypt::MAX_ENCRYPTED_BYTES)?
                .is_some_and(|outer| outer.scheme == scheme)
            && decrypt(repo, path, &raw, interactive)? == *object
        {
            return Ok(raw);
        }
    }
    let recipients = parse_recipients(&strings, interactive)?;
    encrypt(repo, path, object, &scheme, &recipients)
}

/// The normalized recipient list and the scheme an envelope records for it.
fn scheme(recipients: &[String]) -> (Vec<String>, String) {
    let mut strings = recipients.to_vec();
    strings.sort();
    strings.dedup();
    let scheme = mise_util::hash::hash_sha256_to_str(&strings.join("\n"));
    (strings, scheme)
}

fn parse_recipients(
    strings: &[String],
    interactive: bool,
) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    strings
        .iter()
        .map(|recipient| {
            agecrypt::parse_recipient_mode(recipient, interactive)?
                .ok_or_else(|| eyre::eyre!("invalid age recipient: {recipient}"))
        })
        .collect()
}

/// Re-encrypt every encrypted file in `tree` whose envelope names other
/// recipients than the tree's manifest, keeping the contents the tree holds:
/// a saved version is never replaced by live contents. Returns the new tree
/// and the paths whose recipients changed since `previous`, both those
/// re-encrypted here and those the capture already encrypted afresh. When
/// this machine cannot unlock a file, refuses and names each one, replacing
/// nothing.
pub(crate) fn re_encrypt(
    repo: &HistoryRepo,
    tree: &str,
    previous: Option<&str>,
    interactive: bool,
) -> Result<(String, Vec<String>)> {
    let Some(manifest) = crate::history::manifest::Manifest::read(repo, tree)? else {
        return Ok((tree.into(), vec![]));
    };
    let encrypted = encrypted_paths(repo, Some(tree))?;
    let (strings, scheme) = scheme(&manifest.recipients);
    let mut recipients = None;
    let mut overlays = vec![];
    let mut locked = vec![];
    // files the capture read live are already encrypted to the current
    // recipients; they count when the previous checkpoint used others
    let mut captured = vec![];
    for entry in repo.ls_tree(tree)? {
        if !encrypted.contains(&entry.path) {
            continue;
        }
        let object = (entry.mode, entry.oid);
        // a file outside an envelope is the publish audit's to refuse
        let Some(outer) = envelope(repo, &object, agecrypt::MAX_ENCRYPTED_BYTES)? else {
            continue;
        };
        if outer.scheme == scheme {
            if let Some(previous) = previous
                && let Some(before) = repo.object_at(previous, &entry.path)?
                && envelope(repo, &before, agecrypt::MAX_ENCRYPTED_BYTES)?
                    .is_some_and(|before| before.scheme != scheme)
            {
                captured.push(entry.path);
            }
            continue;
        }
        let plain = match decrypt(repo, &entry.path, &object, interactive) {
            Ok(plain) => plain,
            Err(err) => {
                debug!("history: {err:#}");
                locked.push(crate::history::tracked::tree_path_to_display(&entry.path));
                continue;
            }
        };
        let recipients = match &recipients {
            Some(recipients) => recipients,
            None => recipients.insert(parse_recipients(&strings, interactive)?),
        };
        let object = encrypt(repo, &entry.path, &plain, &scheme, recipients)?;
        overlays.push(crate::history::shadow::Overlay {
            path: entry.path,
            object: Some(object),
        });
    }
    if !locked.is_empty() {
        bail!(
            "cannot re-encrypt {}: no age identity on this machine unlocks them; nothing was saved. Run `mise dot save --re-encrypt` where they can be unlocked",
            locked.join(", ")
        );
    }
    let paths = overlays
        .iter()
        .map(|overlay| overlay.path.clone())
        .chain(captured)
        .collect();
    Ok((repo.compose(tree, &overlays)?, paths))
}

/// Encrypt bytes before they enter Git. Callers may store only the returned
/// envelope, never the input or the decrypted payload in repository objects.
pub(crate) fn encode(
    path: &str,
    mode: &str,
    content: &[u8],
    scheme: &str,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<Vec<u8>> {
    if control_file(path) {
        bail!("encrypt an external dotfile source instead of configuration: {path}");
    }
    if !matches!(mode, "100644" | "100755" | "120000") {
        bail!("unsupported encrypted file mode: {path}");
    }
    let inner = Plaintext {
        path: path.into(),
        mode: mode.into(),
        scheme: scheme.into(),
        content: Bytes(content.to_vec()),
    };
    let bytes = rmp_serde::to_vec_named(&inner)?;
    let outer = Envelope {
        path: path.into(),
        mode: mode.into(),
        scheme: scheme.into(),
        ciphertext: Bytes(agecrypt::encrypt_bytes(&bytes, recipients)?),
    };
    let mut encoded = MAGIC.to_vec();
    encoded.extend(rmp_serde::to_vec_named(&outer)?);
    if encoded.len() as u64 > agecrypt::MAX_ENCRYPTED_BYTES {
        bail!("encrypted file exceeds the size limit: {path}");
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    #[test]
    fn audit_reuses_verified_ancestry_but_rechecks_new_encryption_policy() {
        use crate::history::manifest::{Enrollment, Manifest};
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let tree = repo
            .write_tree(&[(
                "100644".into(),
                repo.hash_blob(b"plain").unwrap(),
                "home/secret".into(),
            )])
            .unwrap();
        let first = repo.commit_tree(&tree, vec![], "first").unwrap();
        assert_eq!(
            audit_history_cached(&repo, &first, &BTreeSet::new()).unwrap(),
            1
        );
        assert_eq!(
            audit_history_cached(&repo, &first, &BTreeSet::new()).unwrap(),
            0
        );
        let second = repo.commit_tree(&tree, vec![&first], "second").unwrap();
        assert_eq!(
            audit_history_cached(&repo, &second, &BTreeSet::new()).unwrap(),
            1
        );

        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let encrypted = repo
            .hash_blob(&encode("home/secret", "100644", b"plain", "test", &recipients).unwrap())
            .unwrap();
        let encrypted_tree = repo
            .write_tree(&[("100644".into(), encrypted, "home/secret".into())])
            .unwrap();
        let manifest = Manifest {
            enrollment: vec![Enrollment {
                path: "home/secret".into(),
                autosave: true,
                encrypt: true,
                allow_plaintext: None,
                variants: vec![],
                exclude: None,
                include: None,
            }],
            ..Default::default()
        };
        let encrypted_tree = manifest.write(&repo, &encrypted_tree).unwrap();
        let encrypted = repo
            .commit_tree(&encrypted_tree, vec![&second], "encrypt now")
            .unwrap();
        // No caller-supplied policy is needed: the new manifest expands the
        // protected set and forces the earlier plaintext commits to be checked.
        assert!(audit_history_cached(&repo, &encrypted, &BTreeSet::new()).is_err());

        // An unrelated branch cannot reuse proof about the previous branch.
        let other = repo.commit_tree(&tree, vec![], "unrelated").unwrap();
        assert_eq!(
            audit_history_cached(&repo, &other, &BTreeSet::new()).unwrap(),
            1
        );
        // A live policy change at the same head also invalidates the proof.
        assert!(
            audit_history_cached(&repo, &other, &BTreeSet::from(["home/secret".into()])).is_err()
        );
    }

    /// A verified ancestry written beside the history repository must skip
    /// that history after this process forgets it. Clearing only the
    /// in-memory proof must not force the commits to be read again, and a
    /// later plaintext version of a protected path must still be refused.
    #[test]
    fn persisted_audit_proof_skips_verified_history() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        // a repository path, not a machine path: no home directory is read
        let path = "tracked/home/secret"; // portable-home-ok
        let cipher = repo
            .hash_blob(&encode(path, "100644", b"private", "test", &recipients).unwrap())
            .unwrap();
        let tree = repo
            .write_tree(&[("100644".into(), cipher, path.into())])
            .unwrap();
        let head = repo
            .commit_tree(&tree, vec![], "encrypted from the first commit")
            .unwrap();
        let protected = BTreeSet::from([path.to_string()]);

        assert!(
            audit_history_cached(&repo, &head, &protected).unwrap() > 0,
            "the first audit must read the history"
        );
        // This process still remembers the audit. Drop only that memory, as
        // a fresh process would, and require the proof beside the repository
        // to carry it. The removal is this repository alone.
        AUDITS.lock().unwrap().remove(repo.dir());
        assert_eq!(
            audit_history_cached(&repo, &head, &protected).unwrap(),
            0,
            "a verified proof beside the repository must skip the history"
        );

        let plain = repo.hash_blob(b"private").unwrap();
        let exposed = repo
            .write_tree(&[("100644".into(), plain, path.into())])
            .unwrap();
        let exposed = repo
            .commit_tree(&exposed, vec![&head], "plaintext after encryption")
            .unwrap();
        assert!(
            audit_history_cached(&repo, &exposed, &protected).is_err(),
            "a new protected plaintext version must still be refused"
        );
    }

    /// A proof that does not belong to this repository, or that no longer
    /// describes its history, is not proof. Each case forgets only this
    /// repository's memory and must read the history again.
    #[test]
    fn a_proof_that_does_not_belong_to_this_repository_is_not_proof() {
        let (_tmp, repo, head, protected) = audited_history();
        let proof = std::fs::read(proof_file(repo.dir())).unwrap();
        let secret = std::fs::read(proof_secret(repo.dir())).unwrap();

        // Bytes appended after a valid envelope are not a valid proof.
        let mut appended = proof.clone();
        appended.extend_from_slice(b"\nforged");
        forget_and_replace(&repo, &appended);
        assert!(
            audit_history_cached(&repo, &head, &protected).unwrap() > 0,
            "an appended proof must be audited again"
        );

        // A corrupt file is not a proof, even beside the right secret.
        forget_and_replace(&repo, b"not a proof");
        assert!(
            audit_history_cached(&repo, &head, &protected).unwrap() > 0,
            "a corrupt proof must be audited again"
        );

        // A verified head that is not an ancestor of the proposed head is
        // not proof about that head.
        let unrelated = repo
            .commit_tree(&repo.mktree("").unwrap(), vec![], "other")
            .unwrap();
        let foreign = signed_proof(
            &secret,
            &repository_identity(repo.dir()).unwrap(),
            &unrelated,
            &protected,
        );
        forget_and_replace(&repo, &serde_json::to_vec(&foreign).unwrap());
        assert!(
            audit_history_cached(&repo, &head, &protected).unwrap() > 0,
            "a non-ancestor proof must be audited again"
        );

        // The proof covers only the original path. Asking about a larger set
        // must read the history again: the old proof says nothing about the
        // new path. Restore that original proof first; a proof signed for the
        // grown set would legitimately skip it.
        forget_and_replace(&repo, &proof);
        let grown = BTreeSet::from(["tracked/home/secret".into(), "tracked/home/other".into()]); // portable-home-ok
        assert!(
            audit_history_cached(&repo, &head, &grown).unwrap() > 0,
            "a grown protected set must be audited again"
        );
        // The new path's older plaintext is what that reread has to find.
        let other = repo.hash_blob(b"older plaintext").unwrap();
        let exposed = repo
            .write_tree(&[
                (
                    "100644".into(),
                    repo.object_at(&head, "tracked/home/secret") // portable-home-ok
                        .unwrap()
                        .unwrap()
                        .1,
                    "tracked/home/secret".into(), // portable-home-ok
                ),
                ("100644".into(), other, "tracked/home/other".into()), // portable-home-ok
            ])
            .unwrap();
        let exposed = repo
            .commit_tree(&exposed, vec![&head], "plaintext on a newly protected path")
            .unwrap();
        AUDITS.lock().unwrap().remove(repo.dir());
        assert!(
            audit_history_cached(&repo, &exposed, &grown).is_err(),
            "older plaintext on a newly protected path must be refused"
        );

        // A protected object that wears the envelope magic but is not an
        // envelope is not an encrypted version. The proof of the valid
        // parent does not cover it.
        let malformed = repo
            .hash_blob(b"mise-encrypted-file-v1\nnot-an-envelope")
            .unwrap();
        let malformed_tree = repo
            .write_tree(&[("100644".into(), malformed, "tracked/home/secret".into())]) // portable-home-ok
            .unwrap();
        let malformed_head = repo
            .commit_tree(&malformed_tree, vec![&head], "malformed envelope")
            .unwrap();
        AUDITS.lock().unwrap().remove(repo.dir());
        assert!(
            audit_history_cached(&repo, &malformed_head, &protected).is_err(),
            "a malformed envelope must be refused"
        );

        // The same history in another repository does not make this
        // repository's proof belong there. The secret does not travel.
        let other = tempfile::tempdir().unwrap();
        let other = HistoryRepo::open_or_init_in(other.path()).unwrap().unwrap();
        let copied = other
            .commit_tree(&other.mktree("").unwrap(), vec![], "copied")
            .unwrap();
        audit_history_cached(&other, &copied, &BTreeSet::new()).unwrap();
        AUDITS.lock().unwrap().remove(other.dir());
        std::fs::write(proof_file(other.dir()), &proof).unwrap();
        assert!(
            audit_history_cached(&other, &copied, &BTreeSet::new()).unwrap() > 0,
            "a copied proof must not vouch for another repository"
        );

        // A proof written under different rules is not this version's proof.
        let mut wrong = serde_json::from_slice::<DurableProof>(&proof).unwrap();
        wrong.rules = AUDIT_RULES_VERSION + 1;
        forget_and_replace(&repo, &serde_json::to_vec(&wrong).unwrap());
        assert!(
            audit_history_cached(&repo, &head, &protected).unwrap() > 0,
            "a wrong rules version must be audited again"
        );
    }

    fn audited_history() -> (tempfile::TempDir, HistoryRepo, String, BTreeSet<String>) {
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let path = "tracked/home/secret"; // portable-home-ok
        let cipher = repo
            .hash_blob(&encode(path, "100644", b"private", "test", &recipients).unwrap())
            .unwrap();
        let tree = repo
            .write_tree(&[("100644".into(), cipher, path.into())])
            .unwrap();
        let head = repo.commit_tree(&tree, vec![], "encrypted").unwrap();
        let protected = BTreeSet::from([path.to_string()]);
        audit_history_cached(&repo, &head, &protected).unwrap();
        (tmp, repo, head, protected)
    }

    fn forget_and_replace(repo: &HistoryRepo, proof: &[u8]) {
        AUDITS.lock().unwrap().remove(repo.dir());
        std::fs::write(proof_file(repo.dir()), proof).unwrap();
    }

    #[test]
    fn encrypted_tip_does_not_hide_plaintext_in_ancestry_or_merge_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        let path = "home/secret";
        let plain = repo.hash_blob(b"private").unwrap();
        let cipher = repo
            .hash_blob(&encode(path, "100644", b"private", "test", &recipients).unwrap())
            .unwrap();
        let empty = repo.empty_object("tree").unwrap();
        let make_tree = |oid: String| {
            repo.compose(
                &empty,
                &[crate::history::shadow::Overlay {
                    path: path.into(),
                    object: Some(("100644".into(), oid)),
                }],
            )
            .unwrap()
        };
        let plain_tree = make_tree(plain);
        let encrypted_tree = make_tree(cipher);
        let exposed = repo.commit_tree(&plain_tree, vec![], "plaintext").unwrap();
        let encrypted = repo
            .commit_tree(&encrypted_tree, vec![&exposed], "encrypted now")
            .unwrap();
        let protected = BTreeSet::from([path.into()]);
        assert!(audit_history(&repo, &encrypted, &protected).is_err());
        let clean = repo
            .commit_tree(&encrypted_tree, vec![], "encrypted from first commit")
            .unwrap();
        audit_history(&repo, &clean, &protected).unwrap();
        let merge = repo
            .commit_tree(&encrypted_tree, vec![&clean, &exposed], "merge")
            .unwrap();
        assert!(audit_history(&repo, &merge, &protected).is_err());
    }

    #[test]
    fn plaintext_magic_is_not_an_encryption_declaration() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let oid = repo.hash_blob(MAGIC).unwrap();
        let tree = repo
            .write_tree(&[("100644".into(), oid.clone(), "tracked/home/literal".into())])
            .unwrap();
        let upstream = super::super::reconcile::upstream(&repo, Some(&tree)).unwrap();
        assert_eq!(upstream.files["tracked/home/literal"].1, oid);
        assert!(encrypted_paths(&repo, Some(&tree)).unwrap().is_empty());
    }
    use super::*;

    #[test]
    fn plaintext_bypasses_envelope_limit_but_ciphertext_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let larger_than_pipe = vec![b'x'; 128 * 1024];
        for bytes in [
            b"".as_slice(),
            b"ordinary plaintext longer than the envelope limit".as_slice(),
            larger_than_pipe.as_slice(),
        ] {
            let object = ("100644".into(), repo.hash_blob(bytes).unwrap());
            assert!(envelope(&repo, &object, 4).unwrap().is_none());
        }
        let object = ("100644".into(), repo.hash_blob(MAGIC).unwrap());
        assert!(envelope(&repo, &object, 4).is_err());
        // The referenced submodule commit need not exist in the setup repo.
        let gitlink = ("160000".into(), "a".repeat(40));
        assert!(envelope(&repo, &gitlink, 4).unwrap().is_none());
    }

    #[test]
    fn envelope_preserves_modes_and_binds_path_and_scheme() {
        use age::secrecy::ExposeSecret;
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        for mode in ["100644", "100755", "120000"] {
            let object = (
                mode.into(),
                repo.transient_blob_id(b"private contents").unwrap(),
            );
            let encrypted =
                encrypt(&repo, "tracked/home/secret", &object, "scheme", &recipients).unwrap();
            assert_eq!(encrypted.0, "100644");
            let wire = repo.cat_object(&encrypted.1).unwrap();
            assert!(!wire.windows(16).any(|w| w == b"private contents"));
            assert_eq!(
                decrypt(&repo, "tracked/home/secret", &encrypted, false).unwrap(),
                object
            );
            assert!(repo.object_type(&object.1).unwrap().is_none());
            assert!(
                repo.list_refs("refs/mise-decrypted-files/")
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(repo.cat_object(&object.1).unwrap(), b"private contents");
            assert!(decrypt(&repo, "tracked/home/other", &encrypted, false).is_err());
            let mut outer = envelope(&repo, &encrypted, agecrypt::MAX_ENCRYPTED_BYTES)
                .unwrap()
                .unwrap();
            outer.scheme = "forged".into();
            let inner = Plaintext {
                path: outer.path.clone(),
                mode: mode.into(),
                scheme: "scheme".into(),
                content: Bytes(vec![]),
            };
            assert!(validate("tracked/home/secret", &outer, &inner).is_err());
        }
    }

    #[test]
    fn a_record_git_merged_as_text_resolves_by_decrypted_content() {
        use age::secrecy::ExposeSecret;
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(key.to_public())];
        // a repository path, not a machine path: no home directory is read
        let path = "tracked/home/secret"; // portable-home-ok
        // What Git writes when it merges two envelopes as text: the magic line
        // is common, and each side keeps its own envelope body.
        let merged_record = |left: &[u8], right: &[u8]| -> Object {
            let ours = encode(path, "100644", left, "scheme", &recipients).unwrap();
            let theirs = encode(path, "100644", right, "scheme", &recipients).unwrap();
            assert_ne!(ours, theirs, "encryption is randomized");
            let mut merged = MAGIC.to_vec();
            merged.extend_from_slice(OURS);
            merged.extend_from_slice(b"left\n");
            merged.extend_from_slice(&ours[MAGIC.len()..]);
            merged.extend_from_slice(b"\n=======\n");
            merged.extend_from_slice(&theirs[MAGIC.len()..]);
            merged.extend_from_slice(b"\n>>>>>>> right\n");
            ("100644".into(), repo.hash_blob(&merged).unwrap())
        };

        // The same content on both sides: the record reads as that content,
        // nothing plaintext enters history through it, and a save rewrites it.
        let same = merged_record(b"one saved version", b"one saved version");
        let expected = (
            "100644".into(),
            repo.transient_blob_id(b"one saved version").unwrap(),
        );
        assert_eq!(decrypt(&repo, path, &same, false).unwrap(), expected);
        assert!(!holds(
            &repo,
            path,
            &same,
            "100644",
            b"one saved version",
            "scheme"
        ));
        assert!(record_of_envelopes_in(&repo, &repo.gix().unwrap(), &same, path).unwrap());
        // the same record under another path is not that path's record
        let other = "tracked/home/other"; // portable-home-ok
        assert!(!record_of_envelopes_in(&repo, &repo.gix().unwrap(), &same, other).unwrap());

        // Different content is a real conflict, not a record to adopt.
        let conflict = merged_record(b"left version", b"right version");
        let err = decrypt(&repo, path, &conflict, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("two different saved versions"),
            "{err:#}"
        );
        match repair(&repo, path, &conflict, false).unwrap() {
            Repair::Conflict { sides } => assert_eq!(sides.len(), 2),
            other => panic!("expected a conflict, got {other:?}"),
        }
        // and one equal record still yields an envelope a save can keep
        match repair(&repo, path, &same, false).unwrap() {
            Repair::Same { envelope, .. } => assert!(parse_envelope(&envelope).is_some()),
            other => panic!("expected one side, got {other:?}"),
        }
    }

    #[test]
    fn a_damaged_ciphertext_is_not_reported_as_locked() {
        use age::secrecy::ExposeSecret;
        let tmp = tempfile::tempdir().unwrap();
        let repo = HistoryRepo::open_or_init_in(tmp.path()).unwrap().unwrap();
        let key = age::x25519::Identity::generate();
        let mut environment = mise_util::testing::EnvVarGuard::new();
        environment.set("MISE_AGE_KEY", key.to_string().expose_secret());
        let outer = Envelope {
            path: "tracked/home/secret".into(),
            mode: "100644".into(),
            scheme: "scheme".into(),
            ciphertext: Bytes(b"not an age file".to_vec()),
        };
        let mut encoded = MAGIC.to_vec();
        encoded.extend(rmp_serde::to_vec_named(&outer).unwrap());
        let object = ("100644".into(), repo.hash_blob(&encoded).unwrap());
        let err = decrypt(&repo, "tracked/home/secret", &object, false).unwrap_err();
        assert!(err.downcast_ref::<Locked>().is_none(), "{err:#}");
        assert!(
            format!("{err:#}").contains("is not a readable encrypted file"),
            "{err:#}"
        );

        // and one this machine's key does not open is
        let other: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(age::x25519::Identity::generate().to_public())];
        let sealed = repo
            .hash_blob(
                &encode(
                    "tracked/home/secret",
                    "100644",
                    b"private",
                    "scheme",
                    &other,
                )
                .unwrap(),
            )
            .unwrap();
        let err = decrypt(
            &repo,
            "tracked/home/secret",
            &("100644".into(), sealed),
            false,
        )
        .unwrap_err();
        assert!(err.downcast_ref::<Locked>().is_some(), "{err:#}");
    }

    #[test]
    fn refuses_encryption_of_control_configuration() {
        assert!(control_file("config/config.toml"));
        assert!(control_file("config/conf.d/tools.toml"));
        assert!(control_file("config@macos/config.toml"));
        assert!(!control_file("templates/app.toml"));
        assert!(!control_file("home/config.toml"));
    }
}
