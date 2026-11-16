//! Recognize preserved Git conflict records without treating ciphertext as text.
//!
//! MessagePack gives each alternative's exact byte extent. Only Git's complete
//! framing may remain between those extents; no plaintext is ignored or selected.

use std::io::Cursor;

use eyre::Result;
use serde::Deserialize;

use super::{Envelope, HistoryRepo, MAGIC, Object, agecrypt, sealed_for};

pub(super) fn sealed(repo: &HistoryRepo, object: &Object, path: &str) -> Result<bool> {
    if !repo.blob_starts_with(&object.1, MAGIC)? {
        return Ok(false);
    }
    let bytes = repo.cat_object_bounded(&object.1, agecrypt::MAX_ENCRYPTED_BYTES)?;
    Ok(bytes
        .strip_prefix(MAGIC)
        .is_some_and(|body| alternatives(body, path).is_some()))
}

fn alternatives(mut body: &[u8], path: &str) -> Option<()> {
    body = marker(body, b"<<<<<<< ")?;
    body = alternative(body, path)?;
    // Git inserts one newline when a binary envelope has no final newline.
    body = body.strip_prefix(b"\n=======\n")?;
    body = alternative(body, path)?;
    body = body.strip_prefix(b"\n")?;
    marker(body, b">>>>>>> ")?.is_empty().then_some(())
}

fn marker<'a>(body: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let body = body.strip_prefix(prefix)?;
    let label = body.get(..40)?;
    if !label.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    body.get(40..)?.strip_prefix(b"\n")
}

fn alternative<'a>(body: &'a [u8], path: &str) -> Option<&'a [u8]> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(body));
    let envelope = Envelope::deserialize(&mut deserializer).ok()?;
    if !sealed_for(&envelope, path) {
        return None;
    }
    body.get(deserializer.get_ref().position() as usize..)
}
