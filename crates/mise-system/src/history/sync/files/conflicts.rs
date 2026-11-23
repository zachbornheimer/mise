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
        .is_some_and(|body| alternatives(body, path).is_some() || shared_prefix(body, path).is_some()))
}

fn alternatives(body: &[u8], path: &str) -> Option<()> {
    framed(body, b"", path)
}

/// Git keeps the envelope's leading bytes outside the markers when both
/// sides share them up to a newline. Each side is that prefix plus its own
/// bytes; the framing after the prefix is the same as a whole-envelope record.
fn shared_prefix(body: &[u8], path: &str) -> Option<()> {
    let start = body.windows(9).position(|bytes| bytes == b"\n<<<<<<< ")? + 1;
    framed(&body[start..], &body[..start], path)
}

fn framed(mut body: &[u8], prefix: &[u8], path: &str) -> Option<()> {
    body = marker(body, b"<<<<<<< ")?;
    body = alternative(body, prefix, path)?;
    body = body.strip_prefix(b"=======\n")?;
    body = alternative(body, prefix, path)?;
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

fn alternative<'a>(body: &'a [u8], prefix: &[u8], path: &str) -> Option<&'a [u8]> {
    let whole = [prefix, body].concat();
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(whole.as_slice()));
    let envelope = Envelope::deserialize(&mut deserializer).ok()?;
    if !sealed_for(&envelope, path) {
        return None;
    }
    let consumed = (deserializer.get_ref().position() as usize).checked_sub(prefix.len())?;
    if consumed == 0 {
        return None;
    }
    let remaining = body.get(consumed..)?;
    // Git only inserts a newline when the complete envelope lacks one.
    // The envelope's own trailing LF belongs to MessagePack, not framing.
    if body.get(consumed.checked_sub(1)?) == Some(&b'\n') {
        Some(remaining)
    } else {
        remaining.strip_prefix(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    const PATH: &str = "home/secret";

    // Synthetic age framing only: no real ciphertext or key.
    fn envelope(newline: bool) -> Vec<u8> {
        #[derive(Serialize)]
        struct Synthetic<'a> {
            path: &'a str,
            mode: &'a str,
            scheme: &'a str,
            ciphertext: SyntheticBytes,
        }
        struct SyntheticBytes(Vec<u8>);
        impl Serialize for SyntheticBytes {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }
        let mut ciphertext = b"age-encryption.org/v1\nsynthetic".to_vec();
        ciphertext.push(if newline { b'\n' } else { b'x' });
        rmp_serde::to_vec_named(&Synthetic {
            path: PATH,
            mode: "100644",
            scheme: "test",
            ciphertext: SyntheticBytes(ciphertext),
        })
        .unwrap()
    }

    fn record(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut bytes = b"<<<<<<< 1111111111111111111111111111111111111111\n".to_vec();
        bytes.extend_from_slice(left);
        if !left.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(b"=======\n");
        bytes.extend_from_slice(right);
        if !right.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(b">>>>>>> 2222222222222222222222222222222222222222\n");
        bytes
    }

    #[test]
    fn accepts_all_envelope_line_endings() {
        for left in [false, true] {
            for right in [false, true] {
                assert!(
                    alternatives(&record(&envelope(left), &envelope(right)), PATH).is_some(),
                    "left LF={left}, right LF={right}"
                );
            }
        }
    }

    /// Both sides share the envelope's bytes up to its first newline, so Git
    /// leaves that prefix outside the markers.
    fn shared(left: &[u8], right: &[u8]) -> Vec<u8> {
        let split = left.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        assert_eq!(left[..split], right[..split], "fixture sides must share the prefix");
        [&left[..split], &record(&left[split..], &right[split..])].concat()
    }

    fn with_ciphertext(tail: &[u8]) -> Vec<u8> {
        let mut bytes = envelope(false);
        let end = bytes.len() - 1;
        bytes.splice(end..end, tail.iter().copied());
        let bin = bytes.iter().position(|byte| *byte == 0xc4).unwrap();
        bytes[bin + 1] += tail.len() as u8;
        bytes
    }

    #[test]
    fn accepts_conflict_markers_after_a_shared_envelope_prefix() {
        let left = with_ciphertext(b"left");
        let right = with_ciphertext(b"rite");
        let record = shared(&left, &right);
        assert!(alternatives(&record, PATH).is_none());
        assert!(shared_prefix(&record, PATH).is_some());
    }

    #[test]
    fn rejects_shared_prefix_records_with_broken_framing() {
        let left = with_ciphertext(b"left");
        let right = with_ciphertext(b"rite");
        let valid = shared(&left, &right);
        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"trailing");
        assert!(shared_prefix(&trailing, PATH).is_none());
        let separator = valid.windows(8).position(|bytes| bytes == b"=======\n").unwrap();
        let mut missing = valid;
        missing.drain(separator..separator + 8);
        assert!(shared_prefix(&missing, PATH).is_none());
        let other_path = shared(&left, &right);
        assert!(shared_prefix(&other_path, "home/other").is_none());
    }

    #[test]
    fn rejects_malformed_conflict_framing() {
        let left = envelope(false);
        let right = envelope(false);
        let valid = record(&left, &right);
        let separator = valid
            .windows(8)
            .position(|bytes| bytes == b"=======\n")
            .unwrap();
        let mut missing = valid.clone();
        missing.drain(separator..separator + 8);
        assert!(alternatives(&missing, PATH).is_none());
        let mut third = valid.clone();
        third.splice(separator..separator, [right.as_slice(), b"\n"].concat());
        assert!(alternatives(&third, PATH).is_none());
        let mut trailing = valid;
        trailing.extend_from_slice(b"trailing");
        assert!(alternatives(&trailing, PATH).is_none());
        let mut wrong_length = left;
        let bin = wrong_length.iter().position(|byte| *byte == 0xc4).unwrap();
        // Consume part of the separator, not just Git's inserted LF.
        wrong_length[bin + 1] += 2;
        assert!(alternatives(&record(&wrong_length, &right), PATH).is_none());
    }
}
