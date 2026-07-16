//! Byte↔string codecs for values that live in `TEXT` columns and in
//! the `entry_history.snapshot_json` wire format.
//!
//! Both codecs are pinned by the on-disk data they encode, so neither
//! may change variant (base64 alphabet, hex case) without a read of
//! every existing row. They are plain functions with no SQL or model
//! knowledge.

/// Encode bytes as lowercase hex.
///
/// Pairs with [`hex_to_bytes`]. The lowercase choice is load-bearing:
/// `attachment_blob.sha256_hex`-shaped values are compared as strings
/// on some paths, so an uppercase encoder would silently stop matching
/// rows written by this one.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(&mut acc, "{b:02x}");
            acc
        })
}

/// Decode a hex string into bytes. `None` for any invalid input (odd
/// length, non-hex characters). Accepts either case, so it reads back
/// anything [`bytes_to_hex`] wrote plus hex from external sources.
pub(crate) fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Standard base64 **with** padding — no URL-safe variant. The bytes
/// this encodes live inside a JSON string, never in a URL.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode standard base64. The error is stringified rather than typed
/// because callers funnel it into differently-shaped errors
/// (`RevealError::Unwrap`, ingest's row errors).
pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            hex_to_bytes(&bytes_to_hex(&bytes)).as_deref(),
            Some(&bytes[..])
        );
    }

    #[test]
    fn hex_encodes_lowercase_padded() {
        assert_eq!(bytes_to_hex(&[0x00, 0x0f, 0xff, 0xab]), "000fffab");
    }

    #[test]
    fn hex_decodes_either_case() {
        assert_eq!(hex_to_bytes("AbCd"), hex_to_bytes("abcd"));
    }

    #[test]
    fn hex_rejects_odd_length_and_non_hex() {
        assert_eq!(hex_to_bytes("abc"), None);
        assert_eq!(hex_to_bytes("zz"), None);
    }

    #[test]
    fn b64_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(b64_decode(&b64_encode(&bytes)).as_deref(), Ok(&bytes[..]));
    }

    #[test]
    fn b64_encodes_with_padding() {
        assert_eq!(b64_encode(b"a"), "YQ==");
    }

    #[test]
    fn b64_decode_reports_the_error() {
        assert!(b64_decode("!!!").unwrap_err().contains("base64 decode"));
    }
}
