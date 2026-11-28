//! Hex, for the values that travel as text: link bodies and the endpoint id
//! in an advertisement. Written lower-case; read in either case.

use std::fmt::Write as _;

pub(crate) const HEX_CHARS_PER_BYTE: usize = 2;

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(HEX_CHARS_PER_BYTE * bytes.len());
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a String");
    }
    text
}

/// The bytes `text` spells, if it is nothing but whole pairs of hex digits.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let (pairs, leftover) = text.as_bytes().as_chunks::<HEX_CHARS_PER_BYTE>();
    if !leftover.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| {
            let high = char::from(*high).to_digit(16)?;
            let low = char::from(*low).to_digit(16)?;
            u8::try_from(high << 4 | low).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_reads_either_case() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode("000fa5ff").as_deref(), Some(&bytes[..]));
        assert_eq!(decode("000FA5FF").as_deref(), Some(&bytes[..]));
        assert_eq!(decode("").as_deref(), Some(&[][..]));
    }

    #[test]
    fn refuses_odd_lengths_and_anything_that_is_not_a_digit() {
        for bad in ["0", "000", "0g", " 0", "0x", "+1", "é"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }
}
