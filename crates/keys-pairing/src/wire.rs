//! A strict reader for the pairing messages: fixed-width fields, LEB128
//! length-prefixed fields with minimal encodings only, and no trailing bytes.

use crate::cpace::{LEB128_CONTINUATION, LEB128_PAYLOAD_BITS, LEB128_PAYLOAD_MASK};
use crate::protocol::{MessageType, RunFailure};

/// The longest length prefix accepted. Two LEB128 bytes cover lengths up to
/// 16 383, far beyond any field in these messages.
const LEB128_MAX_BYTES: usize = 2;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn byte(&mut self) -> Result<u8, RunFailure> {
        let (&first, rest) = self
            .bytes
            .split_first()
            .ok_or(RunFailure::MalformedMessage)?;
        self.bytes = rest;
        Ok(first)
    }

    pub(crate) fn expect_type(&mut self, expected: MessageType) -> Result<(), RunFailure> {
        if self.byte()? == expected as u8 {
            Ok(())
        } else {
            Err(RunFailure::MalformedMessage)
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RunFailure> {
        if self.bytes.len() < len {
            return Err(RunFailure::MalformedMessage);
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], RunFailure> {
        Ok(self.take(N)?.try_into().expect("took exactly N bytes"))
    }

    /// A minimally encoded LEB128 length.
    fn length(&mut self) -> Result<usize, RunFailure> {
        let mut value = 0usize;
        for index in 0..LEB128_MAX_BYTES {
            let byte = self.byte()?;
            let shift = LEB128_PAYLOAD_BITS * u32::try_from(index).expect("tiny index");
            value |= usize::from(byte & LEB128_PAYLOAD_MASK) << shift;
            if byte & LEB128_CONTINUATION == 0 {
                // A zero final byte after the first is a non-minimal encoding.
                if index > 0 && byte == 0 {
                    return Err(RunFailure::MalformedMessage);
                }
                return Ok(value);
            }
        }
        Err(RunFailure::MalformedMessage)
    }

    /// A `prepend_len` field that must be exactly `N` bytes long.
    pub(crate) fn lv_array<const N: usize>(&mut self) -> Result<[u8; N], RunFailure> {
        if self.length()? != N {
            return Err(RunFailure::MalformedMessage);
        }
        self.array::<N>()
    }

    /// Everything not yet read.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.bytes)
    }

    /// Fails if anything is left over.
    pub(crate) fn finish(&self) -> Result<(), RunFailure> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(RunFailure::MalformedMessage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpace::lv_cat;

    #[test]
    fn reads_what_lv_cat_writes() {
        let a = [1u8; 32];
        let b = [2u8; 64];
        let encoded = lv_cat(&[&a, &b]);
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.lv_array::<32>().unwrap(), a);
        assert_eq!(reader.lv_array::<64>().unwrap(), b);
        reader.finish().unwrap();
    }

    #[test]
    fn refuses_wrong_lengths_trailing_bytes_and_padding() {
        let encoded = lv_cat(&[&[1u8; 31]]);
        assert!(Reader::new(&encoded).lv_array::<32>().is_err());

        let mut trailing = lv_cat(&[&[1u8; 32]]);
        trailing.push(0);
        let mut reader = Reader::new(&trailing);
        reader.lv_array::<32>().unwrap();
        assert!(reader.finish().is_err());

        // 32 encoded as two LEB128 bytes (0xa0 0x00) is not minimal.
        let mut padded = vec![0xa0, 0x00];
        padded.extend_from_slice(&[1u8; 32]);
        assert!(Reader::new(&padded).lv_array::<32>().is_err());

        // A length prefix that never ends.
        assert!(Reader::new(&[0x80, 0x80, 0x80]).lv_array::<32>().is_err());
    }
}
