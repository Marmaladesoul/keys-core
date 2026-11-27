//! The six-digit pairing code: the `CPace` password.
//!
//! The displaying side draws it uniformly at random and never transmits it;
//! the typing side parses what the person typed. Either way it is used for
//! exactly one exchange run.

use zeroize::{Zeroize, Zeroizing};

use crate::PairingError;
use crate::secret::Secret;

/// Number of decimal digits in a pairing code.
pub const CODE_DIGITS: usize = CODE_DIGIT_COUNT as usize;
/// [`CODE_DIGITS`], as the exponent of [`CODE_SPACE`].
const CODE_DIGIT_COUNT: u32 = 6;
/// Number of distinct codes, `10^CODE_DIGITS`.
const CODE_SPACE: u32 = 10u32.pow(CODE_DIGIT_COUNT);
/// Random bits drawn per rejection-sampling attempt: the smallest power of two
/// at or above [`CODE_SPACE`] (2^20 = 1 048 576), so about 95% of draws land.
const CODE_DRAW_MASK: u32 = (1 << 20) - 1;
// The mask covers the code space, and no more than twice over: a change to
// the digit count that forgets the mask fails to compile.
const _: () = assert!(CODE_SPACE <= CODE_DRAW_MASK + 1 && CODE_DRAW_MASK < 2 * CODE_SPACE);

/// A six-digit pairing code. Its digits live in an allocation of their own,
/// are wiped on drop, and never print through `Debug`.
#[derive(Clone)]
pub struct PairingCode(Secret<CODE_DIGITS>);

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

impl PairingCode {
    /// Draws a code uniformly from the 10^6 possibilities by rejection
    /// sampling: 20 random bits, redrawn whenever they're 10^6 or more. No
    /// modular reduction, so no digit is favoured.
    ///
    /// # Errors
    /// [`PairingError::Random`] if the system random source fails.
    pub fn generate() -> Result<Self, PairingError> {
        loop {
            let mut raw = Zeroizing::new([0u8; 4]);
            crate::random::fill(raw.as_mut()).map_err(|_| PairingError::Random)?;
            let mut value = u32::from_le_bytes(*raw) & CODE_DRAW_MASK;
            if value < CODE_SPACE {
                let code = Self::from_value(value);
                value.zeroize();
                return Ok(code);
            }
        }
    }

    fn from_value(mut value: u32) -> Self {
        let mut digits = Secret::zeroed();
        for slot in digits.as_mut().iter_mut().rev() {
            *slot = b'0' + u8::try_from(value % 10).expect("a decimal digit");
            value /= 10;
        }
        Self(digits)
    }

    /// Parses what the person typed: exactly six ASCII digits and nothing
    /// else. Any grouping the field shows (a space in the middle, say) is
    /// for the client to strip before calling this.
    ///
    /// # Errors
    /// [`PairingError::MalformedCode`] for anything else.
    pub fn parse(typed: &str) -> Result<Self, PairingError> {
        let bytes = typed.as_bytes();
        if bytes.len() != CODE_DIGITS || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(PairingError::MalformedCode);
        }
        let mut digits = Secret::zeroed();
        digits.as_mut().copy_from_slice(bytes);
        Ok(Self(digits))
    }

    /// The code as six ASCII digits, for display. The caller owns the copy.
    #[must_use]
    pub fn digits(&self) -> Zeroizing<String> {
        // Sized up front, so the digits are written once and never copied
        // by a growing buffer.
        let mut digits = Zeroizing::new(String::with_capacity(CODE_DIGITS));
        digits.extend(self.0.as_bytes().iter().map(|&digit| char::from(digit)));
        digits
    }

    /// The `CPace` password string (PRS): the six ASCII digits. For a string of
    /// digits the RFC 8265 encoding the draft asks for (§4.3) is the identity.
    pub(crate) fn prs(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether two codes are the same, compared in constant time.
    #[cfg(test)]
    fn same_as(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_six_digits() {
        for _ in 0..256 {
            let code = PairingCode::generate().expect("rng");
            let digits = code.digits();
            assert_eq!(digits.len(), CODE_DIGITS);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn from_value_zero_pads() {
        assert_eq!(PairingCode::from_value(42).digits().as_str(), "000042");
        assert_eq!(
            PairingCode::from_value(CODE_SPACE - 1).digits().as_str(),
            "999999"
        );
    }

    #[test]
    fn parse_accepts_exactly_six_digits() {
        let code = PairingCode::parse("482913").expect("six digits");
        assert_eq!(code.digits().as_str(), "482913");
        for bad in [
            "",
            "48291",
            "4829134",
            "482 913",
            "48291a",
            "４８２９１３",
            " 482913",
        ] {
            assert!(
                matches!(PairingCode::parse(bad), Err(PairingError::MalformedCode)),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn parsed_and_generated_codes_compare() {
        let generated = PairingCode::generate().expect("rng");
        let typed = PairingCode::parse(&generated.digits()).expect("round-trips");
        assert!(generated.same_as(&typed));
    }

    #[test]
    fn debug_never_prints_digits() {
        let code = PairingCode::parse("123456").expect("six digits");
        assert!(!format!("{code:?}").contains("123456"));
    }

    /// Every digit position is roughly uniform. Not a proof, just a guard
    /// against an accidental modulo bias or a stuck digit: 10 000 draws give
    /// each digit about 1 000 hits per position, and the bound is generous.
    #[test]
    fn digits_are_roughly_uniform() {
        const DRAWS: usize = 10_000;
        const EXPECTED: usize = DRAWS / 10;
        const TOLERANCE: usize = EXPECTED / 4;
        let mut counts = [[0usize; 10]; CODE_DIGITS];
        for _ in 0..DRAWS {
            let code = PairingCode::generate().expect("rng");
            for (position, digit) in code.digits().bytes().enumerate() {
                counts[position][usize::from(digit - b'0')] += 1;
            }
        }
        for position in counts {
            for count in position {
                assert!(count.abs_diff(EXPECTED) < TOLERANCE, "skewed: {count}");
            }
        }
    }
}
