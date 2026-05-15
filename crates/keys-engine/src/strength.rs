//! Password strength estimation via character-class entropy.
//!
//! Ports the algorithm used by the macOS app's `PasswordStrength` Swift
//! enum verbatim, so existing entries don't get re-bucketed when the
//! engine takes over the column from the Swift `StrengthCache`. The
//! formula is deliberately naive — no dictionary checks, no zxcvbn-style
//! token sequencing — because that's what's stored in the on-disk cache
//! today and Phase 6.12 retires the cache on the assumption of bit-for-bit
//! parity.
//!
//! # Algorithm
//!
//! 1. Walk every character, recording which character *classes* are
//!    present: lowercase letter, uppercase letter, digit, ASCII symbol,
//!    non-ASCII Unicode.
//! 2. Sum the pool sizes of the classes that fired: `26 + 26 + 10 + 33 +
//!    100` for the five buckets respectively.
//! 3. Entropy bits = `len × log2(pool_size)`. Empty password → 0.
//! 4. Map to a [`StrengthBucket`]:
//!    - `≤ 0`  → `VeryWeak`   (mirrors Swift `.empty`)
//!    - `< 50` → `Weak`       (mirrors Swift `.weak`)
//!    - `< 70` → `Reasonable` (mirrors Swift `.fair`)
//!    - `< 100`→ `Strong`     (mirrors Swift `.strong`)
//!    - `≥ 100`→ `VeryStrong` (mirrors Swift `.excellent`)
//!
//! # Parity notes
//!
//! Swift iterates `for char in password`, which yields grapheme clusters,
//! and uses `password.count` (grapheme count) for the length factor.
//! Rust here iterates [`char`] (Unicode scalars), so a password containing
//! combining sequences (e.g. base + combining accent) would count as two
//! scalars in Rust vs. one grapheme in Swift. No real-world password we
//! care about exercises that path; the cross-check test vectors are all
//! single-scalar inputs.
//!
//! Class detection mirrors Swift's `Character.isLowercase` /
//! `isUppercase` / `isNumber` / `isASCII` priority order. In particular
//! `isNumber` is Unicode-aware in Swift, so things like roman-numeral
//! scalars get bucketed as digits there; [`char::is_numeric`] preserves
//! the same behaviour in Rust.

use crate::model::StrengthBucket;

/// Result of a strength computation.
///
/// Carries both the raw entropy estimate (suitable for the
/// `entry.password_entropy` column) and the discrete bucket (suitable
/// for `entry.password_strength_bucket`). Callers persist both — the
/// bucket is what the UI displays; the entropy is what gets re-bucketed
/// if the boundaries ever shift.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// `len * log2(pool_size)` in bits. Zero for empty password.
    pub entropy_bits: f64,
    /// Discrete bucket derived from `entropy_bits` per the boundaries
    /// documented on the module.
    pub bucket: StrengthBucket,
}

/// Compute the [`Strength`] of `password`.
///
/// See module docs for the algorithm. Pure function; no allocation
/// beyond the implicit iteration. Safe to call from any thread.
#[must_use]
pub fn strength(password: &str) -> Strength {
    let entropy_bits = entropy(password);
    Strength {
        entropy_bits,
        bucket: bucket_for(entropy_bits),
    }
}

/// Character-class entropy in bits for `password`.
fn entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_unicode = false;
    let mut len: u32 = 0;

    for c in password.chars() {
        len += 1;
        if c.is_lowercase() {
            has_lower = true;
        } else if c.is_uppercase() {
            has_upper = true;
        } else if c.is_numeric() {
            has_digit = true;
        } else if c.is_ascii() {
            has_symbol = true;
        } else {
            has_unicode = true;
        }
    }

    let mut pool = 0u32;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_unicode {
        pool += 100;
    }

    if pool == 0 {
        return 0.0;
    }

    f64::from(len) * f64::from(pool).log2()
}

/// Map an entropy estimate to a [`StrengthBucket`] per the boundaries in
/// the Swift implementation. See module docs.
fn bucket_for(entropy_bits: f64) -> StrengthBucket {
    if entropy_bits <= 0.0 {
        StrengthBucket::VeryWeak
    } else if entropy_bits < 50.0 {
        StrengthBucket::Weak
    } else if entropy_bits < 70.0 {
        StrengthBucket::Reasonable
    } else if entropy_bits < 100.0 {
        StrengthBucket::Strong
    } else {
        StrengthBucket::VeryStrong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Approximate-equality assertion for entropy comparisons.
    fn approx(a: f64, b: f64) {
        assert!(
            (a - b).abs() < 0.01,
            "expected {b}, got {a} (delta {})",
            (a - b).abs()
        );
    }

    /// Cross-check against the Swift `PasswordStrength.entropy(of:)`
    /// implementation. The expected values are hand-computed from the
    /// same `len * log2(pool)` formula Swift uses, so any drift in the
    /// Rust port surfaces here.
    ///
    /// Pool reminder: lower=26, upper=26, digit=10, symbol=33,
    /// unicode=100; summed by class presence.
    #[test]
    fn entropy_matches_swift_for_canonical_inputs() {
        // (input, expected_entropy, expected_bucket)
        // log2 values rounded to 6dp for the comment math:
        //   log2(26)  ≈ 4.700440
        //   log2(36)  ≈ 5.169925
        //   log2(62)  ≈ 5.954196
        //   log2(95)  ≈ 6.569856  (lower+upper+digit+symbol)
        //   log2(33)  ≈ 5.044394
        let cases: &[(&str, f64, StrengthBucket)] = &[
            // empty → 0
            ("", 0.0, StrengthBucket::VeryWeak),
            // "abc": 3 * log2(26) ≈ 14.1013
            ("abc", 3.0 * 26f64.log2(), StrengthBucket::Weak),
            // "correcthorse": 12 * log2(26) ≈ 56.4053 → Reasonable
            (
                "correcthorse",
                12.0 * 26f64.log2(),
                StrengthBucket::Reasonable,
            ),
            // "password1": 9 * log2(36) ≈ 46.5293 → Weak
            ("password1", 9.0 * 36f64.log2(), StrengthBucket::Weak),
            // "Password1": 9 * log2(62) ≈ 53.5878 → Reasonable
            ("Password1", 9.0 * 62f64.log2(), StrengthBucket::Reasonable),
            // "Tr0ub4dor&3": 11 * log2(95) ≈ 72.2684 → Strong
            ("Tr0ub4dor&3", 11.0 * 95f64.log2(), StrengthBucket::Strong),
            // "!@#": 3 * log2(33) ≈ 15.1332 → Weak
            ("!@#", 3.0 * 33f64.log2(), StrengthBucket::Weak),
            // "correcthorsebatterystaple": 25 * log2(26) ≈ 117.5110 → VeryStrong
            (
                "correcthorsebatterystaple",
                25.0 * 26f64.log2(),
                StrengthBucket::VeryStrong,
            ),
            // 32 lowercase: 32 * log2(26) ≈ 150.4141 → VeryStrong
            (
                "abcdefghijklmnopqrstuvwxyzabcdef",
                32.0 * 26f64.log2(),
                StrengthBucket::VeryStrong,
            ),
            // "aaaaaaaa": 8 * log2(26) ≈ 37.6035 → Weak (no repeat penalty in Swift)
            ("aaaaaaaa", 8.0 * 26f64.log2(), StrengthBucket::Weak),
            // "12345": 5 * log2(10) ≈ 16.6096 → Weak
            ("12345", 5.0 * 10f64.log2(), StrengthBucket::Weak),
            // "Aa1!Bb2@Cc3#": 12 * log2(95) ≈ 78.8383 → Strong
            ("Aa1!Bb2@Cc3#", 12.0 * 95f64.log2(), StrengthBucket::Strong),
        ];

        for (input, expected_entropy, expected_bucket) in cases {
            let got = strength(input);
            approx(got.entropy_bits, *expected_entropy);
            assert_eq!(
                got.bucket, *expected_bucket,
                "bucket mismatch for {input:?}: got {:?}, expected {:?}",
                got.bucket, expected_bucket
            );
        }
    }

    /// Each bucket boundary is hit by a hand-tuned input. Probing
    /// "just below" and "at or above" the edge confirms the comparisons
    /// match the Swift `if entropy < N` ladder exactly.
    #[test]
    fn bucket_boundaries() {
        // Empty / VeryWeak edge.
        assert_eq!(strength("").bucket, StrengthBucket::VeryWeak);

        // Weak / Reasonable boundary at 50 bits.
        // 10 lowercase chars: 10 * log2(26) ≈ 47.00 → Weak.
        assert_eq!(strength("abcdefghij").bucket, StrengthBucket::Weak);
        // 11 lowercase chars: 11 * log2(26) ≈ 51.70 → Reasonable.
        assert_eq!(strength("abcdefghijk").bucket, StrengthBucket::Reasonable);

        // Reasonable / Strong boundary at 70 bits.
        // 14 lowercase: 14 * log2(26) ≈ 65.81 → Reasonable.
        assert_eq!(
            strength("abcdefghijklmn").bucket,
            StrengthBucket::Reasonable
        );
        // 15 lowercase: 15 * log2(26) ≈ 70.51 → Strong.
        assert_eq!(strength("abcdefghijklmno").bucket, StrengthBucket::Strong);

        // Strong / VeryStrong boundary at 100 bits.
        // 21 lowercase: 21 * log2(26) ≈ 98.71 → Strong.
        assert_eq!(
            strength("abcdefghijklmnopqrstu").bucket,
            StrengthBucket::Strong
        );
        // 22 lowercase: 22 * log2(26) ≈ 103.41 → VeryStrong.
        assert_eq!(
            strength("abcdefghijklmnopqrstuv").bucket,
            StrengthBucket::VeryStrong
        );
    }

    #[test]
    fn empty_password_lowest_bucket() {
        let got = strength("");
        approx(got.entropy_bits, 0.0);
        assert_eq!(got.bucket, StrengthBucket::VeryWeak);
    }

    #[test]
    fn monotonic_in_length() {
        // Same character class, longer string → entropy must not shrink.
        let short = strength("abc").entropy_bits;
        let medium = strength("abcdef").entropy_bits;
        let long = strength("abcdefghij").entropy_bits;
        assert!(short <= medium);
        assert!(medium <= long);
    }

    #[test]
    fn class_diversity_increases_alphabet() {
        // "aaaa" → pool 26; "aA1!" → pool 95. Same length, diverse wins.
        let homo = strength("aaaa").entropy_bits;
        let diverse = strength("aA1!").entropy_bits;
        assert!(
            diverse > homo,
            "diverse classes ({diverse}) should beat single-class ({homo})"
        );
    }
}
