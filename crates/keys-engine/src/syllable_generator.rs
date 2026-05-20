// `cast_precision_loss` fires on `array.len() as f64` for the
// onset/nucleus/coda/separator tables. The lengths are static, in the
// dozens — well under f64's 52-bit mantissa. Allowing here rather than
// littering the entropy maths with `try_from` noise.
#![allow(clippy::cast_precision_loss)]

//! Generates pronounceable passwords from random syllables with digit/symbol
//! separators.
//!
//! Inspired by 1Password's Strong Password Generator (SPG), MIT-licensed.
//! <https://github.com/1Password/spg>

use rand::RngCore;
use rand::rngs::OsRng;

/// Common English onset consonants/clusters.
pub static ONSETS: &[&str] = &[
    "", "b", "bl", "br", "c", "ch", "cl", "cr", "d", "dr", "f", "fl", "fr", "g", "gl", "gr", "h",
    "j", "k", "kn", "l", "m", "n", "p", "pl", "pr", "qu", "r", "s", "sc", "sh", "sk", "sl", "sm",
    "sn", "sp", "st", "str", "sw", "t", "th", "tr", "tw", "v", "w", "wh", "wr", "z",
];

/// Common English vowel nuclei.
pub static NUCLEI: &[&str] = &[
    "a", "e", "i", "o", "u", "ai", "au", "ea", "ee", "ei", "ia", "ie", "io", "oa", "oo", "ou", "ue",
];

/// Common English coda consonants/clusters.
pub static CODAS: &[&str] = &[
    "", "b", "ck", "d", "f", "g", "k", "l", "ll", "m", "mp", "n", "nd", "ng", "nk", "nt", "p", "r",
    "rk", "rm", "rn", "rs", "rt", "s", "sh", "sk", "sp", "ss", "st", "t", "th", "x", "z",
];

/// Separators: digits and a few symbols.
pub static SEPARATORS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '-'];

/// Options for generating a pronounceable password.
#[derive(Clone, Copy, Debug)]
pub struct SyllableOptions {
    pub syllable_count: u32,
    pub capitalise_one: bool,
}

impl Default for SyllableOptions {
    fn default() -> Self {
        Self {
            syllable_count: 4,
            capitalise_one: true,
        }
    }
}

/// Generate a pronounceable password.
///
/// Example output: `brent4SKOO7dalf`.
#[must_use]
pub fn generate(opts: &SyllableOptions) -> String {
    let count = opts.syllable_count as usize;
    let total_bytes = count.saturating_mul(4).max(32);
    let mut random_bytes = vec![0u8; total_bytes];
    OsRng.fill_bytes(&mut random_bytes);

    let mut byte_index: usize = 0;
    let mut next_byte = || -> u8 {
        let b = random_bytes[byte_index % random_bytes.len()];
        byte_index += 1;
        b
    };

    let mut syllables: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        let onset = ONSETS[next_byte() as usize % ONSETS.len()];
        let nucleus = NUCLEI[next_byte() as usize % NUCLEI.len()];
        let coda = CODAS[next_byte() as usize % CODAS.len()];
        syllables.push(format!("{onset}{nucleus}{coda}"));
    }

    if opts.capitalise_one && !syllables.is_empty() {
        let cap_index = next_byte() as usize % syllables.len();
        syllables[cap_index] = syllables[cap_index].to_uppercase();
    }

    let mut result = String::new();
    let len = syllables.len();
    for (i, syllable) in syllables.into_iter().enumerate() {
        result.push_str(&syllable);
        if i + 1 < len {
            let sep = SEPARATORS[next_byte() as usize % SEPARATORS.len()];
            result.push(sep);
        }
    }

    result
}

/// Estimate entropy (in bits) for a pronounceable password.
#[must_use]
pub fn estimate_entropy(opts: &SyllableOptions) -> f64 {
    let syllable_space = (ONSETS.len() * NUCLEI.len() * CODAS.len()) as f64;
    let separator_space = SEPARATORS.len() as f64;
    let syllable_bits = syllable_space.log2();
    let separator_bits = separator_space.log2();

    let count = f64::from(opts.syllable_count);
    let between = (f64::from(opts.syllable_count).max(1.0)) - 1.0;
    let cap_bits = if opts.capitalise_one && opts.syllable_count > 0 {
        f64::from(opts.syllable_count).log2()
    } else {
        0.0
    };

    count * syllable_bits + between * separator_bits + cap_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_non_empty() {
        let s = generate(&SyllableOptions::default());
        assert!(!s.is_empty());
    }

    #[test]
    fn generate_length_grows_with_syllable_count() {
        // Average length should scale roughly linearly with syllable_count.
        // We sample multiple times to smooth out variance.
        fn avg_len(count: u32) -> f64 {
            let opts = SyllableOptions {
                syllable_count: count,
                capitalise_one: false,
            };
            let n = 50;
            let total: usize = (0..n).map(|_| generate(&opts).len()).sum();
            total as f64 / f64::from(n)
        }

        let a = avg_len(2);
        let b = avg_len(8);
        assert!(
            b > a,
            "longer count should produce longer output on average: 2->{a}, 8->{b}"
        );
    }

    #[test]
    fn capitalise_one_yields_uppercase_letter() {
        let opts = SyllableOptions {
            syllable_count: 4,
            capitalise_one: true,
        };
        // Run several times — every output must contain at least one uppercase
        // ASCII letter, since exactly one syllable is uppercased.
        for _ in 0..50 {
            let s = generate(&opts);
            assert!(
                s.chars().any(|c| c.is_ascii_uppercase()),
                "expected an uppercase letter in {s}"
            );
        }
    }

    #[test]
    fn no_capitalisation_yields_no_uppercase() {
        let opts = SyllableOptions {
            syllable_count: 4,
            capitalise_one: false,
        };
        for _ in 0..50 {
            let s = generate(&opts);
            assert!(
                !s.chars().any(|c| c.is_ascii_uppercase()),
                "expected no uppercase letters in {s}"
            );
        }
    }

    #[test]
    fn entropy_matches_formula() {
        // Hand-computed against the Swift formula.
        let syllable_space = (ONSETS.len() * NUCLEI.len() * CODAS.len()) as f64;
        let sep_space = SEPARATORS.len() as f64;

        let cases = [
            (
                SyllableOptions {
                    syllable_count: 4,
                    capitalise_one: true,
                },
                4.0 * syllable_space.log2() + 3.0 * sep_space.log2() + 4.0_f64.log2(),
            ),
            (
                SyllableOptions {
                    syllable_count: 4,
                    capitalise_one: false,
                },
                4.0 * syllable_space.log2() + 3.0 * sep_space.log2(),
            ),
            (
                SyllableOptions {
                    syllable_count: 1,
                    capitalise_one: true,
                },
                1.0 * syllable_space.log2() + 0.0 * sep_space.log2() + 1.0_f64.log2(),
            ),
            (
                SyllableOptions {
                    syllable_count: 6,
                    capitalise_one: true,
                },
                6.0 * syllable_space.log2() + 5.0 * sep_space.log2() + 6.0_f64.log2(),
            ),
        ];

        for (opts, expected) in cases {
            let got = estimate_entropy(&opts);
            assert!(
                (got - expected).abs() < 1e-9,
                "entropy mismatch for {opts:?}: got {got}, expected {expected}"
            );
        }
    }
}
