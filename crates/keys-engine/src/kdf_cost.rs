//! The KDF cost a KDBX envelope demands of whoever opens it.
//!
//! A KDBX file's outer header names its own KDF parameters, and the KDF
//! has to run before anything else about the file can be checked: the
//! header HMAC (KDBX4) and the decrypted payload (KDBX3) are both keyed
//! by its output. The parameters themselves are unauthenticated until
//! then. So a file can make its reader allocate and spin for whatever it
//! asks, before the reader learns whether the file is even the right
//! vault under the right key.
//!
//! The replicas of one vault share their KDF parameters — only the salt
//! (KDBX4) or transform seed (KDBX3) is per-envelope, and a save may
//! rotate it. [`KdfCost`] is the parameters minus that salt: the work
//! asked, nothing else. A peer replica whose cost differs from the
//! mirror's recorded cost is refused unread
//! ([`crate::EngineError::KdfParametersMismatch`]), so ingesting a peer
//! never costs more than opening this vault already does.

use std::fmt;

use keepass_core::format::{Argon2Variant, KdfParams};

/// The work a KDBX envelope's KDF demands: its [`KdfParams`] with the
/// salt / transform seed cleared. Two envelopes with equal `KdfCost`
/// take the same derivation work to open, whatever their salts.
///
/// [`fmt::Display`] renders the Info-tab form, e.g.
/// `"Argon2id (64 MB · 2 iter · 4 threads)"` or
/// `"AES-KDF (6,000,000 rounds)"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfCost(KdfParams);

impl KdfCost {
    /// The cost of an envelope with these KDF parameters.
    #[must_use]
    pub fn of(params: &KdfParams) -> Self {
        let cost = match params.clone() {
            KdfParams::AesKdf { rounds, .. } => KdfParams::AesKdf {
                seed: [0; 32],
                rounds,
            },
            KdfParams::Argon2 {
                variant,
                iterations,
                memory_bytes,
                parallelism,
                version,
                ..
            } => KdfParams::Argon2 {
                variant,
                salt: Vec::new(),
                iterations,
                memory_bytes,
                parallelism,
                version,
            },
            // A KDF family this build doesn't model compares whole, salt
            // included: stricter than needed, never looser.
            other => other,
        };
        Self(cost)
    }

    /// The cost of an AES-KDF envelope of `rounds` rounds — the form a
    /// KDBX3 outer header states directly.
    #[must_use]
    pub fn aes_kdf(rounds: u64) -> Self {
        Self::of(&KdfParams::AesKdf {
            seed: [0; 32],
            rounds,
        })
    }
}

impl fmt::Display for KdfCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            KdfParams::AesKdf { rounds, .. } => {
                write!(f, "AES-KDF ({} rounds)", format_with_thousands(*rounds))
            }
            KdfParams::Argon2 {
                variant,
                memory_bytes,
                iterations,
                parallelism,
                ..
            } => {
                let name = match variant {
                    Argon2Variant::Argon2d => "Argon2d",
                    Argon2Variant::Argon2id => "Argon2id",
                    _ => "Argon2",
                };
                let mib = memory_bytes / (1024 * 1024);
                write!(
                    f,
                    "{name} ({mib} MB \u{00B7} {iterations} iter \u{00B7} {parallelism} threads)"
                )
            }
            _ => f.write_str("Unknown KDF"),
        }
    }
}

/// Format an integer with comma thousands separators (e.g. 6000000 →
/// "6,000,000"). Used by the AES-KDF branch.
fn format_with_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass_core::format::Argon2Version;

    fn argon2(salt: &[u8], memory_bytes: u64) -> KdfParams {
        KdfParams::Argon2 {
            variant: Argon2Variant::Argon2id,
            salt: salt.to_vec(),
            iterations: 2,
            memory_bytes,
            parallelism: 2,
            version: Argon2Version::V13,
        }
    }

    #[test]
    fn salt_and_seed_are_not_cost() {
        assert_eq!(
            KdfCost::of(&argon2(&[1; 32], 64 << 20)),
            KdfCost::of(&argon2(&[2; 32], 64 << 20))
        );
        assert_eq!(
            KdfCost::of(&KdfParams::AesKdf {
                seed: [7; 32],
                rounds: 60_000
            }),
            KdfCost::aes_kdf(60_000)
        );
    }

    #[test]
    fn every_work_parameter_is_cost() {
        let base = KdfCost::of(&argon2(&[1; 32], 64 << 20));
        assert_ne!(base, KdfCost::of(&argon2(&[1; 32], 6 << 30)));
        let more_passes = KdfParams::Argon2 {
            variant: Argon2Variant::Argon2id,
            salt: vec![1; 32],
            iterations: 3,
            memory_bytes: 64 << 20,
            parallelism: 2,
            version: Argon2Version::V13,
        };
        assert_ne!(base, KdfCost::of(&more_passes));
        assert_ne!(base, KdfCost::aes_kdf(60_000));
        assert_ne!(KdfCost::aes_kdf(60_000), KdfCost::aes_kdf(60_001));
    }

    #[test]
    fn display_matches_the_info_tab_form() {
        assert_eq!(
            KdfCost::of(&argon2(&[1; 32], 64 << 20)).to_string(),
            "Argon2id (64 MB \u{00B7} 2 iter \u{00B7} 2 threads)"
        );
        assert_eq!(
            KdfCost::aes_kdf(6_000_000).to_string(),
            "AES-KDF (6,000,000 rounds)"
        );
    }
}
