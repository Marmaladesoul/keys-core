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
//! never costs more than opening this vault already does — unless the
//! user approved exactly that peer cost ([`crate::Engine::adopt_peer_kdf`]).
//!
//! The vault's own file is gated too ([`check_vault_file`]): its cost must
//! equal the cost the mirror recorded for it, or — with nothing recorded
//! yet — stay within a [`KdfCeiling`]. Anything else is
//! [`crate::EngineError::KdfApprovalRequired`] until the caller passes the
//! file's exact cost back as an approval ([`KdfPolicy::approved`]). An
//! approval covers that one cost, checked against the bytes about to be
//! derived, so a file that changes after the user said yes is refused
//! again rather than derived.
//!
//! What such a prompt should say about a change — whether the new settings
//! are weaker — is [`KdfCost::weakenings_from`]: a partial order (family,
//! then memory, work, variant, version), not a comparison of time
//! estimates, which can't see a loss of memory-hardness.

use std::fmt;

use keepass_core::format::{Argon2Variant, Argon2Version, KdfParams};
use keepass_core::kdbx::{HeaderRead, Kdbx};

use crate::error::EngineError;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Argon2 work this crate's Argon2 sustains on the reference device (an
/// Apple M1-class core), in bytes of memory × passes per second. The
/// implementation fills its lanes one after another, so parallelism does
/// not divide the time. Measured at 300–800 MiB-passes/s; the low end is
/// used so the estimate errs long on slower devices.
#[allow(clippy::cast_precision_loss)] // exact: 400 MiB is far below 2^52
const ARGON2_REFERENCE_BYTES_PER_SECOND: f64 = (400 * MIB) as f64;

/// AES-KDF rounds per second on the same reference device. Measured at
/// 15–37 million; the low end again.
const AES_KDF_REFERENCE_ROUNDS_PER_SECOND: f64 = 15_000_000.0;

/// How long a derive may be estimated to take before it needs the user's
/// approval — long enough for any setting a client's own "derive in about a
/// second" calibration picks on a slower device, short enough that the
/// approval stands between the user and a stalled open.
const DERIVE_SECONDS_NEEDING_APPROVAL: f64 = 10.0;

/// The Argon2 memory a derive may allocate without approval in an ordinary
/// app process: 16× the 64 MiB the common clients default to.
const STANDARD_MAX_MEMORY_BYTES: u64 = GIB;

/// The same, for a process with a hard memory budget — an iOS credential
/// provider extension is killed at roughly 120 MB, and the derive shares that with
/// the extension itself. 64 MiB is the common clients' default, so a
/// default vault still opens there.
const CONSTRAINED_MAX_MEMORY_BYTES: u64 = 64 * MIB;

/// The least Argon2 memory credited with memory-hardness when judging a
/// change away from AES-KDF ([`KdfCost::weakenings_from`]): OWASP's minimum
/// Argon2id memory, 19 MiB. Below it, the change is judged on its time
/// estimate, as a change within one family is on its work.
const MEMORY_HARD_FLOOR_BYTES: u64 = 19 * MIB;

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
    /// The cost a read KDBX file's outer header demands.
    ///
    /// # Errors
    ///
    /// [`EngineError::Serialise`] if the header's KDF parameters don't
    /// decode.
    pub fn of_header(read: &Kdbx<HeaderRead>) -> Result<Self, EngineError> {
        let params = read
            .header()
            .decode_kdf_params()
            .map_err(|e| EngineError::Serialise(format!("read kdf parameters: {e}")))?;
        Ok(Self::of(&params))
    }

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

impl KdfCost {
    /// The KDF parameters this cost stands for. The salt / transform seed
    /// is zeroed (or empty): it is not part of the cost.
    #[must_use]
    pub fn params(&self) -> &KdfParams {
        &self.0
    }

    /// What deriving at this cost takes: the memory it allocates and an
    /// estimate of how long it runs on the reference device. `None` for a
    /// KDF family this build doesn't model, whose cost can't be estimated.
    #[must_use]
    pub fn estimate(&self) -> Option<KdfEstimate> {
        match &self.0 {
            KdfParams::AesKdf { rounds, .. } => Some(KdfEstimate {
                // AES-KDF transforms a 32-byte block in place.
                memory_bytes: 0,
                #[allow(clippy::cast_precision_loss)]
                seconds: *rounds as f64 / AES_KDF_REFERENCE_ROUNDS_PER_SECOND,
            }),
            KdfParams::Argon2 {
                memory_bytes,
                iterations,
                ..
            } => Some(KdfEstimate {
                memory_bytes: *memory_bytes,
                #[allow(clippy::cast_precision_loss)]
                seconds: *memory_bytes as f64 * *iterations as f64
                    / ARGON2_REFERENCE_BYTES_PER_SECOND,
            }),
            _ => None,
        }
    }

    /// Whether deriving at this cost goes past `ceiling` — or can't be
    /// estimated at all, which no ceiling can vouch for.
    #[must_use]
    pub fn exceeds(&self, ceiling: KdfCeiling) -> bool {
        self.estimate().is_none_or(|e| {
            e.memory_bytes > ceiling.max_memory_bytes || e.seconds > ceiling.max_seconds
        })
    }

    /// Every respect in which this cost, proposed to replace `current`, is
    /// weaker than `current` against someone guessing the password offline —
    /// empty when it is weaker in none.
    ///
    /// Not a comparison of time estimates: two settings can take the same
    /// time on the reference device and resist an attacker very
    /// differently. The order is family first (memory-hard Argon2 above
    /// AES-KDF), then within Argon2 memory, total work, variant and
    /// version, each judged on its own. Moving from AES-KDF to Argon2 is
    /// not weaker, whatever the estimates — it gains memory-hardness — so
    /// long as the Argon2 memory is enough to count (19 MiB, OWASP's
    /// minimum); below that it is judged on its time estimate. A
    /// KDF family this build doesn't model can't be judged, so a change to
    /// or from one is [`KdfWeakening::Unmodelled`].
    #[must_use]
    pub fn weakenings_from(&self, current: &KdfCost) -> Vec<KdfWeakening> {
        let mut weakenings = Vec::new();
        if self == current {
            return weakenings;
        }
        match (&current.0, &self.0) {
            (
                KdfParams::Argon2 {
                    variant: current_variant,
                    memory_bytes: current_memory,
                    iterations: current_iterations,
                    version: current_version,
                    ..
                },
                KdfParams::Argon2 {
                    variant,
                    memory_bytes,
                    iterations,
                    version,
                    ..
                },
            ) => {
                if memory_bytes < current_memory {
                    weakenings.push(KdfWeakening::LessMemory);
                }
                // Memory × passes is the work; exact in u128.
                if u128::from(*memory_bytes) * u128::from(*iterations)
                    < u128::from(*current_memory) * u128::from(*current_iterations)
                {
                    weakenings.push(KdfWeakening::LessWork);
                }
                if *current_variant == Argon2Variant::Argon2id
                    && *variant != Argon2Variant::Argon2id
                {
                    weakenings.push(KdfWeakening::LosesArgon2id);
                }
                if *current_version == Argon2Version::V13 && *version != Argon2Version::V13 {
                    weakenings.push(KdfWeakening::OlderArgon2Version);
                }
            }
            (
                KdfParams::AesKdf {
                    rounds: current_rounds,
                    ..
                },
                KdfParams::AesKdf { rounds, .. },
            ) => {
                if rounds < current_rounds {
                    weakenings.push(KdfWeakening::LessWork);
                }
            }
            (KdfParams::Argon2 { .. }, KdfParams::AesKdf { .. }) => {
                weakenings.push(KdfWeakening::LosesMemoryHardness);
            }
            (KdfParams::AesKdf { .. }, KdfParams::Argon2 { memory_bytes, .. }) => {
                // Gains memory-hardness — unless it hardly uses any memory,
                // when it is only as good as the work it asks.
                let quicker = self
                    .estimate()
                    .zip(current.estimate())
                    .is_some_and(|(proposed, current)| proposed.seconds < current.seconds);
                if *memory_bytes < MEMORY_HARD_FLOOR_BYTES && quicker {
                    weakenings.push(KdfWeakening::LessWork);
                }
            }
            _ => weakenings.push(KdfWeakening::Unmodelled),
        }
        weakenings
    }
}

/// One respect in which proposed KDF settings are weaker than the ones they
/// replace ([`KdfCost::weakenings_from`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfWeakening {
    /// Argon2 replaced by AES-KDF, which is not memory-hard: a GPU or ASIC
    /// runs far more guesses per second against it than the time estimate
    /// suggests.
    LosesMemoryHardness,
    /// Less Argon2 memory, so each guess needs less of the resource that
    /// makes Argon2 costly to attack in parallel.
    LessMemory,
    /// Less work within the same KDF family: fewer Argon2 memory-passes, or
    /// fewer AES-KDF rounds.
    LessWork,
    /// Argon2id replaced by another variant (Argon2d), giving up Argon2id's
    /// resistance to side-channel attacks.
    LosesArgon2id,
    /// Argon2 version 1.3 replaced by an older one (1.0), which 1.3 made
    /// harder to attack with time-memory trade-offs.
    OlderArgon2Version,
    /// A change to or from a KDF family this build doesn't model, which
    /// can't be judged.
    Unmodelled,
}

/// What a derive at some [`KdfCost`] takes ([`KdfCost::estimate`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfEstimate {
    /// Memory the KDF allocates, in bytes.
    pub memory_bytes: u64,
    /// Estimated wall-clock seconds on the reference device. Slower
    /// devices take longer.
    pub seconds: f64,
}

/// The most a derive may cost before it needs the user's approval, when
/// there is no recorded cost to compare with ([`check_vault_file`]).
///
/// An approval threshold, not a hard limit: a file whose cost matches the
/// recorded one, or that the user approved, derives whatever the ceiling.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfCeiling {
    /// Most Argon2 memory, in bytes.
    pub max_memory_bytes: u64,
    /// Longest estimated derive, in seconds ([`KdfEstimate::seconds`]).
    pub max_seconds: f64,
}

impl KdfCeiling {
    /// An ordinary app process.
    pub const STANDARD: Self = Self {
        max_memory_bytes: STANDARD_MAX_MEMORY_BYTES,
        max_seconds: DERIVE_SECONDS_NEEDING_APPROVAL,
    };

    /// A process with a hard memory budget, such as a credential provider
    /// extension.
    pub const MEMORY_CONSTRAINED: Self = Self {
        max_memory_bytes: CONSTRAINED_MAX_MEMORY_BYTES,
        max_seconds: DERIVE_SECONDS_NEEDING_APPROVAL,
    };
}

/// How a derive of the vault's own file is gated ([`check_vault_file`]).
#[derive(Debug, Clone, Copy)]
pub struct KdfPolicy<'a> {
    /// The bound for a file with no recorded cost to compare with.
    pub ceiling: KdfCeiling,
    /// A cost the user has approved after being shown it. Lets a file of
    /// exactly this cost through, and nothing else.
    pub approved: Option<&'a KdfCost>,
}

impl KdfPolicy<'static> {
    /// [`KdfCeiling::STANDARD`], nothing approved.
    pub const STANDARD: Self = Self {
        ceiling: KdfCeiling::STANDARD,
        approved: None,
    };
}

/// The gate in front of deriving the vault's own file, whose outer header
/// demands `file`. Passes when:
///
/// - `file` is exactly the approved cost; or
/// - the mirror has a `recorded` cost and `file` equals it (the vault's
///   settings are unchanged, at whatever cost they were accepted); or
/// - nothing is recorded (a vault being opened for the first time, or a
///   mirror being rebuilt) and `file` is within the ceiling.
///
/// Anything else — a changed cost, or a first open past the ceiling — is
/// for the user to approve.
///
/// # Errors
///
/// [`EngineError::KdfApprovalRequired`] carrying `recorded` and `file`.
pub fn check_vault_file(
    file: &KdfCost,
    recorded: Option<&KdfCost>,
    policy: KdfPolicy<'_>,
) -> Result<(), EngineError> {
    let passes = policy.approved == Some(file)
        || match recorded {
            Some(recorded) => recorded == file,
            None => !file.exceeds(policy.ceiling),
        };
    if passes {
        Ok(())
    } else {
        Err(EngineError::KdfApprovalRequired {
            recorded: recorded.cloned(),
            file: file.clone(),
        })
    }
}

/// [`check_vault_file`] for a read vault file, from its outer header alone:
/// the gate every derive of a vault file passes first.
///
/// # Errors
///
/// As [`check_vault_file`], and as [`KdfCost::of_header`].
pub fn check_vault_header(
    read: &Kdbx<HeaderRead>,
    recorded: Option<&KdfCost>,
    policy: KdfPolicy<'_>,
) -> Result<(), EngineError> {
    check_vault_file(&KdfCost::of_header(read)?, recorded, policy)
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

    fn approval_required(r: &Result<(), EngineError>) -> bool {
        matches!(r, Err(EngineError::KdfApprovalRequired { .. }))
    }

    #[test]
    fn the_ceiling_bounds_memory_and_estimated_time() {
        let default = KdfCost::of(&argon2(&[1; 32], 64 * MIB));
        assert!(!default.exceeds(KdfCeiling::STANDARD));
        assert!(!default.exceeds(KdfCeiling::MEMORY_CONSTRAINED));

        let big = KdfCost::of(&argon2(&[1; 32], 128 * MIB));
        assert!(!big.exceeds(KdfCeiling::STANDARD));
        assert!(big.exceeds(KdfCeiling::MEMORY_CONSTRAINED));

        assert!(KdfCost::of(&argon2(&[1; 32], 2 * GIB)).exceeds(KdfCeiling::STANDARD));

        // Within the memory bound, but too many passes to finish in time.
        let slow = KdfParams::Argon2 {
            variant: Argon2Variant::Argon2id,
            salt: vec![1; 32],
            iterations: 1_000,
            memory_bytes: 64 * MIB,
            parallelism: 2,
            version: Argon2Version::V13,
        };
        assert!(KdfCost::of(&slow).exceeds(KdfCeiling::STANDARD));

        assert!(!KdfCost::aes_kdf(6_000_000).exceeds(KdfCeiling::STANDARD));
        assert!(KdfCost::aes_kdf(u64::from(u32::MAX)).exceeds(KdfCeiling::STANDARD));
    }

    #[test]
    fn an_unchanged_recorded_cost_passes_whatever_it_is() {
        let huge = KdfCost::of(&argon2(&[1; 32], 2 * GIB));
        assert!(check_vault_file(&huge, Some(&huge), KdfPolicy::STANDARD).is_ok());
    }

    #[test]
    fn any_change_from_the_recorded_cost_needs_approval() {
        let recorded = KdfCost::of(&argon2(&[1; 32], 64 * MIB));
        let file = KdfCost::of(&argon2(&[1; 32], 128 * MIB));
        assert!(approval_required(&check_vault_file(
            &file,
            Some(&recorded),
            KdfPolicy::STANDARD
        )));
        let approved = KdfPolicy {
            approved: Some(&file),
            ..KdfPolicy::STANDARD
        };
        assert!(check_vault_file(&file, Some(&recorded), approved).is_ok());
    }

    #[test]
    fn with_nothing_recorded_the_ceiling_decides() {
        let ok = KdfCost::of(&argon2(&[1; 32], 64 * MIB));
        let huge = KdfCost::of(&argon2(&[1; 32], 2 * GIB));
        assert!(check_vault_file(&ok, None, KdfPolicy::STANDARD).is_ok());
        assert!(approval_required(&check_vault_file(
            &huge,
            None,
            KdfPolicy::STANDARD
        )));
        let constrained = KdfPolicy {
            ceiling: KdfCeiling::MEMORY_CONSTRAINED,
            approved: None,
        };
        let big = KdfCost::of(&argon2(&[1; 32], 128 * MIB));
        assert!(approval_required(&check_vault_file(
            &big,
            None,
            constrained
        )));
    }

    #[test]
    fn an_approval_covers_exactly_the_cost_approved() {
        let approved = KdfCost::of(&argon2(&[1; 32], 2 * GIB));
        let other = KdfCost::of(&argon2(&[1; 32], 3 * GIB));
        let policy = KdfPolicy {
            approved: Some(&approved),
            ..KdfPolicy::STANDARD
        };
        assert!(check_vault_file(&approved, None, policy).is_ok());
        assert!(approval_required(&check_vault_file(&other, None, policy)));
    }

    fn argon2_cost(
        variant: Argon2Variant,
        memory_bytes: u64,
        iterations: u64,
        version: Argon2Version,
    ) -> KdfCost {
        KdfCost::of(&KdfParams::Argon2 {
            variant,
            salt: vec![1; 32],
            iterations,
            memory_bytes,
            parallelism: 2,
            version,
        })
    }

    fn argon2id(memory_bytes: u64, iterations: u64) -> KdfCost {
        argon2_cost(
            Argon2Variant::Argon2id,
            memory_bytes,
            iterations,
            Argon2Version::V13,
        )
    }

    /// What `weakenings_from` returns for a change that is weaker in no respect.
    const NOT_WEAKER: [KdfWeakening; 0] = [];

    fn seconds(cost: &KdfCost) -> f64 {
        cost.estimate().expect("modelled").seconds
    }

    /// Each downgrade the time estimate can't see: the proposed settings
    /// take at least as long to derive as the current ones, yet are weaker.
    #[test]
    fn a_downgrade_is_weaker_whatever_the_time_estimate() {
        let current = argon2id(64 * MIB, 2);
        let cases = [
            (
                KdfCost::aes_kdf(6_000_000),
                KdfWeakening::LosesMemoryHardness,
            ),
            (argon2id(8 * MIB, 16), KdfWeakening::LessMemory),
            (
                argon2_cost(Argon2Variant::Argon2d, 64 * MIB, 2, Argon2Version::V13),
                KdfWeakening::LosesArgon2id,
            ),
            (
                argon2_cost(Argon2Variant::Argon2id, 64 * MIB, 2, Argon2Version::V10),
                KdfWeakening::OlderArgon2Version,
            ),
        ];
        for (proposed, expected) in cases {
            assert!(
                seconds(&proposed) >= seconds(&current),
                "{proposed} should take no less time than {current}"
            );
            assert_eq!(
                proposed.weakenings_from(&current),
                [expected],
                "{current} -> {proposed}"
            );
        }
    }

    #[test]
    fn less_memory_at_the_same_work_is_weaker() {
        // 1 GiB × 1 → 8 MiB × 128: the same memory-passes, an eighth of the
        // memory an attacker needs per guess.
        let current = argon2id(GIB, 1);
        let proposed = argon2id(8 * MIB, 128);
        assert!((seconds(&proposed) - seconds(&current)).abs() < f64::EPSILON);
        assert_eq!(
            proposed.weakenings_from(&current),
            [KdfWeakening::LessMemory]
        );
    }

    #[test]
    fn less_work_in_the_same_family_is_weaker() {
        assert_eq!(
            argon2id(64 * MIB, 1).weakenings_from(&argon2id(64 * MIB, 2)),
            [KdfWeakening::LessWork]
        );
        assert_eq!(
            argon2id(32 * MIB, 1).weakenings_from(&argon2id(64 * MIB, 2)),
            [KdfWeakening::LessMemory, KdfWeakening::LessWork]
        );
        assert_eq!(
            KdfCost::aes_kdf(60_000).weakenings_from(&KdfCost::aes_kdf(6_000_000)),
            [KdfWeakening::LessWork]
        );
    }

    #[test]
    fn every_weakening_is_reported_together() {
        let current = argon2id(64 * MIB, 2);
        let proposed = argon2_cost(Argon2Variant::Argon2d, 16 * MIB, 1, Argon2Version::V10);
        assert_eq!(
            proposed.weakenings_from(&current),
            [
                KdfWeakening::LessMemory,
                KdfWeakening::LessWork,
                KdfWeakening::LosesArgon2id,
                KdfWeakening::OlderArgon2Version,
            ]
        );
    }

    #[test]
    fn a_stronger_or_unchanged_setting_is_not_weaker() {
        let current = argon2id(64 * MIB, 2);
        for proposed in [
            current.clone(),
            argon2id(128 * MIB, 2),
            argon2id(64 * MIB, 3),
            // Lanes don't change an attacker's cost.
            KdfCost::of(&KdfParams::Argon2 {
                variant: Argon2Variant::Argon2id,
                salt: vec![9; 32],
                iterations: 2,
                memory_bytes: 64 * MIB,
                parallelism: 1,
                version: Argon2Version::V13,
            }),
            // Argon2d → Argon2id and 1.0 → 1.3 are upgrades.
        ] {
            assert_eq!(proposed.weakenings_from(&current), NOT_WEAKER, "{proposed}");
        }
        let legacy = argon2_cost(Argon2Variant::Argon2d, 64 * MIB, 2, Argon2Version::V10);
        assert_eq!(current.weakenings_from(&legacy), NOT_WEAKER);
        assert_eq!(
            KdfCost::aes_kdf(6_000_001).weakenings_from(&KdfCost::aes_kdf(6_000_000)),
            NOT_WEAKER
        );
    }

    #[test]
    fn moving_from_aes_kdf_to_argon2_is_not_weaker() {
        // Quicker by the estimate, but memory-hard: an upgrade.
        let current = KdfCost::aes_kdf(60_000_000);
        let proposed = argon2id(64 * MIB, 2);
        assert!(seconds(&proposed) < seconds(&current));
        assert_eq!(proposed.weakenings_from(&current), NOT_WEAKER);
        assert_eq!(
            argon2id(MEMORY_HARD_FLOOR_BYTES, 1).weakenings_from(&current),
            NOT_WEAKER
        );
    }

    #[test]
    fn argon2_with_too_little_memory_to_count_is_judged_on_its_work() {
        let current = KdfCost::aes_kdf(60_000_000);
        // Next to no memory, and next to no time: no upgrade at all.
        let token = argon2_cost(Argon2Variant::Argon2d, 8 * 1024, 1, Argon2Version::V13);
        assert_eq!(token.weakenings_from(&current), [KdfWeakening::LessWork]);
        // Too little memory to count, but as slow as what it replaces.
        let slow = argon2id(MIB, 4_000);
        assert!(seconds(&slow) >= seconds(&current));
        assert_eq!(slow.weakenings_from(&current), NOT_WEAKER);
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
