//! KDF settings across the seam: what a vault file's KDF demands, shown to
//! the user before it is derived, and the exact settings they approve. The
//! gate and the approval flow are described on [`KdfSettings`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use keepass_core::format::{Argon2Variant, Argon2Version, KdfParams};
use keepass_core::kdbx::{Kdbx, Unlocked};
use keys_engine::KdbxStateSignature;
use keys_engine::kdf_cost::{self, KdfCeiling, KdfCost, KdfPolicy};
use secrecy::{ExposeSecret, SecretString};

use crate::engine_error::EngineError;

/// The salt length written into the parameters an approval rebuilds. Only
/// the cost is compared, so the value is immaterial; 32 bytes is what KDBX
/// writers emit.
const APPROVAL_SALT_LEN: usize = 32;

/// Argon2 algorithm version 1.0, as KDBX4 stores it.
const ARGON2_VERSION_10: u32 = 0x10;
/// Argon2 algorithm version 1.3, as KDBX4 stores it.
const ARGON2_VERSION_13: u32 = 0x13;

/// The exact KDF settings a vault file demands, salt aside — what the user
/// is shown and, on approval, what is passed back as `approved_kdf`.
///
/// A KDBX file's outer header names its own KDF parameters, and the KDF
/// has to run before anything else about the file can be checked. So every
/// derive of a vault file is gated on its cost
/// ([`keys_engine::kdf_cost::check_vault_file`]): it must equal the cost
/// the mirror recorded for the file, or — with nothing recorded — stay
/// within this process's [`KdfCeilingProfile`]. Anything else fails with
/// [`EngineError::KdfApprovalRequired`] before deriving.
///
/// The approval flow is: read what the file demands with
/// [`read_kdbx_kdf`] (header only, no derive) and, for a change, what the
/// vault had with `Engine::recorded_kdf`; show both; on the user's yes,
/// repeat the call passing [`KdfSummary::settings`] as `approved_kdf`. The
/// engine re-reads the file and derives only if it still demands exactly
/// those settings, so an approval never covers a file that changed after
/// the user saw it.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum KdfSettings {
    /// Legacy AES-KDF (KDBX3, or KDBX4 with AES-KDF).
    AesKdf {
        /// AES transformation rounds.
        rounds: u64,
    },
    /// Argon2 (KDBX4).
    Argon2 {
        /// Argon2d or Argon2id.
        variant: Argon2Kind,
        /// Memory cost, in bytes.
        memory_bytes: u64,
        /// Passes.
        iterations: u64,
        /// Lanes.
        parallelism: u32,
        /// Algorithm version as KDBX stores it: `0x10` or `0x13`.
        version: u32,
    },
}

/// Which Argon2.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2Kind {
    /// Argon2d.
    Argon2d,
    /// Argon2id.
    Argon2id,
}

/// [`KdfSettings`] with what deriving at them takes — the record a client
/// shows when asking the user to approve them.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct KdfSummary {
    /// The exact settings: pass these back as `approved_kdf`.
    pub settings: KdfSettings,
    /// Display form, e.g. `"Argon2id (64 MB · 2 iter · 4 threads)"` or
    /// `"AES-KDF (6,000,000 rounds)"`.
    pub description: String,
    /// Memory the derive allocates, in bytes.
    pub memory_bytes: u64,
    /// Estimated derive time in seconds on a recent Mac or phone; slower
    /// devices take longer. Not a measure of strength: two settings with the
    /// same estimate can resist an attacker very differently, so judge a
    /// change with [`kdf_weakenings`], not by comparing these.
    pub estimated_seconds: f64,
    /// Whether these settings go past this process's ceiling
    /// ([`set_kdf_ceiling`]) — a first open would need approval.
    pub exceeds_ceiling: bool,
}

/// One respect in which proposed KDF settings are weaker than the ones they
/// would replace — see [`kdf_weakenings`].
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfWeakening {
    /// Argon2 replaced by AES-KDF, which is not memory-hard: a GPU or ASIC
    /// runs far more guesses per second against it than the time estimate
    /// suggests.
    LosesMemoryHardness,
    /// Less Argon2 memory per guess.
    LessMemory,
    /// Less work within the same KDF family: fewer Argon2 memory-passes, or
    /// fewer AES-KDF rounds.
    LessWork,
    /// Argon2id replaced by Argon2d, giving up Argon2id's resistance to
    /// side-channel attacks.
    LosesArgon2id,
    /// Argon2 version 1.3 replaced by 1.0, which is easier to attack with
    /// time-memory trade-offs.
    OlderArgon2Version,
    /// A change to or from a KDF this build doesn't model, which can't be
    /// judged.
    Unmodelled,
}

impl From<keys_engine::KdfWeakening> for KdfWeakening {
    fn from(w: keys_engine::KdfWeakening) -> Self {
        use keys_engine::KdfWeakening as E;
        match w {
            E::LosesMemoryHardness => Self::LosesMemoryHardness,
            E::LessMemory => Self::LessMemory,
            E::LessWork => Self::LessWork,
            E::LosesArgon2id => Self::LosesArgon2id,
            E::OlderArgon2Version => Self::OlderArgon2Version,
            E::Unmodelled => Self::Unmodelled,
        }
    }
}

/// Every respect in which the `proposed` KDF settings are weaker than the
/// `current` ones against someone guessing the password offline — empty
/// when they are weaker in none. A client asking the user to approve a
/// change ([`KdfSettings`]) shows these, rather than judging strength
/// itself: two settings can take the same time to derive and resist an
/// attacker very differently (Argon2 vs AES-KDF, less memory for more
/// passes, Argon2id vs Argon2d, Argon2 1.3 vs 1.0), so comparing
/// [`KdfSummary::estimated_seconds`] misses them. Moving from AES-KDF to
/// Argon2 is never weaker.
///
/// # Errors
///
/// [`EngineError::Internal`] if either side names an Argon2 version other
/// than `0x10` or `0x13`.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // uniffi exports take owned arguments
pub fn kdf_weakenings(
    current: KdfSettings,
    proposed: KdfSettings,
) -> Result<Vec<KdfWeakening>, EngineError> {
    Ok(cost_of_settings(&proposed)?
        .weakenings_from(&cost_of_settings(&current)?)
        .into_iter()
        .map(KdfWeakening::from)
        .collect())
}

/// How much KDF cost this process derives without approval when there is no
/// recorded cost to compare with (a vault's first open, a mirror rebuild).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfCeilingProfile {
    /// An ordinary app process: up to 1 GiB of Argon2 memory and an
    /// estimated 10 s derive.
    Standard,
    /// A process with a hard memory budget, such as a credential provider
    /// extension: up to 64 MiB of Argon2 memory. Like the standard ceiling
    /// it applies only where nothing is recorded or approved — a vault whose
    /// recorded settings go past it still derives at them.
    MemoryConstrained,
}

/// Whether this process set [`KdfCeilingProfile::MemoryConstrained`]. The
/// memory budget belongs to the process, so the profile is process-wide.
static MEMORY_CONSTRAINED: AtomicBool = AtomicBool::new(false);

/// Set this process's KDF ceiling. Call once at start-up from a
/// memory-constrained process (a credential provider extension); an app process can
/// leave the default, [`KdfCeilingProfile::Standard`].
#[uniffi::export]
pub fn set_kdf_ceiling(profile: KdfCeilingProfile) {
    MEMORY_CONSTRAINED.store(
        profile == KdfCeilingProfile::MemoryConstrained,
        Ordering::Relaxed,
    );
}

/// What the KDBX file at `path` demands of its KDF, read from its outer
/// header alone: no password, no derive. The "show the settings" half of
/// the approval flow.
///
/// # Errors
///
/// [`EngineError::Internal`] if the file can't be read, isn't a KDBX file,
/// or names a KDF this build doesn't model.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // uniffi exports take owned arguments
pub fn read_kdbx_kdf(path: String) -> Result<KdfSummary, EngineError> {
    summary(&KdfCost::of_header(
        &Kdbx::open(Path::new(&path))
            .and_then(Kdbx::read_header)
            .map_err(|e| EngineError::Internal(format!("read kdbx header: {e}")))?,
    )?)
}

/// This process's ceiling.
pub(crate) fn ceiling() -> KdfCeiling {
    if MEMORY_CONSTRAINED.load(Ordering::Relaxed) {
        KdfCeiling::MEMORY_CONSTRAINED
    } else {
        KdfCeiling::STANDARD
    }
}

/// This process's gate policy, with `approved` (if any).
pub(crate) fn policy(approved: Option<&KdfCost>) -> KdfPolicy<'_> {
    KdfPolicy {
        ceiling: ceiling(),
        approved,
    }
}

/// The settings `approved` stands for, as an engine [`KdfCost`].
pub(crate) fn approved_cost(approved: Option<KdfSettings>) -> Result<Option<KdfCost>, EngineError> {
    approved.map(|s| cost_of_settings(&s)).transpose()
}

/// The summary of a cost, for display and approval.
pub(crate) fn summary(cost: &KdfCost) -> Result<KdfSummary, EngineError> {
    let estimate = cost
        .estimate()
        .ok_or_else(|| EngineError::Internal(format!("KDF not modelled: {cost}")))?;
    Ok(KdfSummary {
        settings: settings_of_cost(cost)?,
        description: cost.to_string(),
        memory_bytes: estimate.memory_bytes,
        estimated_seconds: estimate.seconds,
        exceeds_ceiling: cost.exceeds(ceiling()),
    })
}

/// Open the vault's own file at `path` under `password` + `keyfile`,
/// deriving only if its KDF cost passes the gate against `recorded` (the
/// cost the mirror recorded for it, if any) and `approved`.
///
/// Also returns the signature of the file as it was read, which is what a
/// caller ingesting it must record: the derive can take seconds, and a stat
/// afterwards would describe any change that landed meanwhile.
///
/// # Errors
///
/// [`EngineError::KdfApprovalRequired`] from the header alone when the gate
/// refuses; [`EngineError::Internal`] for an unreadable / undecryptable
/// file, as before the gate.
pub(crate) fn open_vault_file(
    path: &Path,
    password: &SecretString,
    keyfile: Option<&[u8]>,
    recorded: Option<&KdfCost>,
    approved: Option<&KdfCost>,
) -> Result<(Kdbx<Unlocked>, KdbxStateSignature), EngineError> {
    let composite =
        crate::keyfile::composite_for_engine(password.expose_secret().as_bytes(), keyfile)?;
    let (bytes, signature) = KdbxStateSignature::read_file(path)
        .map_err(|e| EngineError::Internal(format!("open kdbx: {e}")))?;
    let read = Kdbx::open_from_bytes(bytes)
        .and_then(Kdbx::read_header)
        .map_err(|e| EngineError::Internal(format!("open kdbx: {e}")))?;
    kdf_cost::check_vault_header(&read, recorded, policy(approved))?;
    let unlocked = read
        .unlock(&composite)
        .map_err(|e| EngineError::Internal(format!("open kdbx: {e}")))?;
    Ok((unlocked, signature))
}

/// Gate a file read with no mirror to hold it to: it may be derived within
/// this process's ceiling, or at exactly the `approved` settings.
///
/// # Errors
///
/// [`crate::VaultError::KdfApprovalRequired`] (carrying the file's settings)
/// otherwise; [`crate::VaultError::Unexpected`] if the header's KDF
/// parameters don't decode.
pub(crate) fn check_unrecorded_file(
    read: &Kdbx<keepass_core::kdbx::HeaderRead>,
    approved: Option<&KdfCost>,
) -> Result<(), crate::VaultError> {
    let cost =
        KdfCost::of_header(read).map_err(|e| crate::VaultError::Unexpected(e.to_string()))?;
    kdf_cost::check_vault_file(&cost, None, policy(approved))
        .map_err(|_| crate::VaultError::KdfApprovalRequired(cost.to_string()))
}

fn settings_of_cost(cost: &KdfCost) -> Result<KdfSettings, EngineError> {
    match cost.params() {
        KdfParams::AesKdf { rounds, .. } => Ok(KdfSettings::AesKdf { rounds: *rounds }),
        KdfParams::Argon2 {
            variant,
            iterations,
            memory_bytes,
            parallelism,
            version,
            ..
        } => Ok(KdfSettings::Argon2 {
            variant: match variant {
                Argon2Variant::Argon2d => Argon2Kind::Argon2d,
                Argon2Variant::Argon2id => Argon2Kind::Argon2id,
                other => {
                    return Err(EngineError::Internal(format!(
                        "Argon2 variant not modelled: {other:?}"
                    )));
                }
            },
            memory_bytes: *memory_bytes,
            iterations: *iterations,
            parallelism: *parallelism,
            version: match version {
                Argon2Version::V10 => ARGON2_VERSION_10,
                Argon2Version::V13 => ARGON2_VERSION_13,
                other => {
                    return Err(EngineError::Internal(format!(
                        "Argon2 version not modelled: {other:?}"
                    )));
                }
            },
        }),
        other => Err(EngineError::Internal(format!(
            "KDF not modelled: {other:?}"
        ))),
    }
}

pub(crate) fn cost_of_settings(settings: &KdfSettings) -> Result<KdfCost, EngineError> {
    let params = match *settings {
        KdfSettings::AesKdf { rounds } => KdfParams::AesKdf {
            seed: [0; APPROVAL_SALT_LEN],
            rounds,
        },
        KdfSettings::Argon2 {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            version,
        } => KdfParams::Argon2 {
            variant: match variant {
                Argon2Kind::Argon2d => Argon2Variant::Argon2d,
                Argon2Kind::Argon2id => Argon2Variant::Argon2id,
            },
            salt: vec![0; APPROVAL_SALT_LEN],
            iterations,
            memory_bytes,
            parallelism,
            version: match version {
                ARGON2_VERSION_10 => Argon2Version::V10,
                ARGON2_VERSION_13 => Argon2Version::V13,
                other => {
                    return Err(EngineError::Internal(format!(
                        "approved Argon2 version {other:#x} is not 0x10 or 0x13"
                    )));
                }
            },
        },
    };
    Ok(KdfCost::of(&params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_through_the_engine_cost() {
        for settings in [
            KdfSettings::AesKdf { rounds: 60_000 },
            KdfSettings::Argon2 {
                variant: Argon2Kind::Argon2id,
                memory_bytes: 64 << 20,
                iterations: 2,
                parallelism: 4,
                version: ARGON2_VERSION_13,
            },
            KdfSettings::Argon2 {
                variant: Argon2Kind::Argon2d,
                memory_bytes: 1 << 30,
                iterations: 9,
                parallelism: 1,
                version: ARGON2_VERSION_10,
            },
        ] {
            let cost = cost_of_settings(&settings).expect("cost");
            assert_eq!(settings_of_cost(&cost).expect("settings"), settings);
        }
    }

    #[test]
    fn weakenings_cross_the_seam_from_the_engine() {
        let argon2id = KdfSettings::Argon2 {
            variant: Argon2Kind::Argon2id,
            memory_bytes: 64 << 20,
            iterations: 2,
            parallelism: 4,
            version: ARGON2_VERSION_13,
        };
        let aes = KdfSettings::AesKdf { rounds: 6_000_000 };
        assert_eq!(
            kdf_weakenings(argon2id.clone(), aes.clone()).expect("judge"),
            [KdfWeakening::LosesMemoryHardness]
        );
        let not_weaker: [KdfWeakening; 0] = [];
        assert_eq!(kdf_weakenings(aes, argon2id).expect("judge"), not_weaker);
    }

    #[test]
    fn an_unknown_argon2_version_is_not_approvable() {
        let bogus = KdfSettings::Argon2 {
            variant: Argon2Kind::Argon2id,
            memory_bytes: 64 << 20,
            iterations: 2,
            parallelism: 4,
            version: 0x14,
        };
        assert!(cost_of_settings(&bogus).is_err());
    }
}
