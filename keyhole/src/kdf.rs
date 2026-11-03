//! KDF settings on the command line: the `--approve-kdf` spec, the `kdf`
//! report that prints one, and `set-kdf`, which changes a vault file's KDF
//! settings the way another client would.
//!
//! A spec names exact settings, salt aside:
//! `argon2id:memory=67108864:iterations=2:parallelism=2:version=19`
//! (also `argon2d:…`) or `aes-kdf:rounds=60000`. `keyhole kdf <vault>`
//! prints the spec of what a file demands, so a scenario approves exactly
//! what it was shown.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use keys_ffi::{Argon2Kind, Engine, KdfSettings, KdfSummary, read_kdbx_kdf};

use crate::adapters::{FixedDbKey, FixedProtector};

/// The settings `--approve-kdf` approved for this one command. keyhole runs
/// one command per process, so the approval is process-wide by construction.
static APPROVED: OnceLock<Option<KdfSettings>> = OnceLock::new();

/// Record this command's `--approve-kdf`, parsed. Call once, from `main`.
pub fn set_approved(spec: Option<&str>) -> Result<()> {
    let approved = spec.map(parse_spec).transpose()?;
    APPROVED
        .set(approved)
        .map_err(|_| anyhow::anyhow!("--approve-kdf recorded twice"))
}

/// The settings `--approve-kdf` approved, if any.
pub fn approved() -> Option<KdfSettings> {
    APPROVED.get().cloned().flatten()
}

/// Print what the vault file demands of its KDF — one line, the scenario
/// contract: `<spec>\t<description>\tmemory_bytes=<n>\testimated_seconds=<s>\texceeds_ceiling=<bool>`.
/// With `recorded`, print instead what the vault's mirror recorded for it
/// (`none` when nothing is), read without syncing the mirror.
pub fn print(vault: &Path, recorded: bool) -> Result<()> {
    let summary = if recorded {
        let db = crate::mirror_db_for(vault);
        anyhow::ensure!(db.exists(), "no mirror for {}", vault.display());
        let engine = Engine::open(
            db.to_string_lossy().into_owned(),
            std::sync::Arc::new(FixedDbKey),
            std::sync::Arc::new(FixedProtector),
            None,
        )
        .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?;
        engine
            .recorded_kdf()
            .map_err(|e| anyhow::anyhow!("recorded_kdf: {e:?}"))?
    } else {
        Some(
            read_kdbx_kdf(vault.to_string_lossy().into_owned())
                .map_err(|e| anyhow::anyhow!("read_kdbx_kdf: {e:?}"))?,
        )
    };
    match summary {
        Some(s) => println!("{}", render(&s)),
        None => println!("none"),
    }
    Ok(())
}

fn render(s: &KdfSummary) -> String {
    format!(
        "{}\t{}\tmemory_bytes={}\testimated_seconds={:.2}\texceeds_ceiling={}",
        format_spec(&s.settings),
        s.description,
        s.memory_bytes,
        s.estimated_seconds,
        s.exceeds_ceiling
    )
}

/// Change the KDF settings of the vault file at `vault` in place, as
/// another client would: re-key it under the same password with the
/// overridden parameters. Not a client capability of Keys, so it bypasses
/// the seam and uses keepass-core directly.
pub fn set_kdf(
    vault: &Path,
    password: &str,
    argon2_memory_mib: Option<u64>,
    argon2_iterations: Option<u64>,
    aes_rounds: Option<u64>,
) -> Result<()> {
    use keepass_core::CompositeKey;
    use keepass_core::format::KdfParams;
    use keepass_core::kdbx::Kdbx;

    let key = CompositeKey::from_password(password.as_bytes());
    let mut kdbx = Kdbx::open(vault)
        .with_context(|| format!("open {}", vault.display()))?
        .read_header()
        .context("read outer header")?
        .unlock(&key)
        .context("unlock")?;
    let mut params = kdbx
        .outer_header()
        .decode_kdf_params()
        .context("decode KDF parameters")?;
    match &mut params {
        KdfParams::Argon2 {
            memory_bytes,
            iterations,
            ..
        } => {
            anyhow::ensure!(aes_rounds.is_none(), "--aes-rounds on an Argon2 vault");
            if let Some(mib) = argon2_memory_mib {
                *memory_bytes = mib
                    .checked_mul(1024 * 1024)
                    .context("--argon2-memory-mib overflows a byte count")?;
            }
            if let Some(passes) = argon2_iterations {
                *iterations = passes;
            }
        }
        KdfParams::AesKdf { rounds, .. } => {
            anyhow::ensure!(
                argon2_memory_mib.is_none() && argon2_iterations.is_none(),
                "--argon2-* on an AES-KDF vault"
            );
            if let Some(r) = aes_rounds {
                *rounds = r;
            }
        }
        other => anyhow::bail!("unsupported KDF family: {other:?}"),
    }
    kdbx.rekey_with_kdf(&key, &params)
        .context("re-key with the new KDF parameters")?;
    let bytes = kdbx.save_to_bytes().context("save")?;
    std::fs::write(vault, bytes).with_context(|| format!("write {}", vault.display()))?;
    println!("set KDF of {}", vault.display());
    Ok(())
}

fn format_spec(settings: &KdfSettings) -> String {
    match settings {
        KdfSettings::AesKdf { rounds } => format!("aes-kdf:rounds={rounds}"),
        KdfSettings::Argon2 {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            version,
        } => {
            let name = match variant {
                Argon2Kind::Argon2d => "argon2d",
                Argon2Kind::Argon2id => "argon2id",
            };
            format!(
                "{name}:memory={memory_bytes}:iterations={iterations}:parallelism={parallelism}:version={version}"
            )
        }
    }
}

fn parse_spec(spec: &str) -> Result<KdfSettings> {
    let mut parts = spec.split(':');
    let family = parts.next().unwrap_or_default();
    let mut fields = std::collections::HashMap::new();
    for part in parts {
        let (k, v) = part
            .split_once('=')
            .with_context(|| format!("KDF spec field without '=': {part}"))?;
        let v: u64 = v
            .parse()
            .with_context(|| format!("KDF spec field {k} is not a number"))?;
        anyhow::ensure!(fields.insert(k, v).is_none(), "KDF spec repeats {k}");
    }
    let mut take = |k: &str| {
        fields
            .remove(k)
            .with_context(|| format!("KDF spec lacks {k}"))
    };
    let settings = match family {
        "aes-kdf" => KdfSettings::AesKdf {
            rounds: take("rounds")?,
        },
        "argon2d" | "argon2id" => KdfSettings::Argon2 {
            variant: if family == "argon2d" {
                Argon2Kind::Argon2d
            } else {
                Argon2Kind::Argon2id
            },
            memory_bytes: take("memory")?,
            iterations: take("iterations")?,
            parallelism: u32::try_from(take("parallelism")?).context("parallelism")?,
            version: u32::try_from(take("version")?).context("version")?,
        },
        other => anyhow::bail!("unknown KDF family in spec: {other}"),
    };
    anyhow::ensure!(
        fields.is_empty(),
        "KDF spec has unknown fields: {:?}",
        fields.keys()
    );
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_round_trip() {
        for s in [
            "aes-kdf:rounds=60000",
            "argon2id:memory=67108864:iterations=2:parallelism=2:version=19",
            "argon2d:memory=1048576:iterations=9:parallelism=1:version=16",
        ] {
            assert_eq!(format_spec(&parse_spec(s).expect("parse")), s);
        }
        assert!(parse_spec("argon2id:memory=1").is_err());
        assert!(parse_spec("scrypt:n=1").is_err());
    }
}
