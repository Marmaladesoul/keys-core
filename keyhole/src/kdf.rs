//! KDF settings on the command line: the `--approve-kdf` spec, the `kdf`
//! report that prints one (or how a file's settings weaken a vault's
//! recorded ones), `set-kdf`, which changes a vault file's KDF settings the
//! way another client would, and the envelope tools `envelope` / `rewrap`.
//!
//! A spec names exact settings, salt aside:
//! `argon2id:memory=67108864:iterations=2:parallelism=2:version=19`
//! (also `argon2d:…`) or `aes-kdf:rounds=60000`. `keyhole kdf <vault>`
//! prints the spec of what a file demands, so a scenario approves exactly
//! what it was shown.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use keys_ffi::{
    Argon2Kind, Engine, KdfSettings, KdfSummary, KdfWeakening, kdf_weakenings, read_kdbx_kdf,
};

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
/// (`none` when nothing is), read without syncing the mirror. With
/// `against`, print instead how the file's settings would weaken those
/// that vault's mirror recorded — `weaker=<comma-separated weakenings>`, or
/// `weaker=none` — the judgement a client shows beside an approval prompt.
pub fn print(vault: &Path, recorded: bool, against: Option<&Path>) -> Result<()> {
    if let Some(against) = against {
        let current = recorded_summary(against)?
            .with_context(|| format!("no recorded KDF settings for {}", against.display()))?;
        let weakenings = kdf_weakenings(current.settings, file_summary(vault)?.settings)
            .map_err(|e| anyhow::anyhow!("kdf_weakenings: {e:?}"))?;
        let rendered: Vec<&str> = weakenings.into_iter().map(weakening_name).collect();
        println!(
            "weaker={}",
            if rendered.is_empty() {
                "none".to_owned()
            } else {
                rendered.join(",")
            }
        );
        return Ok(());
    }
    let summary = if recorded {
        recorded_summary(vault)?
    } else {
        Some(file_summary(vault)?)
    };
    match summary {
        Some(s) => println!("{}", render(&s)),
        None => println!("none"),
    }
    Ok(())
}

/// What the file at `vault` demands, from its header alone.
fn file_summary(vault: &Path) -> Result<KdfSummary> {
    read_kdbx_kdf(vault.to_string_lossy().into_owned())
        .map_err(|e| anyhow::anyhow!("read_kdbx_kdf: {e:?}"))
}

/// What the vault's mirror recorded for its file, read without syncing.
fn recorded_summary(vault: &Path) -> Result<Option<KdfSummary>> {
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
        .map_err(|e| anyhow::anyhow!("recorded_kdf: {e:?}"))
}

fn weakening_name(w: KdfWeakening) -> &'static str {
    match w {
        KdfWeakening::LosesMemoryHardness => "loses-memory-hardness",
        KdfWeakening::LessMemory => "less-memory",
        KdfWeakening::LessWork => "less-work",
        KdfWeakening::LosesArgon2id => "loses-argon2id",
        KdfWeakening::OlderArgon2Version => "older-argon2-version",
        KdfWeakening::Unmodelled => "unmodelled",
    }
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
/// overridden parameters, or with exactly the settings `spec` names (which
/// may switch family, variant or version). Not a client capability of
/// Keys, so it bypasses the seam and uses keepass-core directly.
pub fn set_kdf(
    vault: &Path,
    password: &str,
    spec: Option<&str>,
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
    if let Some(spec) = spec {
        anyhow::ensure!(
            argon2_memory_mib.is_none() && argon2_iterations.is_none() && aes_rounds.is_none(),
            "--kdf names the whole setting; don't combine it with --argon2-* / --aes-rounds"
        );
        params = params_of(&parse_spec(spec)?)?;
    }
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

/// The salt length `params_of` writes; the re-key replaces the bytes with
/// fresh ones of this length. 32 is what KDBX writers emit.
const SPEC_SALT_LEN: usize = 32;

/// Argon2 1.0, as KDBX stores it.
const ARGON2_VERSION_10: u32 = 0x10;
/// Argon2 1.3, as KDBX stores it.
const ARGON2_VERSION_13: u32 = 0x13;

/// keepass-core parameters for exactly `settings`, with a placeholder salt.
fn params_of(settings: &KdfSettings) -> Result<keepass_core::format::KdfParams> {
    use keepass_core::format::{Argon2Variant, Argon2Version, KdfParams};
    Ok(match *settings {
        KdfSettings::AesKdf { rounds } => KdfParams::AesKdf {
            seed: [0; SPEC_SALT_LEN],
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
            salt: vec![0; SPEC_SALT_LEN],
            iterations,
            memory_bytes,
            parallelism,
            version: match version {
                ARGON2_VERSION_10 => Argon2Version::V10,
                ARGON2_VERSION_13 => Argon2Version::V13,
                other => anyhow::bail!("Argon2 version {other} is not 16 (1.0) or 19 (1.3)"),
            },
        },
    })
}

/// Print the parts of a file's envelope an approval of its KDF settings
/// doesn't cover, from its header alone:
/// `kdbx=<major>\tcipher=<uuid>\tcompression=<none|gzip>`.
pub fn envelope(vault: &Path) -> Result<()> {
    use keepass_core::format::{CompressionFlags, Version};
    use keepass_core::kdbx::Kdbx;

    let read = Kdbx::open(vault)
        .with_context(|| format!("open {}", vault.display()))?
        .read_header()
        .context("read outer header")?;
    let major = match read.version() {
        Version::V3 => "3",
        Version::V4 => "4",
        other => anyhow::bail!("unmodelled KDBX version: {other:?}"),
    };
    let compression = match read.header().compression {
        CompressionFlags::None => "none",
        CompressionFlags::Gzip => "gzip",
        other => anyhow::bail!("unmodelled compression: {other:?}"),
    };
    println!(
        "kdbx={major}\tcipher={}\tcompression={compression}",
        read.header().cipher_id.0.hyphenated()
    );
    Ok(())
}

/// Write the contents of the vault file at `vault` (opened under
/// `password`) into the envelope of the file at `template` (opened under
/// `template_password`) — its KDBX version, cipher and KDF — re-keyed to
/// `password`, at `out`: the same vault as another client writing another
/// format would save it. keepass-core authors KDBX4 only, so this is how a
/// scenario gets a KDBX3 replica. Not a client capability of Keys, so it
/// bypasses the seam.
pub fn rewrap(
    vault: &Path,
    template: &Path,
    out: &Path,
    password: &str,
    template_password: &str,
) -> Result<()> {
    use keepass_core::CompositeKey;
    use keepass_core::kdbx::Kdbx;

    let key = CompositeKey::from_password(password.as_bytes());
    let contents = Kdbx::open(vault)
        .with_context(|| format!("open {}", vault.display()))?
        .read_header()
        .context("read vault header")?
        .unlock(&key)
        .context("unlock vault")?;
    let mut wrapped = Kdbx::open(template)
        .with_context(|| format!("open {}", template.display()))?
        .read_header()
        .context("read template header")?
        .unlock(&CompositeKey::from_password(template_password.as_bytes()))
        .context("unlock template")?;
    wrapped.replace_vault(contents.vault().clone());
    wrapped
        .rekey(&key)
        .context("re-key to the vault's password")?;
    let bytes = wrapped.save_to_bytes().context("save")?;
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "rewrapped {} in the envelope of {}",
        vault.display(),
        template.display()
    );
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
