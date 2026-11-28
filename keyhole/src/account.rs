//! `account-*`: account identity driven through the `keys-ffi` seam.
//!
//! A directory stands in for one device's secure storage: each stored form
//! the seam hands back goes in a file of its own, as a client would put each
//! in its own Keychain item, and a later keyhole process reads them back. The
//! files are what a real client keeps secret; keyhole writes them mode 0600
//! in a directory of its own, and only for throwaway test accounts.
//!
//! - `account-create`: a fresh account and this device's keys, stored, with
//!   this device's enrolment. The recovery code goes in a file, for
//!   scenarios to type back; it is never printed.
//! - `account-device-keygen`: a device's keys only (a new device before it
//!   is paired).
//! - `account-show`: the stored keys read back by a fresh process, as an
//!   unlocked or a locked device can.
//! - `account-recovery`: a typed recovery code, checked against the stored
//!   account or for its form alone.
//! - `account-enrol`: the stored account signs another device's enrolment.
//! - `account-open-enrolment`: an enrolment checked against an account.
//!
//! Output is one `what: detail` line per fact, for scenarios to grep. A
//! refusal is a `refused: <reason>` line and still exits 0, so scenarios can
//! assert on it.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use keys_ffi::{
    AccountFfiError, DeviceSyncKeys, DeviceVaultKey, PairingAccountKeys, PairingDeviceKeys,
    RecoveryCodeCheck, generate_pairing_account, open_device_enrolment, read_recovery_code,
};

use crate::pairing::{hex, kebab};

/// The files in a device directory, one per secure-storage item.
const ACCOUNT_FILE: &str = "account.keys";
const DEVICE_SYNC_FILE: &str = "device-sync.keys";
const DEVICE_VAULT_FILE: &str = "device-vault.keys";
const ENROLMENT_FILE: &str = "enrolment";
const RECOVERY_CODE_FILE: &str = "recovery-code";
/// Owner read and write only.
const SECRET_FILE_MODE: u32 = 0o600;
const SECRET_DIR_MODE: u32 = 0o700;

/// `account-create`: generate and store an account and this device's keys,
/// and enrol this device under `endpoint` and `author`.
pub fn create(dir: &Path, endpoint: &str, author: &str) -> Result<()> {
    let endpoint = parse_key(endpoint, "--endpoint")?;
    let author = parse_key(author, "--author")?;
    make_secret_dir(dir)?;
    let account = generate_pairing_account()?;
    let device = PairingDeviceKeys::generate()?;
    write_secret(dir, ACCOUNT_FILE, &account.keys.stored_form())?;
    write_secret(
        dir,
        RECOVERY_CODE_FILE,
        account.recovery_secret.recovery_code().as_bytes(),
    )?;
    store_device(dir, &device)?;
    let enrolment =
        account
            .keys
            .enrol_device(device.public_keys(), endpoint.to_vec(), author.to_vec())?;
    write_secret(dir, ENROLMENT_FILE, &enrolment)?;
    print_account(&account.keys);
    let public = device.public_keys();
    print_device(&public.signing, &public.relay);
    println!("device vault {}", hex(&public.vault));
    Ok(())
}

/// `account-device-keygen`: generate and store a device's keys only.
pub fn device_keygen(dir: &Path) -> Result<()> {
    make_secret_dir(dir)?;
    let device = PairingDeviceKeys::generate()?;
    store_device(dir, &device)?;
    let public = device.public_keys();
    print_device(&public.signing, &public.relay);
    println!("device vault {}", hex(&public.vault));
    Ok(())
}

/// `account-show`: read the stored keys back from a directory made by
/// `account-create` (one from `account-device-keygen` has no account to
/// show, and reads only `--locked`). A locked device reads only what is
/// readable after first unlock: the device's signing and relay keys.
pub fn show(dir: &Path, locked: bool) -> Result<()> {
    let sync = match DeviceSyncKeys::from_stored(read(dir, DEVICE_SYNC_FILE)?) {
        Ok(sync) => sync,
        Err(error) => {
            refused(DEVICE_SYNC_FILE, &error);
            return Ok(());
        }
    };
    print_device(&sync.signing_public_key(), &sync.relay_public_key());
    if locked {
        println!("account: locked");
        return Ok(());
    }
    match DeviceVaultKey::from_stored(read(dir, DEVICE_VAULT_FILE)?) {
        Ok(vault) => println!("device vault {}", hex(&vault.public_key())),
        Err(error) => {
            refused(DEVICE_VAULT_FILE, &error);
            return Ok(());
        }
    }
    match PairingAccountKeys::from_stored(read(dir, ACCOUNT_FILE)?) {
        Ok(account) => print_account(&account),
        Err(error) => {
            refused(ACCOUNT_FILE, &error);
            return Ok(());
        }
    }
    Ok(())
}

/// `account-recovery`: check the recovery code in `code_file`, against the
/// account stored in `dir` or, without one, for its form only.
pub fn recovery(dir: Option<&Path>, code_file: &Path) -> Result<()> {
    let typed = fs::read_to_string(code_file)
        .with_context(|| format!("reading {}", code_file.display()))?;
    let check = match dir {
        Some(dir) => match PairingAccountKeys::from_stored(read(dir, ACCOUNT_FILE)?) {
            Ok(account) => account.check_recovery_code(typed),
            Err(error) => {
                refused(ACCOUNT_FILE, &error);
                return Ok(());
            }
        },
        None => read_recovery_code(typed),
    };
    println!("recovery-code: {}", describe_check(check));
    Ok(())
}

/// `account-enrol`: the account stored in `dir` enrols the device whose keys
/// are stored in `device_dir`, writing the enrolment to `out`.
pub fn enrol(
    dir: &Path,
    device_dir: &Path,
    endpoint: &str,
    author: &str,
    out: &Path,
) -> Result<()> {
    let endpoint = parse_key(endpoint, "--endpoint")?;
    let author = parse_key(author, "--author")?;
    let account = match PairingAccountKeys::from_stored(read(dir, ACCOUNT_FILE)?) {
        Ok(account) => account,
        Err(error) => {
            refused(ACCOUNT_FILE, &error);
            return Ok(());
        }
    };
    let sync = match DeviceSyncKeys::from_stored(read(device_dir, DEVICE_SYNC_FILE)?) {
        Ok(sync) => sync,
        Err(error) => {
            refused(DEVICE_SYNC_FILE, &error);
            return Ok(());
        }
    };
    let vault = match DeviceVaultKey::from_stored(read(device_dir, DEVICE_VAULT_FILE)?) {
        Ok(vault) => vault,
        Err(error) => {
            refused(DEVICE_VAULT_FILE, &error);
            return Ok(());
        }
    };
    let device = keys_ffi::PairingDevicePublicKeys {
        signing: sync.signing_public_key(),
        relay: sync.relay_public_key(),
        vault: vault.public_key(),
    };
    match account.enrol_device(device, endpoint.to_vec(), author.to_vec()) {
        Ok(enrolment) => {
            fs::write(out, enrolment).with_context(|| format!("writing {}", out.display()))?;
            println!("enrolment: signed");
            Ok(())
        }
        Err(error) => {
            refused("enrolment", &error);
            Ok(())
        }
    }
}

/// `account-open-enrolment`: check the enrolment in `file` against the
/// account identity key `identity`.
pub fn open_enrolment(file: &Path, identity: &str) -> Result<()> {
    let identity = parse_key(identity, "--identity")?;
    let enrolment = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    match open_device_enrolment(enrolment, identity.to_vec()) {
        Ok(record) => {
            println!("enrolment: valid");
            println!("device id {}", hex(&record.device_id));
            println!("device signing {}", hex(&record.keys.signing));
            println!("device relay {}", hex(&record.keys.relay));
            println!("device vault {}", hex(&record.keys.vault));
            println!("device endpoint {}", hex(&record.endpoint_id));
            println!("device author {}", hex(&record.author_id));
            Ok(())
        }
        Err(error) => {
            refused("enrolment", &error);
            Ok(())
        }
    }
}

/// The contents of a stored file in a device directory.
fn read(dir: &Path, name: &str) -> Result<Vec<u8>> {
    let path = dir.join(name);
    fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

fn store_device(dir: &Path, device: &Arc<PairingDeviceKeys>) -> Result<()> {
    write_secret(dir, DEVICE_SYNC_FILE, &device.sync_stored_form())?;
    write_secret(dir, DEVICE_VAULT_FILE, &device.vault_stored_form())
}

fn print_account(account: &PairingAccountKeys) {
    let keys = account.public_keys();
    println!("account identity {}", hex(&keys.identity));
    println!("account recovery {}", hex(&keys.recovery));
    println!("account encryption {}", hex(&keys.encryption));
}

/// A device's id is its signing public key.
fn print_device(signing: &[u8], relay: &[u8]) {
    println!("device id {}", hex(signing));
    println!("device relay {}", hex(relay));
}

fn refused(what: &str, error: &AccountFfiError) {
    println!("refused: {what} {}", kebab(&format!("{error:?}")));
}

fn describe_check(check: RecoveryCodeCheck) -> String {
    match check {
        RecoveryCodeCheck::Valid => "valid".to_owned(),
        RecoveryCodeCheck::WrongLength { characters } => {
            format!("wrong-length characters={characters}")
        }
        RecoveryCodeCheck::NotInAlphabet { group } => format!("not-in-alphabet group={group}"),
        RecoveryCodeCheck::Typo { group } => format!("typo group={group}"),
        RecoveryCodeCheck::Unreadable => "unreadable".to_owned(),
        RecoveryCodeCheck::NotThisAccount => "not-this-account".to_owned(),
    }
}

fn parse_key(text: &str, flag: &str) -> Result<[u8; 32]> {
    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{flag} must be 32 bytes of hex");
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>();
    match bytes.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
        Some(key) => Ok(key),
        None => bail!("{flag} must be 32 bytes of hex"),
    }
}

/// Creates `dir` for secrets, refusing one that already exists so a run
/// never mixes two accounts' files.
fn make_secret_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        bail!(
            "{} already exists; keys go in a fresh directory",
            dir.display()
        );
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    set_mode(dir, SECRET_DIR_MODE)
}

/// Writes a new file that is owner-only from the moment it exists.
fn write_secret(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let path = dir.join(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, SECRET_FILE_MODE);
    options
        .open(&path)
        .and_then(|mut file| file.write_all(bytes))
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
