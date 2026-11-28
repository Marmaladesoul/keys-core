//! Fuzz target for reading a vault document's head records: entries anyone
//! holding the document's write ticket can write, under any author, and
//! anyone holding a device's store can write under that device's author.
//!
//! A panic is a bug. So is acceptance of anything but the one head the
//! device signed, byte for byte, read under that device's own author and
//! newer than what the reader last accepted. The fuzzer writes bytes of its
//! own or alters the genuine head, and picks the author it is read under
//! (the signing device's, the other device's, or a stranger's) and the
//! reader's last accepted sequence. It also asks whether arbitrary entry
//! metadata would be fetched: only a head-key entry from a bound author,
//! small enough to be a head, may be.

#![no_main]

use std::sync::OnceLock;

use keys_account::statement::MAX_STATEMENT_BYTES;
use keys_account::vault_head::VAULT_HEAD_KEY;
use keys_account::{
    DeviceEnrolment, Roster, VaultHead, accept_vault_head, head_to_fetch, sign_vault_head,
};
use keys_pairing::{AccountKeys, DeviceKeys};
use libfuzzer_sys::fuzz_target;

/// Seed for the scripted random stream, so the account, the devices and so
/// the genuine head are the same on every run.
const SEED: &[u8] = b"keys-account fuzz: vault head";
const DOC: [u8; 32] = [0xd0; 32];
const SEQUENCE: u64 = 5;
const HEAD: VaultHead = VaultHead {
    content_hash: [0xc0; 32],
    size: 4096,
};

struct Fixture {
    roster: Roster,
    /// The signing device's author, then the other device's, then one that
    /// is no device's.
    authors: [[u8; 32]; 3],
    signer: [u8; 32],
    /// The other device's id, bound to `authors[1]`.
    other: [u8; 32],
    genuine: Vec<u8>,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn usable_key() -> [u8; 32] {
    DeviceKeys::generate()
        .expect("scripted random")
        .public_keys()
        .signing
}

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        keys_pairing::script_random_for_fuzzing(SEED);
        let (account, _) = AccountKeys::generate().expect("scripted random");
        let alice = DeviceKeys::generate().expect("scripted random");
        let bob = DeviceKeys::generate().expect("scripted random");
        let enrol = |device: &DeviceKeys, author| {
            DeviceEnrolment::sign(&account, device.public_keys(), usable_key(), author)
                .expect("usable keys")
                .to_bytes()
        };
        let authors = [usable_key(), usable_key(), usable_key()];
        let roster = Roster::open(
            &account.public_keys().identity,
            [
                enrol(&alice, authors[0]).as_slice(),
                enrol(&bob, authors[1]).as_slice(),
            ],
        )
        .expect("roster");
        Fixture {
            roster,
            authors,
            signer: alice.public_keys().signing,
            other: bob.public_keys().signing,
            genuine: sign_vault_head(alice.sync_keys(), &DOC, SEQUENCE, HEAD),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let Some((&[mode, author, last, cap], rest)) = data.split_first_chunk::<4>() else {
        return;
    };
    // A cap below, at or above the genuine head's copy.
    let cap = match cap % 3 {
        0 => HEAD.size - 1,
        1 => HEAD.size,
        _ => u64::MAX,
    };
    let author = fixture.authors[usize::from(author % 3)];
    // Below, at and above the genuine sequence, or nothing accepted yet.
    let last = match last % 4 {
        0 => None,
        n => Some(SEQUENCE + u64::from(n) - 2),
    };

    match mode % 3 {
        0 | 1 => {
            let candidate = if mode % 3 == 0 {
                rest.to_vec()
            } else {
                // XOR the input over the genuine head, then cut or pad it to
                // the input's length if that differs.
                let mut altered = fixture.genuine.clone();
                for (byte, mask) in altered.iter_mut().zip(rest) {
                    *byte ^= mask;
                }
                altered.resize(rest.len().max(1).min(2 * fixture.genuine.len()), 0);
                altered
            };
            if let Ok(accepted) =
                accept_vault_head(&fixture.roster, &DOC, &author, &candidate, last, cap)
            {
                assert_eq!(
                    candidate, fixture.genuine,
                    "a head nobody signed was accepted"
                );
                assert_eq!(
                    author, fixture.authors[0],
                    "a head was accepted under another author"
                );
                assert!(
                    last.is_none_or(|last| last < SEQUENCE),
                    "a head not newer was accepted"
                );
                assert!(
                    HEAD.size <= cap,
                    "a head naming a copy over the cap was accepted"
                );
                assert_eq!(accepted.device_id, fixture.signer);
                assert_eq!(accepted.sequence, SEQUENCE);
                assert_eq!(accepted.head, HEAD);
            }
        }
        _ => {
            // Arbitrary entry metadata: the first eight bytes a size, the rest
            // an entry key.
            let Some((size, key)) = rest.split_first_chunk::<8>() else {
                return;
            };
            let size = u64::from_be_bytes(*size);
            if let Ok(device) = head_to_fetch(&fixture.roster, &author, key, size) {
                assert_eq!(key, VAULT_HEAD_KEY, "a non-head entry would be fetched");
                assert_ne!(
                    author, fixture.authors[2],
                    "a stranger's entry would be fetched"
                );
                assert!(
                    size <= MAX_STATEMENT_BYTES as u64,
                    "an oversize head would be fetched"
                );
                let bound = if author == fixture.authors[0] {
                    fixture.signer
                } else {
                    fixture.other
                };
                assert_eq!(device, bound, "an author was bound to another device");
            }
        }
    }
});
