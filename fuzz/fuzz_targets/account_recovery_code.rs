//! Fuzz target for reading a typed recovery code back: whatever a person
//! types, or pastes.
//!
//! A panic is a bug. So is a code that reads back as a secret whose own code
//! isn't what was typed (once spelling is forgiven as the reader forgives
//! it), and a single typo the reader doesn't put in its group.

#![no_main]

use keys_account::recovery_code::{CHARACTERS, GROUP_LENGTH, is_separator};
use keys_account::{RecoveryCodeError, parse_recovery_code, recovery_code};
use keys_pairing::RecoverySecret;
use libfuzzer_sys::fuzz_target;

/// What the reader reads: separators dropped, upper case, O as 0, I and L
/// as 1.
fn normalised(typed: &str) -> String {
    typed
        .chars()
        .filter(|&c| !is_separator(c))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// The alphabet's symbols, in value order.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fuzz_target!(|data: &[u8]| {
    // Anything typed: if it reads, it is that secret's code.
    if let Ok(typed) = std::str::from_utf8(data) {
        if let Ok(secret) = parse_recovery_code(typed) {
            assert_eq!(
                normalised(&recovery_code(&secret)),
                normalised(typed),
                "a code read back as another secret"
            );
        }
    }

    // A real code with one character changed: the typo is in its group.
    let Some((secret, rest)) = data.split_first_chunk::<16>() else {
        return;
    };
    let [position, replacement, ..] = rest else {
        return;
    };
    let code: Vec<u8> = recovery_code(&RecoverySecret::from_bytes(secret))
        .bytes()
        .filter(|&b| b != b'-')
        .collect();
    let position = usize::from(*position) % CHARACTERS;
    let replacement = ALPHABET[usize::from(*replacement) % ALPHABET.len()];
    if replacement == code[position] {
        return;
    }
    let mut typed = code;
    typed[position] = replacement;
    let typed = String::from_utf8(typed).expect("the alphabet is ASCII");
    assert_eq!(
        parse_recovery_code(&typed).err(),
        Some(RecoveryCodeError::Typo {
            group: u8::try_from(position / GROUP_LENGTH + 1).expect("seven groups")
        }),
        "a single typo wasn't put in its group"
    );
});
