//! The recovery code: an account's recovery secret written out for a person
//! to record, and read back.
//!
//! The recovery secret is 128 random bits, and its only copy outside the
//! moment of account creation is what the person writes down. It is written
//! as 28 characters in seven groups of four, `XXXX-XXXX-…-XXXX`:
//!
//! - **Alphabet.** Crockford's base32: the digits and the capitals without
//!   I, L, O and U, so no two characters look alike.
//! - **The first 26 characters** carry the secret, most significant bit
//!   first, then two zero bits.
//! - **The last 2 are check characters**: the code is a shortened
//!   Reed-Solomon codeword over GF(32) (primitive polynomial `x⁵ + x² + 1`)
//!   whose polynomial, first character highest, vanishes at 1 and at α. Its
//!   minimum distance is 3, so any one or two wrong characters are caught,
//!   and a single wrong character is located: reading back names the group
//!   it is in.
//! - **Reading is lenient** where Crockford's base32 is: any case, `O` for
//!   `0`, `I` or `L` for `1`, and spaces and hyphens anywhere.
//!
//! The group a [`RecoveryCodeError::Typo`] names is a hint. With one wrong
//! character it is always the right group; with more it may not be, and a
//! code with three or more wrong characters can occasionally pass the checks
//! as another code (about one in four thousand, counting the two zero bits).
//! Where the account's recovery public key is to hand,
//! [`check_recovery_code`] settles it.

use keys_pairing::RecoverySecret;
use keys_pairing::keys::{PUBLIC_KEY_BYTES, RECOVERY_SECRET_BYTES};
use zeroize::Zeroizing;

/// Number of groups in a recovery code.
pub const GROUPS: usize = 7;
/// Characters per group.
pub const GROUP_LENGTH: usize = 4;
/// Characters in a recovery code, separators aside.
pub const CHARACTERS: usize = GROUPS * GROUP_LENGTH;
/// Characters at the end that are checks, not secret.
const CHECK_CHARACTERS: usize = 2;
/// Characters that carry the secret.
const DATA_CHARACTERS: usize = CHARACTERS - CHECK_CHARACTERS;
const BITS_PER_CHARACTER: usize = 5;
const SECRET_BITS: usize = RECOVERY_SECRET_BYTES * 8;
/// Zero bits after the secret, filling out the last data character.
const PAD_BITS: usize = DATA_CHARACTERS * BITS_PER_CHARACTER - SECRET_BITS;
const SYMBOL_MASK: u128 = (1 << BITS_PER_CHARACTER) - 1;
const PAD_MASK: u8 = (1 << PAD_BITS) - 1;
/// Crockford's base32 alphabet, in value order.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// What goes between groups when a code is written out.
const GROUP_SEPARATOR: char = '-';

const _: () = assert!(
    PAD_BITS < BITS_PER_CHARACTER,
    "the secret fills the data characters"
);
const _: () = assert!(
    CHARACTERS < gf32::ORDER,
    "a Reed-Solomon code over GF(32) is at most 31 long"
);

/// Why a typed recovery code was refused. None of these carries any of the
/// code itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryCodeError {
    /// Not 28 characters, once spaces and hyphens are set aside.
    #[error("a recovery code is {CHARACTERS} characters, and this has {characters}")]
    WrongLength { characters: usize },
    /// A character that is never in a recovery code, in this group
    /// (counting from 1).
    #[error("group {group} has a character that is never in a recovery code")]
    NotInAlphabet { group: u8 },
    /// The checks fail, most likely because of a mistyped character in this
    /// group (counting from 1).
    #[error("the recovery code doesn't check out: group {group} looks mistyped")]
    Typo { group: u8 },
    /// The checks fail, and no single character explains it.
    #[error("the recovery code doesn't check out")]
    Unreadable,
    /// A well-formed recovery code, but not this account's.
    #[error("that is not this account's recovery code")]
    NotThisAccount,
}

/// The recovery code for `secret`, written out in groups. It is the secret
/// itself: show it once and don't log it.
#[must_use]
pub fn recovery_code(secret: &RecoverySecret) -> Zeroizing<String> {
    let value = Zeroizing::new(u128::from_be_bytes(*secret.as_bytes()));
    let mut symbols = Zeroizing::new([0u8; CHARACTERS]);
    for (index, symbol) in symbols[..DATA_CHARACTERS].iter_mut().enumerate() {
        // Bits [5·index, 5·index + 5) of the secret followed by the pad.
        let end = (index + 1) * BITS_PER_CHARACTER;
        let bits = if end <= SECRET_BITS {
            *value >> (SECRET_BITS - end)
        } else {
            *value << (end - SECRET_BITS)
        };
        #[allow(clippy::cast_possible_truncation)] // masked to five bits
        {
            *symbol = (bits & SYMBOL_MASK) as u8;
        }
    }
    add_checks(&mut symbols);

    let mut code = Zeroizing::new(String::with_capacity(CHARACTERS + GROUPS - 1));
    for (index, &symbol) in symbols.iter().enumerate() {
        if index > 0 && index % GROUP_LENGTH == 0 {
            code.push(GROUP_SEPARATOR);
        }
        code.push(char::from(ALPHABET[usize::from(symbol)]));
    }
    code
}

/// Reads a typed recovery code back into the recovery secret, checking its
/// form and its check characters only. Use [`check_recovery_code`] where the
/// account's recovery public key is known.
///
/// # Errors
/// [`RecoveryCodeError`] saying what is wrong with it, and where if it can.
/// Never [`RecoveryCodeError::NotThisAccount`].
pub fn parse_recovery_code(typed: &str) -> Result<RecoverySecret, RecoveryCodeError> {
    let mut symbols = Zeroizing::new([0u8; CHARACTERS]);
    let mut count = 0;
    for character in typed.chars() {
        if character.is_whitespace() || character == GROUP_SEPARATOR {
            continue;
        }
        if count < CHARACTERS {
            symbols[count] = symbol_value(character).ok_or(RecoveryCodeError::NotInAlphabet {
                group: group_of(count),
            })?;
        }
        count += 1;
    }
    if count != CHARACTERS {
        return Err(RecoveryCodeError::WrongLength { characters: count });
    }

    match syndromes(&symbols) {
        (0, 0) => {}
        (first, second) if first != 0 && second != 0 => {
            // One wrong character at degree p, by e, makes the syndromes e
            // and e·αᵖ.
            let degree = (gf32::log(second) + gf32::ORDER - gf32::log(first)) % gf32::ORDER;
            return Err(if degree < CHARACTERS {
                RecoveryCodeError::Typo {
                    group: group_of(CHARACTERS - 1 - degree),
                }
            } else {
                RecoveryCodeError::Unreadable
            });
        }
        // One syndrome zero and the other not: at least two are wrong.
        _ => return Err(RecoveryCodeError::Unreadable),
    }

    let last = symbols[DATA_CHARACTERS - 1];
    if last & PAD_MASK != 0 {
        return Err(RecoveryCodeError::Unreadable);
    }
    let mut value = Zeroizing::new(0u128);
    for &symbol in &symbols[..DATA_CHARACTERS - 1] {
        *value = (*value << BITS_PER_CHARACTER) | u128::from(symbol);
    }
    *value = (*value << (BITS_PER_CHARACTER - PAD_BITS)) | u128::from(last >> PAD_BITS);
    Ok(RecoverySecret::from_bytes(&Zeroizing::new(
        value.to_be_bytes(),
    )))
}

/// Reads a typed recovery code back and checks it is the code of the account
/// whose recovery public key is `recovery_public`.
///
/// # Errors
/// [`RecoveryCodeError`]: what [`parse_recovery_code`] refuses, and
/// [`RecoveryCodeError::NotThisAccount`] for a well-formed code of another
/// account (or one with enough typos to pass the checks).
pub fn check_recovery_code(
    typed: &str,
    recovery_public: &[u8; PUBLIC_KEY_BYTES],
) -> Result<RecoverySecret, RecoveryCodeError> {
    let secret = parse_recovery_code(typed)?;
    if secret.public_key() != *recovery_public {
        return Err(RecoveryCodeError::NotThisAccount);
    }
    Ok(secret)
}

/// The value of a typed character, read as Crockford's base32 reads it.
fn symbol_value(character: char) -> Option<u8> {
    let folded = match character.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    let byte = u8::try_from(folded).ok()?;
    #[allow(clippy::cast_possible_truncation)] // a position in a 32-symbol alphabet
    ALPHABET
        .iter()
        .position(|&candidate| candidate == byte)
        .map(|value| value as u8)
}

/// The group, counting from 1, of the character at `index`, which is less
/// than [`CHARACTERS`].
fn group_of(index: usize) -> u8 {
    const { assert!(GROUPS <= u8::MAX as usize) };
    debug_assert!(index < CHARACTERS);
    // At most GROUPS, which fits.
    #[allow(clippy::cast_possible_truncation)]
    let group = (index / GROUP_LENGTH + 1) as u8;
    group
}

/// The weight of the character at `index` in the codeword polynomial: αᵖ for
/// its degree p, the first character being the highest.
fn weight(index: usize) -> u8 {
    gf32::alpha_pow(CHARACTERS - 1 - index)
}

/// The codeword evaluated at 1 and at α.
fn syndromes(symbols: &[u8; CHARACTERS]) -> (u8, u8) {
    symbols
        .iter()
        .enumerate()
        .fold((0, 0), |(at_one, at_alpha), (index, &symbol)| {
            (at_one ^ symbol, at_alpha ^ gf32::mul(symbol, weight(index)))
        })
}

/// Fills in the two check characters so the codeword vanishes at 1 and α.
/// With the data's syndromes a and b, and checks c₀ (degree 1, weight α) and
/// c₁ (degree 0, weight 1): a + c₀ + c₁ = 0 and b + α·c₀ + c₁ = 0, so
/// c₀ = (a + b) / (1 + α) and c₁ = a + c₀.
fn add_checks(symbols: &mut [u8; CHARACTERS]) {
    symbols[DATA_CHARACTERS..].fill(0);
    let (at_one, at_alpha) = syndromes(symbols);
    let first = gf32::div(at_one ^ at_alpha, 1 ^ gf32::alpha_pow(1));
    symbols[DATA_CHARACTERS] = first;
    symbols[DATA_CHARACTERS + 1] = at_one ^ first;
}

/// Arithmetic in GF(32) = GF(2)[x] / (x⁵ + x² + 1), α = x.
mod gf32 {
    /// The order of the multiplicative group.
    pub(super) const ORDER: usize = 31;
    /// x⁵ + x² + 1, primitive over GF(2).
    const PRIMITIVE_POLYNOMIAL: u8 = 0b10_0101;
    /// The bit that marks a product reaching degree 5.
    const OVERFLOW: u8 = 0b10_0000;

    /// αⁱ for i in 0..31, and the discrete log of every non-zero element.
    const TABLES: ([u8; ORDER], [u8; ORDER + 1]) = {
        let mut exp = [0u8; ORDER];
        let mut log = [0u8; ORDER + 1];
        let mut element: u8 = 1;
        let mut power = 0;
        while power < ORDER {
            exp[power] = element;
            #[allow(clippy::cast_possible_truncation)] // power < 31
            {
                log[element as usize] = power as u8;
            }
            element <<= 1;
            if element & OVERFLOW != 0 {
                element ^= PRIMITIVE_POLYNOMIAL;
            }
            power += 1;
        }
        (exp, log)
    };

    pub(super) fn alpha_pow(power: usize) -> u8 {
        TABLES.0[power % ORDER]
    }

    /// The discrete log of a non-zero element.
    pub(super) fn log(element: u8) -> usize {
        debug_assert_ne!(element, 0, "zero has no log");
        usize::from(TABLES.1[usize::from(element)])
    }

    pub(super) fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        alpha_pow(log(a) + log(b))
    }

    /// `a / b` for a non-zero `b`.
    pub(super) fn div(a: u8, b: u8) -> u8 {
        assert_ne!(b, 0, "division by zero in GF(32)");
        if a == 0 {
            return 0;
        }
        alpha_pow(log(a) + ORDER - log(b))
    }

    #[cfg(test)]
    pub(super) fn exp_table() -> [u8; ORDER] {
        TABLES.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys_pairing::AccountKeys;

    fn code_for(bytes: [u8; RECOVERY_SECRET_BYTES]) -> String {
        recovery_code(&RecoverySecret::from_bytes(&bytes)).to_string()
    }

    fn secret_of(typed: &str) -> [u8; RECOVERY_SECRET_BYTES] {
        *parse_recovery_code(typed).expect("parses").as_bytes()
    }

    /// The 28 characters of a code, separators removed.
    fn characters(code: &str) -> Vec<u8> {
        code.bytes().filter(|&b| b != b'-').collect()
    }

    fn with_characters(characters: &[u8]) -> String {
        String::from_utf8(characters.to_vec()).expect("ascii")
    }

    /// A spread of secrets: all zeros, all ones, and a scripted walk.
    fn sample_secrets() -> Vec<[u8; RECOVERY_SECRET_BYTES]> {
        let mut secrets = vec![[0; RECOVERY_SECRET_BYTES], [0xff; RECOVERY_SECRET_BYTES]];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..32 {
            let mut secret = [0u8; RECOVERY_SECRET_BYTES];
            for byte in &mut secret {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = state.to_be_bytes()[0];
            }
            secrets.push(secret);
        }
        secrets
    }

    #[test]
    fn alpha_generates_the_whole_field() {
        let mut seen = gf32::exp_table().to_vec();
        seen.sort_unstable();
        assert_eq!(seen, (1..=31).collect::<Vec<u8>>());
    }

    #[test]
    fn codes_have_seven_groups_of_four_from_the_alphabet() {
        for secret in sample_secrets() {
            let code = code_for(secret);
            let groups: Vec<&str> = code.split('-').collect();
            assert_eq!(groups.len(), GROUPS, "{code}");
            assert!(
                groups.iter().all(|group| group.len() == GROUP_LENGTH),
                "{code}"
            );
            assert!(
                characters(&code).iter().all(|c| ALPHABET.contains(c)),
                "{code}"
            );
        }
    }

    /// Pinned literals, so the format can't drift unnoticed. All zeros has
    /// all-zero checks; the other was checked with a separate implementation
    /// of the field and the syndromes (both vanish, and the data bits are the
    /// secret followed by two zeros).
    #[test]
    fn known_answers() {
        assert_eq!(
            code_for([0; RECOVERY_SECRET_BYTES]),
            "0000-0000-0000-0000-0000-0000-0000"
        );
        assert_eq!(code_for(KNOWN_SECRET), KNOWN_CODE);
        assert_eq!(secret_of(KNOWN_CODE), KNOWN_SECRET);
    }

    const KNOWN_SECRET: [u8; RECOVERY_SECRET_BYTES] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const KNOWN_CODE: &str = "008J-4CT4-ANK7-F24S-NAXW-SQFE-ZWXR";

    #[test]
    fn every_secret_reads_back() {
        for secret in sample_secrets() {
            assert_eq!(secret_of(&code_for(secret)), secret);
        }
    }

    #[test]
    fn reading_is_lenient_where_crockford_is() {
        let secret = sample_secrets()[5];
        let code = code_for(secret);
        // Lower case, no separators, spaces instead, stray spacing.
        assert_eq!(secret_of(&code.to_lowercase()), secret);
        assert_eq!(secret_of(&code.replace('-', "")), secret);
        assert_eq!(secret_of(&code.replace('-', " ")), secret);
        assert_eq!(
            secret_of(&format!("  {}\n", code.replace('-', " - "))),
            secret
        );
        // O for 0 and I or L for 1, in either case.
        let zeros = code_for([0; RECOVERY_SECRET_BYTES]);
        assert_eq!(
            secret_of(&zeros.replace('0', "O")),
            [0; RECOVERY_SECRET_BYTES]
        );
        assert_eq!(
            secret_of(&zeros.replace('0', "o")),
            [0; RECOVERY_SECRET_BYTES]
        );
        // The bit pattern 00001 repeated: every data character is a 1.
        let ones_secret = [
            0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84,
            0x21, 0x08,
        ];
        let ones = code_for(ones_secret);
        assert!(ones.starts_with("1111-1111"), "{ones}");
        for one in ["I", "i", "L", "l"] {
            assert_eq!(secret_of(&ones.replace('1', one)), ones_secret, "{one}");
        }
    }

    #[test]
    fn every_single_typo_is_found_in_its_group() {
        for secret in sample_secrets().into_iter().take(6) {
            let good = characters(&code_for(secret));
            for index in 0..CHARACTERS {
                for &replacement in ALPHABET {
                    if replacement == good[index] {
                        continue;
                    }
                    let mut typed = good.clone();
                    typed[index] = replacement;
                    assert_eq!(
                        parse_recovery_code(&with_characters(&typed)).err(),
                        Some(RecoveryCodeError::Typo {
                            group: u8::try_from(index / GROUP_LENGTH + 1).expect("seven groups")
                        }),
                        "character {index} replaced"
                    );
                }
            }
        }
    }

    #[test]
    fn every_two_typos_are_caught() {
        let good = characters(&code_for(sample_secrets()[3]));
        for first in 0..CHARACTERS {
            for second in first + 1..CHARACTERS {
                for &a in ALPHABET {
                    if a == good[first] {
                        continue;
                    }
                    for &b in ALPHABET {
                        if b == good[second] {
                            continue;
                        }
                        let mut typed = good.clone();
                        typed[first] = a;
                        typed[second] = b;
                        assert!(
                            parse_recovery_code(&with_characters(&typed)).is_err(),
                            "characters {first} and {second} replaced"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn swapped_neighbours_are_caught() {
        for secret in sample_secrets() {
            let good = characters(&code_for(secret));
            for index in 0..CHARACTERS - 1 {
                if good[index] == good[index + 1] {
                    continue;
                }
                let mut typed = good.clone();
                typed.swap(index, index + 1);
                assert!(parse_recovery_code(&with_characters(&typed)).is_err());
            }
        }
    }

    #[test]
    fn a_character_outside_the_alphabet_names_its_group() {
        let good = characters(&code_for(sample_secrets()[7]));
        for (index, bad) in [(0, b'U'), (9, b'*'), (27, b'U')] {
            let mut typed = good.clone();
            typed[index] = bad;
            assert_eq!(
                parse_recovery_code(&with_characters(&typed)).err(),
                Some(RecoveryCodeError::NotInAlphabet {
                    group: u8::try_from(index / GROUP_LENGTH + 1).expect("seven groups")
                })
            );
        }
        let mut accented = with_characters(&good);
        accented.replace_range(0..1, "é");
        assert_eq!(
            parse_recovery_code(&accented).err(),
            Some(RecoveryCodeError::NotInAlphabet { group: 1 })
        );
    }

    #[test]
    fn the_wrong_number_of_characters_is_refused() {
        let good = characters(&code_for(sample_secrets()[2]));
        for len in [0, 1, CHARACTERS - 1] {
            assert_eq!(
                parse_recovery_code(&with_characters(&good[..len])).err(),
                Some(RecoveryCodeError::WrongLength { characters: len })
            );
        }
        let mut long = good.clone();
        long.extend_from_slice(b"00");
        assert_eq!(
            parse_recovery_code(&with_characters(&long)).err(),
            Some(RecoveryCodeError::WrongLength {
                characters: CHARACTERS + 2
            })
        );
    }

    /// A codeword whose checks hold but whose pad bits aren't zero is no
    /// code: it can only come from several typos.
    #[test]
    fn set_pad_bits_are_refused() {
        let mut symbols = [0u8; CHARACTERS];
        symbols[DATA_CHARACTERS - 1] = 1;
        add_checks(&mut symbols);
        assert_eq!(syndromes(&symbols), (0, 0));
        let typed: Vec<u8> = symbols.iter().map(|&s| ALPHABET[usize::from(s)]).collect();
        assert_eq!(
            parse_recovery_code(&with_characters(&typed)).err(),
            Some(RecoveryCodeError::Unreadable)
        );
    }

    #[test]
    fn a_code_is_checked_against_the_account() {
        let (keys, recovery) = AccountKeys::generate().expect("rng");
        let code = recovery_code(&recovery);
        let recovery_public = keys.public_keys().recovery;
        let read = check_recovery_code(&code, &recovery_public).expect("its own code");
        assert_eq!(read.as_bytes(), recovery.as_bytes());

        let (_, other) = AccountKeys::generate().expect("rng");
        assert_eq!(
            check_recovery_code(&recovery_code(&other), &recovery_public).err(),
            Some(RecoveryCodeError::NotThisAccount)
        );
        // A form error is reported as such, not as another account's code.
        assert_eq!(
            check_recovery_code("0000", &recovery_public).err(),
            Some(RecoveryCodeError::WrongLength { characters: 4 })
        );
    }
}
