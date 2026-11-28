//! The `keys://pair/…` links: how an address or an invite travels as text.
//!
//! Two links, told apart by their path:
//!
//! - `keys://pair/device/<hex>`: a device's [`PairingAddress`] and nothing
//!   else. A device waiting to join an account shows it (as text and as a
//!   QR code) so a device on another network can find it.
//! - `keys://pair/person/<hex>`: an [`Invite`].
//!
//! **Neither carries a secret.** A link is read off screens, pasted into
//! messages, forwarded and stored; the code is the only secret in a pairing
//! and never goes in one.
//!
//! The body is hex (either case, so it survives a channel that changes
//! case, and a QR code can hold it compactly): a version byte, the fields,
//! and a four-byte checksum. The checksum catches a link damaged in
//! copying; it is not authentication, and anyone can make a valid link.
//! Parsing is strict (one encoding of each field, nothing after the last)
//! with one exception: an invite's name is sanitised on the way in, not
//! refused, so a name this version would have written differently still
//! reads, as what this version shows.

use sha2::{Digest, Sha512};

use crate::address::MAX_DISPLAY_NAME_BYTES;
use crate::address::{MAX_RELAY_URL_BYTES, PairingAddress, sanitize_display_name};
use crate::cpace::push_prepend_len;
use crate::hex::{self, HEX_CHARS_PER_BYTE};
use crate::invite::{INVITE_ID_BYTES, Invite};
use crate::keys::PUBLIC_KEY_BYTES;
use crate::wire::Reader;

/// The link format's version.
pub const LINK_VERSION: u8 = 1;
/// The longest link accepted, in bytes of text. Above the longest link this
/// version can produce (see the assertion below).
pub const MAX_LINK_BYTES: usize = 1536;

const LINK_PREFIX: &str = "keys://pair/";
const DEVICE_PATH: &str = "device/";
const PERSON_PATH: &str = "person/";
const CHECKSUM_LABEL: &[u8] = b"keys-pairing link";
const CHECKSUM_BYTES: usize = 4;
const EXPIRY_BYTES: usize = 8;
const ENDPOINT_BYTES: usize = 32;
/// The longest LEB128 length prefix a field here needs.
const LENGTH_PREFIX_MAX_BYTES: usize = 2;

/// The longest body this version produces: an invite with the longest relay
/// URL and the longest name.
const MAX_BODY_BYTES: usize = 1
    + PUBLIC_KEY_BYTES
    + ENDPOINT_BYTES
    + INVITE_ID_BYTES
    + EXPIRY_BYTES
    + LENGTH_PREFIX_MAX_BYTES
    + MAX_RELAY_URL_BYTES
    + LENGTH_PREFIX_MAX_BYTES
    + MAX_DISPLAY_NAME_BYTES
    + CHECKSUM_BYTES;
const _: () = assert!(
    LINK_PREFIX.len() + PERSON_PATH.len() + HEX_CHARS_PER_BYTE * MAX_BODY_BYTES <= MAX_LINK_BYTES
);

/// Why a link didn't parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Not a `keys://pair/…` link at all.
    #[error("not a Keys pairing link")]
    NotAPairingLink,
    /// A pairing link from a later version than this build reads. (The
    /// version sits behind the checksum, so this is only reported for a
    /// version that keeps this one's paths and checksum.)
    #[error("this pairing link needs a newer version of Keys")]
    UnsupportedVersion,
    /// The checksum doesn't match: the link was cut short or altered on the
    /// way.
    #[error("the pairing link is damaged")]
    Damaged,
    /// The checksum matches but the contents aren't a link this version
    /// writes.
    #[error("the pairing link is malformed")]
    Malformed,
}

/// A parsed `keys://pair/…` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingLink {
    /// Where a device waiting to join an account can be reached.
    Device(PairingAddress),
    /// An invite to pair as People.
    Person(Invite),
}

#[derive(Clone, Copy)]
enum LinkKind {
    Device,
    Person,
}

impl LinkKind {
    fn path(self) -> &'static str {
        match self {
            Self::Device => DEVICE_PATH,
            Self::Person => PERSON_PATH,
        }
    }
}

/// The first bytes of `SHA-512(label || path || fields)`. The path is in it
/// so a body moved from one kind of link to the other doesn't check out.
fn checksum(kind: LinkKind, fields: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(CHECKSUM_LABEL);
    hasher.update(kind.path().as_bytes());
    hasher.update(fields);
    let digest = hasher.finalize();
    digest[..CHECKSUM_BYTES]
        .try_into()
        .expect("a digest is longer than a checksum")
}

fn to_text(kind: LinkKind, mut fields: Vec<u8>) -> String {
    let sum = checksum(kind, &fields);
    fields.extend_from_slice(&sum);
    let mut text = String::with_capacity(
        LINK_PREFIX.len() + kind.path().len() + HEX_CHARS_PER_BYTE * fields.len(),
    );
    text.push_str(LINK_PREFIX);
    text.push_str(kind.path());
    text.push_str(&hex::encode(&fields));
    text
}

/// Fuzzing builds only: the text of a link whose body is `fields` with a
/// checksum that matches, so a fuzzer reaches the parser behind the
/// checksum. `person` picks the invite's path; otherwise the device's.
#[cfg(fuzzing)]
#[must_use]
pub fn link_with_matching_checksum_for_fuzzing(person: bool, fields: &[u8]) -> String {
    let kind = if person {
        LinkKind::Person
    } else {
        LinkKind::Device
    };
    to_text(kind, fields.to_vec())
}

fn push_address(fields: &mut Vec<u8>, address: &PairingAddress) {
    fields.extend_from_slice(address.endpoint());
    push_prepend_len(fields, address.relay_url().unwrap_or_default().as_bytes());
}

fn read_address(reader: &mut Reader<'_>) -> Result<PairingAddress, LinkError> {
    let endpoint = reader
        .array::<ENDPOINT_BYTES>()
        .map_err(|_| LinkError::Malformed)?;
    let relay = reader
        .lv_bytes(MAX_RELAY_URL_BYTES)
        .map_err(|_| LinkError::Malformed)?;
    let relay_url = if relay.is_empty() {
        None
    } else {
        Some(
            std::str::from_utf8(relay)
                .map_err(|_| LinkError::Malformed)?
                .to_owned(),
        )
    };
    PairingAddress::new(endpoint, relay_url).map_err(|_| LinkError::Malformed)
}

impl PairingLink {
    /// The link as text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut fields = vec![LINK_VERSION];
        match self {
            Self::Device(address) => {
                push_address(&mut fields, address);
                to_text(LinkKind::Device, fields)
            }
            Self::Person(invite) => {
                fields.extend_from_slice(&invite.inviter_identity);
                fields.extend_from_slice(&invite.invite_id);
                fields.extend_from_slice(&invite.expires_at.to_be_bytes());
                push_address(&mut fields, &invite.address);
                push_prepend_len(
                    &mut fields,
                    sanitize_display_name(&invite.inviter_name).as_bytes(),
                );
                to_text(LinkKind::Person, fields)
            }
        }
    }

    /// Reads a link from text a person pasted or a camera scanned.
    /// Whitespace around it is ignored. An invite's name comes back
    /// sanitised whatever the link held.
    ///
    /// This does not check an invite's expiry: see [`Invite::is_expired`].
    ///
    /// # Errors
    /// A [`LinkError`] saying why the text isn't a link this version reads.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if text.len() > MAX_LINK_BYTES {
            return Err(LinkError::NotAPairingLink);
        }
        let rest =
            strip_prefix_ignoring_case(text, LINK_PREFIX).ok_or(LinkError::NotAPairingLink)?;
        let (kind, body_hex) = if let Some(body) = strip_prefix_ignoring_case(rest, DEVICE_PATH) {
            (LinkKind::Device, body)
        } else if let Some(body) = strip_prefix_ignoring_case(rest, PERSON_PATH) {
            (LinkKind::Person, body)
        } else {
            return Err(LinkError::NotAPairingLink);
        };
        let body = hex::decode(body_hex).ok_or(LinkError::Damaged)?;
        let Some(fields_len) = body.len().checked_sub(CHECKSUM_BYTES) else {
            return Err(LinkError::Damaged);
        };
        let (fields, sum) = body.split_at(fields_len);
        if sum != checksum(kind, fields) {
            return Err(LinkError::Damaged);
        }

        let mut reader = Reader::new(fields);
        let version = reader.byte().map_err(|_| LinkError::Malformed)?;
        // No version came before the first, so a lower number is no link.
        if version > LINK_VERSION {
            return Err(LinkError::UnsupportedVersion);
        }
        if version < LINK_VERSION {
            return Err(LinkError::Malformed);
        }
        let link = match kind {
            LinkKind::Device => Self::Device(read_address(&mut reader)?),
            LinkKind::Person => Self::Person(read_invite(&mut reader)?),
        };
        reader.finish().map_err(|_| LinkError::Malformed)?;
        Ok(link)
    }
}

fn read_invite(reader: &mut Reader<'_>) -> Result<Invite, LinkError> {
    let inviter_identity = reader
        .array::<PUBLIC_KEY_BYTES>()
        .map_err(|_| LinkError::Malformed)?;
    let invite_id = reader
        .array::<INVITE_ID_BYTES>()
        .map_err(|_| LinkError::Malformed)?;
    let expires_at = u64::from_be_bytes(
        reader
            .array::<EXPIRY_BYTES>()
            .map_err(|_| LinkError::Malformed)?,
    );
    let address = read_address(reader)?;
    let name = reader
        .lv_bytes(MAX_DISPLAY_NAME_BYTES)
        .map_err(|_| LinkError::Malformed)?;
    let name = std::str::from_utf8(name).map_err(|_| LinkError::Malformed)?;
    Ok(Invite {
        inviter_identity,
        address,
        invite_id,
        expires_at,
        inviter_name: sanitize_display_name(name),
    })
}

/// `text` without `prefix`, if it starts with it in any ASCII case.
fn strip_prefix_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EndpointId;

    const ENDPOINT: EndpointId = [0xe1; 32];
    const IDENTITY: [u8; PUBLIC_KEY_BYTES] = [0xa1; PUBLIC_KEY_BYTES];
    const INVITE_ID: [u8; INVITE_ID_BYTES] = [0x1d; INVITE_ID_BYTES];
    const RELAY: &str = "https://relay.example./";

    fn address() -> PairingAddress {
        PairingAddress::new(ENDPOINT, Some(RELAY.into())).unwrap()
    }

    fn invite() -> Invite {
        Invite {
            inviter_identity: IDENTITY,
            address: address(),
            invite_id: INVITE_ID,
            expires_at: 1_800_000_000,
            inviter_name: "Jeff".into(),
        }
    }

    /// A link's text with its body replaced by `fields` and a checksum that
    /// matches, for bodies no encoder would write.
    fn forged(kind: LinkKind, fields: &[u8]) -> String {
        to_text(kind, fields.to_vec())
    }

    #[test]
    fn a_device_link_round_trips_with_and_without_a_relay() {
        for address in [address(), PairingAddress::new(ENDPOINT, None).unwrap()] {
            let link = PairingLink::Device(address);
            let text = link.to_text();
            assert!(text.starts_with("keys://pair/device/"));
            assert_eq!(PairingLink::parse(&text), Ok(link));
        }
    }

    #[test]
    fn an_invite_link_round_trips() {
        let link = PairingLink::Person(invite());
        let text = link.to_text();
        assert!(text.starts_with("keys://pair/person/"));
        assert_eq!(PairingLink::parse(&text), Ok(link));
    }

    /// The exact text of both links, checksum included, so a change to the
    /// format (the fields, their order, the checksum's label or what it
    /// covers) is a deliberate one: it would break every link already sent.
    /// The checksums were computed outside this crate.
    #[test]
    fn the_link_text_is_pinned() {
        let device = PairingLink::Device(PairingAddress::new(ENDPOINT, None).unwrap());
        let device_text = format!("keys://pair/device/01{}008ff338e5", "e1".repeat(32));
        assert_eq!(device.to_text(), device_text);
        assert_eq!(PairingLink::parse(&device_text), Ok(device));

        let person = PairingLink::Person(invite());
        let person_text = format!(
            "keys://pair/person/01{}{}000000006b49d200{}17{}044a656666fe89ff80",
            "a1".repeat(32),
            "1d".repeat(16),
            "e1".repeat(32),
            hex::encode(RELAY.as_bytes()),
        );
        assert_eq!(person.to_text(), person_text);
        assert_eq!(PairingLink::parse(&person_text), Ok(person));
    }

    #[test]
    fn a_link_carries_no_more_than_its_public_fields() {
        // Version, endpoint, an empty relay, checksum: nothing else fits.
        let text = PairingLink::Device(PairingAddress::new(ENDPOINT, None).unwrap()).to_text();
        let hex = text.strip_prefix("keys://pair/device/").unwrap();
        assert_eq!(hex.len(), 2 * (1 + 32 + 1 + CHECKSUM_BYTES));
    }

    #[test]
    fn case_and_surrounding_whitespace_do_not_matter() {
        let link = PairingLink::Person(invite());
        let text = link.to_text();
        assert_eq!(
            PairingLink::parse(&text.to_ascii_uppercase()),
            Ok(link.clone())
        );
        assert_eq!(PairingLink::parse(&format!("  {text}\r\n")), Ok(link));
    }

    #[test]
    fn text_that_is_not_a_pairing_link_is_refused_as_such() {
        let huge = format!("keys://pair/device/{}", "0".repeat(MAX_LINK_BYTES));
        for text in [
            "",
            "keys://",
            "keys://pair/",
            "keys://pair/vault/00",
            "https://example.com/keys://pair/device/00",
            "keys://pairdevice/00",
            "kéys://pair/device/00",
            huge.as_str(),
        ] {
            assert_eq!(
                PairingLink::parse(text),
                Err(LinkError::NotAPairingLink),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_damaged_link_is_reported_as_damaged() {
        let text = PairingLink::Person(invite()).to_text();
        let prefix_len = "keys://pair/person/".len();

        // Cut short, by a character and by a byte.
        assert_eq!(
            PairingLink::parse(&text[..text.len() - 1]),
            Err(LinkError::Damaged)
        );
        assert_eq!(
            PairingLink::parse(&text[..text.len() - 2]),
            Err(LinkError::Damaged)
        );
        // Nothing after the path, or too little for a checksum.
        assert_eq!(
            PairingLink::parse(&text[..prefix_len]),
            Err(LinkError::Damaged)
        );
        assert_eq!(
            PairingLink::parse(&text[..prefix_len + 6]),
            Err(LinkError::Damaged)
        );
        // Each character of the body changed in turn.
        for index in prefix_len..text.len() {
            let mut altered = text.clone().into_bytes();
            altered[index] = if altered[index] == b'0' { b'1' } else { b'0' };
            let altered = String::from_utf8(altered).unwrap();
            assert_eq!(
                PairingLink::parse(&altered),
                Err(LinkError::Damaged),
                "index {index}"
            );
        }
        // Not hex, including a multi-byte character where a digit belongs.
        assert_eq!(
            PairingLink::parse(&format!("{}zz", &text[..text.len() - 2])),
            Err(LinkError::Damaged)
        );
        assert_eq!(
            PairingLink::parse(&format!("{}é", &text[..text.len() - 2])),
            Err(LinkError::Damaged)
        );
    }

    #[test]
    fn a_body_moved_to_the_other_kind_of_link_does_not_check_out() {
        let device = PairingLink::Device(address()).to_text();
        let moved = device.replace("/device/", "/person/");
        assert_eq!(PairingLink::parse(&moved), Err(LinkError::Damaged));
    }

    #[test]
    fn another_version_is_reported_as_unsupported() {
        let mut fields = vec![LINK_VERSION + 1];
        push_address(&mut fields, &address());
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &fields)),
            Err(LinkError::UnsupportedVersion)
        );
        // There was no version before the first.
        fields[0] = LINK_VERSION - 1;
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &fields)),
            Err(LinkError::Malformed)
        );
    }

    #[test]
    fn a_name_written_differently_reads_as_the_same_invite() {
        // The one place two links read alike: the name is sanitised on the
        // way in.
        let plain = PairingLink::parse(&forged(LinkKind::Person, &invite_fields(b"Jeff")));
        let padded = PairingLink::parse(&forged(
            LinkKind::Person,
            &invite_fields("  Jeff\n\0".as_bytes()),
        ));
        assert_eq!(plain, Ok(PairingLink::Person(invite())));
        assert_eq!(padded, plain);
    }

    #[test]
    fn contents_no_encoder_writes_are_malformed() {
        let mut good = vec![LINK_VERSION];
        push_address(&mut good, &address());

        // Nothing at all, and a version with nothing after it.
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &[])),
            Err(LinkError::Malformed)
        );
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &[LINK_VERSION])),
            Err(LinkError::Malformed)
        );
        // A trailing byte.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &trailing)),
            Err(LinkError::Malformed)
        );
        // A relay that isn't an https URL.
        let mut bad_relay = vec![LINK_VERSION];
        bad_relay.extend_from_slice(&ENDPOINT);
        push_prepend_len(&mut bad_relay, b"http://relay.example");
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &bad_relay)),
            Err(LinkError::Malformed)
        );
        // A relay that isn't UTF-8.
        let mut not_utf8 = vec![LINK_VERSION];
        not_utf8.extend_from_slice(&ENDPOINT);
        push_prepend_len(&mut not_utf8, &[0xff, 0xfe]);
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &not_utf8)),
            Err(LinkError::Malformed)
        );
        // A relay length written the long way (0x97 0x00 for 23).
        let mut padded = vec![LINK_VERSION];
        padded.extend_from_slice(&ENDPOINT);
        padded.extend_from_slice(&[0x80 | u8::try_from(RELAY.len()).unwrap(), 0x00]);
        padded.extend_from_slice(RELAY.as_bytes());
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Device, &padded)),
            Err(LinkError::Malformed)
        );
    }

    fn invite_fields(name: &[u8]) -> Vec<u8> {
        let mut fields = vec![LINK_VERSION];
        fields.extend_from_slice(&IDENTITY);
        fields.extend_from_slice(&INVITE_ID);
        fields.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        push_address(&mut fields, &address());
        push_prepend_len(&mut fields, name);
        fields
    }

    #[test]
    fn a_hostile_name_in_an_invite_comes_back_sanitised() {
        let hostile = "  Jeff\u{202e}gpj.exe\u{0}\n".as_bytes();
        let parsed = PairingLink::parse(&forged(LinkKind::Person, &invite_fields(hostile)));
        let Ok(PairingLink::Person(invite)) = parsed else {
            panic!("an invite, got {parsed:?}");
        };
        assert_eq!(invite.inviter_name, "Jeffgpj.exe");
    }

    #[test]
    fn an_invite_name_that_is_too_long_or_not_text_is_malformed() {
        let too_long = vec![b'a'; MAX_DISPLAY_NAME_BYTES + 1];
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Person, &invite_fields(&too_long))),
            Err(LinkError::Malformed)
        );
        assert_eq!(
            PairingLink::parse(&forged(LinkKind::Person, &invite_fields(&[0xff]))),
            Err(LinkError::Malformed)
        );
        // The longest name the wire allows parses, capped in characters.
        let longest = vec![b'a'; MAX_DISPLAY_NAME_BYTES];
        let parsed = PairingLink::parse(&forged(LinkKind::Person, &invite_fields(&longest)));
        let Ok(PairingLink::Person(invite)) = parsed else {
            panic!("an invite, got {parsed:?}");
        };
        assert_eq!(
            invite.inviter_name.len(),
            crate::address::MAX_DISPLAY_NAME_CHARS
        );
    }

    #[test]
    fn the_longest_link_fits_the_cap() {
        let name: String = "\u{1f600}".repeat(crate::address::MAX_DISPLAY_NAME_CHARS);
        let scheme = "https://";
        let domain = ".example";
        let label = "r".repeat(MAX_RELAY_URL_BYTES - scheme.len() - domain.len());
        let relay = format!("{scheme}{label}{domain}");
        assert_eq!(relay.len(), MAX_RELAY_URL_BYTES);
        let link = PairingLink::Person(Invite {
            address: PairingAddress::new(ENDPOINT, Some(relay)).unwrap(),
            inviter_name: name,
            ..invite()
        });
        let text = link.to_text();
        assert!(text.len() <= MAX_LINK_BYTES);
        assert_eq!(PairingLink::parse(&text), Ok(link));
    }
}
