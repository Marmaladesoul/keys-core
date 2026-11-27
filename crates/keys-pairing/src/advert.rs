//! What a device says about itself on the local network while its pairing
//! sheet is open.
//!
//! A device waiting to join an account advertises a DNS-SD (Bonjour)
//! service of type [`SERVICE_TYPE`] on the port its transport listens on.
//! The platform does the advertising and the browsing; this module fixes
//! what the service's TXT record says, so every client writes and reads the
//! same thing. The record carries a [`PairingAddress`] and a version. The
//! browser adds the host and port it resolved, which is how two devices on
//! one network reach each other without a relay.
//!
//! **Advertise only while the sheet is open.** The record names an endpoint
//! to everyone on the network; a device that isn't pairing has no reason to
//! say it exists.
//!
//! Nothing in a record is trusted. It says where to dial; the code decides
//! whether the device that answers is the right one. The service's instance
//! name is the device's own name for itself and is chosen by whoever
//! advertises: pass it through
//! [`sanitize_display_name`](crate::address::sanitize_display_name) before
//! showing it.

use crate::EndpointId;
use crate::address::PairingAddress;
use crate::hex;

/// The DNS-SD service type a pairing sheet advertises.
pub const SERVICE_TYPE: &str = "_keys-pair._udp";
/// The advertisement format's version, as the `v` entry carries it.
pub const ADVERT_VERSION: &str = "1";

const KEY_VERSION: &str = "v";
const KEY_ENDPOINT: &str = "id";
const KEY_RELAY: &str = "relay";

/// Why a TXT record wasn't a pairing advertisement this version reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdvertError {
    /// No `v` entry, or more than one of an entry this version reads.
    #[error("not a pairing advertisement")]
    NotAnAdvert,
    /// A `v` this build doesn't read.
    #[error("this advertisement needs a newer version of Keys")]
    UnsupportedVersion,
    /// The endpoint id or the relay URL isn't usable.
    #[error("the advertisement is malformed")]
    Malformed,
}

/// The TXT entries that advertise `address`, as key and value pairs.
#[must_use]
pub fn txt_entries(address: &PairingAddress) -> Vec<(String, String)> {
    let mut entries = vec![
        (KEY_VERSION.to_owned(), ADVERT_VERSION.to_owned()),
        (KEY_ENDPOINT.to_owned(), hex::encode(address.endpoint())),
    ];
    if let Some(relay) = address.relay_url() {
        entries.push((KEY_RELAY.to_owned(), relay.to_owned()));
    }
    entries
}

/// Reads the address out of a discovered service's TXT entries. Entries
/// this version doesn't know are skipped, so a later version can add some.
///
/// # Errors
/// An [`AdvertError`] saying why the record isn't usable.
pub fn address_from_txt(entries: &[(String, String)]) -> Result<PairingAddress, AdvertError> {
    let version = only_entry(entries, KEY_VERSION)?.ok_or(AdvertError::NotAnAdvert)?;
    if version != ADVERT_VERSION {
        return Err(AdvertError::UnsupportedVersion);
    }
    let endpoint = only_entry(entries, KEY_ENDPOINT)?
        .and_then(endpoint_from_hex)
        .ok_or(AdvertError::Malformed)?;
    let relay = only_entry(entries, KEY_RELAY)?.map(str::to_owned);
    PairingAddress::new(endpoint, relay).map_err(|_| AdvertError::Malformed)
}

/// The value of the one entry named `key`, if there is one. A record that
/// names it twice is refused: which value counts would be up to the reader.
/// Keys are compared without regard to ASCII case, as DNS-SD compares them,
/// so `ID` beside `id` is the same key twice.
fn only_entry<'a>(
    entries: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, AdvertError> {
    let mut values = entries
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        return Err(AdvertError::NotAnAdvert);
    }
    Ok(first)
}

fn endpoint_from_hex(text: &str) -> Option<EndpointId> {
    hex::decode(text)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: EndpointId = [0xe1; 32];
    const RELAY: &str = "https://relay.example./";

    fn entry(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    #[test]
    fn an_advert_round_trips_with_and_without_a_relay() {
        for relay in [Some(RELAY.to_owned()), None] {
            let address = PairingAddress::new(ENDPOINT, relay).unwrap();
            assert_eq!(address_from_txt(&txt_entries(&address)), Ok(address));
        }
    }

    /// The record itself, so a change to it is a deliberate one.
    #[test]
    fn the_record_is_pinned() {
        let address = PairingAddress::new(ENDPOINT, Some(RELAY.into())).unwrap();
        assert_eq!(
            txt_entries(&address),
            vec![
                entry("v", "1"),
                entry("id", &"e1".repeat(32)),
                entry("relay", RELAY),
            ]
        );
        assert_eq!(SERVICE_TYPE, "_keys-pair._udp");
    }

    #[test]
    fn entries_from_a_later_version_are_skipped_and_order_is_free() {
        let entries = vec![
            entry("future", "thing"),
            entry("ID", &"E1".repeat(32)),
            entry("v", "1"),
        ];
        assert_eq!(
            address_from_txt(&entries),
            Ok(PairingAddress::new(ENDPOINT, None).unwrap())
        );
    }

    #[test]
    fn a_record_without_a_version_or_with_another_is_refused() {
        let id = "e1".repeat(32);
        assert_eq!(
            address_from_txt(&[entry("id", &id)]),
            Err(AdvertError::NotAnAdvert)
        );
        assert_eq!(address_from_txt(&[]), Err(AdvertError::NotAnAdvert));
        assert_eq!(
            address_from_txt(&[entry("v", "2"), entry("id", &id)]),
            Err(AdvertError::UnsupportedVersion)
        );
    }

    #[test]
    fn a_record_that_names_an_entry_twice_is_refused() {
        let id = "e1".repeat(32);
        let other = "e2".repeat(32);
        for entries in [
            vec![entry("v", "1"), entry("id", &id), entry("id", &other)],
            // The same key in another case is the same key.
            vec![entry("v", "1"), entry("id", &id), entry("ID", &other)],
            vec![entry("V", "1"), entry("v", "1"), entry("id", &id)],
            vec![entry("v", "1"), entry("v", "1"), entry("id", &id)],
            vec![
                entry("v", "1"),
                entry("id", &id),
                entry("relay", RELAY),
                entry("relay", "https://other.example./"),
            ],
        ] {
            assert_eq!(address_from_txt(&entries), Err(AdvertError::NotAnAdvert));
        }
    }

    #[test]
    fn an_unusable_endpoint_or_relay_is_malformed() {
        let id = "e1".repeat(32);
        let non_ascii = format!("{}é", "e1".repeat(31));
        for bad_id in [
            "",
            "e1",
            &id[..63],
            &format!("{id}00"),
            &"zz".repeat(32),
            &non_ascii,
        ] {
            assert_eq!(
                address_from_txt(&[entry("v", "1"), entry("id", bad_id)]),
                Err(AdvertError::Malformed),
                "{bad_id:?}"
            );
        }
        assert_eq!(
            address_from_txt(&[entry("v", "1")]),
            Err(AdvertError::Malformed)
        );
        assert_eq!(
            address_from_txt(&[
                entry("v", "1"),
                entry("id", &id),
                entry("relay", "http://relay.example")
            ]),
            Err(AdvertError::Malformed)
        );
    }
}
