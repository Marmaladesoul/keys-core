//! Where a pairing endpoint can be reached, and the one piece of
//! stranger-chosen text a pairing shows before anything is verified.
//!
//! A [`PairingAddress`] is public: an endpoint id and, optionally, the relay
//! it listens through. It never carries a direct network address. Addresses
//! travel in links that are forwarded, stored and searched, and an IP
//! address in one would say where its device is.

use crate::EndpointId;

/// The longest relay URL an address carries.
pub const MAX_RELAY_URL_BYTES: usize = 255;
/// The longest display name shown from an unverified source, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// The most bytes one character takes in UTF-8.
const MAX_UTF8_CHAR_BYTES: usize = 4;
/// The longest a sanitised name is in UTF-8.
pub const MAX_DISPLAY_NAME_BYTES: usize = MAX_DISPLAY_NAME_CHARS * MAX_UTF8_CHAR_BYTES;

/// The only scheme a relay URL may have.
const RELAY_URL_SCHEME: &str = "https://";

/// Why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// The relay URL is not a plain `https://` URL of printable ASCII, at
    /// most [`MAX_RELAY_URL_BYTES`] long.
    #[error("the relay URL is not a usable https URL")]
    RelayUrl,
}

/// How to reach a pairing endpoint: its id, and the relay it listens
/// through if it has one. No direct addresses, by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAddress {
    endpoint: EndpointId,
    relay_url: Option<String>,
}

impl PairingAddress {
    /// # Errors
    /// [`AddressError::RelayUrl`] if a relay URL is given and isn't a plain
    /// `https://` URL.
    pub fn new(endpoint: EndpointId, relay_url: Option<String>) -> Result<Self, AddressError> {
        if let Some(url) = &relay_url
            && !is_plain_https_url(url)
        {
            return Err(AddressError::RelayUrl);
        }
        Ok(Self {
            endpoint,
            relay_url,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    #[must_use]
    pub fn relay_url(&self) -> Option<&str> {
        self.relay_url.as_deref()
    }
}

/// Whether `url` is `https://`, a host name, and optionally a port and a
/// path, all of it printable ASCII with no spaces. The host must be a name:
/// an IP address in a link would say where a device is. Credentials, a
/// query and a fragment have no business in a relay's address and are
/// refused. The transport parses the URL properly before dialling; this
/// only keeps anything else out of a link.
fn is_plain_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix(RELAY_URL_SCHEME) else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default();
    url.len() <= MAX_RELAY_URL_BYTES
        && url.bytes().all(|byte| byte.is_ascii_graphic())
        && !url.contains(['@', '?', '#'])
        && is_host_name(host)
}

/// Names reserved for a machine itself or for its own network
/// (RFC 6761 `localhost`, RFC 6762 `local`, RFC 8375 `home.arpa`, and
/// ICANN's `internal`). A relay named under one of them is somewhere on the
/// reader's own network, never a public relay.
const LOCAL_ONLY_DOMAINS: [&str; 4] = ["localhost", "local", "home.arpa", "internal"];

/// Whether `host` is a public DNS name and not an IP address: letters,
/// digits, dots and hyphens, at least two labels, a last label that starts
/// with a letter, and not under a domain in [`LOCAL_ONLY_DOMAINS`]. An IPv6
/// literal is bracketed. An IPv4 one, in any of the spellings URL parsers
/// accept (decimal, octal, hex, with or without dots), ends in a label
/// that starts with a digit, and no top-level domain does. A name with one
/// label is looked up on the reader's own network, if at all.
///
/// This is a check on the name only: a public name can still resolve to a
/// private address.
fn is_host_name(host: &str) -> bool {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let Some((_, last_label)) = name.rsplit_once('.') else {
        return false;
    };
    let is_local_only = LOCAL_ONLY_DOMAINS
        .iter()
        .any(|domain| name == *domain || name.ends_with(&format!(".{domain}")));
    host.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        && last_label
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        && !is_local_only
}

/// Makes a name from an unverified source safe to show as plain text: no
/// control characters, no invisible or format characters (nothing that
/// reorders, hides or pads the text), surrounding whitespace trimmed, at
/// most [`MAX_DISPLAY_NAME_CHARS`] characters, and empty unless something
/// in it can be seen.
///
/// An invite's name and a discovered device's name are chosen by whoever
/// made them. This is applied when a name is put into an invite and again
/// when one is read out, so what a client shows never depends on the sender
/// having behaved. The two joiners that scripts and emoji need (U+200C,
/// U+200D) are kept, as are emoji variation selectors.
///
/// It does not make a name honest: lookalike letters and a plausible lie
/// pass. A name is a claim to show beside the code, never in place of it.
#[must_use]
pub fn sanitize_display_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|&character| !is_unsafe_in_a_name(character))
        .collect();
    let capped: String = kept
        .trim_start_matches(is_dropped_from_the_start_of_a_name)
        .trim_end_matches(is_dropped_from_the_end_of_a_name)
        .chars()
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect();
    // The cap can land just after a space or a non-joiner inside the name.
    let name = capped.trim_end_matches(is_dropped_from_the_end_of_a_name);
    if name.chars().any(is_visible_by_itself) {
        name.to_owned()
    } else {
        String::new()
    }
}

/// The zero-width non-joiner and joiner: format characters that real names
/// (Persian, Indic scripts) and emoji sequences are spelt with.
const JOINERS: [char; 2] = [ZERO_WIDTH_NON_JOINER, '\u{200d}'];
const ZERO_WIDTH_NON_JOINER: char = '\u{200c}';

/// Whitespace and the [`JOINERS`]: with nothing before it, a joiner shows
/// nothing and changes nothing.
fn is_dropped_from_the_start_of_a_name(character: char) -> bool {
    character.is_whitespace() || JOINERS.contains(&character)
}

/// Whitespace and the zero-width non-joiner, which with nothing after it
/// has nothing to keep apart. A zero-width joiner at the end stays: after
/// an Indic virama it chooses the form of the letter before it, and names
/// are spelt that way.
fn is_dropped_from_the_end_of_a_name(character: char) -> bool {
    character.is_whitespace() || character == ZERO_WIDTH_NON_JOINER
}

/// Control characters (category Cc), every format character (category Cf)
/// but the two [`JOINERS`], the line and paragraph separators, the letters
/// and marks that render as nothing (the Hangul fillers, the Khmer inherent
/// vowels, the combining grapheme joiner, the blank Braille pattern), and
/// the code points Unicode reserves as ignorable when displayed (the rest
/// of the specials block's head and of the tags plane).
///
/// The ranges are Unicode 16's, written out because the standard library
/// has no category tables. An invisible character added by a later Unicode
/// version passes until it is added here.
fn is_unsafe_in_a_name(character: char) -> bool {
    if JOINERS.contains(&character) {
        return false;
    }
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e00ff}'
                | '\u{e01f0}'..='\u{e0fff}'
        )
}

/// Whether `character`, alone, puts something on screen: not whitespace, a
/// joiner or a variation selector (the general ones, the supplement, and
/// the Mongolian free variation selectors).
fn is_visible_by_itself(character: char) -> bool {
    !character.is_whitespace()
        && !JOINERS.contains(&character)
        && !matches!(
            character,
            '\u{180b}'..='\u{180f}' | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: EndpointId = [0xe1; 32];

    #[test]
    fn an_address_takes_a_plain_https_relay_or_none() {
        let with = PairingAddress::new(ENDPOINT, Some("https://relay.example./".into())).unwrap();
        assert_eq!(with.relay_url(), Some("https://relay.example./"));
        assert_eq!(with.endpoint(), &ENDPOINT);
        assert_eq!(
            PairingAddress::new(ENDPOINT, None).unwrap().relay_url(),
            None
        );
        for good in [
            "https://relay.example",
            "https://relay.example:8443/path",
            "https://use1-1.relay.example.net./",
            // A numeric label is fine where the last one is a name.
            "https://10.relay.example/",
            // Only a whole local-only label counts.
            "https://relay.localhost.example/",
            "https://notlocal.example/",
            "https://relay.mylocal/",
        ] {
            assert!(
                PairingAddress::new(ENDPOINT, Some(good.into())).is_ok(),
                "{good:?}"
            );
        }
    }

    #[test]
    fn an_address_refuses_anything_else_as_a_relay() {
        let too_long = format!("https://{}", "a".repeat(MAX_RELAY_URL_BYTES));
        for bad in [
            "",
            "https://",
            "https:///",
            "https://:443/",
            "http://relay.example",
            "HTTPS://relay.example",
            "https://relay.example/ path",
            "https://relay.example/\n",
            "https://rélay.example",
            "javascript:alert(1)",
            // Credentials, a query, a fragment.
            "https://user:pw@relay.example/",
            "https://relay.example/?next=1",
            "https://relay.example/#top",
            // An IP address is where a device is, not the name of a relay.
            "https://10.0.0.1/",
            "https://10.0.0.1:8443/x",
            "https://[::1]/",
            "https://[2001:db8::1]:443/",
            "https://192.168.1.20.",
            // The same thing spelt in hex, whole or in part.
            "https://0x7f000001/",
            "https://0xC0A80114:8443/",
            "https://1.2.3.0x4/",
            "https://relay.example.0a/",
            // One label, or a name for the reader's own machine or network.
            "https://relay",
            "https://relay./",
            "https://localhost:8443/",
            "https://LOCALHOST/",
            "https://relay.localhost/",
            "https://printer.local/",
            "https://router.home.arpa/",
            "https://relay.internal/",
            too_long.as_str(),
        ] {
            assert_eq!(
                PairingAddress::new(ENDPOINT, Some(bad.into())),
                Err(AddressError::RelayUrl),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_name_loses_controls_and_direction_marks_and_keeps_the_rest() {
        assert_eq!(sanitize_display_name("  Mum \n"), "Mum");
        assert_eq!(sanitize_display_name("a\u{0}b\u{1b}[31mc\u{7f}"), "ab[31mc");
        // A right-to-left override that would show "gpj.exe" reversed.
        assert_eq!(sanitize_display_name("Jeff\u{202e}exe.jpg"), "Jeffexe.jpg");
        assert_eq!(
            sanitize_display_name("\u{2066}a\u{2069}\u{200e}\u{200f}\u{061c}\u{feff}b\u{2028}c"),
            "abc"
        );
        assert_eq!(sanitize_display_name("x\u{e0041}\u{e007f}y"), "xy");
        // Joiners are part of real names and of emoji.
        assert_eq!(sanitize_display_name("می\u{200c}خواهم"), "می\u{200c}خواهم");
        assert_eq!(sanitize_display_name("👩\u{200d}👧"), "👩\u{200d}👧");
    }

    #[test]
    fn a_name_loses_everything_invisible() {
        // Format characters of every kind: soft hyphen, zero-width space,
        // word joiner and the invisible operators, deprecated format
        // controls, interlinear annotation, Mongolian vowel separator.
        for invisible in [
            '\u{00ad}',
            '\u{200b}',
            '\u{2060}',
            '\u{2061}',
            '\u{2064}',
            '\u{2065}',
            '\u{206a}',
            '\u{206f}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{180e}',
            '\u{0600}',
            '\u{06dd}',
            '\u{110bd}',
            '\u{1d173}',
            '\u{e0001}',
            // Reserved as ignorable: shown as nothing, whatever they become.
            '\u{fff0}',
            '\u{fff8}',
            '\u{e0080}',
            '\u{e00ff}',
            '\u{e01f0}',
            '\u{e0fff}',
            // Not format characters, but blank all the same.
            '\u{034f}',
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}',
            '\u{17b4}',
            '\u{2800}',
        ] {
            assert_eq!(
                sanitize_display_name(&format!("a{invisible}b")),
                "ab",
                "U+{:04X} between letters",
                u32::from(invisible)
            );
            assert_eq!(
                sanitize_display_name(&invisible.to_string()),
                "",
                "U+{:04X} alone",
                u32::from(invisible)
            );
        }
    }

    #[test]
    fn a_name_with_nothing_to_see_is_empty() {
        // Joiners and variation selectors are kept inside a name, but a
        // name made only of them, or of them and spaces, shows nothing.
        for blank in [
            "\u{200d}",
            "\u{200c}\u{200d}",
            "\u{fe0f}",
            " \u{200d} \u{fe0f} ",
            "\u{200b}\u{3164}",
            "   ",
            // Mongolian variation selectors, with nothing to vary.
            "\u{180b}",
            "\u{180c}\u{180d}\u{180f}",
        ] {
            assert_eq!(sanitize_display_name(blank), "", "{blank:?}");
        }
        // One visible character is enough, and what it carries stays.
        assert_eq!(sanitize_display_name("ᠠ\u{180b}"), "ᠠ\u{180b}");
        // A joiner at the start joins nothing and goes, and so does a
        // non-joiner at the end; inside, both stay.
        assert_eq!(sanitize_display_name("\u{200d}x"), "x");
        assert_eq!(
            sanitize_display_name(" \u{200c} a\u{200d}b \u{200c} "),
            "a\u{200d}b"
        );
        assert_eq!(sanitize_display_name("a\u{200c}b\u{200c}"), "a\u{200c}b");
        // A joiner at the end can be part of the spelling: Malayalam
        // "Rajan" written with na, virama and a joiner for the chillu form.
        let rajan = "രാജന\u{0d4d}\u{200d}";
        assert_eq!(sanitize_display_name(rajan), rajan);
    }

    #[test]
    fn a_name_is_capped_in_characters_after_trimming() {
        let long = format!("  {}  ", "é".repeat(MAX_DISPLAY_NAME_CHARS + 10));
        let capped = sanitize_display_name(&long);
        assert_eq!(capped.chars().count(), MAX_DISPLAY_NAME_CHARS);
        assert!(capped.chars().all(|character| character == 'é'));
        // Only controls: nothing left.
        assert_eq!(sanitize_display_name("\u{0}\u{202e}\t"), "");
    }

    #[test]
    fn sanitising_twice_changes_nothing() {
        // The last is a name whose cap falls inside a run of spaces: found
        // by the link fuzzer, when a capped name came back ending in them.
        let cut_in_spaces = format!("{}{}tail", "a".repeat(50), " ".repeat(30));
        let cut_in_joiners = format!("{}{}tail", "a".repeat(60), "\u{200c} ".repeat(10));
        for name in [
            cut_in_joiners.as_str(),
            "  Mum \n",
            "Jeff\u{202e}exe.jpg",
            "a \u{0} b",
            "",
            cut_in_spaces.as_str(),
        ] {
            let once = sanitize_display_name(name);
            assert_eq!(sanitize_display_name(&once), once, "{name:?}");
        }
        assert_eq!(sanitize_display_name(&cut_in_spaces), "a".repeat(50));
    }
}
