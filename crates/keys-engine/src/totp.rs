// Pedantic clippy lints that fire on idiomatic TOTP/HOTP code:
// - `cast_possible_truncation` on `u64 % period as u32` — the modulo
//   is mathematically bounded by `period: u32`, so the truncation
//   can never happen.
// - `cast_lossless` / `cast_possible_truncation` on `char as u32` and
//   `usize as u32` inside the base32 decoder — bounded by the 32-char
//   alphabet, never overflows.
// - `assigning_clones` on `params.issuer = issuer.to_owned()` — the
//   suggested `clone_into` would be a marginal optimisation on
//   strings that are decoded once per URI; not worth the readability
//   hit.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::assigning_clones
)]

//! TOTP (RFC 6238) — presence detection plus code generation.
//!
//! Two surfaces live in this module:
//!
//! 1. **Presence detection** (`is_totp_field`, `url_is_otpauth`) for the
//!    precomputed `entry.has_totp` column. The Swift side mirrors these
//!    checks in `Keys-Mac/Keys/Services/TOTPGenerator.swift::hasTOTP` and
//!    `Keys-Mac/Keys/Services/QuickTypeService.swift::hasTOTP`. The set
//!    of recognised field names and the URL-prefix rule must stay in
//!    lock-step on both sides — drift means the engine's precomputed
//!    flag disagrees with what the rest of the app considers a TOTP
//!    entry. Migration 0005 also bakes the same list into its backfill;
//!    see `crates/keys-engine/src/migrations/0005_entry_has_totp.sql`.
//!
//! 2. **Code generation** (`generate_code`, `parse_uri`, `base32_decode`,
//!    …) implementing RFC 6238 on top of RFC 4226. Ported from
//!    `Keys-Mac/Keys/Services/TOTPGenerator.swift` and validated against
//!    the RFC 6238 Appendix B test vectors.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// ────────────────────────────────────────────────────────────────────────
// Presence detection
// ────────────────────────────────────────────────────────────────────────

/// Case-sensitive set of custom-field names that indicate a TOTP
/// secret. Matches the Swift `Set<String>` exactly.
const TOTP_FIELD_NAMES: &[&str] = &["otp", "TOTP", "OTPAuth", "TOTP Seed"];

/// `true` when the named custom field (protected or not) holds a TOTP
/// secret per the shared convention.
pub(crate) fn is_totp_field(name: &str) -> bool {
    TOTP_FIELD_NAMES.contains(&name)
}

/// `true` when the entry's URL is itself an `otpauth://` URI.
/// `KeePass` clients sometimes shove the whole TOTP URI into the URL slot
/// rather than a custom field.
pub(crate) fn url_is_otpauth(url: &str) -> bool {
    url.starts_with("otpauth://")
}

// ────────────────────────────────────────────────────────────────────────
// Code generation (RFC 6238 / RFC 4226)
// ────────────────────────────────────────────────────────────────────────

/// HMAC algorithm used by the HOTP/TOTP construction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// Parameters for generating a TOTP code. Defaults match the Swift
/// `TOTPGenerator.Params` defaults — SHA-1, 6 digits, 30s period.
#[derive(Debug, Clone)]
pub struct TotpParams {
    /// Raw secret bytes (base32-decoded).
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
    pub issuer: String,
    pub account_name: String,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: String::new(),
            account_name: String::new(),
        }
    }
}

/// Generate the TOTP code for `unix_seconds` (seconds since the Unix
/// epoch).
#[must_use]
pub fn generate_code(params: &TotpParams, unix_seconds: u64) -> String {
    let period = u64::from(params.period.max(1));
    let counter = unix_seconds / period;
    generate_hotp(&params.secret, counter, params.digits, params.algorithm)
}

/// Seconds remaining until the current TOTP code expires.
#[must_use]
pub fn seconds_remaining(period: u32, unix_seconds: u64) -> u32 {
    let period = period.max(1);
    let elapsed = (unix_seconds % u64::from(period)) as u32;
    period - elapsed
}

/// Progress fraction across the current period — 0.0 = just generated,
/// approaching 1.0 = about to expire.
#[must_use]
pub fn progress(period: u32, unix_seconds: u64) -> f64 {
    let period = period.max(1);
    let elapsed = (unix_seconds % u64::from(period)) as u32;
    f64::from(elapsed) / f64::from(period)
}

fn generate_hotp(secret: &[u8], counter: u64, digits: u32, algorithm: TotpAlgorithm) -> String {
    let counter_bytes = counter.to_be_bytes();
    let hmac = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
                .expect("HMAC accepts arbitrary key length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
                .expect("HMAC accepts arbitrary key length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
                .expect("HMAC accepts arbitrary key length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // RFC 4226 dynamic truncation.
    let offset = (hmac[hmac.len() - 1] & 0x0F) as usize;
    let truncated = ((u32::from(hmac[offset]) & 0x7F) << 24)
        | (u32::from(hmac[offset + 1]) << 16)
        | (u32::from(hmac[offset + 2]) << 8)
        | u32::from(hmac[offset + 3]);

    let modulus = 10u32.pow(digits);
    let code = truncated % modulus;
    format!("{:0width$}", code, width = digits as usize)
}

// ────────────────────────────────────────────────────────────────────────
// otpauth:// URI parsing
// ────────────────────────────────────────────────────────────────────────

/// Parse an `otpauth://totp/...` URI into [`TotpParams`].
///
/// Returns `None` for non-`otpauth` schemes, non-`totp` hosts, or when
/// the `secret` query parameter is missing or fails to decode.
#[must_use]
pub fn parse_uri(uri: &str) -> Option<TotpParams> {
    let parsed = url::Url::parse(uri).ok()?;
    if parsed.scheme() != "otpauth" {
        return None;
    }
    if parsed.host_str() != Some("totp") {
        return None;
    }

    // Path is `/Issuer:account` or `/account` (already percent-decoded
    // by url::Url::path() — no, path is NOT percent-decoded. We have
    // to decode it ourselves.)
    let raw_path = parsed.path().trim_start_matches('/');
    let path = percent_decode(raw_path);

    let mut params = TotpParams::default();

    if let Some((issuer, account)) = path.split_once(':') {
        params.issuer = issuer.to_owned();
        params.account_name = account.to_owned();
    } else {
        params.account_name = path;
    }

    let mut secret: Option<Vec<u8>> = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => {
                secret = Some(base32_decode(value.as_ref())?);
            }
            "issuer" => {
                params.issuer = value.into_owned();
            }
            "algorithm" => match value.to_ascii_uppercase().as_str() {
                "SHA256" => params.algorithm = TotpAlgorithm::Sha256,
                "SHA512" => params.algorithm = TotpAlgorithm::Sha512,
                _ => params.algorithm = TotpAlgorithm::Sha1,
            },
            "digits" => {
                if let Ok(d) = value.parse::<u32>() {
                    params.digits = d;
                }
            }
            "period" => {
                if let Ok(p) = value.parse::<u32>() {
                    params.period = p;
                }
            }
            _ => {}
        }
    }

    params.secret = secret?;
    Some(params)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────────────
// Base32 (RFC 4648 §6)
// ────────────────────────────────────────────────────────────────────────

/// Decode a base32 string (RFC 4648). Case-insensitive, spaces ignored,
/// padding (`=`) optional. Returns `None` if a non-alphabet character is
/// encountered.
#[must_use]
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 8);

    for ch in input.chars() {
        if ch == '=' || ch == ' ' {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let byte = upper as u32;
        if byte > 0x7F {
            return None;
        }
        let idx = alphabet.iter().position(|&c| c as u32 == byte)?;
        value = (value << 5) | (idx as u32);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((value >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Presence-detection tests (pre-existing) ─────────────────────

    #[test]
    fn recognised_field_names() {
        for name in ["otp", "TOTP", "OTPAuth", "TOTP Seed"] {
            assert!(is_totp_field(name), "{name} should be recognised");
        }
    }

    #[test]
    fn unrecognised_field_names() {
        // Case matters — Swift uses a literal Set<String>, not
        // case-insensitive comparison. Match that.
        for name in ["", "Password", "TOTP_Seed", "otpauth", "OTP", "totp"] {
            assert!(!is_totp_field(name), "{name} should not be recognised");
        }
    }

    #[test]
    fn otpauth_url_detection() {
        assert!(url_is_otpauth("otpauth://totp/Acme:alice?secret=ABC"));
        assert!(!url_is_otpauth("https://example.com"));
        assert!(!url_is_otpauth(""));
        assert!(!url_is_otpauth("OTPAUTH://"));
    }

    // ── RFC 6238 Appendix B — canonical vectors ──────────────────────
    //
    // Secrets are the ASCII string "12345678901234567890" (and longer
    // repeats for SHA-256/SHA-512), 8-digit codes, period=30.

    fn sha1_secret() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }
    fn sha256_secret() -> Vec<u8> {
        b"12345678901234567890123456789012".to_vec()
    }
    fn sha512_secret() -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
    }

    fn vector_code(secret: Vec<u8>, alg: TotpAlgorithm, time: u64) -> String {
        let params = TotpParams {
            secret,
            algorithm: alg,
            digits: 8,
            period: 30,
            ..Default::default()
        };
        generate_code(&params, time)
    }

    #[test]
    fn rfc6238_sha1() {
        let s = sha1_secret();
        assert_eq!(vector_code(s.clone(), TotpAlgorithm::Sha1, 59), "94287082");
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha1, 1_111_111_109),
            "07081804"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha1, 1_111_111_111),
            "14050471"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha1, 1_234_567_890),
            "89005924"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha1, 2_000_000_000),
            "69279037"
        );
        assert_eq!(
            vector_code(s, TotpAlgorithm::Sha1, 20_000_000_000),
            "65353130"
        );
    }

    #[test]
    fn rfc6238_sha256() {
        let s = sha256_secret();
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha256, 59),
            "46119246"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha256, 1_111_111_109),
            "68084774"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha256, 1_111_111_111),
            "67062674"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha256, 1_234_567_890),
            "91819424"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha256, 2_000_000_000),
            "90698825"
        );
        assert_eq!(
            vector_code(s, TotpAlgorithm::Sha256, 20_000_000_000),
            "77737706"
        );
    }

    #[test]
    fn rfc6238_sha512() {
        let s = sha512_secret();
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha512, 59),
            "90693936"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha512, 1_111_111_109),
            "25091201"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha512, 1_111_111_111),
            "99943326"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha512, 1_234_567_890),
            "93441116"
        );
        assert_eq!(
            vector_code(s.clone(), TotpAlgorithm::Sha512, 2_000_000_000),
            "38618901"
        );
        assert_eq!(
            vector_code(s, TotpAlgorithm::Sha512, 20_000_000_000),
            "47863826"
        );
    }

    // ── Default-parameter check ──────────────────────────────────────

    #[test]
    fn defaults_match_swift() {
        let p = TotpParams::default();
        assert_eq!(p.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
        assert!(p.secret.is_empty());
        assert!(p.issuer.is_empty());
        assert!(p.account_name.is_empty());
    }

    // ── Base32 decoding (RFC 4648 §10) ───────────────────────────────

    #[test]
    fn base32_empty() {
        assert_eq!(base32_decode(""), Some(Vec::new()));
    }

    #[test]
    fn base32_f() {
        assert_eq!(base32_decode("MY"), Some(b"f".to_vec()));
        assert_eq!(base32_decode("MY======"), Some(b"f".to_vec()));
    }

    #[test]
    fn base32_foo() {
        assert_eq!(base32_decode("MZXW6"), Some(b"foo".to_vec()));
        assert_eq!(base32_decode("MZXW6==="), Some(b"foo".to_vec()));
    }

    #[test]
    fn base32_foobar() {
        assert_eq!(base32_decode("MZXW6YTBOI"), Some(b"foobar".to_vec()));
        assert_eq!(base32_decode("MZXW6YTBOI======"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn base32_case_insensitive_and_spaces() {
        assert_eq!(base32_decode("mzxw6ytboi"), Some(b"foobar".to_vec()));
        assert_eq!(base32_decode("MZ XW 6Y TB OI"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn base32_invalid_returns_none() {
        assert_eq!(base32_decode("MZXW6!"), None);
        // '1' is not in the base32 alphabet.
        assert_eq!(base32_decode("1234"), None);
    }

    // ── URI parsing ──────────────────────────────────────────────────

    #[test]
    fn parse_uri_full_example() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let p = parse_uri(uri).expect("parse should succeed");
        assert_eq!(p.issuer, "Example");
        assert_eq!(p.account_name, "alice@example.com");
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert_eq!(p.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(p.secret, base32_decode("JBSWY3DPEHPK3PXP").unwrap());
    }

    #[test]
    fn parse_uri_with_percent_encoded_label() {
        let uri = "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&period=60&digits=8";
        let p = parse_uri(uri).expect("parse should succeed");
        assert_eq!(p.issuer, "ACME Co");
        assert_eq!(p.account_name, "alice@example.com");
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
    }

    #[test]
    fn parse_uri_empty_secret_decodes_to_empty() {
        let p = parse_uri("otpauth://totp/test?secret=").expect("parse should succeed");
        assert!(p.secret.is_empty());
    }

    #[test]
    fn parse_uri_account_only() {
        let p = parse_uri("otpauth://totp/alice?secret=MZXW6").expect("parse should succeed");
        assert_eq!(p.issuer, "");
        assert_eq!(p.account_name, "alice");
    }

    #[test]
    fn parse_uri_rejects_non_otpauth_scheme() {
        assert!(parse_uri("https://totp/x?secret=MY").is_none());
    }

    #[test]
    fn parse_uri_rejects_non_totp_host() {
        assert!(parse_uri("otpauth://hotp/x?secret=MY").is_none());
    }

    #[test]
    fn parse_uri_missing_secret_returns_none() {
        assert!(parse_uri("otpauth://totp/x?issuer=foo").is_none());
    }

    #[test]
    fn parse_uri_unknown_algorithm_defaults_to_sha1() {
        let p = parse_uri("otpauth://totp/x?secret=MY&algorithm=MD5").unwrap();
        assert_eq!(p.algorithm, TotpAlgorithm::Sha1);
    }

    // ── Period boundary behaviour ───────────────────────────────────

    #[test]
    fn seconds_remaining_boundaries() {
        // At t=0 (period boundary), a full period remains.
        assert_eq!(seconds_remaining(30, 0), 30);
        assert_eq!(seconds_remaining(30, 30), 30);
        // Just-past boundary → period - 1 seconds remaining.
        assert_eq!(seconds_remaining(30, 1), 29);
        assert_eq!(seconds_remaining(30, 29), 1);
        assert_eq!(seconds_remaining(60, 59), 1);
    }

    #[test]
    fn progress_boundaries() {
        assert!((progress(30, 0) - 0.0).abs() < 1e-9);
        assert!((progress(30, 15) - 0.5).abs() < 1e-9);
        // Just before rollover.
        assert!((progress(30, 29) - (29.0 / 30.0)).abs() < 1e-9);
        // Rollover wraps back to 0.
        assert!((progress(30, 30) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn default_digits_padding() {
        // The default 6-digit setting should zero-pad short codes.
        let secret = base32_decode("MZXW6YTBOI").unwrap();
        let params = TotpParams {
            secret,
            ..Default::default()
        };
        let code = generate_code(&params, 0);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
