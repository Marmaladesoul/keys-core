//! TOTP (RFC 6238) FFI surface.
//!
//! Thin wrapper over [`keys_engine::totp`]. Translates the FFI-friendly
//! `TotpParams` record into the engine's native struct and forwards.

use keys_engine as eng;

/// HMAC algorithm used by the HOTP/TOTP construction.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<TotpAlgorithm> for eng::TotpAlgorithm {
    fn from(a: TotpAlgorithm) -> Self {
        match a {
            TotpAlgorithm::Sha1 => Self::Sha1,
            TotpAlgorithm::Sha256 => Self::Sha256,
            TotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<eng::TotpAlgorithm> for TotpAlgorithm {
    fn from(a: eng::TotpAlgorithm) -> Self {
        match a {
            eng::TotpAlgorithm::Sha1 => Self::Sha1,
            eng::TotpAlgorithm::Sha256 => Self::Sha256,
            eng::TotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

/// FFI-mirrored TOTP parameters. Matches [`keys_engine::TotpParams`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct TotpParams {
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
    pub issuer: String,
    pub account_name: String,
}

impl From<TotpParams> for eng::TotpParams {
    fn from(p: TotpParams) -> Self {
        Self {
            secret: p.secret,
            algorithm: p.algorithm.into(),
            digits: p.digits,
            period: p.period,
            issuer: p.issuer,
            account_name: p.account_name,
        }
    }
}

impl From<eng::TotpParams> for TotpParams {
    fn from(p: eng::TotpParams) -> Self {
        Self {
            secret: p.secret,
            algorithm: p.algorithm.into(),
            digits: p.digits,
            period: p.period,
            issuer: p.issuer,
            account_name: p.account_name,
        }
    }
}

/// Generate a TOTP code for the given `unix_seconds`.
#[uniffi::export]
#[must_use]
pub fn totp_generate_code(params: TotpParams, unix_seconds: u64) -> String {
    let engine_params: eng::TotpParams = params.into();
    eng::totp_generate_code(&engine_params, unix_seconds)
}

/// Seconds remaining until the current TOTP code expires.
#[uniffi::export]
#[must_use]
pub fn totp_seconds_remaining(period: u32, unix_seconds: u64) -> u32 {
    eng::totp_seconds_remaining(period, unix_seconds)
}

/// Progress fraction (0.0 = just generated, ~1.0 = about to expire).
#[uniffi::export]
#[must_use]
pub fn totp_progress(period: u32, unix_seconds: u64) -> f64 {
    eng::totp_progress(period, unix_seconds)
}

/// Parse an `otpauth://totp/...` URI into [`TotpParams`].
#[uniffi::export]
#[must_use]
pub fn totp_parse_uri(uri: &str) -> Option<TotpParams> {
    eng::totp_parse_uri(uri).map(Into::into)
}

/// Decode a base32 string (RFC 4648).
#[uniffi::export]
#[must_use]
pub fn totp_base32_decode(input: &str) -> Option<Vec<u8>> {
    eng::totp_base32_decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_generate_matches_rfc6238_sha1_t59() {
        let params = TotpParams {
            secret: b"12345678901234567890".to_vec(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            issuer: String::new(),
            account_name: String::new(),
        };
        assert_eq!(totp_generate_code(params, 59), "94287082");
    }

    #[test]
    fn ffi_parse_uri_roundtrip() {
        let p = totp_parse_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(p.issuer, "Example");
        assert_eq!(p.account_name, "alice@example.com");
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert_eq!(p.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn ffi_base32_decode_known_vector() {
        assert_eq!(totp_base32_decode("MZXW6YTBOI"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn ffi_seconds_remaining_and_progress() {
        assert_eq!(totp_seconds_remaining(30, 0), 30);
        assert_eq!(totp_seconds_remaining(30, 29), 1);
        assert!((totp_progress(30, 15) - 0.5).abs() < 1e-9);
    }
}
