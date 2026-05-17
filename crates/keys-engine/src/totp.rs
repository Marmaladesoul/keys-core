//! TOTP-presence detection for the precomputed `entry.has_totp` column.
//!
//! The Swift side mirrors these checks in
//! `Keys-Mac/Keys/Services/TOTPGenerator.swift::hasTOTP` and
//! `Keys-Mac/Keys/Services/QuickTypeService.swift::hasTOTP`. The set
//! of recognised field names and the URL-prefix rule must stay in
//! lock-step on both sides — drift means the engine's precomputed
//! flag disagrees with what the rest of the app considers a TOTP
//! entry. Migration 0005 also bakes the same list into its backfill;
//! see `crates/keys-engine/src/migrations/0005_entry_has_totp.sql`.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
