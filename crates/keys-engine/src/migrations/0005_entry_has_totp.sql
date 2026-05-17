-- Migration 0005: `entry.has_totp` precomputed boolean for AutoFill's
-- OTP-picker filter.
--
-- AutoFill's `prepareOneTimeCodeCredentialList` filters entry summaries
-- down to those carrying a TOTP secret. Computing that per-row at
-- query time would require an `EXISTS (...)` subquery over
-- `entry_protected` / `entry_custom_field` on the AutoFill hot path
-- (`search_by_service`), which negates the perf win that path exists
-- to deliver. Cheaper to spend one bit per entry and write it at the
-- handful of places that mutate the relevant fields.
--
-- Detection convention (must match the Swift side — see
-- `Keys-Mac/Keys/Services/TOTPGenerator.swift::hasTOTP` and
-- `QuickTypeService.swift::hasTOTP`):
--   * `entry.url` starts with `otpauth://`, OR
--   * any custom field (protected or non-protected) whose name is
--     one of: `otp`, `TOTP`, `OTPAuth`, `TOTP Seed` (case-sensitive,
--     matching the Swift `Set<String>` exactly).
--
-- The Rust side mirrors this in `crate::totp::is_totp_field` and
-- `crate::totp::url_is_otpauth`. Backfill below uses the same names.
-- Engine-internal column — does NOT round-trip to KDBX.

ALTER TABLE entry ADD COLUMN has_totp INTEGER NOT NULL DEFAULT 0;

-- Backfill: mark every existing entry whose URL or custom-field set
-- already implies a TOTP secret. Idempotent re-runs are not a concern
-- (migrations table gates re-execution), but the UPDATEs themselves
-- are: rerunning would write the same 1s back. Field-name match list
-- below MUST stay in lock-step with `is_totp_field` Rust-side.

UPDATE entry SET has_totp = 1 WHERE url LIKE 'otpauth://%';

UPDATE entry SET has_totp = 1 WHERE uuid IN (
    SELECT entry_uuid FROM entry_protected
    WHERE field_name IN ('otp', 'TOTP', 'OTPAuth', 'TOTP Seed')
);

UPDATE entry SET has_totp = 1 WHERE uuid IN (
    SELECT entry_uuid FROM entry_custom_field
    WHERE field_name IN ('otp', 'TOTP', 'OTPAuth', 'TOTP Seed')
);
