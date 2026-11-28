//! Account identity for Keys.
//!
//! An account is one person's: one identity key, one encryption key and one
//! recovery key, shared by all of their devices, and a set of devices, each
//! with keys of its own. The key sets themselves, their stored forms and the
//! list of everything the account identity key signs live in
//! [`keys_pairing::keys`], because pairing binds them; this crate holds what
//! sits on top:
//!
//! - [`mod@recovery_code`]: the recovery secret written out for a person to
//!   record, and read back, with check characters that point at a typo.
//! - [`enrolment`]: the account-signed statement that makes a device one of
//!   the account's.

pub mod enrolment;
pub mod recovery_code;

pub use enrolment::{DeviceEnrolment, EnrolmentError};
pub use recovery_code::{
    RecoveryCodeError, check_recovery_code, parse_recovery_code, recovery_code,
};
