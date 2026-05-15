//! Reveal-on-demand paths for protected entry fields (task 3.4).
//!
//! Three entry points — `reveal_password`, `reveal_custom_field`,
//! `reveal_history_field` — each delegated to from the matching
//! method on [`crate::Engine`]. The first two fetch the wrapped blob
//! from `entry_protected`, ask the field-protector callback for a
//! fresh session key, and AES-GCM-open in process. The third — by
//! design — does **not** unwrap anything: history snapshots are stored
//! as plaintext JSON inside `entry_history.snapshot_json`, so the
//! reveal is just a JSON lookup. See the rustdoc on
//! [`crate::Engine::reveal_history_field`] for the rationale.
//!
//! ## Session-key discipline
//!
//! Each reveal call acquires a fresh
//! [`SessionKey`](keepass_core::protector::SessionKey) via the
//! [`FieldProtector`] and drops it as soon as the unwrap returns. We
//! deliberately do **not** cache the key on the engine — every reveal
//! is one Keychain hit + one AES-GCM open, matching the trust model
//! described in `_localdocs/SQLITE_MIGRATION.md` (and the Swift side's
//! reveal-on-select behaviour).

use std::collections::HashMap;

use keepass_core::protector::FieldProtector;
use rusqlite::{Connection, OptionalExtension, params};
use secrecy::SecretString;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::unwrap_with_session_key;
use crate::error::{EngineError, RevealError};

/// Canonical KDBX field name for an entry's password slot — kept in
/// lock-step with [`crate::ingest`]'s constant of the same name.
const PASSWORD_FIELD: &str = "Password";

/// Reveal the cleartext password for an entry.
///
/// Returns [`EngineError::NotFound`] if the entry has no
/// `entry_protected` row for the `Password` field. Note that
/// [`crate::ingest`] writes the canonical Password row unconditionally
/// — even an empty-string password produces a wrapped blob — so a
/// missing row in practice means the entry doesn't exist, or its
/// password row was deleted out of band. Empty passwords successfully
/// reveal as `SecretString::from("")`.
pub(crate) fn reveal_password(
    conn: &Connection,
    protector: &dyn FieldProtector,
    uuid: Uuid,
) -> Result<SecretString, EngineError> {
    reveal_protected_field(conn, protector, uuid, PASSWORD_FIELD, "password")
}

/// Reveal the cleartext value of a named protected custom field.
///
/// Asking for `field_name = "Password"` is allowed — it routes through
/// the same `entry_protected` row that [`reveal_password`] hits, so the
/// two are equivalent for that name. [`reveal_password`] stays as the
/// canonical entry point because callers reaching for *the password*
/// shouldn't have to spell the field name.
pub(crate) fn reveal_custom_field(
    conn: &Connection,
    protector: &dyn FieldProtector,
    uuid: Uuid,
    field_name: &str,
) -> Result<SecretString, EngineError> {
    reveal_protected_field(conn, protector, uuid, field_name, "custom_field")
}

/// Reveal a field from a historic snapshot of an entry.
///
/// **Asymmetric with the live-reveal paths** — history snapshots are
/// stored as plaintext JSON inside `entry_history.snapshot_json`, not
/// as AES-GCM-wrapped blobs in `entry_protected`. This is by design:
/// per the ingest module's history-snapshot rationale, the surrounding
/// `SQLite` file is itself `SQLCipher`-encrypted at rest, which gives
/// us the same trust posture as the live `entry_protected` blobs —
/// plus we avoid serialising one wrapped blob per protected field per
/// historic snapshot. So this method does **not** call
/// [`FieldProtector::acquire_session_key`]; it deserialises the
/// snapshot JSON and reads the requested field directly.
///
/// `field_name == "Password"` reads `HistorySnapshot.password`; any
/// other name reads the value out of the `custom_fields` map. Returns
/// [`EngineError::NotFound`] if the snapshot doesn't exist or the
/// named field isn't present in it.
pub(crate) fn reveal_history_field(
    conn: &Connection,
    uuid: Uuid,
    history_index: u32,
    field_name: &str,
) -> Result<SecretString, EngineError> {
    let snapshot_json: Option<String> = conn
        .query_row(
            "SELECT snapshot_json FROM entry_history \
             WHERE entry_uuid = ?1 AND history_index = ?2",
            params![uuid.to_string(), i64::from(history_index)],
            |r| r.get::<_, String>(0),
        )
        .optional()?;

    let Some(json) = snapshot_json else {
        return Err(EngineError::NotFound {
            entity: "history_snapshot",
        });
    };

    let snap: HistorySnapshot =
        serde_json::from_str(&json).map_err(|e| EngineError::Reveal(RevealError::Json(e)))?;

    let value: String = if field_name == PASSWORD_FIELD {
        snap.password
    } else if let Some(cf) = snap.custom_fields.get(field_name) {
        cf.value.clone()
    } else {
        return Err(EngineError::NotFound {
            entity: "history_field",
        });
    };

    Ok(SecretString::from(value))
}

fn reveal_protected_field(
    conn: &Connection,
    protector: &dyn FieldProtector,
    uuid: Uuid,
    field_name: &str,
    not_found_entity: &'static str,
) -> Result<SecretString, EngineError> {
    let wrapped: Option<Vec<u8>> = conn
        .query_row(
            "SELECT wrapped_blob FROM entry_protected \
             WHERE entry_uuid = ?1 AND field_name = ?2",
            params![uuid.to_string(), field_name],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    let Some(wrapped) = wrapped else {
        return Err(EngineError::NotFound {
            entity: not_found_entity,
        });
    };

    // Acquire a fresh session key. The `SessionKey` zeroes on drop —
    // we keep it in a tight scope so it's wiped the moment the unwrap
    // returns.
    let session_key = protector
        .acquire_session_key()
        .map_err(|e| EngineError::Reveal(RevealError::SessionKey(e.to_string())))?;

    // Plaintext into a Zeroizing buffer first so the intermediate
    // `Vec<u8>` doesn't linger past the conversion into `SecretString`.
    let plaintext = unwrap_with_session_key(&session_key, &wrapped)
        .map(Zeroizing::new)
        .map_err(|e| EngineError::Reveal(RevealError::Unwrap(e)))?;
    drop(session_key);

    let plaintext_str = std::str::from_utf8(&plaintext)
        .map_err(|e| EngineError::Reveal(RevealError::Unwrap(format!("non-utf8 plaintext: {e}"))))?
        .to_owned();

    Ok(SecretString::from(plaintext_str))
}

// ───────────────────────── history shape ─────────────────────────

/// Deserialise side of the shape written by
/// `crate::ingest::HistorySnapshot`. Lives here rather than being
/// shared with [`crate::projection`] because we only need a couple of
/// fields and pulling in the full projection shape would couple this
/// module to a moving target.
#[derive(Deserialize)]
struct HistorySnapshot {
    password: String,
    custom_fields: HashMap<String, HistoryCustomField>,
}

#[derive(Deserialize)]
struct HistoryCustomField {
    value: String,
}
