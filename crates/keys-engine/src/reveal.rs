//! Reveal-on-demand paths for protected entry fields (task 3.4).
//!
//! Three entry points — `reveal_password`, `reveal_custom_field`,
//! `reveal_history_field` — each delegated to from the matching
//! method on [`crate::Engine`]. All three fetch wrapped bytes, ask the
//! field-protector callback for a fresh session key, and AES-GCM-open
//! in process: `reveal_password` and `reveal_custom_field` read from
//! `entry_protected.wrapped_blob` directly; `reveal_history_field`
//! deserialises `entry_history.snapshot_json` and base64-decodes the
//! wrapped bytes that live inside it. Non-protected history fields
//! (custom fields with `protected: false`) skip the unwrap and return
//! the plaintext from the JSON directly.
//!
//! ## Session-key discipline
//!
//! Each reveal call acquires a fresh
//! [`SessionKey`](keepass_core::protector::SessionKey) via the
//! [`FieldProtector`] and drops it as soon as the unwrap returns. We
//! deliberately do **not** cache the key on the engine — every reveal
//! is one Keychain hit + one AES-GCM open, matching the client's
//! reveal-on-select behaviour.

use keepass_core::protector::{FieldProtector, open_with_key};
use rusqlite::{Connection, OptionalExtension, params};
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{EngineError, RevealError};
use crate::history_snapshot::HistorySnapshotIo;
use crate::util::PASSWORD_FIELD;
use crate::util::codec::b64_decode;

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
/// **Symmetric with the live-reveal paths**: protected fields inside a
/// history snapshot (the canonical `password` slot and any custom field
/// marked `protected: true`) are AES-GCM-sealed under the same session
/// key used for live `entry_protected.wrapped_blob` rows, then
/// base64-encoded into the snapshot JSON. This method deserialises the
/// JSON, base64-decodes the wrapped bytes for the requested field,
/// acquires a fresh session key via the [`FieldProtector`], and
/// AES-GCM-opens — exactly the same shape as [`reveal_password`].
///
/// Non-protected custom fields (`protected: false`) carry plaintext in
/// the JSON and are returned without an unwrap; no session key is
/// acquired in that case.
///
/// `field_name == "Password"` reads `HistorySnapshotIo.password`; any
/// other name reads the value out of the `custom_fields` map. Returns
/// [`EngineError::NotFound`] if the snapshot doesn't exist or the
/// named field isn't present in it.
pub(crate) fn reveal_history_field(
    conn: &Connection,
    protector: &dyn FieldProtector,
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

    let snap: HistorySnapshotIo =
        serde_json::from_str(&json).map_err(|e| EngineError::Reveal(RevealError::Json(e)))?;

    // Decide what to do with the named field before touching the
    // session-key callback — non-protected fields skip the unwrap.
    let payload: FieldPayload = if field_name == PASSWORD_FIELD {
        FieldPayload::Wrapped(snap.password)
    } else if let Some(cf) = snap.custom_fields.get(field_name) {
        if cf.protected {
            FieldPayload::Wrapped(cf.value.clone())
        } else {
            FieldPayload::Plain(cf.value.clone())
        }
    } else {
        return Err(EngineError::NotFound {
            entity: "history_field",
        });
    };

    match payload {
        FieldPayload::Plain(s) => Ok(SecretString::from(s)),
        FieldPayload::Wrapped(b64) => {
            let wrapped =
                b64_decode(&b64).map_err(|e| EngineError::Reveal(RevealError::Unwrap(e)))?;
            let session_key = protector
                .acquire_session_key()
                .map_err(|e| EngineError::Reveal(RevealError::SessionKey(e.to_string())))?;
            let plaintext = open_with_key(&session_key, &wrapped)
                .map(Zeroizing::new)
                .map_err(|e| EngineError::Reveal(RevealError::Unwrap(e.to_string())))?;
            drop(session_key);
            let plaintext_str = std::str::from_utf8(&plaintext)
                .map_err(|e| {
                    EngineError::Reveal(RevealError::Unwrap(format!("non-utf8 plaintext: {e}")))
                })?
                .to_owned();
            Ok(SecretString::from(plaintext_str))
        }
    }
}

/// Decide tree for what to do with a named field inside a history
/// snapshot — keeps the session-key acquisition out of the `Plain`
/// branch and avoids the `items_after_statements` clippy lint.
enum FieldPayload {
    Wrapped(String),
    Plain(String),
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
    let plaintext = open_with_key(&session_key, &wrapped)
        .map(Zeroizing::new)
        .map_err(|e| EngineError::Reveal(RevealError::Unwrap(e.to_string())))?;
    drop(session_key);

    let plaintext_str = std::str::from_utf8(&plaintext)
        .map_err(|e| EngineError::Reveal(RevealError::Unwrap(format!("non-utf8 plaintext: {e}"))))?
        .to_owned();

    Ok(SecretString::from(plaintext_str))
}
