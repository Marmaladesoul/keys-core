//! The `entry_history.snapshot_json` wire format — one declaration,
//! read and write.
//!
//! This is a **persisted, secret-bearing** format: history snapshots
//! carry the entry's password and any protected custom fields, sealed
//! under the engine's session key. Rows written by every build the
//! engine has ever shipped must keep deserialising, so the shape is
//! append-only in practice and the back-compat policy below is part of
//! the format, not an implementation detail.
//!
//! Everything about the format lives here: the field list, the
//! `#[serde(default)]` policy, the sub-shapes, and the entry→snapshot
//! construction the write path uses. Consumers deserialise
//! [`HistorySnapshotIo`] and read the fields they care about; a partial
//! reader is a partial *read*, never a partial re-declaration of the
//! shape.
//!
//! ## Protection
//!
//! The canonical password slot and any custom field with `protected:
//! true` are AES-GCM-sealed under the same session key that protects
//! the live `entry_protected.wrapped_blob` rows, then base64-encoded so
//! the bytes survive a `TEXT` column. History is therefore symmetric
//! with live entries: plaintext never appears in DB-stored JSON.
//! Non-protected custom fields keep their plaintext in `value`; the
//! `protected` flag tells the read side which interpretation applies.
//!
//! ## Back-compat policy
//!
//! `title`, `username` and `url` are the initial shipped shape and are
//! required. **Every field added since is `#[serde(default)]`**, so a
//! row written by an older build deserialises cleanly and surfaces
//! zero/empty for what genuinely wasn't recorded at write time. The
//! write side always emits the full payload.
//!
//! That policy is stated once, here, because it is exactly what a
//! five-way copy of this shape could not keep straight: a field that is
//! `default` on three readers and required on the fourth turns old rows
//! into a hard error on one path only — the kind of divergence that
//! shows up as "saving this vault fails" long after the field was
//! added.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "title": "...", "username": "...", "url": "...",
//!   "url_host": "...", "notes": "...",
//!   "password": "<base64(nonce|ct|tag)>",
//!   "tags": [...],
//!   "created_at": ..., "modified_at": ..., "accessed_at": ...,
//!   "last_used_at": ..., "expires_at": ...,
//!   "icon_index": 0, "icon_custom_uuid": null,
//!   "password_strength_bucket": 3, "password_entropy": 42.5,
//!   "attachments": [
//!     { "name": "doc.txt", "size": 1234, "sha256_hex": "<hex>" }
//!   ],
//!   "custom_fields": {
//!     "Token":   { "value": "<base64(nonce|ct|tag)>", "protected": true  },
//!     "Website": { "value": "example.com",            "protected": false }
//!   },
//!   "custom_data": [
//!     { "key": "...", "value": "...", "last_modified_at": ... }
//!   ]
//! }
//! ```

use std::collections::HashMap;

use keepass_core::model::Entry;
use keepass_core::protector::{SessionKey, seal_with_key};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EngineError, IngestError};
use crate::strength;
use crate::util::codec::{b64_encode, bytes_to_hex};
use crate::util::sql::{dt_to_ms, expiry_ms, parse_host};

/// One `entry_history.snapshot_json` record.
///
/// Field order here is the order the write side emits. Note that
/// `custom_fields` is a `HashMap`, so JSON key order within it is
/// already unspecified — nothing may depend on the serialised byte
/// layout of a snapshot (and nothing does: the content hash used for
/// history tombstones is computed over the *projected*
/// [`Entry`], never over these bytes).
#[derive(Serialize, Deserialize)]
pub(crate) struct HistorySnapshotIo {
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) url_host: String,
    #[serde(default)]
    pub(crate) notes: String,
    /// Base64 of `seal_with_key(session_key, password_plaintext)`.
    ///
    /// Empty only for pre-widening snapshots that predate the canonical
    /// password slot. Consumers differ deliberately on what that means:
    /// the restore path copies the value verbatim into
    /// `entry_protected`, so empty means "no password row" rather than
    /// "the empty-string password" (sealing an empty string still
    /// yields a non-empty blob). The projection path instead feeds it
    /// to the unsealer and fails closed. Both are policy decisions
    /// owned by the consumer — this module only carries the bytes.
    #[serde(default)]
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) created_at: i64,
    #[serde(default)]
    pub(crate) modified_at: i64,
    #[serde(default)]
    pub(crate) accessed_at: i64,
    #[serde(default)]
    pub(crate) last_used_at: Option<i64>,
    #[serde(default)]
    pub(crate) expires_at: Option<i64>,
    #[serde(default)]
    pub(crate) icon_index: Option<u32>,
    #[serde(default)]
    pub(crate) icon_custom_uuid: Option<String>,
    #[serde(default)]
    pub(crate) password_strength_bucket: Option<u8>,
    #[serde(default)]
    pub(crate) password_entropy: Option<f64>,
    #[serde(default)]
    pub(crate) attachments: Vec<HistoryAttachmentIo>,
    #[serde(default)]
    pub(crate) custom_fields: HashMap<String, HistoryCustomFieldIo>,
    /// Per-record `<CustomData>`. Round-trips the parked-conflict
    /// marker (`keys.field_conflict.v1`) and any other client-specific
    /// metadata attached to a history snapshot.
    #[serde(default)]
    pub(crate) custom_data: Vec<HistoryCustomDataItemIo>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HistoryAttachmentIo {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) size: u64,
    /// Hex-encoded SHA-256 of the attachment bytes. Lets the read side
    /// resolve a snapshot's attachment to the content-addressed blob in
    /// `attachment_blob` without relying on the live `entry_attachment`
    /// link row (which a later edit may have overwritten).
    ///
    /// Empty on rows written before this field existed; those
    /// attachments are unresolvable, and every consumer skips them
    /// rather than guessing.
    #[serde(default)]
    pub(crate) sha256_hex: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HistoryCustomFieldIo {
    /// For `protected = true`, base64 of `seal_with_key(...)`; for
    /// `protected = false`, the plaintext value.
    pub(crate) value: String,
    #[serde(default)]
    pub(crate) protected: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct HistoryCustomDataItemIo {
    pub(crate) key: String,
    pub(crate) value: String,
    /// Milliseconds since the Unix epoch (UTC). `None` matches the
    /// `keepass-core` model when KDBX3 writers omit
    /// `<LastModificationTime>`.
    #[serde(default)]
    pub(crate) last_modified_at: Option<i64>,
}

impl HistorySnapshotIo {
    /// Build a snapshot from a `keepass-core` entry, sealing the
    /// password and every protected custom field under `session_key`.
    ///
    /// `binaries` is the KDBX binary pool the entry's attachment
    /// `ref_id`s index into; an out-of-range ref contributes empty
    /// bytes (and therefore the SHA-256 of the empty string), matching
    /// the pool-resolution posture of the surrounding ingest walk.
    pub(crate) fn from_entry(
        entry: &Entry,
        session_key: &SessionKey,
        binaries: &[&[u8]],
    ) -> Result<Self, EngineError> {
        let seal = |plaintext: &[u8]| -> Result<String, EngineError> {
            seal_with_key(session_key, plaintext)
                .map(|wrapped| b64_encode(&wrapped))
                .map_err(|e| EngineError::Ingest(IngestError::Wrap(e.to_string())))
        };

        let mut custom_fields: HashMap<String, HistoryCustomFieldIo> = HashMap::new();
        for cf in &entry.custom_fields {
            let value = if cf.protected {
                seal(cf.value.as_bytes())?
            } else {
                cf.value.clone()
            };
            custom_fields.insert(
                cf.key.clone(),
                HistoryCustomFieldIo {
                    value,
                    protected: cf.protected,
                },
            );
        }

        let strength_result = strength::strength(&entry.password);
        let (password_strength_bucket, password_entropy) = if entry.password.is_empty() {
            (None, None)
        } else {
            (
                Some(strength_result.bucket as u8),
                Some(strength_result.entropy_bits),
            )
        };

        let attachments = entry
            .attachments
            .iter()
            .map(|att| {
                let bytes = binaries.get(att.ref_id as usize).copied().unwrap_or(&[]);
                HistoryAttachmentIo {
                    name: att.name.clone(),
                    size: u64::try_from(bytes.len()).unwrap_or(0),
                    sha256_hex: bytes_to_hex(&Sha256::digest(bytes)),
                }
            })
            .collect();

        Ok(Self {
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            url_host: parse_host(&entry.url),
            notes: entry.notes.clone(),
            password: seal(entry.password.as_bytes())?,
            tags: entry.tags.clone(),
            created_at: dt_to_ms(entry.times.creation_time),
            modified_at: dt_to_ms(entry.times.last_modification_time),
            accessed_at: dt_to_ms(entry.times.last_access_time),
            last_used_at: entry.times.last_access_time.map(|d| d.timestamp_millis()),
            expires_at: expiry_ms(&entry.times),
            icon_index: Some(entry.icon_id),
            icon_custom_uuid: entry.custom_icon_uuid.map(|u| u.to_string()),
            password_strength_bucket,
            password_entropy,
            attachments,
            custom_fields,
            custom_data: entry
                .custom_data
                .iter()
                .map(|cd| HistoryCustomDataItemIo {
                    key: cd.key.clone(),
                    value: cd.value.clone(),
                    last_modified_at: cd.last_modified.map(|d| d.timestamp_millis()),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field the write side emits, as JSON.
    fn full_json() -> serde_json::Value {
        serde_json::json!({
            "title": "t", "username": "u", "url": "https://example.com/x",
            "url_host": "example.com", "notes": "n",
            "password": "cGFzcw==", "tags": ["a", "b"],
            "created_at": 1, "modified_at": 2, "accessed_at": 3,
            "last_used_at": 4, "expires_at": 5,
            "icon_index": 6, "icon_custom_uuid": "some-uuid",
            "password_strength_bucket": 3, "password_entropy": 42.5,
            "attachments": [{"name": "doc.txt", "size": 12, "sha256_hex": "ab"}],
            "custom_fields": {"K": {"value": "v", "protected": true}},
            "custom_data": [{"key": "ck", "value": "cv", "last_modified_at": 7}],
        })
    }

    #[test]
    fn full_shape_round_trips() {
        let snap: HistorySnapshotIo = serde_json::from_value(full_json()).expect("deserialise");
        let back = serde_json::to_value(&snap).expect("serialise");
        assert_eq!(back, full_json());
    }

    /// The initial shipped shape — title/username/url and nothing else —
    /// must still deserialise, since rows that old exist. This is the
    /// case the five-way copy disagreed about.
    #[test]
    fn initial_shipped_shape_deserialises_with_defaults() {
        let snap: HistorySnapshotIo =
            serde_json::from_str(r#"{"title":"t","username":"u","url":"r"}"#)
                .expect("pre-widening row must deserialise");

        assert_eq!(snap.title, "t");
        assert_eq!(snap.url_host, "");
        assert_eq!(snap.notes, "");
        assert_eq!(snap.password, "");
        assert_eq!(snap.created_at, 0);
        assert_eq!(snap.modified_at, 0);
        assert_eq!(snap.accessed_at, 0);
        assert_eq!(snap.last_used_at, None);
        assert_eq!(snap.expires_at, None);
        assert_eq!(snap.icon_index, None);
        assert_eq!(snap.icon_custom_uuid, None);
        assert_eq!(snap.password_strength_bucket, None);
        assert_eq!(snap.password_entropy, None);
        assert!(snap.tags.is_empty());
        assert!(snap.attachments.is_empty());
        assert!(snap.custom_fields.is_empty());
        assert!(snap.custom_data.is_empty());
    }

    #[test]
    fn only_the_initial_shape_is_required() {
        for missing in ["title", "username", "url"] {
            let mut v = full_json();
            v.as_object_mut().expect("object").remove(missing);
            assert!(
                serde_json::from_value::<HistorySnapshotIo>(v).is_err(),
                "{missing} is part of the initial shape and must stay required"
            );
        }
    }

    #[test]
    fn sub_shapes_default_everything_but_their_key() {
        let att: HistoryAttachmentIo =
            serde_json::from_str(r#"{"name":"only"}"#).expect("attachment");
        assert_eq!(att.size, 0);
        assert_eq!(att.sha256_hex, "");

        let cf: HistoryCustomFieldIo = serde_json::from_str(r#"{"value":"v"}"#).expect("field");
        assert!(!cf.protected);

        let cd: HistoryCustomDataItemIo =
            serde_json::from_str(r#"{"key":"k","value":"v"}"#).expect("custom data");
        assert_eq!(cd.last_modified_at, None);
    }

    #[test]
    fn unknown_fields_are_ignored_so_a_newer_writer_stays_readable() {
        let mut v = full_json();
        v.as_object_mut()
            .expect("object")
            .insert("field_from_the_future".into(), serde_json::json!("x"));
        assert!(serde_json::from_value::<HistorySnapshotIo>(v).is_ok());
    }
}
