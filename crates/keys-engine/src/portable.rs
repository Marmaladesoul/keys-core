//! In-process carrier for cross-database entry moves (Phase 6.17-F).
//!
//! [`Engine::export_entry`](crate::Engine::export_entry) serialises an
//! entry into a [`PortableEntry`]: every field (title / username / url /
//! notes / icon / tags / timestamps), every protected slot revealed
//! into a [`SecretString`], every non-protected custom field, every
//! attachment (bytes + name + optional MIME), and — when the entry
//! references a custom icon — the icon's raw PNG bytes so the target
//! database can rehome the icon under its own UUID rather than
//! inheriting a dangling reference.
//!
//! [`Engine::import_entry`](crate::Engine::import_entry) consumes the
//! carrier on the *target* engine: it dedups the custom-icon bytes
//! into the target's icon pool (minting a fresh UUID if the bytes
//! aren't already present), then funnels every field through the
//! existing [`Engine::create_entry`](crate::Engine::create_entry) +
//! attachment-write paths so a single round-trip materialises a brand
//! new entry with all the source's data intact.
//!
//! The carrier is **in-process only**: it isn't persisted, isn't
//! `Serialize`able, and the protected-field plaintext sits in
//! [`SecretString`]s that zero on drop. The caller is expected to do
//! the dance `source.export_entry(uuid)` → `target.import_entry(…)` →
//! `source.delete_entry(uuid)` in one breath; callers that hold the
//! carrier alive longer than that are abusing the surface.
//!
//! Custom-icon handling deliberately ferries **bytes**, not the source
//! UUID — the source's icon pool isn't visible from the target, so a
//! UUID-only carrier would either dangle or require the target to
//! pre-seed the same pool. Bytes-and-dedup is the only correct shape
//! for the cross-database move use case the maintainer actually needs.

use keepass_core::protector::FieldProtector;
use rusqlite::{Connection, params};
use secrecy::SecretString;
use uuid::Uuid;

use crate::error::EngineError;
use crate::model::{IconRef, NewCustomField, NewEntryFields};
use crate::mutations;
use crate::reveal;

/// One attachment as carried by a [`PortableEntry`]. Bytes are owned
/// by the carrier; the engine's content-addressed
/// [`attach_file`](crate::Engine::attach_file) path on the target
/// rehashes and dedups on import.
#[derive(Debug)]
pub struct PortableAttachment {
    /// Attachment filename as recorded in the source's
    /// `entry_attachment.attachment_name`.
    pub name: String,
    /// Raw bytes of the attachment. Pulled from `attachment_blob.bytes`
    /// on export.
    pub bytes: Vec<u8>,
    /// Optional MIME hint. The engine schema doesn't track MIME — this
    /// is reserved for future use and is currently always `None` on
    /// exports. Carriers built outside the engine (tests, fixtures)
    /// may populate it; the engine ignores it on import.
    pub mime: Option<String>,
}

/// Self-contained snapshot of an entry suitable for inserting into a
/// different (or the same) database via
/// [`Engine::import_entry`](crate::Engine::import_entry).
///
/// Construct via [`Engine::export_entry`](crate::Engine::export_entry);
/// callers don't introspect the contents in normal use. Manual
/// construction is fine for tests / fixtures — every field is `pub`.
///
/// **Not** `Serialize` / `Deserialize`: the carrier is for in-process
/// hand-off only. The protected-field plaintext lives in
/// [`SecretString`]s that zero on drop, so dropping the carrier
/// reliably wipes secrets even if the import path errors out
/// mid-write.
///
/// History is intentionally **not** carried — the import path mints a
/// brand new entry and the source's history snapshots describe edits
/// that happened in a different database. Mirrors the
/// `mint_new_uuid = true` branch of the legacy
/// `keepass_core::Kdbx::import_entry`, which preserves history but
/// rewrites every snapshot's UUID; for the cross-DB move flow callers
/// actually want, "fresh entry, no inherited history" is the simpler
/// (and more honest) shape.
#[derive(Debug)]
pub struct PortableEntry {
    /// Entry title.
    pub title: String,
    /// Username field.
    pub username: String,
    /// URL field (raw, as the user entered it).
    pub url: String,
    /// Notes field (plain text).
    pub notes: String,
    /// Icon reference. If [`IconRef::Custom`], the icon's PNG bytes
    /// **must** also be carried in [`Self::custom_icon_png`] so the
    /// target can rehome the icon. Carriers with a custom icon ref
    /// but `None` in `custom_icon_png` will surface as
    /// [`EngineError::NotFound`](crate::EngineError) on import.
    pub icon: IconRef,
    /// Tags in their original order; the target will trim and dedup
    /// them again on insert.
    pub tags: Vec<String>,
    /// Source's `created_at` in ms since the Unix epoch. Surfaced for
    /// future preservation paths; the current import path always
    /// stamps `now` instead (matching `create_entry` semantics).
    pub created_at: Option<i64>,
    /// Source's `modified_at` in ms. See `created_at` note.
    pub modified_at: Option<i64>,
    /// Source's `accessed_at` in ms. See `created_at` note.
    pub accessed_at: Option<i64>,
    /// Source's `last_used_at` in ms. See `created_at` note.
    pub last_used_at: Option<i64>,
    /// Source's `expires_at` in ms (`None` = no expiry). Preserved on
    /// import via a post-create `update_entry` patch.
    pub expires_at: Option<i64>,
    /// Canonical password slot, revealed in process. Held as a
    /// [`SecretString`] so it zeroes on drop if the carrier is
    /// abandoned without import.
    pub password: SecretString,
    /// All other protected custom fields, revealed in process. The
    /// canonical `Password` slot is **not** included here — it's
    /// carried separately in [`Self::password`].
    pub protected_fields: Vec<(String, SecretString)>,
    /// Non-protected custom fields, name + plaintext value.
    pub custom_fields: Vec<(String, String)>,
    /// Every attachment on the source entry, with bytes inlined so
    /// the target can rehash + dedup against its own
    /// `attachment_blob` pool.
    pub attachments: Vec<PortableAttachment>,
    /// Raw PNG bytes of the source's custom icon, if the entry's
    /// `icon` is [`IconRef::Custom`]. The target rehomes these via
    /// [`Engine::add_custom_icon`](crate::Engine::add_custom_icon)
    /// (content-hash dedup) so the resulting entry's `icon_custom_uuid`
    /// points at the *target's* pool, never a dangling source UUID.
    pub custom_icon_png: Option<Vec<u8>>,
}

/// Build a [`PortableEntry`] for the entry identified by `entry_uuid`.
///
/// Read-only on the source: reveals every protected field through the
/// supplied [`FieldProtector`] (one session-key fetch per protected
/// slot, matching the [`crate::reveal`] discipline), loads attachment
/// bytes from `attachment_blob`, and — when the entry has a custom
/// icon — copies the PNG out of `meta_custom_icon` so the target can
/// rehome it.
///
/// History is **not** included in the carrier; see the [`PortableEntry`]
/// docs for the rationale.
pub(crate) fn export_entry(
    conn: &Connection,
    protector: &dyn FieldProtector,
    entry_uuid: Uuid,
) -> Result<PortableEntry, EngineError> {
    let entry =
        crate::reads::entry(conn, entry_uuid)?.ok_or(EngineError::NotFound { entity: "entry" })?;

    // Reveal the canonical password first. Empty passwords reveal
    // cleanly as `SecretString::from("")` thanks to the unconditional
    // `entry_protected` Password row written by `create_entry`.
    let password = reveal::reveal_password(conn, protector, entry_uuid)?;

    // Reveal every other protected slot. `EntryFull::custom_fields`
    // already excludes the canonical Password row, so we don't risk
    // double-carrying it.
    let mut protected_fields: Vec<(String, SecretString)> = Vec::new();
    let mut custom_fields: Vec<(String, String)> = Vec::new();
    for cf in &entry.custom_fields {
        if cf.is_protected {
            let value = reveal::reveal_custom_field(conn, protector, entry_uuid, &cf.name)?;
            protected_fields.push((cf.name.clone(), value));
        } else {
            // Non-protected values live in `entry_custom_field` as
            // plaintext; pull them directly rather than round-tripping
            // through a reveal that would just `clone` the row.
            let value: String = conn.query_row(
                "SELECT value FROM entry_custom_field \
                 WHERE entry_uuid = ?1 AND field_name = ?2",
                params![entry_uuid.to_string(), cf.name],
                |r| r.get(0),
            )?;
            custom_fields.push((cf.name.clone(), value));
        }
    }

    // Pull each attachment's bytes. `EntryFull::attachments` lists
    // names + sizes; the bytes themselves come from the content-addressed
    // pool join.
    let mut attachments: Vec<PortableAttachment> = Vec::with_capacity(entry.attachments.len());
    for att in &entry.attachments {
        let bytes = crate::reads::attachment_bytes(conn, entry_uuid, &att.name)?;
        attachments.push(PortableAttachment {
            name: att.name.clone(),
            bytes,
            mime: None,
        });
    }

    // If the entry references a custom icon, copy the PNG so the
    // target can rehome it. A dangling reference (icon UUID not in
    // the pool) downgrades to a built-in icon 0 on the carrier — the
    // target would have nothing to rehome anyway, and creating an
    // import that immediately errors out doesn't serve any caller.
    let (icon, custom_icon_png) = match entry.icon {
        IconRef::Custom(icon_uuid) => match crate::meta::read_custom_icon_bytes(conn, icon_uuid)? {
            Some(bytes) => (IconRef::Custom(icon_uuid), Some(bytes)),
            None => (IconRef::Builtin(0), None),
        },
        IconRef::Builtin(idx) => (IconRef::Builtin(idx), None),
    };

    Ok(PortableEntry {
        title: entry.title,
        username: entry.username,
        url: entry.url,
        notes: entry.notes,
        icon,
        tags: entry.tags,
        created_at: Some(entry.created_at),
        modified_at: Some(entry.modified_at),
        accessed_at: Some(entry.accessed_at),
        last_used_at: entry.last_used_at,
        expires_at: entry.expires_at,
        password,
        protected_fields,
        custom_fields,
        attachments,
        custom_icon_png,
    })
}

/// Insert a [`PortableEntry`] under `target_group_uuid` as a brand new
/// entry. Returns the freshly-minted entry's UUID.
///
/// Reuses [`crate::mutations::create_entry`] for the row write +
/// protected-field seal under the target's [`FieldProtector`] (so the
/// session-key boundary stays clean across the move), then writes each
/// attachment through the existing [`crate::mutations::attach_file`]
/// content-addressed-dedup path.
///
/// **Icon rehoming.** If the carrier has `custom_icon_png` bytes, they
/// land in the target's `meta_custom_icon` pool via
/// [`crate::meta::add_custom_icon_dedup`] — content-hash dedup, so if
/// the same PNG already exists in the target the existing UUID wins
/// and no row is added. The resulting (possibly-pre-existing) UUID is
/// what the new entry's `icon_custom_uuid` column points at; the
/// source's icon UUID is irrelevant.
///
/// **Timestamps.** The current implementation stamps `now` for
/// `created_at`/`modified_at`/`accessed_at` via `create_entry`'s
/// existing semantics — the carrier's source-side timestamps are
/// retained on the struct for future preservation paths but not used.
/// `expires_at` *is* preserved via a post-create `update_entry` patch.
pub(crate) fn import_entry(
    conn: &mut Connection,
    fingerprint_key: &[u8; 32],
    protector: &dyn FieldProtector,
    target_group_uuid: Uuid,
    portable: PortableEntry,
    now: i64,
    entry_uuid: Uuid,
) -> Result<(Uuid, bool), EngineError> {
    // Custom-icon rehoming runs *before* the create-entry transaction
    // so the resulting UUID is available to thread through
    // `NewEntryFields.icon`. `add_custom_icon_dedup` is single-statement
    // and runs against `conn` directly (no caller transaction); a
    // crash between this and create_entry leaves an orphan icon row in
    // the pool, which is harmless — it'll be GC'd by the next save-path
    // sweep.
    let (icon, icon_inserted) = match (&portable.icon, &portable.custom_icon_png) {
        (IconRef::Custom(_), Some(png_bytes)) => {
            let (uuid, inserted) = crate::meta::add_custom_icon_dedup(conn, png_bytes)?;
            (IconRef::Custom(uuid), inserted)
        }
        (IconRef::Custom(_), None) => {
            // Carrier promised a custom icon but didn't supply the
            // bytes. Refuse rather than silently downgrading to a
            // built-in — that would corrupt the user's intent.
            return Err(EngineError::NotFound {
                entity: "custom_icon",
            });
        }
        (IconRef::Builtin(idx), _) => (IconRef::Builtin(*idx), false),
    };

    // Translate the carrier's protected + non-protected fields into
    // the `NewEntryFields.custom_fields` shape `create_entry` expects.
    let mut custom_fields: Vec<NewCustomField> =
        Vec::with_capacity(portable.protected_fields.len() + portable.custom_fields.len());
    for (name, value) in portable.protected_fields {
        custom_fields.push(NewCustomField {
            name,
            value,
            protected: true,
        });
    }
    for (name, value) in portable.custom_fields {
        custom_fields.push(NewCustomField {
            name,
            value: SecretString::from(value),
            protected: false,
        });
    }

    let fields = NewEntryFields {
        title: portable.title,
        username: portable.username,
        url: portable.url,
        notes: portable.notes,
        password: portable.password,
        icon,
        custom_fields,
        tags: portable.tags,
    };

    let new_uuid = mutations::create_entry(
        conn,
        fingerprint_key,
        protector,
        target_group_uuid,
        fields,
        now,
        entry_uuid,
    )?;

    // Preserve `expires_at` if the carrier had one. `create_entry`
    // never writes an expiry; do it as a separate `update_entry`
    // round-trip so the column lands without bloating the create path.
    if let Some(expiry) = portable.expires_at {
        let patch = crate::model::EntryUpdate {
            expires_at: Some(Some(expiry)),
            ..Default::default()
        };
        mutations::update_entry(conn, fingerprint_key, protector, new_uuid, patch, now)?;
    }

    // Replay attachments through the regular `attach_file` path so the
    // content-addressed pool dedup runs (bytes shared with other entries
    // in the target won't be re-inserted).
    for att in portable.attachments {
        mutations::attach_file(conn, protector, new_uuid, &att.name, att.bytes, now)?;
    }

    Ok((new_uuid, icon_inserted))
}
