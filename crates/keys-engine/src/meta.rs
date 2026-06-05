//! Meta persistence — shared `Kdbx::vault().meta` ↔ `SQLite` helpers.
//!
//! Used by both [`crate::ingest`] (write Meta into `SQLite` on ingest)
//! and [`crate::projection`] (read Meta back when projecting a `Vault`
//! from `SQLite`). The shape of the persisted Meta is documented in
//! migration 0003 and `docs/schema.md`.
//!
//! Encoding conventions:
//!
//! * Scalar TEXT fields go in `setting.value` as raw utf-8 bytes (the
//!   column is `BLOB`, but values are still well-formed utf-8 strings).
//! * Scalar integer fields go in `setting.value` as little-endian fixed
//!   widths — `i64`/`u32`/`i32` follow Rust's native sizes so a corrupted
//!   row of the wrong length surfaces as a parse error rather than a
//!   silent reinterpretation.
//! * Timestamps are stored as little-endian `i64` milliseconds since the
//!   Unix epoch in UTC. `None` is represented by the absence of the
//!   `setting` row.
//! * `memory_protection` packs the five booleans into a single byte
//!   bitfield (bit 0 = `protect_title`, bit 1 = `protect_username`,
//!   bit 2 = `protect_password`, bit 3 = `protect_url`,
//!   bit 4 = `protect_notes`).
//! * `unknown_xml` is serialised as a JSON array of
//!   `{ "tag": "...", "raw_xml": "<base64>" }` records. JSON because the
//!   list is variable-length and human-readable when peeked at; base64
//!   because the `raw_xml` bytes may contain non-utf-8 if a future
//!   vendor extension embeds binary data.

use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use keepass_core::model::{
    CustomDataItem, CustomIcon, DeletedObject, MemoryProtection, Meta, UnknownElement,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EngineError, ProjectionError};

// ─────────────────────── setting keys ───────────────────────

pub(crate) const KEY_GENERATOR: &str = "meta.generator";
pub(crate) const KEY_DATABASE_NAME: &str = "meta.database_name";
pub(crate) const KEY_DATABASE_DESCRIPTION: &str = "meta.database_description";
pub(crate) const KEY_DATABASE_NAME_CHANGED: &str = "meta.database_name_changed";
pub(crate) const KEY_DATABASE_DESCRIPTION_CHANGED: &str = "meta.database_description_changed";
pub(crate) const KEY_DEFAULT_USERNAME: &str = "meta.default_username";
pub(crate) const KEY_DEFAULT_USERNAME_CHANGED: &str = "meta.default_username_changed";
pub(crate) const KEY_RECYCLE_BIN_CHANGED: &str = "meta.recycle_bin_changed";
pub(crate) const KEY_SETTINGS_CHANGED: &str = "meta.settings_changed";
pub(crate) const KEY_MASTER_KEY_CHANGED: &str = "meta.master_key_changed";
pub(crate) const KEY_MASTER_KEY_CHANGE_REC: &str = "meta.master_key_change_rec";
pub(crate) const KEY_MASTER_KEY_CHANGE_FORCE: &str = "meta.master_key_change_force";
pub(crate) const KEY_RECYCLE_BIN_ENABLED: &str = "meta.recycle_bin_enabled";
/// Event-only setting key for the recycle-bin uuid. The actual uuid
/// lives on the `group` table's `is_recycle_bin = 1` row, not in
/// `setting` — this constant exists so `ChangeEvent::MetaUpdated` can
/// name the field observers subscribe to without inventing a string at
/// each callsite.
pub(crate) const KEY_RECYCLE_BIN_UUID: &str = "meta.recycle_bin_uuid";
pub(crate) const KEY_HISTORY_MAX_ITEMS: &str = "meta.history_max_items";
pub(crate) const KEY_HISTORY_MAX_SIZE: &str = "meta.history_max_size";
pub(crate) const KEY_MAINTENANCE_HISTORY_DAYS: &str = "meta.maintenance_history_days";
pub(crate) const KEY_COLOR: &str = "meta.color";
pub(crate) const KEY_HEADER_HASH: &str = "meta.header_hash";
pub(crate) const KEY_MEMORY_PROTECTION: &str = "meta.memory_protection";
pub(crate) const KEY_UNKNOWN_XML: &str = "meta.unknown_xml";

// KDBX outer-header facts. Not part of `Meta` (they live on the
// envelope, not the XML payload) but persisted as `meta.*` setting rows
// so the engine's `database_metadata` accessor can render the Info-tab
// cipher and KDF strings without holding a live `Kdbx` handle. Written
// at ingest time from the outer header; absent on engines created
// pre-Phase-6.17-I-3c, in which case `database_metadata` falls back to
// "Unknown" displays.
pub(crate) const KEY_KDBX_CIPHER_OID: &str = "meta.kdbx_cipher_oid";
pub(crate) const KEY_KDBX_KDF_PARAMETERS: &str = "meta.kdbx_kdf_parameters";
pub(crate) const KEY_KDBX_TRANSFORM_ROUNDS: &str = "meta.kdbx_transform_rounds";

// ─────────────────────── write path ───────────────────────

/// Persist every field of `meta` into the `setting` table and the
/// `meta_*` companion tables. Intended to be called inside an ingest
/// transaction.
///
/// The caller is responsible for clearing pre-existing Meta rows before
/// invoking this — see [`clear_meta_tables`].
pub(crate) fn write_meta(conn: &Connection, meta: &Meta) -> Result<(), rusqlite::Error> {
    // Strings — always set, even if empty, so a default-empty value
    // round-trips cleanly rather than disappearing.
    set_text(conn, KEY_GENERATOR, &meta.generator)?;
    set_text(conn, KEY_DATABASE_NAME, &meta.database_name)?;
    set_text(conn, KEY_DATABASE_DESCRIPTION, &meta.database_description)?;
    set_text(conn, KEY_DEFAULT_USERNAME, &meta.default_username)?;
    set_text(conn, KEY_COLOR, &meta.color)?;
    set_text(conn, KEY_HEADER_HASH, &meta.header_hash)?;

    // Timestamps — write the row only when `Some`, so projection can
    // distinguish "never set" from "set to epoch".
    set_optional_timestamp(conn, KEY_DATABASE_NAME_CHANGED, meta.database_name_changed)?;
    set_optional_timestamp(
        conn,
        KEY_DATABASE_DESCRIPTION_CHANGED,
        meta.database_description_changed,
    )?;
    set_optional_timestamp(
        conn,
        KEY_DEFAULT_USERNAME_CHANGED,
        meta.default_username_changed,
    )?;
    set_optional_timestamp(conn, KEY_RECYCLE_BIN_CHANGED, meta.recycle_bin_changed)?;
    set_optional_timestamp(conn, KEY_SETTINGS_CHANGED, meta.settings_changed)?;
    set_optional_timestamp(conn, KEY_MASTER_KEY_CHANGED, meta.master_key_changed)?;

    // Integer scalars.
    set_i64(conn, KEY_MASTER_KEY_CHANGE_REC, meta.master_key_change_rec)?;
    set_i64(
        conn,
        KEY_MASTER_KEY_CHANGE_FORCE,
        meta.master_key_change_force,
    )?;
    set_i32(conn, KEY_HISTORY_MAX_ITEMS, meta.history_max_items)?;
    set_i64(conn, KEY_HISTORY_MAX_SIZE, meta.history_max_size)?;
    set_u32(
        conn,
        KEY_MAINTENANCE_HISTORY_DAYS,
        meta.maintenance_history_days,
    )?;

    // Memory protection — packed 1-byte bitfield.
    set_blob(
        conn,
        KEY_MEMORY_PROTECTION,
        &[pack_memory_protection(meta.memory_protection)],
    )?;

    // Unknown XML — JSON array of (tag, base64(raw_xml)) tuples.
    let unknown_json = serialise_unknown_xml(&meta.unknown_xml)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    set_text(conn, KEY_UNKNOWN_XML, &unknown_json)?;

    // List-shaped tables.
    for icon in &meta.custom_icons {
        conn.execute(
            "INSERT INTO meta_custom_icon (uuid, name, bytes, last_modified_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                icon.uuid.to_string(),
                icon.name,
                icon.data,
                icon.last_modified.map(|d| d.timestamp_millis()),
            ],
        )?;
    }

    for item in &meta.custom_data {
        conn.execute(
            "INSERT INTO meta_custom_data (key, value, last_modified_at) VALUES (?1, ?2, ?3)",
            params![
                item.key,
                item.value,
                item.last_modified.map(|d| d.timestamp_millis()),
            ],
        )?;
    }

    Ok(())
}

/// Persist tombstones from `Vault::deleted_objects`. Separate from
/// [`write_meta`] because the field lives on `Vault`, not `Meta`.
pub(crate) fn write_deleted_objects(
    conn: &Connection,
    deleted_objects: &[DeletedObject],
) -> Result<(), rusqlite::Error> {
    for obj in deleted_objects {
        conn.execute(
            "INSERT INTO meta_deleted_object (uuid, deleted_at) VALUES (?1, ?2)",
            params![
                obj.uuid.to_string(),
                obj.deleted_at.map(|d| d.timestamp_millis()),
            ],
        )?;
    }
    Ok(())
}

/// Delete every Meta-owned row so re-ingest produces a clean slate.
/// Mirrors `clear_vault_tables` in `ingest.rs`.
pub(crate) fn clear_meta_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute("DELETE FROM meta_custom_icon", [])?;
    conn.execute("DELETE FROM meta_custom_data", [])?;
    conn.execute("DELETE FROM meta_deleted_object", [])?;
    // Setting rows: only delete meta.* keys, not fingerprint_key /
    // last_saved_kdbx_bytes / meta.recycle_bin_enabled (the last is
    // re-written by ingest, but using a wildcard keeps cleanup honest).
    conn.execute(
        "DELETE FROM setting WHERE key LIKE 'meta.%' AND key != 'meta.recycle_bin_enabled'",
        [],
    )?;
    Ok(())
}

// ─────────────────────── public meta accessors ───────────────────────
//
// Standalone get/set helpers for the small handful of meta scalars the
// frontend reads outside of a full vault projection (recycle-bin pair,
// history caps). These bypass `read_meta_into` / `write_meta` so the
// caller doesn't have to round-trip a whole `Meta` to touch a single
// field.

/// Read `meta.recycle_bin_uuid` from the `group` table — i.e. the uuid
/// of the group flagged `is_recycle_bin = 1`, or `None` if no bin
/// exists.
///
/// The recycle-bin uuid isn't stored in `setting` (the bin group is
/// identified by its `is_recycle_bin` column, not a meta scalar); this
/// helper hides that detail behind a meta-shaped accessor.
pub(crate) fn read_recycle_bin_uuid(conn: &Connection) -> Result<Option<String>, EngineError> {
    conn.query_row(
        "SELECT uuid FROM \"group\" WHERE is_recycle_bin = 1 LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(EngineError::Sqlite)
}

/// Read `meta.recycle_bin_enabled` from the explicit setting row.
///
/// Falls back to "does a bin group exist?" if the row is missing —
/// matching the projection-side semantics in
/// [`crate::projection`].
pub(crate) fn read_recycle_bin_enabled(conn: &Connection) -> Result<bool, EngineError> {
    let result: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM setting WHERE key = 'meta.recycle_bin_enabled'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    );
    match result {
        Ok(bytes) if bytes.len() == 1 => Ok(bytes[0] != 0),
        Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Fall back to derived: does a bin group exist?
            Ok(read_recycle_bin_uuid(conn)?.is_some())
        }
        Err(err) => Err(EngineError::Sqlite(err)),
    }
}

/// Write `meta.recycle_bin_enabled` as a 1-byte blob. Matches the
/// shape ingest writes (see `ingest.rs`), so the projection / read-back
/// paths don't need a parallel decode branch. Caller is responsible
/// for emitting the change event after the surrounding transaction
/// commits.
pub(crate) fn write_recycle_bin_enabled(
    conn: &Connection,
    enabled: bool,
) -> Result<(), rusqlite::Error> {
    let blob: [u8; 1] = [u8::from(enabled)];
    set_blob(conn, KEY_RECYCLE_BIN_ENABLED, &blob)
}

/// Designate the group with `uuid` as the vault's recycle bin. Sets
/// `group.is_recycle_bin = 1` for that row and clears the flag on any
/// previously-designated bin group — KDBX permits exactly one bin per
/// vault, and the schema documents that invariant.
///
/// Caller must have verified the target group exists before calling.
pub(crate) fn write_recycle_bin_group(
    conn: &Connection,
    uuid: &str,
) -> Result<(), rusqlite::Error> {
    // Clear any existing bin flag first — exclusivity invariant.
    conn.execute(
        "UPDATE \"group\" SET is_recycle_bin = 0 WHERE is_recycle_bin = 1 AND uuid != ?1",
        params![uuid],
    )?;
    conn.execute(
        "UPDATE \"group\" SET is_recycle_bin = 1 WHERE uuid = ?1",
        params![uuid],
    )?;
    Ok(())
}

/// Clear the bin designation from whichever group currently holds it.
/// No-op if no group is flagged. Used by `Engine::set_recycle_bin` when
/// the caller passes `group_uuid = None` alongside `enabled = true`
/// (enabled but no bin chosen yet — `recycle_entry` will lazily create
/// one).
pub(crate) fn clear_recycle_bin_group(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE \"group\" SET is_recycle_bin = 0 WHERE is_recycle_bin = 1",
        [],
    )?;
    Ok(())
}

/// Read `meta.history_max_items`. Returns the keepass-core default
/// (`10`) when the row is absent — matches `Meta::default()`.
pub(crate) fn read_history_max_items(conn: &Connection) -> Result<i32, EngineError> {
    Ok(get_i32(conn, KEY_HISTORY_MAX_ITEMS)?.unwrap_or_else(|| Meta::default().history_max_items))
}

/// Read `meta.history_max_size`. Returns the keepass-core default
/// (`6 * 1024 * 1024`) when the row is absent — matches `Meta::default()`.
pub(crate) fn read_history_max_size(conn: &Connection) -> Result<i64, EngineError> {
    Ok(get_i64(conn, KEY_HISTORY_MAX_SIZE)?.unwrap_or_else(|| Meta::default().history_max_size))
}

/// Write `meta.history_max_items`. Caller is responsible for emitting
/// the change event after the surrounding transaction commits.
pub(crate) fn write_history_max_items(
    conn: &Connection,
    value: i32,
) -> Result<(), rusqlite::Error> {
    set_i32(conn, KEY_HISTORY_MAX_ITEMS, value)
}

/// Write `meta.history_max_size`. Caller is responsible for emitting
/// the change event after the surrounding transaction commits.
pub(crate) fn write_history_max_size(conn: &Connection, value: i64) -> Result<(), rusqlite::Error> {
    set_i64(conn, KEY_HISTORY_MAX_SIZE, value)
}

// ─────────────────────── kdbx outer-header accessors ───────────────────────
//
// Cipher + KDF live on the encrypted envelope, not in the XML payload
// that becomes `Meta`. Persist the three relevant outer-header fields
// at ingest time so the engine can render the Info-tab strings without
// re-parsing the file. Display formatting lives below in
// [`format_cipher_display`] / [`format_kdf_display`].

/// Read-only facts about the encrypted database envelope and binary
/// pool that back the "database properties" Info-tab in the frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseMetadata {
    /// Generator string written into the KDBX `Meta` block by whoever
    /// last saved the file — e.g. `"Keys"`, `"KeePassXC"`. Empty if
    /// never set.
    pub generator: String,
    /// Display label for the outer cipher — `"AES-256-CBC"`,
    /// `"ChaCha20"`, `"Twofish-CBC"`, or `"Unknown"` for a cipher UUID
    /// this build doesn't recognise / hasn't been persisted yet.
    pub cipher_display: String,
    /// Single-line display string for the KDF parameters — e.g.
    /// `"Argon2id (64 MB · 2 iter · 4 threads)"`,
    /// `"AES-KDF (6,000,000 rounds)"`, or `"Unknown KDF"` for a
    /// blob we couldn't decode / a vault ingested before this surface
    /// existed.
    pub kdf_display: String,
    /// Distinct attachment blobs in the content-addressed pool.
    pub attachment_total_count: u32,
    /// Sum of `attachment_blob.size` across the pool, in bytes.
    pub attachment_total_bytes: u64,
}

/// Persist the three outer-header facts needed for cipher / KDF
/// display. Caller is responsible for clearing stale rows first
/// (`clear_meta_tables` does this via the `meta.%` wildcard).
pub(crate) fn write_kdbx_outer_header_facts(
    conn: &Connection,
    cipher_id_bytes: [u8; 16],
    kdf_parameters: Option<&[u8]>,
    transform_rounds: Option<u64>,
) -> Result<(), rusqlite::Error> {
    set_blob(conn, KEY_KDBX_CIPHER_OID, &cipher_id_bytes)?;
    if let Some(blob) = kdf_parameters {
        set_blob(conn, KEY_KDBX_KDF_PARAMETERS, blob)?;
    } else {
        conn.execute(
            "DELETE FROM setting WHERE key = ?1",
            params![KEY_KDBX_KDF_PARAMETERS],
        )?;
    }
    if let Some(rounds) = transform_rounds {
        // Store as i64 little-endian. `transform_rounds` is u64 in
        // keepass-core; reinterpret bits — round counts that actually
        // fit a u64 but not an i64 are far beyond anything practical
        // and would just round-trip the bit pattern unchanged.
        #[allow(clippy::cast_possible_wrap)]
        set_i64(conn, KEY_KDBX_TRANSFORM_ROUNDS, rounds as i64)?;
    } else {
        conn.execute(
            "DELETE FROM setting WHERE key = ?1",
            params![KEY_KDBX_TRANSFORM_ROUNDS],
        )?;
    }
    Ok(())
}

/// Read `Engine::database_metadata`'s read-only payload.
///
/// Generator: from `meta.generator` (already persisted by `write_meta`).
/// Cipher / KDF: from the outer-header facts written at ingest. Absent
/// rows surface as `"Unknown"` displays — see the field docs on
/// [`DatabaseMetadata`].
/// Attachment count + bytes: SQL over `attachment_blob`.
pub(crate) fn read_database_metadata(conn: &Connection) -> Result<DatabaseMetadata, EngineError> {
    let generator = get_text(conn, KEY_GENERATOR)?.unwrap_or_default();
    let cipher_display = read_cipher_display(conn)?;
    let kdf_display = read_kdf_display(conn)?;
    let (attachment_total_count, attachment_total_bytes) = read_attachment_pool_stats(conn)?;
    Ok(DatabaseMetadata {
        generator,
        cipher_display,
        kdf_display,
        attachment_total_count,
        attachment_total_bytes,
    })
}

fn read_cipher_display(conn: &Connection) -> Result<String, EngineError> {
    use keepass_core::format::{CipherId, KnownCipher};
    let Some(bytes) = get_blob(conn, KEY_KDBX_CIPHER_OID)? else {
        return Ok("Unknown".to_owned());
    };
    let array: [u8; 16] = match bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Ok("Unknown".to_owned()),
    };
    let cipher = CipherId(Uuid::from_bytes(array));
    let label = match cipher.well_known() {
        Some(KnownCipher::Aes256Cbc) => "AES-256-CBC",
        Some(KnownCipher::ChaCha20) => "ChaCha20",
        Some(KnownCipher::TwofishCbc) => "Twofish-CBC",
        _ => "Unknown",
    };
    Ok(label.to_owned())
}

fn read_kdf_display(conn: &Connection) -> Result<String, EngineError> {
    use keepass_core::format::KdfParams;
    use keepass_core::format::var_dictionary::VarDictionary;

    // KDBX4: VarDictionary in `meta.kdbx_kdf_parameters`.
    if let Some(blob) = get_blob(conn, KEY_KDBX_KDF_PARAMETERS)? {
        if let Ok(dict) = VarDictionary::parse(&blob)
            && let Ok(params) = KdfParams::from_var_dictionary(&dict)
        {
            return Ok(format_kdf_params(&params));
        }
    }
    // KDBX3: rounds + seed in their own outer-header fields.
    if let Some(rounds_i64) = get_i64(conn, KEY_KDBX_TRANSFORM_ROUNDS)? {
        // We stored u64 as i64 bits; reinterpret the same way.
        #[allow(clippy::cast_sign_loss)]
        let rounds = rounds_i64 as u64;
        let formatted = format_with_thousands(rounds);
        return Ok(format!("AES-KDF ({formatted} rounds)"));
    }
    Ok("Unknown KDF".to_owned())
}

fn read_attachment_pool_stats(conn: &Connection) -> Result<(u32, u64), EngineError> {
    // `attachment_blob` is content-addressed; one row per distinct
    // payload. Mirrors `Vault::binaries.len()` / sum-of-bytes on the
    // legacy in-memory pool.
    conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM attachment_blob",
        [],
        |row| {
            let count: i64 = row.get(0)?;
            let total: i64 = row.get(1)?;
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let count_u32 = u32::try_from(count.max(0)).unwrap_or(u32::MAX);
            #[allow(clippy::cast_sign_loss)]
            let total_u64 = total.max(0) as u64;
            Ok((count_u32, total_u64))
        },
    )
    .map_err(EngineError::Sqlite)
}

/// Format a parsed [`keepass_core::format::KdfParams`] as a single-line
/// display string. Argon2 variants render as
/// `"<name> (<mib> MB · <iter> iter · <threads> threads)"`; AES-KDF as
/// `"AES-KDF (<rounds> rounds)"` with thousands separators. Mirrors the
/// legacy `Vault::kdf_display` formatter so the Info-tab string is
/// byte-identical to what the in-memory shim produced.
fn format_kdf_params(params: &keepass_core::format::KdfParams) -> String {
    use keepass_core::format::{Argon2Variant, KdfParams};
    match params {
        KdfParams::AesKdf { rounds, .. } => {
            let formatted = format_with_thousands(*rounds);
            format!("AES-KDF ({formatted} rounds)")
        }
        KdfParams::Argon2 {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            ..
        } => {
            let name = match variant {
                Argon2Variant::Argon2d => "Argon2d",
                Argon2Variant::Argon2id => "Argon2id",
                _ => "Argon2",
            };
            let mib = memory_bytes / (1024 * 1024);
            format!("{name} ({mib} MB \u{00B7} {iterations} iter \u{00B7} {parallelism} threads)")
        }
        _ => "Unknown KDF".to_owned(),
    }
}

/// Format an integer with comma thousands separators (e.g. 6000000 →
/// "6,000,000"). Used by the AES-KDF branch.
fn format_with_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch as char);
    }
    out
}

// ─────────────────────── custom-icon accessors ───────────────────────
//
// Pool-level reads/writes that bypass the full `Meta` round-trip so the
// frontend can add / fetch icon blobs without re-projecting every meta
// field. Dedup-by-content-hash mirrors `keepass-core::Kdbx::add_custom_icon`
// so the in-memory and SQLite paths produce the same UUIDs for the same
// bytes (load-bearing for the Keys-Mac shim during the migration window).

/// Setting key used in [`crate::events::ChangeEvent::MetaUpdated`] when
/// the custom-icon pool changes. Not a real `setting` row — the pool
/// lives in `meta_custom_icon`, this string is just the namespaced
/// identifier observers subscribe to.
pub(crate) const KEY_CUSTOM_ICONS: &str = "meta.custom_icons";

/// Insert a custom-icon blob into `meta_custom_icon`, deduplicating by
/// SHA-256 of the bytes. Returns the existing icon's UUID on a dedup
/// hit (and `inserted = false`), or a freshly generated v4 UUID on a
/// new insert (and `inserted = true`).
///
/// Mirrors `keepass-core::kdbx::add_or_dedup_icon`: same hash, same
/// preserve-existing-metadata semantics (`name` / `last_modified_at`
/// on a dedup hit are NOT overwritten). Callers that want event
/// emission should fire it themselves after the surrounding
/// transaction commits, conditional on `inserted` if desired.
pub(crate) fn add_custom_icon_dedup(
    conn: &Connection,
    bytes: &[u8],
) -> Result<(Uuid, bool), EngineError> {
    use sha2::{Digest, Sha256};
    let incoming: [u8; 32] = Sha256::digest(bytes).into();

    // Hash every existing icon and check for a match. Pool sizes are
    // small (typically <50 icons in the wild) so an in-Rust scan beats
    // adding a hash column and an index.
    let mut stmt = conn.prepare("SELECT uuid, bytes FROM meta_custom_icon")?;
    let rows = stmt
        .query_map([], |row| {
            let uuid_str: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((uuid_str, blob))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (uuid_str, blob) in rows {
        let hash: [u8; 32] = Sha256::digest(&blob).into();
        if hash == incoming {
            let existing = Uuid::parse_str(&uuid_str).map_err(|e| {
                EngineError::Projection(ProjectionError::SchemaInvariant(format!(
                    "meta_custom_icon.uuid not a UUID: {e}"
                )))
            })?;
            return Ok((existing, false));
        }
    }

    // Content-addressed UUID, NOT random. Two devices that
    // independently fetch the same favicon must mint the *same*
    // `custom_icon_uuid`, or the sync merge sees the entry's icon as
    // divergent with no shared-history LCA, parks it as an
    // unresolvable conflict, and ping-pongs forever (each park grows
    // the file and re-triggers on the peer). The in-pool dedup above
    // only collapses duplicates *within* one device; deriving the
    // UUID from the icon bytes makes dedup converge *across* devices
    // too — for every sync backend (iroh, Syncthing, manual copy),
    // not just one.
    let uuid = content_addressed_icon_uuid(&incoming);
    let now_ms = Utc::now().timestamp_millis();
    conn.execute(
        "INSERT INTO meta_custom_icon (uuid, name, bytes, last_modified_at) \
         VALUES (?1, '', ?2, ?3)",
        params![uuid.to_string(), bytes, now_ms],
    )?;
    Ok((uuid, true))
}

/// Deterministic UUID derived from a custom icon's SHA-256 content
/// hash, so the same image yields the same UUID on every device.
/// Uses the first 16 hash bytes with RFC-4122 version (8, "custom")
/// and variant bits set so the result is a well-formed UUID. Collision
/// requires a SHA-256 prefix collision — negligible.
fn content_addressed_icon_uuid(sha256: &[u8; 32]) -> Uuid {
    let mut b = [0u8; 16];
    b.copy_from_slice(&sha256[..16]);
    b[6] = (b[6] & 0x0F) | 0x80; // version 8 (custom)
    b[8] = (b[8] & 0x3F) | 0x80; // RFC 4122 variant
    Uuid::from_bytes(b)
}

/// Look up the raw bytes for a custom icon by UUID. Returns `Ok(None)`
/// when no row matches — callers should treat that as "icon no longer
/// in pool", not an error (icons can be referenced after deletion in
/// stale snapshots).
pub(crate) fn read_custom_icon_bytes(
    conn: &Connection,
    uuid: Uuid,
) -> Result<Option<Vec<u8>>, EngineError> {
    conn.query_row(
        "SELECT bytes FROM meta_custom_icon WHERE uuid = ?1",
        params![uuid.to_string()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(EngineError::Sqlite)
}

// ─────────────────────── read path ───────────────────────

/// Read every persisted Meta field and merge onto `meta`. Fields that
/// have no row leave `meta`'s default in place — matching the absence
/// semantics of the on-disk XML.
pub(crate) fn read_meta_into(conn: &Connection, meta: &mut Meta) -> Result<(), EngineError> {
    if let Some(v) = get_text(conn, KEY_GENERATOR)? {
        meta.generator = v;
    }
    if let Some(v) = get_text(conn, KEY_DATABASE_NAME)? {
        meta.database_name = v;
    }
    if let Some(v) = get_text(conn, KEY_DATABASE_DESCRIPTION)? {
        meta.database_description = v;
    }
    if let Some(v) = get_text(conn, KEY_DEFAULT_USERNAME)? {
        meta.default_username = v;
    }
    if let Some(v) = get_text(conn, KEY_COLOR)? {
        meta.color = v;
    }
    if let Some(v) = get_text(conn, KEY_HEADER_HASH)? {
        meta.header_hash = v;
    }

    meta.database_name_changed = get_optional_timestamp(conn, KEY_DATABASE_NAME_CHANGED)?;
    meta.database_description_changed =
        get_optional_timestamp(conn, KEY_DATABASE_DESCRIPTION_CHANGED)?;
    meta.default_username_changed = get_optional_timestamp(conn, KEY_DEFAULT_USERNAME_CHANGED)?;
    meta.recycle_bin_changed = get_optional_timestamp(conn, KEY_RECYCLE_BIN_CHANGED)?;
    meta.settings_changed = get_optional_timestamp(conn, KEY_SETTINGS_CHANGED)?;
    meta.master_key_changed = get_optional_timestamp(conn, KEY_MASTER_KEY_CHANGED)?;

    if let Some(v) = get_i64(conn, KEY_MASTER_KEY_CHANGE_REC)? {
        meta.master_key_change_rec = v;
    }
    if let Some(v) = get_i64(conn, KEY_MASTER_KEY_CHANGE_FORCE)? {
        meta.master_key_change_force = v;
    }
    if let Some(v) = get_i32(conn, KEY_HISTORY_MAX_ITEMS)? {
        meta.history_max_items = v;
    }
    if let Some(v) = get_i64(conn, KEY_HISTORY_MAX_SIZE)? {
        meta.history_max_size = v;
    }
    if let Some(v) = get_u32(conn, KEY_MAINTENANCE_HISTORY_DAYS)? {
        meta.maintenance_history_days = v;
    }

    if let Some(v) = get_blob(conn, KEY_MEMORY_PROTECTION)? {
        if v.len() == 1 {
            meta.memory_protection = unpack_memory_protection(v[0]);
        }
        // Other shapes left as default — corrupt row, not worth poisoning
        // the projection over.
    }

    if let Some(json) = get_text(conn, KEY_UNKNOWN_XML)? {
        meta.unknown_xml = deserialise_unknown_xml(&json).map_err(|e| {
            EngineError::Projection(ProjectionError::SchemaInvariant(format!(
                "meta.unknown_xml: {e}"
            )))
        })?;
    }

    meta.custom_icons = read_custom_icons(conn)?;
    meta.custom_data = read_custom_data(conn)?;
    Ok(())
}

/// Read tombstones for `Vault::deleted_objects`. Separate from
/// [`read_meta_into`] because the field lives on `Vault`.
pub(crate) fn read_deleted_objects(conn: &Connection) -> Result<Vec<DeletedObject>, EngineError> {
    let mut stmt =
        conn.prepare("SELECT uuid, deleted_at FROM meta_deleted_object ORDER BY uuid")?;
    let rows = stmt
        .query_map([], |row| {
            let uuid_str: String = row.get(0)?;
            let deleted_at: Option<i64> = row.get(1)?;
            Ok((uuid_str, deleted_at))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (uuid_str, deleted_at_ms) in rows {
        let uuid = Uuid::parse_str(&uuid_str).map_err(|e| {
            EngineError::Projection(ProjectionError::SchemaInvariant(format!(
                "meta_deleted_object.uuid not a UUID: {e}"
            )))
        })?;
        out.push(DeletedObject::new(uuid, deleted_at_ms.and_then(ms_to_dt)));
    }
    Ok(out)
}

fn read_custom_icons(conn: &Connection) -> Result<Vec<CustomIcon>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT uuid, name, bytes, last_modified_at FROM meta_custom_icon ORDER BY uuid",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let uuid_str: String = row.get(0)?;
            let name: String = row.get(1)?;
            let bytes: Vec<u8> = row.get(2)?;
            let last_modified: Option<i64> = row.get(3)?;
            Ok((uuid_str, name, bytes, last_modified))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (uuid_str, name, bytes, last_modified_ms) in rows {
        let uuid = Uuid::parse_str(&uuid_str).map_err(|e| {
            EngineError::Projection(ProjectionError::SchemaInvariant(format!(
                "meta_custom_icon.uuid not a UUID: {e}"
            )))
        })?;
        out.push(CustomIcon::new(
            uuid,
            bytes,
            name,
            last_modified_ms.and_then(ms_to_dt),
        ));
    }
    Ok(out)
}

fn read_custom_data(conn: &Connection) -> Result<Vec<CustomDataItem>, EngineError> {
    let mut stmt =
        conn.prepare("SELECT key, value, last_modified_at FROM meta_custom_data ORDER BY key")?;
    let rows = stmt
        .query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            let last_modified: Option<i64> = row.get(2)?;
            Ok(CustomDataItem::new(
                key,
                value,
                last_modified.and_then(ms_to_dt),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ─────────────────────── helpers ───────────────────────

fn set_text(conn: &Connection, key: &str, value: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR REPLACE INTO setting(key, value) VALUES (?1, ?2)",
        params![key, value.as_bytes()],
    )?;
    Ok(())
}

fn set_blob(conn: &Connection, key: &str, value: &[u8]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR REPLACE INTO setting(key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn set_i64(conn: &Connection, key: &str, value: i64) -> Result<(), rusqlite::Error> {
    set_blob(conn, key, &value.to_le_bytes())
}

fn set_i32(conn: &Connection, key: &str, value: i32) -> Result<(), rusqlite::Error> {
    set_blob(conn, key, &value.to_le_bytes())
}

fn set_u32(conn: &Connection, key: &str, value: u32) -> Result<(), rusqlite::Error> {
    set_blob(conn, key, &value.to_le_bytes())
}

fn set_optional_timestamp(
    conn: &Connection,
    key: &str,
    value: Option<DateTime<Utc>>,
) -> Result<(), rusqlite::Error> {
    if let Some(dt) = value {
        set_i64(conn, key, dt.timestamp_millis())
    } else {
        // Explicitly delete a stale row if one existed — `Meta` was
        // cleared at the start of ingest, but be defensive.
        conn.execute("DELETE FROM setting WHERE key = ?1", params![key])?;
        Ok(())
    }
}

fn get_blob(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, EngineError> {
    conn.query_row("SELECT value FROM setting WHERE key = ?1", [key], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .optional()
    .map_err(EngineError::Sqlite)
}

fn get_text(conn: &Connection, key: &str) -> Result<Option<String>, EngineError> {
    let Some(bytes) = get_blob(conn, key)? else {
        return Ok(None);
    };
    let s = String::from_utf8(bytes).map_err(|e| {
        EngineError::Projection(ProjectionError::SchemaInvariant(format!(
            "{key}: non-utf8 setting value: {e}"
        )))
    })?;
    Ok(Some(s))
}

fn get_i64(conn: &Connection, key: &str) -> Result<Option<i64>, EngineError> {
    let Some(bytes) = get_blob(conn, key)? else {
        return Ok(None);
    };
    let array: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
        EngineError::Projection(ProjectionError::SchemaInvariant(format!(
            "{key}: expected 8-byte i64, got {} bytes",
            bytes.len()
        )))
    })?;
    Ok(Some(i64::from_le_bytes(array)))
}

fn get_i32(conn: &Connection, key: &str) -> Result<Option<i32>, EngineError> {
    let Some(bytes) = get_blob(conn, key)? else {
        return Ok(None);
    };
    let array: [u8; 4] = bytes.as_slice().try_into().map_err(|_| {
        EngineError::Projection(ProjectionError::SchemaInvariant(format!(
            "{key}: expected 4-byte i32, got {} bytes",
            bytes.len()
        )))
    })?;
    Ok(Some(i32::from_le_bytes(array)))
}

fn get_u32(conn: &Connection, key: &str) -> Result<Option<u32>, EngineError> {
    let Some(bytes) = get_blob(conn, key)? else {
        return Ok(None);
    };
    let array: [u8; 4] = bytes.as_slice().try_into().map_err(|_| {
        EngineError::Projection(ProjectionError::SchemaInvariant(format!(
            "{key}: expected 4-byte u32, got {} bytes",
            bytes.len()
        )))
    })?;
    Ok(Some(u32::from_le_bytes(array)))
}

fn get_optional_timestamp(
    conn: &Connection,
    key: &str,
) -> Result<Option<DateTime<Utc>>, EngineError> {
    Ok(get_i64(conn, key)?.and_then(ms_to_dt))
}

fn ms_to_dt(ms: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms).single()
}

const MP_TITLE: u8 = 0b0000_0001;
const MP_USERNAME: u8 = 0b0000_0010;
const MP_PASSWORD: u8 = 0b0000_0100;
const MP_URL: u8 = 0b0000_1000;
const MP_NOTES: u8 = 0b0001_0000;

fn pack_memory_protection(mp: MemoryProtection) -> u8 {
    let mut b = 0u8;
    if mp.protect_title {
        b |= MP_TITLE;
    }
    if mp.protect_username {
        b |= MP_USERNAME;
    }
    if mp.protect_password {
        b |= MP_PASSWORD;
    }
    if mp.protect_url {
        b |= MP_URL;
    }
    if mp.protect_notes {
        b |= MP_NOTES;
    }
    b
}

fn unpack_memory_protection(b: u8) -> MemoryProtection {
    // `MemoryProtection` is `#[non_exhaustive]`, so we can't construct
    // it with struct-literal syntax from this crate. `Default` is
    // implemented in keepass-core; we start from that and mutate the
    // five public booleans in place.
    let mut mp = MemoryProtection::default();
    mp.protect_title = (b & MP_TITLE) != 0;
    mp.protect_username = (b & MP_USERNAME) != 0;
    mp.protect_password = (b & MP_PASSWORD) != 0;
    mp.protect_url = (b & MP_URL) != 0;
    mp.protect_notes = (b & MP_NOTES) != 0;
    mp
}

#[derive(Serialize, Deserialize)]
struct UnknownXmlRecord {
    tag: String,
    /// Base64 of the captured `raw_xml` bytes — see [`UnknownElement`].
    raw_xml: String,
}

fn serialise_unknown_xml(elements: &[UnknownElement]) -> Result<String, serde_json::Error> {
    let records: Vec<UnknownXmlRecord> = elements
        .iter()
        .map(|e| UnknownXmlRecord {
            tag: e.tag.clone(),
            raw_xml: base64::engine::general_purpose::STANDARD.encode(&e.raw_xml),
        })
        .collect();
    serde_json::to_string(&records)
}

fn deserialise_unknown_xml(json: &str) -> Result<Vec<UnknownElement>, String> {
    let records: Vec<UnknownXmlRecord> =
        serde_json::from_str(json).map_err(|e| format!("decode json: {e}"))?;
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        let raw_xml = base64::engine::general_purpose::STANDARD
            .decode(r.raw_xml.as_bytes())
            .map_err(|e| format!("decode raw_xml base64: {e}"))?;
        out.push(UnknownElement::new(r.tag, raw_xml));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressed_icon_uuid_is_deterministic_and_well_formed() {
        use sha2::{Digest, Sha256};
        let h1: [u8; 32] = Sha256::digest(b"icon-bytes-A").into();
        let h2: [u8; 32] = Sha256::digest(b"icon-bytes-B").into();
        // Same content hash → same UUID (cross-device convergence).
        assert_eq!(
            content_addressed_icon_uuid(&h1),
            content_addressed_icon_uuid(&h1)
        );
        // Different content → different UUID.
        assert_ne!(
            content_addressed_icon_uuid(&h1),
            content_addressed_icon_uuid(&h2)
        );
        // Well-formed: RFC-4122 variant + version 8 ("custom").
        let u = content_addressed_icon_uuid(&h1);
        assert_eq!(u.get_version_num(), 8);
        assert_eq!(u.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn memory_protection_round_trips() {
        // `MemoryProtection` is `#[non_exhaustive]`; mutate from
        // `Default::default()` rather than struct-literal.
        let mut mp = MemoryProtection::default();
        mp.protect_title = true;
        mp.protect_username = false;
        mp.protect_password = true;
        mp.protect_url = true;
        mp.protect_notes = false;
        let b = pack_memory_protection(mp);
        let back = unpack_memory_protection(b);
        assert_eq!(mp, back);
    }

    #[test]
    fn unknown_xml_round_trips_through_json() {
        let elements = vec![
            UnknownElement::new(
                "VendorThing".into(),
                b"<VendorThing>hello</VendorThing>".to_vec(),
            ),
            UnknownElement::new("Binary".into(), vec![0x00, 0xff, 0x10, 0x80]),
        ];
        let json = serialise_unknown_xml(&elements).expect("serialise");
        let back = deserialise_unknown_xml(&json).expect("deserialise");
        assert_eq!(elements.len(), back.len());
        for (a, b) in elements.iter().zip(back.iter()) {
            assert_eq!(a.tag, b.tag);
            assert_eq!(a.raw_xml, b.raw_xml);
        }
    }
}
