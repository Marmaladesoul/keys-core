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
pub(crate) const KEY_HISTORY_MAX_ITEMS: &str = "meta.history_max_items";
pub(crate) const KEY_HISTORY_MAX_SIZE: &str = "meta.history_max_size";
pub(crate) const KEY_MAINTENANCE_HISTORY_DAYS: &str = "meta.maintenance_history_days";
pub(crate) const KEY_COLOR: &str = "meta.color";
pub(crate) const KEY_HEADER_HASH: &str = "meta.header_hash";
pub(crate) const KEY_MEMORY_PROTECTION: &str = "meta.memory_protection";
pub(crate) const KEY_UNKNOWN_XML: &str = "meta.unknown_xml";

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
