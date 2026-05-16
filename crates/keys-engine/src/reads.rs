//! Read-side query implementations for the public [`Engine`] surface.
//!
//! Houses the SQL for the entry-listing methods (task 3.1) — keeps
//! [`crate::engine`] focused on lifecycle/wiring while the row-mapping
//! logic lives next to the schema it reads.
//!
//! ## Ordering
//!
//! `list_entries` orders by `entry.modified_at DESC` (most-recently
//! modified first). That mirrors how the Swift entry list pane orders
//! today and is the most useful default for the detail pane caller.
//! Smart folders and future sort-aware variants can override.
//!
//! ## Pagination
//!
//! [`Pagination::all()`] sets `limit = u64::MAX`. We map that onto
//! `SQLite`'s `LIMIT -1` sentinel ("no limit") so the planner doesn't
//! waste effort trying to honour `u64::MAX` as a literal. Any other
//! value clamps into the `i64` `SQLite` parameter type — values above
//! `i64::MAX` saturate to "no limit", which is consistent with the
//! `all()` semantics.
//!
//! ## Non-protected custom fields
//!
//! Per [`crate::ingest`] module doc, v1 ingest **drops** non-protected
//! custom fields (there's no `entry_custom_field` table yet). So when
//! we build [`EntryFull::custom_fields`], every entry returned is
//! `is_protected: true`. This will change once migration 0002 lands
//! the non-protected slot table.
//!
//! [`Engine`]: crate::Engine
//! [`Pagination::all()`]: crate::Pagination::all
//! [`EntryFull::custom_fields`]: crate::EntryFull::custom_fields

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::error::EngineError;
use crate::model::{
    AttachmentRef, CustomFieldRef, EntryFull, EntrySummary, GroupNode, IconRef, Pagination,
    StrengthBucket,
};

/// SQL fragment listing the columns `EntrySummary` needs, plus the
/// correlated attachment-count subquery. Kept as a constant so the
/// `group = None` and `group = Some(_)` variants stay in lock-step.
pub(crate) const SUMMARY_COLUMNS: &str = "\
    uuid, group_uuid, title, username, url, url_host, \
    modified_at, last_used_at, \
    password_strength_bucket, password_entropy, \
    icon_index, icon_custom_uuid, \
    (SELECT COUNT(*) FROM entry_attachment ea WHERE ea.entry_uuid = entry.uuid) \
        AS attachment_count";

pub(crate) fn list_entries(
    conn: &Connection,
    group: Option<Uuid>,
    page: Pagination,
) -> Result<Vec<EntrySummary>, EngineError> {
    let (limit, offset) = clamp_page(page);

    let rows = if let Some(group_uuid) = group {
        let sql = format!(
            "SELECT {SUMMARY_COLUMNS} FROM entry \
             WHERE group_uuid = ?1 \
             ORDER BY modified_at DESC, uuid ASC \
             LIMIT ?2 OFFSET ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(
            params![group_uuid.to_string(), limit, offset],
            row_to_summary,
        )?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        let sql = format!(
            "SELECT {SUMMARY_COLUMNS} FROM entry \
             ORDER BY modified_at DESC, uuid ASC \
             LIMIT ?1 OFFSET ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(params![limit, offset], row_to_summary)?
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok(rows)
}

pub(crate) fn entry(conn: &Connection, uuid: Uuid) -> Result<Option<EntryFull>, EngineError> {
    let uuid_str = uuid.to_string();

    let mut stmt = conn.prepare(
        "SELECT uuid, group_uuid, title, username, url, url_host, notes, \
                created_at, modified_at, accessed_at, last_used_at, expires_at, \
                is_recycled, password_strength_bucket, password_entropy, \
                icon_index, icon_custom_uuid \
         FROM entry WHERE uuid = ?1",
    )?;

    let row = stmt
        .query_row(params![uuid_str], |r| {
            Ok(EntryFullRow {
                uuid: parse_uuid_col(r, 0)?,
                group_uuid: parse_uuid_col(r, 1)?,
                title: r.get(2)?,
                username: r.get(3)?,
                url: r.get(4)?,
                url_host: r.get(5)?,
                notes: r.get(6)?,
                created_at: r.get(7)?,
                modified_at: r.get(8)?,
                accessed_at: r.get(9)?,
                last_used_at: r.get(10)?,
                expires_at: r.get(11)?,
                is_recycled: r.get::<_, i64>(12)? != 0,
                password_strength_bucket: r.get(13)?,
                password_entropy: r.get(14)?,
                icon_index: r.get(15)?,
                icon_custom_uuid: parse_optional_uuid_col(r, 16)?,
            })
        })
        .optional()?;

    let Some(row) = row else { return Ok(None) };

    let tags = load_tags_for(conn, &uuid_str)?;
    let attachments = load_attachments_for(conn, &uuid_str)?;
    let custom_fields = load_custom_fields_for(conn, &uuid_str)?;
    let history_count = load_history_count_for(conn, &uuid_str)?;

    Ok(Some(EntryFull {
        uuid: row.uuid,
        group_uuid: row.group_uuid,
        title: row.title,
        username: row.username,
        url: row.url,
        url_host: row.url_host,
        notes: row.notes,
        created_at: row.created_at,
        modified_at: row.modified_at,
        accessed_at: row.accessed_at,
        last_used_at: row.last_used_at,
        expires_at: row.expires_at,
        is_recycled: row.is_recycled,
        password_strength_bucket: row
            .password_strength_bucket
            .and_then(strength_bucket_from_i64),
        password_entropy: row.password_entropy,
        icon: icon_ref_from(row.icon_index, row.icon_custom_uuid),
        custom_fields,
        tags,
        attachments,
        history_count,
    }))
}

/// Return the full group tree as a flat list, ordered so the root
/// group (NULL `parent_uuid`) comes first, then siblings alphabetically
/// by name.
///
/// `entry_count_direct` counts entries whose `group_uuid` matches the
/// row, with one wrinkle: for the recycle bin group itself we **do**
/// include recycled entries in the count (otherwise it would always
/// read 0, which hides what's in the bin). Regular groups exclude
/// recycled entries — those live in the recycle bin's count instead.
pub(crate) fn group_tree(conn: &Connection) -> Result<Vec<GroupNode>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT uuid, parent_uuid, name, icon_index, icon_custom_uuid, is_recycle_bin, \
                (SELECT COUNT(*) FROM entry \
                 WHERE entry.group_uuid = \"group\".uuid \
                   AND (entry.is_recycled = 0 OR \"group\".is_recycle_bin = 1)) \
                    AS entry_count_direct \
         FROM \"group\" \
         ORDER BY (parent_uuid IS NOT NULL), name ASC, uuid ASC",
    )?;

    let rows = stmt
        .query_map([], |r| {
            let count_i64: i64 = r.get(6)?;
            Ok(GroupNode {
                uuid: parse_uuid_col(r, 0)?,
                parent_uuid: parse_optional_uuid_col(r, 1)?,
                name: r.get(2)?,
                icon: icon_ref_from(r.get(3)?, parse_optional_uuid_col(r, 4)?),
                is_recycle_bin: r.get::<_, i64>(5)? != 0,
                entry_count_direct: u32::try_from(count_i64).unwrap_or(u32::MAX),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Full-text search across `entry_fts`, with a tag-substring fallback
/// merged via `UNION ALL`.
///
/// # Ranking
///
/// Primary FTS5 hits are ordered by `bm25(entry_fts)` ascending (lower
/// is more relevant). Tag-fallback hits land after the FTS hits and
/// are alphabetised by title (deterministic, no relevance signal
/// because tag substring match is binary). The ordering is achieved
/// with a synthetic `bucket` column (0 = FTS hit, 1 = tag fallback)
/// then `rank ASC, title ASC, uuid ASC`.
///
/// # Deduplication
///
/// An entry that matches both FTS and the tag fallback appears only
/// in its FTS bucket — the tag fallback excludes any rowid already
/// in the FTS match set.
///
/// # Empty query
///
/// Empty / whitespace-only queries return an empty Vec without
/// touching the database. FTS5 raises a syntax error on empty
/// `MATCH` strings.
///
/// # Sanitisation
///
/// User input is run through [`escape_fts5_query`] — if the string
/// contains any FTS5-special character (`"`, `*`, `:`, `^`, `(`, `)`)
/// we wrap the whole thing in a quoted phrase so it tokenises
/// literally and never trips a syntax error. Plain word(s) pass
/// through, so users can still use FTS5's `word*` prefix and
/// implicit-AND-of-tokens semantics.
pub(crate) fn search(
    conn: &Connection,
    query: &str,
    page: Pagination,
) -> Result<Vec<EntrySummary>, EngineError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let fts_query = escape_fts5_query(trimmed);
    let tag_like = format!("%{}%", escape_like(trimmed));
    let (limit, offset) = clamp_page(page);

    // The CTE `fts_hits` captures rowids matched by FTS5 (so the tag
    // fallback can exclude them) along with their bm25 ranks.
    //
    // Bucket 0 = FTS hit (ranked by bm25 asc).
    // Bucket 1 = tag-only hit (alphabetised by title).
    let sql = format!(
        "WITH fts_hits AS ( \
             SELECT rowid AS rid, bm25(entry_fts) AS rank \
             FROM entry_fts WHERE entry_fts MATCH ?1 \
         ), \
         tag_hits AS ( \
             SELECT DISTINCT entry.rowid AS rid \
             FROM entry \
             JOIN entry_tag et ON et.entry_uuid = entry.uuid \
             JOIN tag t       ON t.id = et.tag_id \
             WHERE t.name LIKE ?2 ESCAPE '\\' \
               AND entry.rowid NOT IN (SELECT rid FROM fts_hits) \
         ), \
         hits AS ( \
             SELECT rid, 0 AS bucket, rank FROM fts_hits \
             UNION ALL \
             SELECT rid, 1 AS bucket, 0.0 AS rank FROM tag_hits \
         ) \
         SELECT {SUMMARY_COLUMNS} \
         FROM entry \
         JOIN hits ON hits.rid = entry.rowid \
         ORDER BY hits.bucket ASC, hits.rank ASC, entry.title ASC, entry.uuid ASC \
         LIMIT ?3 OFFSET ?4"
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![fts_query, tag_like, limit, offset], row_to_summary)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Escape user input for use as an FTS5 `MATCH` argument.
///
/// FTS5's query grammar treats a wide range of ASCII punctuation as
/// syntax (`"`, `*`, `:`, `^`, `(`, `)`, `-`, `+`, `@`, and others
/// flagged by its tokenizer). Rather than enumerate the full set and
/// hope FTS5 doesn't grow more, we take the conservative line: if
/// the query is *anything other than* alphanumerics, spaces, and the
/// ASCII underscore, wrap it as a quoted phrase. Plain word(s) pass
/// through verbatim so users keep FTS5's implicit-AND and
/// prefix-search (`word*`) semantics.
///
/// Embedded `"` characters are doubled per FTS5's escape rule.
pub(crate) fn escape_fts5_query(query: &str) -> String {
    let safe = query
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '_');
    if safe {
        query.to_string()
    } else {
        let escaped = query.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }
}

/// Escape a string for use in a `LIKE` pattern with `ESCAPE '\\'`.
/// `%` and `_` are LIKE-wildcards; `\` is the chosen escape character.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub(crate) fn entry_count(conn: &Connection, group: Option<Uuid>) -> Result<u64, EngineError> {
    let count: i64 = if let Some(uuid) = group {
        conn.query_row(
            "SELECT COUNT(*) FROM entry WHERE group_uuid = ?1",
            params![uuid.to_string()],
            |r| r.get(0),
        )?
    } else {
        conn.query_row("SELECT COUNT(*) FROM entry", [], |r| r.get(0))?
    };
    Ok(u64::try_from(count).unwrap_or(0))
}

// ────────────────────────── helpers ──────────────────────────

struct EntryFullRow {
    uuid: Uuid,
    group_uuid: Uuid,
    title: String,
    username: String,
    url: String,
    url_host: String,
    notes: String,
    created_at: i64,
    modified_at: i64,
    accessed_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    is_recycled: bool,
    password_strength_bucket: Option<i64>,
    password_entropy: Option<f64>,
    icon_index: Option<i64>,
    icon_custom_uuid: Option<Uuid>,
}

pub(crate) fn row_to_summary(r: &rusqlite::Row<'_>) -> rusqlite::Result<EntrySummary> {
    let attachment_count_i64: i64 = r.get(12)?;
    Ok(EntrySummary {
        uuid: parse_uuid_col(r, 0)?,
        group_uuid: parse_uuid_col(r, 1)?,
        title: r.get(2)?,
        username: r.get(3)?,
        url: r.get(4)?,
        url_host: r.get(5)?,
        modified_at: r.get(6)?,
        last_used_at: r.get(7)?,
        password_strength_bucket: r
            .get::<_, Option<i64>>(8)?
            .and_then(strength_bucket_from_i64),
        password_entropy: r.get(9)?,
        icon: icon_ref_from(r.get(10)?, parse_optional_uuid_col(r, 11)?),
        attachment_count: u32::try_from(attachment_count_i64).unwrap_or(u32::MAX),
    })
}

fn load_tags_for(conn: &Connection, entry_uuid: &str) -> Result<Vec<String>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT t.name FROM tag t \
         JOIN entry_tag et ON et.tag_id = t.id \
         WHERE et.entry_uuid = ?1 \
         ORDER BY t.name",
    )?;
    let rows = stmt
        .query_map(params![entry_uuid], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_attachments_for(
    conn: &Connection,
    entry_uuid: &str,
) -> Result<Vec<AttachmentRef>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT ea.attachment_name, ab.size \
         FROM entry_attachment ea \
         JOIN attachment_blob ab ON ab.sha256 = ea.blob_sha256 \
         WHERE ea.entry_uuid = ?1 \
         ORDER BY ea.attachment_name",
    )?;
    let rows = stmt
        .query_map(params![entry_uuid], |r| {
            let name: String = r.get(0)?;
            let size: i64 = r.get(1)?;
            Ok(AttachmentRef {
                name,
                size: u64::try_from(size).unwrap_or(0),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Load custom-field metadata. Only protected slots are persisted in
/// v1 (see module doc), so every returned `CustomFieldRef` has
/// `is_protected: true`. We filter out the canonical `Password` slot
/// since the model exposes that separately via `reveal_password`.
fn load_custom_fields_for(
    conn: &Connection,
    entry_uuid: &str,
) -> Result<Vec<CustomFieldRef>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT field_name FROM entry_protected \
         WHERE entry_uuid = ?1 AND field_name != 'Password' \
         ORDER BY field_name",
    )?;
    let rows = stmt
        .query_map(params![entry_uuid], |r| {
            Ok(CustomFieldRef {
                name: r.get(0)?,
                is_protected: true,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_history_count_for(conn: &Connection, entry_uuid: &str) -> Result<u32, EngineError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entry_history WHERE entry_uuid = ?1",
        params![entry_uuid],
        |r| r.get(0),
    )?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

fn parse_uuid_col(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Uuid> {
    let s: String = row.get(idx)?;
    Uuid::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_optional_uuid_col(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<Uuid>> {
    let s: Option<String> = row.get(idx)?;
    s.map(|s| {
        Uuid::parse_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
        })
    })
    .transpose()
}

fn strength_bucket_from_i64(v: i64) -> Option<StrengthBucket> {
    match v {
        0 => Some(StrengthBucket::VeryWeak),
        1 => Some(StrengthBucket::Weak),
        2 => Some(StrengthBucket::Reasonable),
        3 => Some(StrengthBucket::Strong),
        4 => Some(StrengthBucket::VeryStrong),
        _ => None,
    }
}

fn icon_ref_from(icon_index: Option<i64>, icon_custom_uuid: Option<Uuid>) -> IconRef {
    // Custom icon wins if present (KDBX semantics: a custom-icon UUID
    // overrides the built-in index for rendering). Otherwise fall back
    // to the built-in index, defaulting to 0 (the standard "key" icon)
    // when both columns are NULL.
    if let Some(uuid) = icon_custom_uuid {
        IconRef::Custom(uuid)
    } else {
        let idx = icon_index.unwrap_or(0);
        IconRef::Builtin(u32::try_from(idx).unwrap_or(0))
    }
}

/// Map [`Pagination`] onto `SQLite`'s `(limit, offset)` parameter pair.
///
/// `u64::MAX` (from [`Pagination::all`]) maps to `-1`, `SQLite`'s
/// "no limit" sentinel. Any value above `i64::MAX` saturates the same
/// way — callers asking for billions of rows almost certainly meant
/// "everything". Other values pass through as `i64`.
///
/// Offset is clamped to `i64::MAX`; an offset beyond that returns
/// zero rows naturally.
///
/// [`Pagination::all`]: crate::Pagination::all
pub(crate) fn clamp_page(page: Pagination) -> (i64, i64) {
    let limit = if page.limit == u64::MAX {
        -1
    } else {
        i64::try_from(page.limit).unwrap_or(-1)
    };
    let offset = i64::try_from(page.offset).unwrap_or(i64::MAX);
    (limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_page_maps_all_to_no_limit() {
        let (l, o) = clamp_page(Pagination::all());
        assert_eq!(l, -1);
        assert_eq!(o, 0);
    }

    #[test]
    fn clamp_page_passes_finite_values_through() {
        let (l, o) = clamp_page(Pagination {
            offset: 50,
            limit: 25,
        });
        assert_eq!(l, 25);
        assert_eq!(o, 50);
    }

    #[test]
    fn strength_bucket_round_trips_known_values() {
        assert_eq!(strength_bucket_from_i64(0), Some(StrengthBucket::VeryWeak));
        assert_eq!(
            strength_bucket_from_i64(4),
            Some(StrengthBucket::VeryStrong)
        );
        assert_eq!(strength_bucket_from_i64(99), None);
    }

    #[test]
    fn escape_fts5_query_passes_plain_words_through() {
        assert_eq!(escape_fts5_query("banking"), "banking");
        assert_eq!(escape_fts5_query("two words"), "two words");
        assert_eq!(escape_fts5_query("with_underscore"), "with_underscore");
    }

    #[test]
    fn escape_fts5_query_quotes_anything_with_punctuation() {
        assert_eq!(escape_fts5_query("user@example"), "\"user@example\"");
        assert_eq!(escape_fts5_query("a:b"), "\"a:b\"");
        assert_eq!(escape_fts5_query("(x)"), "\"(x)\"");
        assert_eq!(escape_fts5_query("prefix*"), "\"prefix*\"");
        assert_eq!(
            escape_fts5_query("he said \"hi\""),
            "\"he said \"\"hi\"\"\""
        );
    }

    #[test]
    fn escape_like_escapes_wildcards() {
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("50%"), "50\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c\\d"), "c\\\\d");
    }

    #[test]
    fn icon_ref_prefers_custom_over_builtin() {
        let u = Uuid::new_v4();
        assert_eq!(icon_ref_from(Some(5), Some(u)), IconRef::Custom(u));
        assert_eq!(icon_ref_from(Some(5), None), IconRef::Builtin(5));
        assert_eq!(icon_ref_from(None, None), IconRef::Builtin(0));
    }
}
