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
//! ## Custom fields
//!
//! [`EntryFull::custom_fields`] surfaces both flavours: protected slots
//! (from `entry_protected`, with `is_protected = true`) and
//! non-protected slots (from `entry_custom_field`, migration 0002,
//! with `is_protected = false`). The canonical `Password` slot is
//! filtered out — callers fetch that via `reveal_password`.
//!
//! [`Engine`]: crate::Engine
//! [`Pagination::all()`]: crate::Pagination::all
//! [`EntryFull::custom_fields`]: crate::EntryFull::custom_fields

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::EngineError;
use crate::model::{
    AttachmentRef, CustomFieldRef, EntryFull, EntrySummary, GroupNode, HistoricEntry, IconRef,
    Pagination, SearchScope, StrengthBucket,
};

/// SQL fragment listing the columns `EntrySummary` needs, plus the
/// correlated attachment-count subquery. Kept as a constant so the
/// `group = None` and `group = Some(_)` variants stay in lock-step.
pub(crate) const SUMMARY_COLUMNS: &str = "\
    uuid, group_uuid, title, username, url, url_host, notes, \
    created_at, modified_at, accessed_at, last_used_at, \
    password_strength_bucket, password_entropy, \
    icon_index, icon_custom_uuid, \
    (SELECT COUNT(*) FROM entry_attachment ea WHERE ea.entry_uuid = entry.uuid) \
        AS attachment_count, \
    has_totp";

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
/// group (NULL `parent_uuid`) comes first, then siblings by
/// `sort_order` (with `name` as a tie-breaker for legacy rows that
/// haven't been re-ingested since migration 0004 and therefore all
/// share the default `sort_order = 0`).
///
/// `entry_count_direct` counts entries whose `group_uuid` matches the
/// row, with one wrinkle: for the recycle bin group itself we **do**
/// include recycled entries in the count (otherwise it would always
/// read 0, which hides what's in the bin). Regular groups exclude
/// recycled entries — those live in the recycle bin's count instead.
pub(crate) fn group_tree(conn: &Connection) -> Result<Vec<GroupNode>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT uuid, parent_uuid, name, icon_index, icon_custom_uuid, is_recycle_bin, \
                sort_order, \
                (SELECT COUNT(*) FROM entry \
                 WHERE entry.group_uuid = \"group\".uuid \
                   AND (entry.is_recycled = 0 OR \"group\".is_recycle_bin = 1)) \
                    AS entry_count_direct \
         FROM \"group\" \
         ORDER BY (parent_uuid IS NOT NULL), sort_order ASC, name ASC, uuid ASC",
    )?;

    let rows = stmt
        .query_map([], |r| {
            let sort_order_i64: i64 = r.get(6)?;
            let count_i64: i64 = r.get(7)?;
            Ok(GroupNode {
                uuid: parse_uuid_col(r, 0)?,
                parent_uuid: parse_optional_uuid_col(r, 1)?,
                name: r.get(2)?,
                icon: icon_ref_from(r.get(3)?, parse_optional_uuid_col(r, 4)?),
                is_recycle_bin: r.get::<_, i64>(5)? != 0,
                sort_order: u32::try_from(sort_order_i64).unwrap_or(0),
                entry_count_direct: u32::try_from(count_i64).unwrap_or(u32::MAX),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Defensive iteration cap for `is_descendant_of`'s `parent_uuid` walk.
///
/// A real vault is a tree, so the walk terminates at the root after at
/// most `<tree depth>` steps. The cap exists to guard against malformed
/// vaults that contain a cycle (`parent_uuid` chain that never reaches
/// `NULL`). 1024 is comfortably above any realistic group nesting depth
/// — `KeePass` UIs become unusable long before that — and keeps the
/// worst-case unbounded.
const MAX_ANCESTRY_WALK: usize = 1024;

/// Return the parent group's UUID for `child_uuid`, or `Ok(None)` if
/// `child_uuid` is the root group.
///
/// Returns [`EngineError::NotFound`] (`entity = "group"`) if no group
/// with that UUID exists.
pub(crate) fn group_parent_uuid(
    conn: &Connection,
    child_uuid: Uuid,
) -> Result<Option<Uuid>, EngineError> {
    let row: Option<Option<String>> = conn
        .query_row(
            "SELECT parent_uuid FROM \"group\" WHERE uuid = ?1",
            params![child_uuid.to_string()],
            |r| r.get(0),
        )
        .optional()?;

    match row {
        None => Err(EngineError::NotFound { entity: "group" }),
        Some(None) => Ok(None),
        Some(Some(s)) => Uuid::parse_str(&s).map(Some).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
                .into()
        }),
    }
}

/// Walk `group_uuid`'s `parent_uuid` chain; return `true` if it passes
/// through `ancestor_uuid`. Not inclusive — a group is not its own
/// descendant.
///
/// Returns [`EngineError::NotFound`] (`entity = "group"`) if
/// `group_uuid` doesn't match any row. A non-existent `ancestor_uuid`
/// is not an error: the walk just terminates at root with `false`.
///
/// Capped at [`MAX_ANCESTRY_WALK`] iterations as a defensive guard
/// against `parent_uuid` cycles in malformed user vaults; a cycle
/// returns `false` rather than spinning.
pub(crate) fn is_descendant_of(
    conn: &Connection,
    group_uuid: Uuid,
    ancestor_uuid: Uuid,
) -> Result<bool, EngineError> {
    if group_uuid == ancestor_uuid {
        // Per chosen semantics: a group is not its own descendant.
        // Still validate that the group exists so the "not found"
        // contract holds.
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM \"group\" WHERE uuid = ?1",
                params![group_uuid.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        return if exists.is_some() {
            Ok(false)
        } else {
            Err(EngineError::NotFound { entity: "group" })
        };
    }

    let mut stmt = conn.prepare("SELECT parent_uuid FROM \"group\" WHERE uuid = ?1")?;
    let mut current = group_uuid;

    for _ in 0..MAX_ANCESTRY_WALK {
        let row: Option<Option<String>> = stmt
            .query_row(params![current.to_string()], |r| r.get(0))
            .optional()?;
        match row {
            // First lookup miss → caller's `group_uuid` doesn't exist.
            // Subsequent misses are impossible (each `parent_uuid` we
            // followed came from an existing row); if one does happen
            // due to a referential-integrity break, treat it as "walk
            // ended" and return false.
            None if current == group_uuid => {
                return Err(EngineError::NotFound { entity: "group" });
            }
            // Reached the root without matching, or hit a dangling
            // `parent_uuid` (treat the same as "walk ended").
            None | Some(None) => return Ok(false),
            Some(Some(parent_str)) => {
                let parent = Uuid::parse_str(&parent_str).map_err(|e| {
                    EngineError::from(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ))
                })?;
                if parent == ancestor_uuid {
                    return Ok(true);
                }
                current = parent;
            }
        }
    }
    // Cap hit — treat as "no, with a clean conscience". A real vault
    // can't reach this; a vault with a cycle does, and `false` is the
    // safer default than spinning or panicking.
    Ok(false)
}

/// Case-insensitive substring search across entry fields, scoped by
/// [`SearchScope`].
///
/// # Matching semantics
///
/// The query is trimmed and split on whitespace into tokens. An entry
/// matches when **every** token appears as a case-insensitive
/// substring of at least one in-scope field — i.e. tokens AND, fields
/// OR. This is what users intuitively expect from a text box:
/// typing `manag` finds entries titled `Management` and typing `one
/// two` finds an entry titled `Tone and Atwog`.
///
/// # Scope
///
/// - [`SearchScope::AnyField`] — title, username, url, notes, and tag
///   names.
/// - [`SearchScope::TitleOnly`] — title only.
/// - [`SearchScope::NotesOnly`] — notes only.
///
/// Protected fields (passwords, custom protected fields) are never
/// searched.
///
/// # Empty query
///
/// Empty / whitespace-only queries return an empty Vec without
/// touching the database.
///
/// # Ordering
///
/// Alphabetical by title (case-insensitive), then by uuid for
/// determinism. There's no relevance ranking — substring match is
/// binary and the client re-sorts by user preference anyway.
pub(crate) fn search(
    conn: &Connection,
    query: &str,
    scope: SearchScope,
    page: Pagination,
) -> Result<Vec<EntrySummary>, EngineError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let tokens: Vec<String> = trimmed
        .split_whitespace()
        .map(|t| format!("%{}%", escape_like(t)))
        .collect();
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    let (limit, offset) = clamp_page(page);

    // Build a per-token clause that ANDs across tokens, ORs across
    // fields inside the scope. `?n` placeholders for each token's
    // LIKE pattern; trailing two placeholders are limit/offset.
    let per_token_clause: &str = match scope {
        SearchScope::AnyField => {
            "(entry.title    LIKE ?{n} ESCAPE '\\' COLLATE NOCASE \
              OR entry.username LIKE ?{n} ESCAPE '\\' COLLATE NOCASE \
              OR entry.url      LIKE ?{n} ESCAPE '\\' COLLATE NOCASE \
              OR entry.notes    LIKE ?{n} ESCAPE '\\' COLLATE NOCASE \
              OR EXISTS ( \
                  SELECT 1 FROM entry_tag et \
                  JOIN tag t ON t.id = et.tag_id \
                  WHERE et.entry_uuid = entry.uuid \
                    AND t.name LIKE ?{n} ESCAPE '\\' COLLATE NOCASE \
              ))"
        }
        SearchScope::TitleOnly => "(entry.title LIKE ?{n} ESCAPE '\\' COLLATE NOCASE)",
        SearchScope::NotesOnly => "(entry.notes LIKE ?{n} ESCAPE '\\' COLLATE NOCASE)",
    };

    let where_clause = tokens
        .iter()
        .enumerate()
        .map(|(i, _)| per_token_clause.replace("?{n}", &format!("?{}", i + 1)))
        .collect::<Vec<_>>()
        .join(" AND ");

    let limit_placeholder = tokens.len() + 1;
    let offset_placeholder = tokens.len() + 2;

    let sql = format!(
        "SELECT {SUMMARY_COLUMNS} \
         FROM entry \
         WHERE {where_clause} \
         ORDER BY entry.title COLLATE NOCASE ASC, entry.uuid ASC \
         LIMIT ?{limit_placeholder} OFFSET ?{offset_placeholder}"
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<&dyn rusqlite::ToSql> =
        tokens.iter().map(|t| t as &dyn rusqlite::ToSql).collect();
    params.push(&limit);
    params.push(&offset);

    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), row_to_summary)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Find entries matching an `AutoFill` service identifier.
///
/// The identifier can be a bare host (`google.com`), a full URL
/// (`https://accounts.google.com/signin?...`), or anything in between.
/// We parse out a host if we can, then match against the indexed
/// `entry.url_host` column in three tiers (most-specific first):
///
/// 1. **Exact host match** — case-insensitive equality with `url_host`.
/// 2. **eTLD+1 match** — strip a leading `www.` and reduce to the
///    registrable domain via [`registrable_domain`]; match entries
///    whose `url_host` either equals that domain or ends in
///    `.<domain>`. Catches `accounts.google.com` finding entries
///    saved as `google.com` and vice versa.
/// 3. **Substring match** — the original identifier appears anywhere
///    inside `entry.url` (LIKE `%id%`). Last-resort tier for entries
///    that don't have a parseable URL.
///
/// Recycled entries are excluded.
///
/// Results are deduplicated by entry uuid (keeping the best tier),
/// ordered by tier ascending, then `last_used_at DESC NULLS LAST`,
/// then `modified_at DESC`, then `uuid ASC` for determinism. Capped
/// at `limit` rows.
///
/// # Why no Public Suffix List
///
/// For v1 we use a tiny right-to-left algorithm with a hand-rolled
/// list of two-label public suffixes (`co.uk`, `com.au`, etc.). This
/// covers the common `AutoFill` cases without pulling in the 200 KB
/// `publicsuffix` crate. A full PSL can land later if real-world
/// usage shows gaps.
pub(crate) fn search_by_service(
    conn: &Connection,
    identifier: &str,
    limit: usize,
) -> Result<Vec<EntrySummary>, EngineError> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }

    // Try to pull a host out of the identifier. URL parsing handles
    // the full-URL case; bare hosts (no scheme) fail to parse, so we
    // fall back to treating the trimmed input as a host candidate.
    let raw_host = url::Url::parse(trimmed)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| trimmed.to_ascii_lowercase());

    let exact_host = strip_www(&raw_host).to_owned();
    let etld1 = registrable_domain(&exact_host);

    // The substring tier matches against the raw `url` column, which
    // is stored verbatim from ingest (mixed case). Use NOCASE
    // collation in the LIKE for case-insensitive matching, escape
    // SQL wildcards in user input.
    let url_like = format!("%{}%", escape_like(trimmed));

    // `etld_suffix_like` matches any url_host ending in `.<etld1>`
    // (a subdomain of the registrable domain). Wildcards in the
    // domain are not possible because etld1 is derived from a parsed
    // host, but escape anyway as defence in depth.
    let etld_suffix_like = format!("%.{}", escape_like(&etld1));

    // SQL strategy: pull every candidate row, tag it with the best
    // tier it satisfies, dedupe by uuid taking MIN(tier), then sort
    // by tier + recency. The CASE expression encodes tier priority
    // (1 = exact host, 2 = eTLD+1, 3 = substring).
    //
    // `entry.is_recycled = 0` filters out recycle-bin entries up
    // front. The candidate set is bounded by the WHERE clause: any
    // row that matches at least one tier.
    let sql = format!(
        "WITH ranked AS ( \
             SELECT entry.uuid AS uuid, \
                    CASE \
                        WHEN entry.url_host = ?1 THEN 1 \
                        WHEN entry.url_host = ?2 OR entry.url_host LIKE ?3 ESCAPE '\\' \
                            THEN 2 \
                        WHEN entry.url LIKE ?4 ESCAPE '\\' COLLATE NOCASE THEN 3 \
                        ELSE 99 \
                    END AS tier \
             FROM entry \
             WHERE entry.is_recycled = 0 \
               AND ( \
                   entry.url_host = ?1 \
                   OR entry.url_host = ?2 \
                   OR entry.url_host LIKE ?3 ESCAPE '\\' \
                   OR entry.url LIKE ?4 ESCAPE '\\' COLLATE NOCASE \
               ) \
         ), \
         best AS ( \
             SELECT uuid AS best_uuid, MIN(tier) AS best_tier \
             FROM ranked GROUP BY uuid \
         ) \
         SELECT {SUMMARY_COLUMNS} \
         FROM entry \
         JOIN best ON best.best_uuid = entry.uuid \
         ORDER BY best.best_tier ASC, \
                  (entry.last_used_at IS NULL) ASC, \
                  entry.last_used_at DESC, \
                  entry.modified_at DESC, \
                  entry.uuid ASC \
         LIMIT ?5"
    );

    // Cap limit at i64::MAX (well above any realistic AutoFill limit).
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(
            params![exact_host, etld1, etld_suffix_like, url_like, limit_i64],
            row_to_summary,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Strip a leading `www.` from a host. Only the literal `www.`
/// prefix — subdomains like `www2.` are left alone. Returns a
/// borrowed slice when no prefix is present.
fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// Reduce a hostname to its registrable domain (a coarse "eTLD+1").
///
/// Algorithm: split on `.`, peel labels from the right. If the last
/// two labels are a known two-label public suffix (`co.uk`,
/// `com.au`, …), the registrable domain is the last three labels;
/// otherwise it's the last two. Inputs with fewer than two labels
/// (IP addresses, single-label hostnames) are returned unchanged.
///
/// This is intentionally not a full Public Suffix List — see the
/// rationale on [`search_by_service`].
fn registrable_domain(host: &str) -> String {
    let host = strip_www(host);
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return host.to_owned();
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if labels.len() >= 3 && TWO_LABEL_PUBLIC_SUFFIXES.contains(&last_two.as_str()) {
        format!("{}.{}", labels[labels.len() - 3], last_two)
    } else {
        last_two
    }
}

/// Hand-curated list of common two-label public suffixes. Covers the
/// usual `AutoFill` country-coded TLDs (`co.uk`, `com.au`, …) without
/// the bulk of a full PSL. If real-world `AutoFill` hits a suffix not
/// listed here, the eTLD+1 tier degrades to a too-aggressive match
/// (e.g. `co.uk` itself), but the exact-host tier still works and
/// the substring tier picks up the slack.
const TWO_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "id.au", "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "go.jp", "co.kr", "or.kr", "co.za", "org.za", "com.br", "net.br", "org.br", "com.mx", "com.ar",
    "com.sg", "com.hk", "com.tw", "com.tr", "co.in", "co.id", "co.il",
];

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

/// Return every unique tag name in use across the vault, sorted
/// alphabetically (case-sensitive `ORDER BY name ASC`, matching the
/// `tag.name` collation).
///
/// The `tag` table is authoritative: every mutation that can orphan a
/// tag row (`set_tags`, `delete_entry`, `delete_group`) runs an
/// in-transaction GC sweep, so a plain `SELECT name FROM tag` cannot
/// surface zombies — if it's in `tag`, at least one `entry_tag` row
/// references it.
///
/// Tag names are normalised at ingest time (whitespace stripped,
/// empties dropped, deduplicated) so this method doesn't re-normalise.
pub(crate) fn list_tags(conn: &Connection) -> Result<Vec<String>, EngineError> {
    let mut stmt = conn.prepare("SELECT name FROM tag ORDER BY name ASC")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return `(tag_name, entry_count)` pairs for every tag with at least
/// one referencing entry, sorted by tag name `COLLATE NOCASE`.
///
/// Includes recycle-bin entries in the count — preserves the legacy
/// Swift `TagListStore::usageCount` behaviour. The `INNER JOIN` against
/// `entry_tag` naturally drops tags with zero references; orphan-row GC
/// in `set_tags`/`delete_entry`/`delete_group` keeps the `tag` table
/// authoritative, but the JOIN is defensive regardless.
pub(crate) fn tag_usage_counts(conn: &Connection) -> Result<Vec<(String, u64)>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT t.name, COUNT(et.entry_uuid) AS n \
         FROM tag t \
         JOIN entry_tag et ON et.tag_id = t.id \
         JOIN entry e ON e.uuid = et.entry_uuid \
         GROUP BY t.id \
         ORDER BY t.name COLLATE NOCASE ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let name: String = r.get(0)?;
            let count: i64 = r.get(1)?;
            Ok((name, u64::try_from(count).unwrap_or(0)))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
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

/// Return the historical snapshots of an entry, ordered oldest-first.
///
/// `EngineError::NotFound { entity: "entry" }` if the entry itself
/// doesn't exist; `Ok(vec![])` if it exists but has no history rows.
pub(crate) fn history(conn: &Connection, uuid: Uuid) -> Result<Vec<HistoricEntry>, EngineError> {
    let uuid_str = uuid.to_string();

    // Distinguish "entry doesn't exist" from "entry exists but has no
    // history" — the bare history query can't tell us, and the FFI
    // surface wants a NotFound for the missing-entry case.
    let entry_exists: bool = conn
        .query_row(
            "SELECT 1 FROM entry WHERE uuid = ?1",
            params![uuid_str],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !entry_exists {
        return Err(EngineError::NotFound { entity: "entry" });
    }

    let mut stmt = conn.prepare(
        "SELECT history_index, snapshot_json FROM entry_history \
         WHERE entry_uuid = ?1 \
         ORDER BY history_index ASC",
    )?;
    let rows = stmt
        .query_map(params![uuid_str], |r| {
            let idx: i64 = r.get(0)?;
            let json: String = r.get(1)?;
            Ok((idx, json))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out: Vec<HistoricEntry> = Vec::with_capacity(rows.len());
    for (idx, json) in rows {
        let snap: HistorySnapshotRead = serde_json::from_str(&json)
            .map_err(|e| EngineError::Reveal(crate::error::RevealError::Json(e)))?;
        // Build CustomFieldRef list sorted by name for deterministic
        // ordering (matches EntryFull.custom_fields).
        let mut custom_fields: Vec<CustomFieldRef> = snap
            .custom_fields
            .into_iter()
            .map(|(name, raw)| CustomFieldRef {
                name,
                is_protected: raw.protected.unwrap_or(false),
            })
            .collect();
        custom_fields.sort_by(|a, b| a.name.cmp(&b.name));
        let icon_custom_uuid = snap
            .icon_custom_uuid
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());
        let icon = icon_ref_from(snap.icon_index.map(i64::from), icon_custom_uuid);
        let attachments: Vec<AttachmentRef> = snap
            .attachments
            .into_iter()
            .map(|a| AttachmentRef {
                name: a.name,
                size: a.size,
            })
            .collect();
        out.push(HistoricEntry {
            history_index: u32::try_from(idx).unwrap_or(u32::MAX),
            title: snap.title,
            username: snap.username,
            url: snap.url,
            url_host: snap.url_host,
            notes: snap.notes,
            icon,
            created_at: snap.created_at,
            modified_at: snap.modified_at,
            accessed_at: snap.accessed_at,
            last_used_at: snap.last_used_at,
            expires_at: snap.expires_at,
            password_strength_bucket: snap
                .password_strength_bucket
                .map(i64::from)
                .and_then(strength_bucket_from_i64),
            password_entropy: snap.password_entropy,
            custom_fields,
            tags: snap.tags,
            attachments,
        });
    }
    Ok(out)
}

/// Fetch the raw bytes of a named attachment on an entry.
///
/// `EngineError::NotFound { entity: "attachment" }` if no matching
/// `entry_attachment` row exists — covers both the missing-entry and
/// missing-attachment-name cases (callers don't need to distinguish).
pub(crate) fn attachment_bytes(
    conn: &Connection,
    uuid: Uuid,
    attachment_name: &str,
) -> Result<Vec<u8>, EngineError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT b.bytes FROM entry_attachment a \
             JOIN attachment_blob b ON b.sha256 = a.blob_sha256 \
             WHERE a.entry_uuid = ?1 AND a.attachment_name = ?2",
            params![uuid.to_string(), attachment_name],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes.ok_or(EngineError::NotFound {
        entity: "attachment",
    })
}

/// Fetch the raw bytes of a named attachment as it existed in a
/// specific history snapshot of an entry.
///
/// Resolution chain:
///
/// 1. Look up `entry_history.snapshot_json` for `(entry_uuid,
///    history_index)`.
/// 2. Deserialise its `attachments` list, find the named attachment,
///    grab its `sha256_hex`.
/// 3. Look up `attachment_blob` by that SHA-256 → bytes.
///
/// `EngineError::NotFound { entity: "attachment" }` for every miss
/// along the chain — missing entry, missing history index, missing
/// attachment name in the snapshot, empty `sha256_hex` (pre-widening
/// snapshots), or a dangling blob reference. Callers don't need to
/// distinguish; the UI surface treats all of them the same way.
pub(crate) fn history_attachment_bytes(
    conn: &Connection,
    uuid: Uuid,
    history_index: u32,
    attachment_name: &str,
) -> Result<Vec<u8>, EngineError> {
    let json: Option<String> = conn
        .query_row(
            "SELECT snapshot_json FROM entry_history \
             WHERE entry_uuid = ?1 AND history_index = ?2",
            params![uuid.to_string(), i64::from(history_index)],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Err(EngineError::NotFound {
            entity: "attachment",
        });
    };
    let snap: HistorySnapshotRead = serde_json::from_str(&json)
        .map_err(|e| EngineError::Reveal(crate::error::RevealError::Json(e)))?;
    let Some(att) = snap
        .attachments
        .into_iter()
        .find(|a| a.name == attachment_name)
    else {
        return Err(EngineError::NotFound {
            entity: "attachment",
        });
    };
    if att.sha256_hex.is_empty() {
        // Pre-widening snapshot — sha256 wasn't recorded, so the bytes
        // can't be resolved deterministically. Treat as missing.
        return Err(EngineError::NotFound {
            entity: "attachment",
        });
    }
    let sha_bytes = hex_to_bytes(&att.sha256_hex).ok_or(EngineError::NotFound {
        entity: "attachment",
    })?;
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT bytes FROM attachment_blob WHERE sha256 = ?1",
            params![sha_bytes],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes.ok_or(EngineError::NotFound {
        entity: "attachment",
    })
}

/// Decode a lowercase hex string into bytes. Returns `None` for any
/// invalid input (odd length, non-hex chars). Kept private — only the
/// history attachment lookup needs it.
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Deserialise side of the shape written by
/// `crate::ingest::HistorySnapshot`. Every field added after the
/// initial shipped shape is `#[serde(default)]` so older JSON
/// (pre-history-widening) deserialises cleanly: those snapshots simply
/// surface zero/empty defaults for the newer fields, which is correct
/// because the data genuinely wasn't recorded at write time. The
/// protected/wrapped values stay in the JSON and are only touched by
/// [`crate::reveal::reveal_history_field`].
#[derive(Deserialize)]
struct HistorySnapshotRead {
    title: String,
    username: String,
    url: String,
    #[serde(default)]
    url_host: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    created_at: i64,
    modified_at: i64,
    #[serde(default)]
    accessed_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    icon_index: Option<u32>,
    #[serde(default)]
    icon_custom_uuid: Option<String>,
    #[serde(default)]
    password_strength_bucket: Option<u8>,
    #[serde(default)]
    password_entropy: Option<f64>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    attachments: Vec<HistoryAttachmentRead>,
    #[serde(default)]
    custom_fields: HashMap<String, HistoryCustomFieldRead>,
}

#[derive(Deserialize)]
struct HistoryAttachmentRead {
    name: String,
    #[serde(default)]
    size: u64,
    /// Hex-encoded SHA-256 of the attachment bytes. Added after the
    /// initial widening (PR #75) so older `snapshot_json` rows omit it —
    /// `#[serde(default)]` surfaces an empty string in that case. The
    /// list-side `history()` reader doesn't use this field; only the
    /// per-snapshot byte fetch needs it.
    #[serde(default)]
    sha256_hex: String,
}

/// Mirrors the write-side `HistoryCustomField` but only carries the
/// `protected` flag — value bytes stay opaque on this read path
/// (`reveal_history_field` parses them separately). `protected` is
/// `Option<bool>` to remain compatible with future shape changes; we
/// default it to `false` if missing.
#[derive(Deserialize)]
struct HistoryCustomFieldRead {
    #[serde(default)]
    protected: Option<bool>,
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
    let attachment_count_i64: i64 = r.get(15)?;
    let has_totp_i64: i64 = r.get(16)?;
    Ok(EntrySummary {
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
        password_strength_bucket: r
            .get::<_, Option<i64>>(11)?
            .and_then(strength_bucket_from_i64),
        password_entropy: r.get(12)?,
        icon: icon_ref_from(r.get(13)?, parse_optional_uuid_col(r, 14)?),
        attachment_count: u32::try_from(attachment_count_i64).unwrap_or(u32::MAX),
        has_totp: has_totp_i64 != 0,
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

/// Load custom-field metadata. Returns the union of:
///
/// * Protected slots from `entry_protected` (excluding the canonical
///   `Password` row, which is exposed separately via
///   `reveal_password`) with `is_protected = true`.
/// * Non-protected slots from `entry_custom_field` (migration 0002)
///   with `is_protected = false`.
///
/// Results are sorted by name ascending across both sources. Ingest
/// puts a given field in exactly one of the two tables, so name
/// collisions across the two are not expected.
fn load_custom_fields_for(
    conn: &Connection,
    entry_uuid: &str,
) -> Result<Vec<CustomFieldRef>, EngineError> {
    let mut stmt = conn.prepare(
        "SELECT field_name, 1 AS is_protected FROM entry_protected \
         WHERE entry_uuid = ?1 AND field_name != 'Password' \
         UNION ALL \
         SELECT field_name, 0 AS is_protected FROM entry_custom_field \
         WHERE entry_uuid = ?1 \
         ORDER BY field_name",
    )?;
    let rows = stmt
        .query_map(params![entry_uuid], |r| {
            Ok(CustomFieldRef {
                name: r.get(0)?,
                is_protected: r.get::<_, i64>(1)? != 0,
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
    fn escape_like_escapes_wildcards() {
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("50%"), "50\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c\\d"), "c\\\\d");
    }

    #[test]
    fn strip_www_only_strips_literal_prefix() {
        assert_eq!(strip_www("www.example.com"), "example.com");
        assert_eq!(strip_www("example.com"), "example.com");
        // Not the literal `www.` prefix — leave alone.
        assert_eq!(strip_www("www2.example.com"), "www2.example.com");
        assert_eq!(strip_www("api.www.example.com"), "api.www.example.com");
    }

    #[test]
    fn registrable_domain_basic_two_label() {
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("accounts.google.com"), "google.com");
        assert_eq!(
            registrable_domain("api.v2.accounts.google.com"),
            "google.com"
        );
    }

    #[test]
    fn registrable_domain_two_label_public_suffix() {
        assert_eq!(registrable_domain("bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("news.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("shop.example.com.au"), "example.com.au");
    }

    #[test]
    fn registrable_domain_strips_www() {
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("www.news.bbc.co.uk"), "bbc.co.uk");
    }

    #[test]
    fn registrable_domain_handles_short_inputs() {
        assert_eq!(registrable_domain(""), "");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("com"), "com");
        // IPv4 — we don't have a notion of registrable for IPs, so
        // the raw "last two labels" semantics is fine; AutoFill is
        // very unlikely to match against raw IPs anyway.
        assert_eq!(registrable_domain("192.168.1.1"), "1.1");
    }

    #[test]
    fn icon_ref_prefers_custom_over_builtin() {
        let u = Uuid::new_v4();
        assert_eq!(icon_ref_from(Some(5), Some(u)), IconRef::Custom(u));
        assert_eq!(icon_ref_from(Some(5), None), IconRef::Builtin(5));
        assert_eq!(icon_ref_from(None, None), IconRef::Builtin(0));
    }
}
