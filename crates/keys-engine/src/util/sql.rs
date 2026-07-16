//! Mirror-facing SQL helpers and the column-value conversions that
//! feed them.
//!
//! Every function takes `&Connection`. Callers holding a
//! `&Transaction` pass it directly — `Transaction` derefs to
//! `Connection` — so one signature serves both the ingest path (which
//! works on a bare connection) and the mutation path (which works
//! inside a transaction). Errors surface as `rusqlite::Error`;
//! `EngineError` callers get the conversion for free via `?`
//! (`EngineError::Sqlite` is `#[from]`).

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

/// Parse the host out of a URL, lowercased, for the indexed
/// `entry.url_host` column (`AutoFill` lookups are case-insensitive).
///
/// Returns the empty string when the input isn't a parseable URL or
/// has no host — matching the schema's `NOT NULL DEFAULT ''` rather
/// than introducing a NULL.
///
/// **Both** the ingest and edit write paths populate `url_host`
/// through this function. That is the point of it living here: were
/// the two to drift, `search_by_service` would match ingest-written
/// rows but not edit-written ones (or vice versa) with nothing failing
/// loudly.
pub(crate) fn parse_host(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    match url::Url::parse(url) {
        Ok(parsed) => parsed
            .host_str()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Convert an optional timestamp to the epoch-millis integer the
/// mirror's `*_at` columns hold.
///
/// Absent becomes `0`, not NULL: the columns are `NOT NULL` and KDBX
/// itself treats a missing time as "unset", which the epoch already
/// encodes.
pub(crate) fn dt_to_ms(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map_or(0, |d| d.timestamp_millis())
}

/// Insert (or no-op) a tag name and return its row id.
pub(crate) fn upsert_tag(conn: &Connection, name: &str) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO tag (name) VALUES (?1)",
        params![name],
    )?;
    conn.query_row("SELECT id FROM tag WHERE name = ?1", params![name], |r| {
        r.get::<_, i64>(0)
    })
}

/// `true` if a live row exists in `entry` with the given uuid.
pub(crate) fn entry_exists(conn: &Connection, uuid: &str) -> Result<bool, rusqlite::Error> {
    row_exists(conn, "SELECT 1 FROM entry WHERE uuid = ?1", uuid)
}

/// `true` if a row exists in `"group"` with the given uuid.
pub(crate) fn group_exists(conn: &Connection, uuid: &str) -> Result<bool, rusqlite::Error> {
    row_exists(conn, "SELECT 1 FROM \"group\" WHERE uuid = ?1", uuid)
}

fn row_exists(conn: &Connection, sql: &str, uuid: &str) -> Result<bool, rusqlite::Error> {
    conn.query_row(sql, params![uuid], |_| Ok(()))
        .optional()
        .map(|row| row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn parse_host_lowercases() {
        assert_eq!(
            parse_host("https://Login.Example.COM/path"),
            "login.example.com"
        );
    }

    #[test]
    fn parse_host_empty_for_unparseable() {
        assert_eq!(parse_host(""), "");
        assert_eq!(parse_host("not a url"), "");
        // Schemeless input is not a URL per RFC 3986; url crate refuses.
        assert_eq!(parse_host("example.com"), "");
    }

    #[test]
    fn parse_host_empty_when_scheme_carries_no_host() {
        assert_eq!(parse_host("mailto:someone@example.com"), "");
    }

    #[test]
    fn dt_to_ms_maps_absent_to_zero() {
        assert_eq!(dt_to_ms(None), 0);
    }

    #[test]
    fn dt_to_ms_converts_to_epoch_millis() {
        let dt = Utc.timestamp_millis_opt(1_234_567_890_123).unwrap();
        assert_eq!(dt_to_ms(Some(dt)), 1_234_567_890_123);
    }
}
