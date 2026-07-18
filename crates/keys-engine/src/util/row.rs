//! Column decoders shared by the modules that read entry/group rows
//! back out of the mirror (`reads`, `projection`).
//!
//! Each of these existed as an identical private copy in more than one
//! module — `parse_uuid_col` verbatim in two, `parse_optional_uuid_col`
//! named in one and inlined four times in the other, and the
//! built-in-icon saturation three times. They decode a single column
//! the same way regardless of which row it came from, so they belong in
//! one place.
//!
//! Scope note: this is deliberately *only* the column-level decoders
//! that were byte-identical across modules. The row-to-model builders
//! themselves (`build_entry_from_row`, `reconstruct_peer_entry`, …)
//! genuinely diverge — different column sets, different protected-value
//! policies, different second-flooring on timestamps — and are left
//! where they are.

use rusqlite::Row;
use rusqlite::types::Type;
use uuid::Uuid;

/// Decode a required `TEXT` uuid column. A value that isn't a valid
/// uuid surfaces as `FromSqlConversionFailure` so the caller's `?`
/// funnels it through `EngineError::Sqlite` rather than panicking.
pub(crate) fn parse_uuid_col(row: &Row<'_>, idx: usize) -> rusqlite::Result<Uuid> {
    let s: String = row.get(idx)?;
    Uuid::parse_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, Type::Text, Box::new(e)))
}

/// Decode a nullable `TEXT` uuid column: `NULL` → `None`, a present but
/// unparseable value → `FromSqlConversionFailure` (as
/// [`parse_uuid_col`]).
pub(crate) fn parse_optional_uuid_col(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<Uuid>> {
    row.get::<_, Option<String>>(idx)?
        .map(|s| {
            Uuid::parse_str(&s).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(idx, Type::Text, Box::new(e))
            })
        })
        .transpose()
}

/// Saturate a persisted `icon_index` into the `u32` the model carries.
///
/// `NULL` → `0` (the standard "key" icon). Ingest bounded the value into
/// `u32` at write time, so anything outside that range here is an ingest
/// invariant violation, not corruption-class data loss — a
/// `debug_assert!` trips it in CI while production falls back to the
/// default icon rather than aborting a whole read. This is the built-in
/// path only; a custom-icon uuid overrides it at the call site
/// (`reads::icon_ref_from`), which is why the caller keeps that
/// branching.
pub(crate) fn builtin_icon_index(icon_index: Option<i64>) -> u32 {
    let idx = icon_index.unwrap_or(0);
    debug_assert!(
        (0..=i64::from(u32::MAX)).contains(&idx),
        "icon_index {idx} out of u32 range — ingest invariant violated",
    );
    u32::try_from(idx).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// One-row, one-column query harness so the decoders can be exercised
    /// against a real `rusqlite::Row` rather than a mock.
    fn decode<T>(
        sql: &str,
        f: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = Connection::open_in_memory().expect("open");
        conn.query_row(sql, [], f)
    }

    #[test]
    fn parse_uuid_col_reads_a_valid_uuid() {
        let want = Uuid::from_u128(0x1234_5678);
        let got = decode(&format!("SELECT '{want}'"), |r| parse_uuid_col(r, 0)).expect("decode");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_uuid_col_rejects_a_non_uuid() {
        let err = decode("SELECT 'not-a-uuid'", |r| parse_uuid_col(r, 0)).unwrap_err();
        assert!(matches!(
            err,
            rusqlite::Error::FromSqlConversionFailure(0, Type::Text, _)
        ));
    }

    #[test]
    fn parse_optional_uuid_col_maps_null_to_none() {
        let got = decode("SELECT NULL", |r| parse_optional_uuid_col(r, 0)).expect("decode");
        assert_eq!(got, None);
    }

    #[test]
    fn parse_optional_uuid_col_reads_a_present_value() {
        let want = Uuid::from_u128(0x9abc);
        let got = decode(&format!("SELECT '{want}'"), |r| {
            parse_optional_uuid_col(r, 0)
        })
        .expect("decode");
        assert_eq!(got, Some(want));
    }

    #[test]
    fn parse_optional_uuid_col_rejects_a_present_non_uuid() {
        let err = decode("SELECT 'nope'", |r| parse_optional_uuid_col(r, 0)).unwrap_err();
        assert!(matches!(
            err,
            rusqlite::Error::FromSqlConversionFailure(0, Type::Text, _)
        ));
    }

    #[test]
    fn builtin_icon_index_defaults_null_to_zero() {
        assert_eq!(builtin_icon_index(None), 0);
    }

    #[test]
    fn builtin_icon_index_passes_through_in_range() {
        assert_eq!(builtin_icon_index(Some(42)), 42);
        assert_eq!(builtin_icon_index(Some(i64::from(u32::MAX))), u32::MAX);
    }

    #[test]
    fn builtin_icon_index_saturates_out_of_range_to_zero() {
        // Out-of-range trips the debug_assert in debug builds, so only
        // assert the release-path saturation when assertions are off.
        if !cfg!(debug_assertions) {
            assert_eq!(builtin_icon_index(Some(-1)), 0);
            assert_eq!(builtin_icon_index(Some(i64::from(u32::MAX) + 1)), 0);
        }
    }
}
