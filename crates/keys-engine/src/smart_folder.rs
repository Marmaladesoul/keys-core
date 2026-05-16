//! CRUD operations against the `smart_folder` table.
//!
//! Reads and writes go through here so [`crate::engine::Engine`] stays
//! focused on lifecycle while the SQL lives next to the schema it
//! touches. Mirrors the layout used for the entry-read paths in
//! [`crate::reads`].
//!
//! ## Timestamps
//!
//! `created_at` and `modified_at` are written as the current wall-clock
//! time in milliseconds since the Unix epoch (UTC). The engine reads
//! that off [`std::time::SystemTime::now`]; tests that need
//! determinism should compare against a `before <= got <= after`
//! window rather than an exact value.
//!
//! ## Evaluable flag
//!
//! [`Predicate::is_evaluable`] is invoked at write time and the
//! `bool` result is persisted to the `evaluable` column. That keeps
//! the sidebar UI a single column-pluck away from "can I run this
//! folder?" without re-walking the tree per render.

use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

use crate::error::EngineError;
use crate::model::{EntrySummary, Pagination, SmartFolder};
use crate::predicate::Predicate;
use crate::predicate_sql::{self, CompileError};
use crate::reads;

/// SQL fragment naming the columns [`row_to_smart_folder`] expects.
/// Kept in a constant so `list_all` and `get_one` stay in lock-step.
const SMART_FOLDER_COLUMNS: &str =
    "id, name, predicate_json, version, evaluable, created_at, modified_at";

pub(crate) fn list_all(conn: &Connection) -> Result<Vec<SmartFolder>, EngineError> {
    let sql = format!("SELECT {SMART_FOLDER_COLUMNS} FROM smart_folder ORDER BY id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], row_to_smart_folder)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub(crate) fn get_one(conn: &Connection, id: i64) -> Result<Option<SmartFolder>, EngineError> {
    let sql = format!("SELECT {SMART_FOLDER_COLUMNS} FROM smart_folder WHERE id = ?1");
    let result = conn
        .query_row(&sql, params![id], row_to_smart_folder)
        .optional()?;
    Ok(result)
}

pub(crate) fn create(
    conn: &mut Connection,
    name: &str,
    predicate: &Predicate,
) -> Result<i64, EngineError> {
    let predicate_json = serde_json::to_string(predicate).map_err(serialise_to_sqlite)?;
    let evaluable = predicate.is_evaluable();
    let now = now_millis();

    conn.execute(
        "INSERT INTO smart_folder \
            (name, predicate_json, version, evaluable, created_at, modified_at) \
         VALUES (?1, ?2, 1, ?3, ?4, ?4)",
        params![name, predicate_json, i64::from(evaluable), now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub(crate) fn update(
    conn: &mut Connection,
    id: i64,
    name: &str,
    predicate: &Predicate,
) -> Result<(), EngineError> {
    let predicate_json = serde_json::to_string(predicate).map_err(serialise_to_sqlite)?;
    let evaluable = predicate.is_evaluable();
    let now = now_millis();

    let rows = conn.execute(
        "UPDATE smart_folder \
            SET name = ?1, predicate_json = ?2, evaluable = ?3, modified_at = ?4 \
            WHERE id = ?5",
        params![name, predicate_json, i64::from(evaluable), now, id],
    )?;
    if rows == 0 {
        return Err(EngineError::NotFound {
            entity: "smart_folder",
        });
    }
    Ok(())
}

pub(crate) fn delete(conn: &mut Connection, id: i64) -> Result<(), EngineError> {
    let rows = conn.execute("DELETE FROM smart_folder WHERE id = ?1", params![id])?;
    if rows == 0 {
        return Err(EngineError::NotFound {
            entity: "smart_folder",
        });
    }
    Ok(())
}

fn row_to_smart_folder(row: &rusqlite::Row<'_>) -> rusqlite::Result<SmartFolder> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let predicate_json: String = row.get(2)?;
    let version: i64 = row.get(3)?;
    let evaluable: i64 = row.get(4)?;
    let created_at: i64 = row.get(5)?;
    let modified_at: i64 = row.get(6)?;

    let predicate: Predicate = serde_json::from_str(&predicate_json).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(err))
    })?;

    Ok(SmartFolder {
        id,
        name,
        predicate,
        version: u32::try_from(version).unwrap_or(1),
        evaluable: evaluable != 0,
        created_at,
        modified_at,
    })
}

/// Current wall-clock time as milliseconds since the Unix epoch.
///
/// Saturates to `i64::MAX` for the date-after-292M-years case rather
/// than panicking — the alternative would be a hard error on a clock
/// that's set absurdly far into the future, which isn't worth
/// surfacing on the write path.
/// Wrap a [`serde_json`] serialisation failure as a
/// `rusqlite::Error` so it flows through the same `?` ladder as the
/// SQL-side errors. Practically only triggers for non-finite
/// `EntropyBelow.bits` values (NaN / ±Inf), which `serde_json` refuses
/// to emit — callers writing those have a bug.
fn serialise_to_sqlite(err: serde_json::Error) -> EngineError {
    EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Convert a [`CompileError`] into the engine-level error type.
///
/// [`CompileError::NotEvaluable`] maps to
/// [`EngineError::NotEvaluable`]. The empty-junction case
/// ([`CompileError::EmptyAndOr`]) is a producer bug — the predicate
/// went through `is_evaluable` checks but had an empty `And` / `Or` /
/// tag list — and we surface it as `NotEvaluable` too rather than
/// inventing a third variant for an authoring-time mistake the UI
/// should have caught.
fn compile_err_to_engine(_err: CompileError) -> EngineError {
    EngineError::NotEvaluable
}

/// Evaluate `predicate` against the entry table and return matching
/// [`EntrySummary`] rows. Ordering and pagination match
/// [`crate::reads::list_entries`].
pub(crate) fn entries_matching(
    conn: &Connection,
    predicate: &Predicate,
    page: Pagination,
) -> Result<Vec<EntrySummary>, EngineError> {
    let compiled =
        predicate_sql::compile(predicate, now_millis()).map_err(compile_err_to_engine)?;
    let (limit, offset) = reads::clamp_page(page);

    let summary_columns = reads::SUMMARY_COLUMNS;
    let sql = format!(
        "SELECT {summary_columns} FROM entry WHERE {where_sql} \
         ORDER BY modified_at DESC, uuid ASC \
         LIMIT ? OFFSET ?",
        where_sql = compiled.where_sql,
    );

    let mut params: Vec<rusqlite::types::Value> = compiled.params;
    params.push(rusqlite::types::Value::Integer(limit));
    params.push(rusqlite::types::Value::Integer(offset));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(params), reads::row_to_summary)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Evaluate `predicate` and return the count of matching entries.
pub(crate) fn count_matching(conn: &Connection, predicate: &Predicate) -> Result<u64, EngineError> {
    let compiled =
        predicate_sql::compile(predicate, now_millis()).map_err(compile_err_to_engine)?;
    let sql = format!(
        "SELECT COUNT(*) FROM entry WHERE {where_sql}",
        where_sql = compiled.where_sql,
    );
    let count: i64 = conn.query_row(&sql, params_from_iter(compiled.params), |r| r.get(0))?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Resolve a smart folder by id and evaluate its predicate.
///
/// `NotFound` if the id does not exist; `NotEvaluable` if the folder's
/// `evaluable` column is `false` (i.e. the persisted predicate
/// contains a [`Predicate::Unknown`] node).
pub(crate) fn smart_folder_entries(
    conn: &Connection,
    folder_id: i64,
    page: Pagination,
) -> Result<Vec<EntrySummary>, EngineError> {
    let folder = get_one(conn, folder_id)?.ok_or(EngineError::NotFound {
        entity: "smart_folder",
    })?;
    if !folder.evaluable {
        return Err(EngineError::NotEvaluable);
    }
    entries_matching(conn, &folder.predicate, page)
}

/// Count variant of [`smart_folder_entries`].
pub(crate) fn smart_folder_count(conn: &Connection, folder_id: i64) -> Result<u64, EngineError> {
    let folder = get_one(conn, folder_id)?.ok_or(EngineError::NotFound {
        entity: "smart_folder",
    })?;
    if !folder.evaluable {
        return Err(EngineError::NotEvaluable);
    }
    count_matching(conn, &folder.predicate)
}
