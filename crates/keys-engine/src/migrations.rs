//! Schema migrations for the `keys-engine` `SQLCipher` database.
//!
//! Migrations are an ordered, append-only list of `(version, name, sql)`
//! records held in the [`MIGRATIONS`] array. Each is applied inside a
//! transaction; the `schema_version` table tracks the highest applied
//! version. [`apply_pending`] is idempotent: it scans the array, applies
//! anything strictly above the recorded version, and rejects databases
//! whose recorded version exceeds the binary's max known version.
//!
//! ## Adding a migration
//!
//! Append a new [`Migration`] entry to [`MIGRATIONS`] with a strictly
//! higher `version` and never edit a previously-shipped migration. Old
//! files in the wild have already executed v1; rewriting v1's SQL
//! changes nothing about their schema and confuses future readers.

use rusqlite::{Connection, params};

/// A single, atomically-applied schema migration step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Strictly increasing version number. v1 is the first migration.
    pub version: u32,
    /// Human-readable name. Surfaces in error messages and tests.
    pub name: &'static str,
    /// SQL body. Run inside a transaction via [`Connection::execute_batch`].
    pub sql: &'static str,
}

/// Ordered list of all migrations the binary knows about.
///
/// Order MUST match the `version` field. The last entry's `version` is
/// the binary's max-known schema version.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_schema",
        sql: include_str!("migrations/0001_initial_schema.sql"),
    },
    Migration {
        version: 2,
        name: "entry_custom_field",
        sql: include_str!("migrations/0002_entry_custom_field.sql"),
    },
    Migration {
        version: 3,
        name: "meta",
        sql: include_str!("migrations/0003_meta.sql"),
    },
    Migration {
        version: 4,
        name: "group_sort_order",
        sql: include_str!("migrations/0004_group_sort_order.sql"),
    },
    Migration {
        version: 5,
        name: "entry_has_totp",
        sql: include_str!("migrations/0005_entry_has_totp.sql"),
    },
    Migration {
        version: 6,
        name: "entry_custom_data",
        sql: include_str!("migrations/0006_entry_custom_data.sql"),
    },
];

/// Errors surfaced by the migration runner.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// The database has been migrated to a schema version newer than
    /// anything this binary knows how to read. Refuse to open; an older
    /// binary touching a newer schema is the path to data loss.
    #[error(
        "database schema version {file_current} is newer than this binary supports (max {binary_max}); upgrade the application"
    )]
    SchemaTooNew {
        /// Highest version known to this binary.
        binary_max: u32,
        /// Version recorded in the database file.
        file_current: u32,
    },

    /// A SQLite-level error from `rusqlite`.
    #[error("sqlite error during migration: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Apply every migration whose version is strictly greater than the
/// version recorded in `schema_version`. Each migration runs in its own
/// transaction.
///
/// # Errors
///
/// - [`MigrationError::SchemaTooNew`] if the database has been migrated
///   past anything this binary knows about.
/// - [`MigrationError::Sqlite`] for any underlying `rusqlite` error.
pub fn apply_pending(conn: &mut Connection) -> Result<(), MigrationError> {
    // The `schema_version` table is itself part of the migration
    // infrastructure, not migration v1. Create it idempotently so a
    // fresh DB has somewhere to record version 0 (i.e. no migrations
    // yet applied) and an existing DB doesn't conflict.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (\
            version INTEGER NOT NULL PRIMARY KEY\
         )",
    )?;

    let current: u32 = {
        let raw: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        u32::try_from(raw).unwrap_or(0)
    };

    let binary_max = MIGRATIONS.last().map_or(0, |m| m.version);

    if current > binary_max {
        return Err(MigrationError::SchemaTooNew {
            binary_max,
            file_current: current,
        });
    }

    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![migration.version],
        )?;
        tx.commit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        Connection::open_in_memory().expect("open in-memory db")
    }

    #[test]
    fn migrations_array_is_strictly_increasing_and_starts_at_one() {
        assert!(!MIGRATIONS.is_empty(), "must ship at least one migration");
        assert_eq!(MIGRATIONS[0].version, 1, "first migration is v1");
        for pair in MIGRATIONS.windows(2) {
            assert!(
                pair[1].version > pair[0].version,
                "migration versions must strictly increase: {:?} -> {:?}",
                pair[0],
                pair[1],
            );
        }
    }

    #[test]
    fn apply_pending_records_max_version() {
        let mut conn = fresh_conn();
        apply_pending(&mut conn).expect("apply");
        let v: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .expect("query");
        assert_eq!(
            u32::try_from(v).expect("non-negative"),
            MIGRATIONS.last().unwrap().version,
        );
    }

    #[test]
    fn apply_pending_is_idempotent() {
        let mut conn = fresh_conn();
        apply_pending(&mut conn).expect("first");
        apply_pending(&mut conn).expect("second");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .expect("query");
        assert_eq!(
            usize::try_from(count).expect("non-negative"),
            MIGRATIONS.len()
        );
    }

    #[test]
    fn apply_pending_rejects_schema_newer_than_binary() {
        let mut conn = fresh_conn();
        apply_pending(&mut conn).expect("apply");
        let future = MIGRATIONS.last().unwrap().version + 1;
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![future],
        )
        .expect("insert future");

        let err = apply_pending(&mut conn).expect_err("must reject");
        match err {
            MigrationError::SchemaTooNew {
                binary_max,
                file_current,
            } => {
                assert_eq!(binary_max, MIGRATIONS.last().unwrap().version);
                assert_eq!(file_current, future);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }
}
