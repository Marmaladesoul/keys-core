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
    Migration {
        version: 7,
        name: "owner_conflict_rows",
        sql: include_str!("migrations/0007_owner_conflict_rows.sql"),
    },
    Migration {
        version: 8,
        name: "entry_previous_parent",
        sql: include_str!("migrations/0008_entry_previous_parent.sql"),
    },
    Migration {
        version: 9,
        name: "conflict_entry_attachment",
        sql: include_str!("migrations/0009_conflict_entry_attachment.sql"),
    },
    Migration {
        version: 10,
        name: "entry_location_changed",
        sql: include_str!("migrations/0010_entry_location_changed.sql"),
    },
    Migration {
        version: 11,
        name: "group_location_changed",
        sql: include_str!("migrations/0011_group_location_changed.sql"),
    },
    Migration {
        version: 12,
        name: "persistence_watermark",
        sql: include_str!("migrations/0012_persistence_watermark.sql"),
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

    /// Migration 0012's watermark triggers must cover every table whose
    /// rows project into the KDBX — and must NOT cover the tables whose
    /// writes are mirror-local (bumping on those would either re-dirty
    /// every save, e.g. the save-time blob GC, or owe phantom writes).
    ///
    /// A future migration adding a projected table MUST add its three
    /// `mutation_seq_*` triggers (and add the table to `PROJECTED`
    /// here); adding a mirror-local table goes in `MIRROR_LOCAL`. A
    /// table in neither list fails the test — the decision is forced,
    /// never silently defaulted.
    #[test]
    fn watermark_trigger_coverage_is_complete() {
        // Tables whose rows project into the KDBX. `setting` is special
        // (only `meta.%` keys project) and asserted separately.
        const PROJECTED: &[&str] = &[
            "entry",
            "entry_attachment",
            "entry_custom_data",
            "entry_custom_field",
            "entry_history",
            "entry_protected",
            "entry_tag",
            "group",
            "meta_custom_data",
            "meta_custom_icon",
            "meta_deleted_object",
            "tag",
        ];
        // Mirror-local tables: never projected, must not bump.
        const MIRROR_LOCAL: &[&str] = &[
            "attachment_blob", // content-addressed pool; save-time GC must not re-dirty
            "conflict_entry",
            "conflict_entry_attachment",
            "conflict_entry_custom_field",
            "conflict_entry_protected",
            "smart_folder",   // engine-local sidebar state
            "schema_version", // migration bookkeeping
            "setting",        // handled by the conditional meta.% triggers
        ];

        let mut conn = fresh_conn();
        apply_pending(&mut conn).expect("apply");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();

        let trigger_count = |table: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'trigger' AND tbl_name = ?1 AND name LIKE 'mutation_seq_%'",
                params![table],
                |r| r.get(0),
            )
            .expect("trigger count")
        };

        for table in &tables {
            let table = table.as_str();
            if PROJECTED.contains(&table) {
                assert_eq!(
                    trigger_count(table),
                    3,
                    "projected table `{table}` must carry INSERT/UPDATE/DELETE \
                     mutation_seq triggers"
                );
            } else if MIRROR_LOCAL.contains(&table) {
                // `setting` carries the three conditional meta.% triggers;
                // every other mirror-local table carries none.
                let want = if table == "setting" { 3 } else { 0 };
                assert_eq!(
                    trigger_count(table),
                    want,
                    "mirror-local table `{table}` has unexpected mutation_seq triggers"
                );
            } else {
                panic!(
                    "table `{table}` is in neither PROJECTED nor MIRROR_LOCAL — \
                     decide whether its rows project into the KDBX and add it \
                     (plus triggers in a new migration if projected)"
                );
            }
        }
    }

    /// Migration 0012's watermark seeding is fail-safe asymmetric: a
    /// database that already holds vault content when the migration
    /// lands must come up DIRTY (its divergence from the KDBX is
    /// unknowable, and false-clean loses an unsaved mutation), while a
    /// brand-new database comes up settled.
    #[test]
    fn watermark_upgrade_seeds_existing_content_dirty() {
        let read_seq = |conn: &Connection, key: &str| -> i64 {
            conn.query_row(
                "SELECT value FROM setting WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .expect("read watermark row")
        };

        // Fresh database: every migration applies in one pass, no
        // content exists at 0012 time → settled 0/0.
        let mut fresh = fresh_conn();
        apply_pending(&mut fresh).expect("apply fresh");
        assert_eq!(read_seq(&fresh, "persistence.mutation_seq"), 0);
        assert_eq!(read_seq(&fresh, "persistence.persisted_seq"), 0);

        // Upgrade: build a pre-0012 database (migrations v1..v11 only,
        // replaying the applier's own steps), give it vault content,
        // then run the real applier for the remainder → dirty 1/0.
        let mut upgraded = fresh_conn();
        upgraded
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (\
                    version INTEGER NOT NULL PRIMARY KEY\
                 )",
            )
            .expect("bootstrap schema_version");
        for migration in MIGRATIONS.iter().filter(|m| m.version <= 11) {
            upgraded
                .execute_batch(migration.sql)
                .expect("apply pre-watermark migration");
            upgraded
                .execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![migration.version],
                )
                .expect("record version");
        }
        upgraded
            .execute(
                "INSERT INTO \"group\" (uuid, parent_uuid, name, created_at, modified_at)
                 VALUES ('root-uuid', NULL, 'Root', 0, 0)",
                [],
            )
            .expect("seed root group");

        apply_pending(&mut upgraded).expect("apply remainder");
        assert_eq!(
            read_seq(&upgraded, "persistence.mutation_seq"),
            1,
            "an upgraded mirror with existing content must read dirty"
        );
        assert_eq!(read_seq(&upgraded, "persistence.persisted_seq"), 0);
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
