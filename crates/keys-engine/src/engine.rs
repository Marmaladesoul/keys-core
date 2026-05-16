//! [`Engine`] — `SQLCipher`-backed `SQLite` handle.
//!
//! Holds an open [`rusqlite::Connection`] keyed via `PRAGMA key` using a
//! raw 32-byte key supplied by a [`KeyProvider`]. The engine never
//! derives a key from a passphrase — the input is already random bytes
//! sourced from the platform Keychain, so the raw-hex BLOB-literal
//! form (`PRAGMA key = "x'<hex>'"`) is used, bypassing `SQLCipher`'s
//! built-in PBKDF2 key derivation.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::protector::FieldProtector;
use rusqlite::{Connection, OpenFlags};
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::EngineError;
use crate::fingerprint;
use crate::ingest;
use crate::key_provider::{DbKey, KeyProvider};
use crate::migrations;
use crate::model::{EntryFull, EntrySummary, GroupNode, HistoricEntry, Pagination, SmartFolder};
use crate::predicate::Predicate;
use crate::projection;
use crate::save::{self, SelfWriteSignature};
use crate::strength::{self, Strength};

/// `SQLCipher`-backed `SQLite` engine handle.
///
/// Construct via [`Engine::open`]. Drop via [`Engine::close`] (or just
/// let it fall out of scope — `Drop` on the inner [`Connection`] does
/// the same finalisation, but `close` lets callers observe any
/// finalisation error).
#[derive(Debug)]
pub struct Engine {
    conn: Connection,
    /// Per-vault HMAC key used to derive
    /// [`entry.password_fingerprint`](crate::fingerprint::fingerprint)
    /// values for duplicate-password detection. Generated on first
    /// open, persisted (encrypted at rest by `SQLCipher`) in the
    /// `setting` table under the `fingerprint_key` row, and reloaded
    /// on every subsequent open. Zeroed on drop.
    fingerprint_key: Zeroizing<[u8; 32]>,
    /// Session-key provider used by ingest (and the future reveal /
    /// mutation paths) to AES-GCM-wrap protected field plaintexts
    /// before they land in `entry_protected.wrapped_blob`.
    ///
    /// Same trait that `keepass-core::Kdbx::open` takes, so a single
    /// frontend-side implementation can drive both the in-memory
    /// kdbx wrap layer and the engine's persisted wrap. Stored as
    /// `Arc<dyn FieldProtector>` because the trait is also held by
    /// the unlocked Kdbx and by future per-thread reveal paths.
    field_protector: Arc<dyn FieldProtector>,
    /// `(mtime, size)` of the most recent KDBX file written by
    /// [`Engine::save_to_kdbx`], or `None` if this engine has never
    /// written one. Consumed in task 2.6 by the watcher integration to
    /// distinguish our own writes from foreign edits.
    last_self_write: Option<SelfWriteSignature>,
}

impl Engine {
    /// Open (or create) a `SQLCipher`-encrypted `SQLite` database at `path`.
    ///
    /// Asks `key_provider` for the 32-byte raw key once, applies it via
    /// `PRAGMA key`, then runs a sanity query against `sqlite_master`
    /// to validate the key. A wrong key surfaces as
    /// [`EngineError::WrongKey`].
    ///
    /// If `path` does not exist the file is created. Parent directories
    /// must already exist — the engine does not `mkdir -p`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::KeyProvider`] if the provider can't produce a key.
    /// - [`EngineError::WrongKey`] if the supplied key doesn't decrypt
    ///   the existing database.
    /// - [`EngineError::Sqlite`] for any other rusqlite-level failure.
    /// - [`EngineError::Io`] currently unused on this path but reserved.
    pub fn open(
        path: &Path,
        key_provider: &dyn KeyProvider,
        field_protector: Arc<dyn FieldProtector>,
    ) -> Result<Self, EngineError> {
        let key = key_provider.acquire_db_key()?;

        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        apply_key(&conn, &key)?;
        drop(key);

        // Sanity-query `sqlite_master`. On an existing file with a
        // wrong key, `SQLCipher` returns `SQLITE_NOTADB` the moment it
        // tries to decrypt the first page. On a brand-new file the
        // master table is empty but legible — no error — and the run
        // through `apply_pending` below performs the first page write
        // that binds the chosen key to the file's encrypted header.
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(_) => {}
            Err(err) if is_wrong_key(&err) => return Err(EngineError::WrongKey),
            Err(err) => return Err(EngineError::Sqlite(err)),
        }

        // Enforce declared foreign-key constraints. SQLite ships with
        // FK enforcement OFF by default for legacy reasons; the engine
        // unconditionally opts in.
        conn.execute_batch("PRAGMA foreign_keys = ON")?;

        migrations::apply_pending(&mut conn)?;

        let fingerprint_key = ensure_fingerprint_key(&mut conn)?;

        Ok(Self {
            conn,
            fingerprint_key,
            field_protector,
            last_self_write: None,
        })
    }

    /// Replace this engine's vault tables with the contents of `kdbx`.
    ///
    /// Walks groups → entries → history → attachments, `INSERTing` rows
    /// in a single transaction. Computes the strength bucket, entropy
    /// estimate, and HMAC fingerprint of every entry's password.
    /// AES-GCM-wraps every protected field plaintext under a session
    /// key fetched from this engine's [`FieldProtector`] and writes the
    /// blob to `entry_protected`. Splits the entry's tag list into
    /// distinct rows in `tag` / `entry_tag`. Content-addresses
    /// attachment bytes via SHA-256 into `attachment_blob`.
    ///
    /// Idempotent: the pre-walk step `DELETE`s every vault row, so a
    /// re-ingest produces the same final state regardless of what was
    /// there before. Schema (tables, indices, triggers, settings) is
    /// preserved.
    ///
    /// Phase 2.4 / 2.5 will land the reverse direction (projection +
    /// serialise). Mutation semantics — adding / editing / deleting a
    /// single entry without rewriting the whole table — are Phase 4.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Ingest`] wrapping an
    ///   [`crate::IngestError::Kdbx`] if the kdbx side refuses to
    ///   expose plaintext-protected vault contents.
    /// - [`EngineError::Ingest`] wrapping an
    ///   [`crate::IngestError::Wrap`] /
    ///   [`crate::IngestError::SessionKey`] if the wrap pass fails.
    /// - [`EngineError::Sqlite`] for transaction / INSERT failures.
    pub fn ingest_from_kdbx(&mut self, kdbx: &Kdbx<Unlocked>) -> Result<(), EngineError> {
        ingest::ingest(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            kdbx,
        )
    }

    /// Project this engine's `SQLite` mirror back into a
    /// [`keepass_core::model::Vault`].
    ///
    /// Inverse of [`Engine::ingest_from_kdbx`]. Reads every group,
    /// entry, protected-field blob, attachment, tag, and history
    /// snapshot row inside a single read transaction; AES-GCM-unwraps
    /// protected blobs under this engine's
    /// [`keepass_core::protector::FieldProtector`] so the returned
    /// [`keepass_core::model::Vault`] carries plaintext on
    /// [`Entry::password`](keepass_core::model::Entry::password) and on
    /// each protected
    /// [`CustomField::value`](keepass_core::model::CustomField::value).
    /// That's the shape the upcoming serialise path (task 2.5)
    /// consumes, and the shape round-trip property tests (task 2.7)
    /// compare against.
    ///
    /// The projected vault carries no per-vault metadata beyond
    /// `recycle_bin_uuid` / `recycle_bin_enabled` — `Meta` fields like
    /// `database_name`, `generator`, `custom_icons`, etc. are not
    /// persisted in the v1 schema. The serialise path is responsible
    /// for re-applying them from a separate source (the live `Kdbx`
    /// handle's meta block).
    ///
    /// # Errors
    ///
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::Unwrap`] if a protected blob fails
    ///   AES-GCM open under the session key.
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::SessionKey`] if the protector
    ///   refuses to release a session key.
    /// - [`EngineError::Projection`] wrapping
    ///   [`crate::ProjectionError::SchemaInvariant`] if the persisted
    ///   shape violates an invariant the projection relies on (e.g.
    ///   no root group).
    /// - [`EngineError::Sqlite`] for `SELECT` failures.
    pub fn project_to_vault(&self) -> Result<keepass_core::model::Vault, EngineError> {
        projection::project(&self.conn, &*self.field_protector)
    }

    /// Project the engine's `SQLite` mirror into a fresh
    /// [`keepass_core::model::Vault`], splice it into `kdbx`,
    /// re-encrypt under `kdbx`'s existing crypto envelope, and
    /// atomically write the resulting bytes to `path`.
    ///
    /// Records the post-write `(mtime, size)` on `self` as a
    /// [`SelfWriteSignature`], readable via
    /// [`Engine::last_self_write`]. Task 2.6 lands the consumer that
    /// matches an observed change against this signature so the
    /// watcher can suppress fires from our own writes.
    ///
    /// ## Meta preservation
    ///
    /// The v1 schema persists only two fields of
    /// [`keepass_core::model::Meta`] (the recycle-bin pair); every
    /// other field — `database_name`, `custom_icons`, `custom_data`,
    /// `unknown_xml`, etc. — is taken from the live `kdbx` handle and
    /// carried forward verbatim onto the projected vault before the
    /// splice. Tombstones (`deleted_objects`) get the same treatment.
    ///
    /// ## Atomic write
    ///
    /// Bytes are written to a sibling tempfile, flushed and
    /// `sync_all`'d, then `rename(2)`'d over `path`. The parent
    /// directory is then `sync_all`'d on a best-effort basis to make
    /// the directory entry durable.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Projection`] if projection fails.
    /// - [`EngineError::Serialise`] if `keepass-core`'s `save_to_bytes`
    ///   rejects the spliced vault.
    /// - [`EngineError::Io`] for tempfile creation / write / rename /
    ///   stat failures.
    pub fn save_to_kdbx(
        &mut self,
        path: &Path,
        kdbx: &mut Kdbx<Unlocked>,
    ) -> Result<(), EngineError> {
        save::save(self, path, kdbx)
    }

    /// The `(mtime, size)` of the most recent KDBX file this engine
    /// wrote, or `None` if no save has happened yet on this handle.
    #[must_use]
    pub fn last_self_write(&self) -> Option<SelfWriteSignature> {
        self.last_self_write
    }

    /// Crate-internal setter used by [`crate::save::save`] to record
    /// the signature after a successful atomic write.
    pub(crate) fn set_last_self_write(&mut self, signature: SelfWriteSignature) {
        self.last_self_write = Some(signature);
    }

    /// One-shot: did `(observed_mtime, observed_size)` come from our own
    /// most recent [`Engine::save_to_kdbx`]?
    ///
    /// Returns `true` and clears the stored signature if it matches
    /// exactly. Returns `false` (and leaves state unchanged) if there's
    /// no signature stored, or if either component diverges.
    ///
    /// Intended for the Phase 4 file-watcher integration: when the
    /// watcher fires on a change to the KDBX path, it stats the file
    /// and asks "was that me?". If yes, the spurious external-change
    /// notification is suppressed. If no, the watcher proceeds with
    /// the merge / reload flow.
    ///
    /// Equality on [`SystemTime`] is exact (no fuzzy comparison). The
    /// signature is captured immediately post-rename via
    /// [`std::fs::Metadata::modified`]; a watcher that stats with the
    /// same call should observe bit-identical timestamps. Any precision
    /// mismatch (e.g. watcher truncates to seconds while engine keeps
    /// nanoseconds) is a bug we want to surface, not paper over with a
    /// tolerance window.
    ///
    /// Unlike the Swift counterpart (`consumePendingSelfWriteSignature`
    /// on `DatabaseDocument`), this method takes the pre-observed
    /// `(mtime, size)` directly rather than re-statting the file — the
    /// caller already has the stat result from its watcher event, so we
    /// avoid a redundant syscall and the API stays IO-free. Also note
    /// no 5-second TTL: the Swift version clears the signature on a
    /// timer to bound the race window; the Rust side leaves TTL
    /// (if needed) to the caller, since the engine has no async
    /// runtime to schedule the clear on.
    pub fn consume_self_write_signature(
        &mut self,
        observed_mtime: SystemTime,
        observed_size: u64,
    ) -> bool {
        let expected = SelfWriteSignature {
            mtime: observed_mtime,
            size: observed_size,
        };
        if self.last_self_write == Some(expected) {
            self.last_self_write = None;
            true
        } else {
            false
        }
    }

    /// HMAC-SHA-256 a plaintext under this vault's persistent
    /// fingerprint key.
    ///
    /// The returned 32 bytes are deterministic for a given (vault,
    /// plaintext) pair across reopens, but differ across vaults
    /// because each vault has its own random fingerprint key. Intended
    /// for populating the `entry.password_fingerprint` column and for
    /// duplicate-password queries.
    #[must_use]
    pub fn fingerprint(&self, plaintext: &[u8]) -> [u8; 32] {
        fingerprint::fingerprint(&self.fingerprint_key, plaintext)
    }

    /// Estimate the strength of a password.
    ///
    /// Pure function — no engine state is touched. Exposed as a method
    /// for API symmetry with [`Engine::fingerprint`] so callers can
    /// drive both off a single handle. See [`crate::strength()`] for the
    /// algorithm.
    #[must_use]
    pub fn strength(&self, password: &str) -> Strength {
        strength::strength(password)
    }

    /// Close the underlying connection, finalising any pending work.
    ///
    /// Consumes `self`. On success the connection is gone. On failure
    /// the rusqlite-returned `(Connection, Error)` pair is collapsed
    /// into a plain [`EngineError::Sqlite`] — the half-closed
    /// connection is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] if `SQLite` can't finalise the
    /// connection cleanly.
    pub fn close(self) -> Result<(), EngineError> {
        self.conn
            .close()
            .map_err(|(_, err)| EngineError::Sqlite(err))
    }

    // ────────────────────────────────────────────────────────────────────
    // Query API — Phase 1 task 1.5 stubs.
    //
    // Type signatures are stable from this point. Bodies land in
    // Phase 3 tasks 3.1–3.8. See `docs/query-surface.md` for the full
    // surface description and per-method semantics.
    // ────────────────────────────────────────────────────────────────────

    /// List entries, optionally filtered to a single group.
    ///
    /// `group = None` → all entries globally; `Some(uuid)` → entries
    /// whose `group_uuid` equals the supplied UUID. Results are
    /// paginated via `page`. Ordering is by `modified_at DESC` (most
    /// recently modified first); callers wanting other orderings get
    /// them via smart folders or later sort-aware variants.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn list_entries(
        &self,
        group: Option<Uuid>,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::list_entries(&self.conn, group, page)
    }

    /// Fetch a full entry by UUID.
    ///
    /// Returns `Ok(None)` if no entry with the given UUID exists.
    /// Returns `Ok(Some(_))` for both live and recycle-bin entries;
    /// `is_recycled` discriminates.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn entry(&self, uuid: Uuid) -> Result<Option<EntryFull>, EngineError> {
        crate::reads::entry(&self.conn, uuid)
    }

    /// Count entries, optionally filtered to a single group.
    ///
    /// `group = None` → total entry count; `Some(uuid)` → count of
    /// direct children of that group.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn entry_count(&self, group: Option<Uuid>) -> Result<u64, EngineError> {
        crate::reads::entry_count(&self.conn, group)
    }

    /// Return the full group tree as a flat list.
    ///
    /// Tree shape is reconstructed by the caller from each
    /// [`GroupNode`]'s `parent_uuid` reference; the root group has
    /// `parent_uuid = None`. Rows are ordered root-first then
    /// alphabetically by name (with `uuid` as a deterministic tie
    /// breaker), so callers can rely on a stable iteration order
    /// across runs of the same vault.
    ///
    /// `entry_count_direct` counts entries directly in each group.
    /// Regular groups exclude recycled entries; the recycle bin group
    /// itself includes its contents (so the bin's count is the number
    /// of items the user could empty).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn group_tree(&self) -> Result<Vec<GroupNode>, EngineError> {
        crate::reads::group_tree(&self.conn)
    }

    /// Full-text search across title / username / URL / notes, with
    /// a tag-substring fallback.
    ///
    /// Backed by the FTS5 virtual table built in migration 0001.
    /// Primary hits are ranked by FTS5's `bm25` (lower = more
    /// relevant); a `UNION ALL` of `tag.name LIKE %query%` matches
    /// (de-duplicated against the FTS bucket) is appended after,
    /// alphabetised by title. Results are paginated by `page`.
    ///
    /// Empty / whitespace-only queries return an empty Vec without
    /// touching the database.
    ///
    /// FTS5 special characters in the query are handled by wrapping
    /// the input in a quoted phrase when needed — see
    /// `escape_fts5_query` in the `reads` module for details.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn search(&self, query: &str, page: Pagination) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::search(&self.conn, query, page)
    }

    /// Evaluate a smart folder and return its matching entries.
    ///
    /// Compiles the folder's [`crate::predicate::Predicate`] to SQL
    /// (Phase 3.6) and runs it. Non-evaluable folders (those that
    /// contain an unknown predicate variant) return
    /// [`EngineError::Sqlite`]-wrapped failure today; a dedicated
    /// `NotEvaluable` error variant lands with task 3.9.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure or non-evaluable
    /// folder.
    pub fn smart_folder_entries(
        &self,
        folder_id: i64,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        let _ = (folder_id, page, &self.conn);
        unimplemented!("task 3.8")
    }

    /// Count entries matching a smart folder.
    ///
    /// Same evaluation rules as [`Engine::smart_folder_entries`]; cheaper
    /// than fetching rows when the caller only needs the badge count.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure or non-evaluable
    /// folder.
    pub fn smart_folder_count(&self, folder_id: i64) -> Result<u64, EngineError> {
        let _ = (folder_id, &self.conn);
        unimplemented!("task 3.8")
    }

    /// List every smart folder, ordered by row id ascending (i.e.
    /// insertion order).
    ///
    /// Each row's `predicate_json` column is deserialised; an
    /// unknown discriminator in the stored JSON surfaces as
    /// [`Predicate::Unknown`] in the returned
    /// [`SmartFolder::predicate`], and the
    /// [`SmartFolder::evaluable`] flag mirrors what was written to
    /// the column (which itself mirrors
    /// [`Predicate::is_evaluable`](crate::predicate::Predicate::is_evaluable)
    /// at write time).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or a
    /// `FromSqlConversionFailure`-flavoured variant if a row's JSON
    /// is malformed for a known predicate variant.
    pub fn list_smart_folders(&self) -> Result<Vec<SmartFolder>, EngineError> {
        crate::smart_folder::list_all(&self.conn)
    }

    /// Fetch a single smart folder by id.
    ///
    /// Returns `Ok(None)` if no row with the given id exists.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure or malformed
    /// stored predicate JSON.
    pub fn smart_folder(&self, id: i64) -> Result<Option<SmartFolder>, EngineError> {
        crate::smart_folder::get_one(&self.conn, id)
    }

    /// Create a new smart folder; return the assigned row id.
    ///
    /// The folder's `evaluable` column is computed from
    /// [`Predicate::is_evaluable`] at write time — passing a tree
    /// containing [`Predicate::Unknown`] is legal but the resulting
    /// row will have `evaluable = false`
    /// and the upcoming evaluation path (task 3.8) will refuse to
    /// run it.
    ///
    /// `created_at` and `modified_at` are both set to the current
    /// wall-clock time in ms since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on `INSERT` failure or
    /// predicate JSON serialisation failure (only happens for
    /// non-finite `EntropyBelow.bits`).
    pub fn create_smart_folder(
        &mut self,
        name: &str,
        predicate: &Predicate,
    ) -> Result<i64, EngineError> {
        crate::smart_folder::create(&mut self.conn, name, predicate)
    }

    /// Update an existing smart folder's name and predicate.
    ///
    /// Rewrites `name`, `predicate_json`, the derived `evaluable`
    /// flag, and `modified_at`. The `version` and `created_at`
    /// columns are left untouched.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::Sqlite`] on `UPDATE` failure or predicate
    ///   JSON serialisation failure.
    pub fn update_smart_folder(
        &mut self,
        id: i64,
        name: &str,
        predicate: &Predicate,
    ) -> Result<(), EngineError> {
        crate::smart_folder::update(&mut self.conn, id, name, predicate)
    }

    /// Delete a smart folder by id.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::Sqlite`] on `DELETE` failure.
    pub fn delete_smart_folder(&mut self, id: i64) -> Result<(), EngineError> {
        crate::smart_folder::delete(&mut self.conn, id)
    }

    /// Reveal the cleartext password for an entry.
    ///
    /// Fetches the wrapped blob from `entry_protected`, asks the
    /// field-protector callback for a fresh session key, and
    /// AES-GCM-opens in process. The result lives in a [`SecretString`]
    /// so it zeroes on drop.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "password"`) if the entry
    ///   has no `entry_protected` Password row.
    /// - [`EngineError::Reveal`] for session-key acquisition failure or
    ///   AES-GCM unwrap failure.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_password(&self, uuid: Uuid) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_password(&self.conn, &*self.field_protector, uuid)
    }

    /// Reveal the cleartext value of a custom field on an entry.
    ///
    /// Symmetric with [`Engine::reveal_password`] but for arbitrary
    /// named protected fields recorded in `entry_protected`. Asking for
    /// `field_name = "Password"` is allowed — it routes through the
    /// same row [`Engine::reveal_password`] reads, so the two are
    /// equivalent for that name; [`Engine::reveal_password`] stays as
    /// the canonical entry point.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "custom_field"`) if no
    ///   `entry_protected` row matches `(uuid, field_name)`.
    /// - [`EngineError::Reveal`] for session-key acquisition failure or
    ///   AES-GCM unwrap failure.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_custom_field(
        &self,
        uuid: Uuid,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_custom_field(&self.conn, &*self.field_protector, uuid, field_name)
    }

    /// Reveal the cleartext value of a field in a historic snapshot of
    /// an entry.
    ///
    /// **Asymmetric with the live-reveal paths.** History snapshots
    /// are stored as plaintext JSON inside `entry_history.snapshot_json`
    /// (the surrounding `SQLite` file is `SQLCipher`-encrypted at rest,
    /// which gives the same trust posture as a per-row AES-GCM wrap
    /// would). This method therefore does **not** call into the
    /// [`keepass_core::protector::FieldProtector`];
    /// it deserialises the snapshot JSON and reads the named field
    /// directly.
    ///
    /// `field_name = "Password"` reads the historic password;
    /// any other name reads from the snapshot's `custom_fields` map.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "history_snapshot"` or
    ///   `"history_field"`) if the snapshot or named field is missing.
    /// - [`EngineError::Reveal`] wrapping
    ///   [`RevealError::Json`](crate::RevealError::Json) if the
    ///   `snapshot_json` is malformed.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_history_field(
        &self,
        uuid: Uuid,
        history_index: u32,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_history_field(&self.conn, uuid, history_index, field_name)
    }

    /// Fetch the bytes of an entry attachment by attachment name.
    ///
    /// Returns the raw blob from `attachment_blob` joined through
    /// `entry_attachment`. Conceptually a query method, so it lands in
    /// 3.1 alongside the rest of the entry-surface implementation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] for query failure.
    pub fn attachment_bytes(
        &self,
        uuid: Uuid,
        attachment_name: &str,
    ) -> Result<Vec<u8>, EngineError> {
        let _ = (uuid, attachment_name, &self.conn);
        unimplemented!("task 3.1")
    }

    /// Return the historical snapshots of an entry.
    ///
    /// Ordered oldest-first (`history_index` ascending). Empty vector
    /// for entries with no history. Protected field values not included;
    /// fetch via [`Engine::reveal_history_field`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] for query failure.
    pub fn history(&self, uuid: Uuid) -> Result<Vec<HistoricEntry>, EngineError> {
        let _ = (uuid, &self.conn);
        unimplemented!("task 3.1")
    }
}

/// Apply the raw 32-byte key via `PRAGMA key = "x'<hex>'"`.
///
/// The BLOB-literal form bypasses `SQLCipher`'s PBKDF2 derivation: the
/// supplied bytes are used directly as the raw 256-bit cipher key,
/// which is what we want — the input is already a random 32-byte key
/// from the platform Keychain.
///
/// rusqlite's [`Connection::pragma_update`] always quotes its argument
/// with single quotes, which would turn `x'…'` into `'x''…'''` — not
/// what `SQLCipher` wants. So we build the statement by hand. The hex
/// payload is constrained to `[0-9a-f]` by [`hex_encode`], so there's
/// no injection surface; even so, the hex string lives in a
/// [`Zeroizing`] buffer and is wiped as soon as the PRAGMA returns.
fn apply_key(conn: &Connection, key: &DbKey) -> Result<(), rusqlite::Error> {
    let hex = hex_encode(key.as_bytes());
    let mut stmt = Zeroizing::new(String::with_capacity(hex.len() + 18));
    stmt.push_str("PRAGMA key = \"x'");
    stmt.push_str(&hex);
    stmt.push_str("'\"");
    conn.execute_batch(&stmt)
}

/// Lowercase hex-encode 32 bytes. Wrapped in [`Zeroizing`] so the
/// formatted key string is wiped from memory after the PRAGMA runs.
fn hex_encode(bytes: &[u8; 32]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Load the per-vault fingerprint key from `setting`, generating and
/// persisting a fresh 32-byte random key if no row exists.
///
/// The key is stored in `setting.value` as a 32-byte BLOB. Encryption
/// at rest is provided by `SQLCipher`'s page-level encryption — no
/// extra layer is applied to the row itself.
///
/// # Errors
///
/// - [`EngineError::Random`] if the OS RNG fails on a first-open path.
/// - [`EngineError::Sqlite`] for read/write failures, or if a row
///   exists but its value isn't 32 bytes (indicates corruption).
fn ensure_fingerprint_key(conn: &mut Connection) -> Result<Zeroizing<[u8; 32]>, EngineError> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM setting WHERE key = 'fingerprint_key'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(Some)
        .or_else(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    if let Some(bytes) = existing {
        let mut buf = Zeroizing::new([0u8; 32]);
        if bytes.len() != 32 {
            // Corrupt / wrong-shape row. Surface as a SQLite-flavoured
            // error rather than panicking. A dedicated variant could
            // land later once we have a story for recovery.
            return Err(EngineError::Sqlite(
                rusqlite::Error::IntegralValueOutOfRange(
                    0,
                    i64::try_from(bytes.len()).unwrap_or(i64::MAX),
                ),
            ));
        }
        buf.copy_from_slice(&bytes);
        // Best-effort wipe of the rusqlite-allocated buffer.
        let mut bytes = bytes;
        bytes.fill(0);
        return Ok(buf);
    }

    let mut buf = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(buf.as_mut_slice())?;

    conn.execute(
        "INSERT INTO setting(key, value) VALUES ('fingerprint_key', ?1)",
        rusqlite::params![&buf[..]],
    )?;

    Ok(buf)
}

/// Recognise `SQLCipher`'s wrong-key signal.
///
/// `SQLCipher` returns extended error code 26 (`SQLITE_NOTADB`) with the
/// message "file is not a database" the first time an encrypted page
/// is read with an incorrect key. We match on the primary error code
/// since the extended-code mapping isn't stable across versions.
fn is_wrong_key(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::NotADatabase
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_lowercases_all_bytes() {
        let bytes = [0xab; 32];
        let s = hex_encode(&bytes);
        assert_eq!(&*s, &"ab".repeat(32));
    }

    #[test]
    fn hex_encode_handles_zero_and_ff() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x00;
        bytes[1] = 0xff;
        bytes[2] = 0x10;
        bytes[3] = 0x0f;
        let s = hex_encode(&bytes);
        assert!(s.starts_with("00ff100f"));
        assert_eq!(s.len(), 64);
    }
}
