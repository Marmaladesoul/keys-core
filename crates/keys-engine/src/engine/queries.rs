//! `Engine` read-side query methods — the entry-listing,
//! group-tree, search, smart-folder, and meta accessors that the
//! frontend uses to render UI without mutating the vault.
//!
//! Most methods are thin wrappers that delegate to the implementation
//! modules (`crate::reads`, `crate::meta`, `crate::smart_folder`,
//! `crate::predicate_sql`); the wrapper lives here because the public
//! shape of `Engine` is more discoverable than the spread of free
//! functions across those modules.

use uuid::Uuid;

use crate::error::EngineError;
use crate::events::ChangeEvent;
use crate::model::{EntryFull, EntrySummary, GroupNode, Pagination, SearchScope, SmartFolder};
use crate::mutations;
use crate::predicate::Predicate;

use super::Engine;

impl Engine {
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

    /// Return every unique tag name in use across the vault, sorted
    /// alphabetically. Empty if no entries are tagged.
    ///
    /// Backs the Swift-side tag list (Phase 6.13 retires the in-memory
    /// `TagListStore` in favour of this engine method). Mutations that
    /// can orphan a tag (`set_tags`, `delete_entry`, `delete_group`)
    /// run an in-transaction GC sweep, so the `tag` table is
    /// authoritative — no zombie filtering required here.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn list_tags(&self) -> Result<Vec<String>, EngineError> {
        crate::reads::list_tags(&self.conn)
    }

    /// Return `(tag_name, entry_count)` pairs for every tag in use,
    /// sorted by tag name `COLLATE NOCASE`.
    ///
    /// Counts include recycle-bin entries — matches the legacy Swift
    /// `TagListStore::usageCount` behaviour, which was fed
    /// `allEntriesIncludingRecycleBin`. Tags with zero referencing
    /// entries don't appear (an `INNER JOIN` against `entry_tag`
    /// filters them naturally).
    ///
    /// Backs the Settings → Tags usage column: one SQL `GROUP BY`
    /// replaces an O(N×M) walk that previously hydrated every entry
    /// (including Secure-Enclave reveals for custom fields) just to
    /// count tag references.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn tag_usage_counts(&self) -> Result<Vec<(String, u64)>, EngineError> {
        crate::reads::tag_usage_counts(&self.conn)
    }

    /// Uuid of the recycle-bin group, or `None` if no bin exists.
    ///
    /// Sourced from the `group` table's `is_recycle_bin = 1` row — the
    /// authoritative location for the bin identity. Backs the Swift-side
    /// recycle-bin uuid accessor (Phase 6.17 retires the in-memory
    /// `Vault::recycleBinUuid()` shim in favour of this).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn recycle_bin_uuid(&self) -> Result<Option<String>, EngineError> {
        crate::meta::read_recycle_bin_uuid(&self.conn)
    }

    /// Whether the recycle-bin feature is enabled for this vault.
    ///
    /// Sourced from the explicit `meta.recycle_bin_enabled` setting row
    /// written by ingest. Falls back to "does a bin group exist?" for
    /// legacy DBs that predate that setting — matches the same
    /// derivation [`Engine::project_to_vault`] uses.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn recycle_bin_enabled(&self) -> Result<bool, EngineError> {
        crate::meta::read_recycle_bin_enabled(&self.conn)
    }

    /// Read-only facts about the encrypted database envelope and the
    /// content-addressed attachment pool, packaged for the frontend's
    /// "database properties" Info-tab.
    ///
    /// Sources:
    ///
    /// * `generator` — `setting`/`meta.generator` (written by
    ///   the engine's meta writer at ingest).
    /// * `cipher_display` — derived from
    ///   `setting`/`meta.kdbx_cipher_oid` (a 16-byte UUID written at
    ///   ingest from the live outer header).
    /// * `kdf_display` — derived from
    ///   `setting`/`meta.kdbx_kdf_parameters` (KDBX4 `VarDictionary`
    ///   blob) or `setting`/`meta.kdbx_transform_rounds` (KDBX3
    ///   fallback) — both written at ingest.
    /// * `attachment_total_count` /
    ///   `attachment_total_bytes` — `SELECT COUNT(*), SUM(size)
    ///   FROM attachment_blob`. The pool is content-addressed, so
    ///   stats are over distinct payloads (matches the legacy
    ///   in-memory `Vault::binaries` semantics).
    ///
    /// Cipher / KDF facts are absent on engines created before this
    /// surface existed; in that case the corresponding fields render
    /// as `"Unknown"` / `"Unknown KDF"`. They become populated on the
    /// next ingest (every save → reopen → ingest cycle refreshes them).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn database_metadata(&self) -> Result<crate::meta::DatabaseMetadata, EngineError> {
        crate::meta::read_database_metadata(&self.conn)
    }

    /// Per-entry history retention count cap.
    ///
    /// Sourced from `setting` row `meta.history_max_items`. Returns the
    /// keepass-core default (`10`) when the row is absent — matches
    /// `Meta::default()`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or
    /// [`EngineError::Projection`] if the persisted blob is the wrong
    /// width.
    pub fn history_max_items(&self) -> Result<i32, EngineError> {
        crate::meta::read_history_max_items(&self.conn)
    }

    /// Per-entry history retention size cap in bytes.
    ///
    /// Sourced from `setting` row `meta.history_max_size`. Returns the
    /// keepass-core default (`6 * 1024 * 1024`) when the row is absent
    /// — matches `Meta::default()`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure, or
    /// [`EngineError::Projection`] if the persisted blob is the wrong
    /// width.
    pub fn history_max_size(&self) -> Result<i64, EngineError> {
        crate::meta::read_history_max_size(&self.conn)
    }

    /// Configure the recycle-bin policy. `enabled` toggles soft-delete
    /// for [`Engine::recycle_entry`] / `recycle_group`; `group_uuid`
    /// selects which group acts as the bin (or `None` to clear the
    /// reference — `recycle_entry` will lazily create a bin on first
    /// soft-delete if `enabled` is true and no bin is set).
    ///
    /// Mirrors `keepass_core::Kdbx::set_recycle_bin`: writes both
    /// fields exactly as supplied, in a single transaction. The schema
    /// invariant "at most one group has `is_recycle_bin = 1`" is
    /// upheld — if `group_uuid` is Some and a different group already
    /// holds the flag, that flag is cleared atomically with the new
    /// designation.
    ///
    /// Emits [`ChangeEvent::MetaUpdated`] carrying the
    /// `meta.recycle_bin_enabled` and `meta.recycle_bin_uuid` keys
    /// (the latter even though it isn't a real `setting` row — the
    /// designation lives on `group.is_recycle_bin`; the key is a bus
    /// identifier only).
    ///
    /// Backs the Keys-Mac fresh-vault creation flow
    /// (`WelcomeView.createVault`), which designates a brand-new bin
    /// group on the first save of a freshly minted vault. Phase 6.17-I
    /// retires the in-memory `Vault::set_recycle_bin` shim in favour
    /// of this engine method.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if `group_uuid`
    ///   is Some but no matching group row exists.
    /// - [`EngineError::Sqlite`] on write failure.
    pub fn set_recycle_bin(
        &mut self,
        enabled: bool,
        group_uuid: Option<Uuid>,
    ) -> Result<(), EngineError> {
        mutations::set_recycle_bin(&mut self.conn, enabled, group_uuid)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![
                crate::meta::KEY_RECYCLE_BIN_ENABLED.to_string(),
                crate::meta::KEY_RECYCLE_BIN_UUID.to_string(),
            ],
        });
        Ok(())
    }

    /// Set the per-entry history retention count cap.
    ///
    /// Persists `meta.history_max_items` and emits
    /// [`ChangeEvent::MetaUpdated`] with that key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure.
    pub fn set_history_max_items(&mut self, max: i32) -> Result<(), EngineError> {
        crate::meta::write_history_max_items(&self.conn, max).map_err(EngineError::Sqlite)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![crate::meta::KEY_HISTORY_MAX_ITEMS.to_string()],
        });
        Ok(())
    }

    /// Set the per-entry history retention size cap in bytes.
    ///
    /// Persists `meta.history_max_size` and emits
    /// [`ChangeEvent::MetaUpdated`] with that key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure.
    pub fn set_history_max_size(&mut self, max: i64) -> Result<(), EngineError> {
        crate::meta::write_history_max_size(&self.conn, max).map_err(EngineError::Sqlite)?;
        self.emit(ChangeEvent::MetaUpdated {
            keys: vec![crate::meta::KEY_HISTORY_MAX_SIZE.to_string()],
        });
        Ok(())
    }

    /// Register a PNG (or any image-format-of-the-frontend's-choosing)
    /// blob in the vault's custom-icon pool and return its UUID.
    ///
    /// Dedup-by-content-hash: if an existing icon already has the same
    /// SHA-256 as `png_bytes`, its UUID is returned and the pool is
    /// left unchanged. Matches `keepass-core`'s
    /// `Kdbx::add_custom_icon` semantics so the SQLite-backed engine
    /// and the in-memory `Vault` shim agree on UUIDs for the same
    /// bytes (load-bearing during the Phase 6.17 migration window).
    ///
    /// Emits [`ChangeEvent::MetaUpdated`] with key
    /// `"meta.custom_icons"` on a fresh insert. A dedup hit does NOT
    /// emit (nothing changed).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on write failure, or
    /// [`EngineError::Projection`] if a persisted UUID row fails to
    /// parse (corrupt DB).
    pub fn add_custom_icon(&mut self, png_bytes: &[u8]) -> Result<String, EngineError> {
        let (uuid, inserted) = crate::meta::add_custom_icon_dedup(&self.conn, png_bytes)?;
        if inserted {
            self.emit(ChangeEvent::MetaUpdated {
                keys: vec![crate::meta::KEY_CUSTOM_ICONS.to_string()],
            });
        }
        Ok(uuid.to_string())
    }

    /// Clear an entry's reference to a custom icon, restoring it to
    /// the built-in icon at `icon_index` (which is left unchanged).
    ///
    /// Does **not** delete the underlying icon blob from
    /// `meta_custom_icon` — other entries or groups may still
    /// reference it. Use [`Engine::add_custom_icon`] +
    /// `update_entry` if you want to swap icons; this method is for
    /// the "go back to default" UX.
    ///
    /// Emits [`ChangeEvent::EntriesUpdated`] with the supplied uuid
    /// (the same event the generic `update_entry` path fires) so
    /// observers don't need to learn a new variant for this one
    /// column.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn clear_entry_custom_icon(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::clear_entry_custom_icon(&mut self.conn, entry_uuid, now)?;
        crate::reconcile::reconcile_conflict_rows(self, entry_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Link a fetched favicon to an entry as its custom icon WITHOUT
    /// archiving a history snapshot or bumping `modified_at`. A favicon
    /// is automatic cosmetic enrichment, not a user edit — see
    /// `mutations::link_entry_custom_icon`. The user-driven icon
    /// picker uses [`Engine::update_entry`] instead, which does archive
    /// and bump. Emits [`ChangeEvent::EntriesUpdated`] so the icon
    /// repaints.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn link_entry_custom_icon(
        &mut self,
        entry_uuid: Uuid,
        icon_uuid: Uuid,
    ) -> Result<(), EngineError> {
        mutations::link_entry_custom_icon(&mut self.conn, entry_uuid, icon_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Bump an entry's `last_used_at` to now. Read-touch flow: nothing
    /// else on the entry changes (no `modified_at` bump, no history
    /// snapshot, no protected-field reseal). Intended for `AutoFill`
    /// fulfilment and in-app password reveal, both of which fire many
    /// times per session.
    ///
    /// Emits [`ChangeEvent::EntryTouched`] rather than
    /// [`ChangeEvent::EntriesUpdated`] — the latter is a heavy refresh
    /// signal that would force listeners (e.g. an open entry detail
    /// pane) to re-pull on every touch. `EntryTouched` is the quiet
    /// last-access channel; listeners that care about Recently-Used
    /// ordering subscribe to it explicitly.
    ///
    /// Mirrors the legacy `Vault::touch_entry` semantics so the Phase
    /// 6.17 Keys-Mac migration is a like-for-like swap.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn touch_entry(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::touch_entry(&mut self.conn, entry_uuid, now)?;
        self.emit(ChangeEvent::EntryTouched { uuid: entry_uuid });
        Ok(())
    }

    /// Clear an entry's `last_used_at`, returning the column to NULL.
    /// User-driven explicit reset from the entry detail editor (e.g.
    /// after `AutoFill` stamped an entry that shouldn't have shown up
    /// in Recently-Used).
    ///
    /// Like [`Engine::touch_entry`], does NOT bump `modified_at` and
    /// takes no history snapshot. Unlike `touch_entry`, this is a
    /// view-affecting user gesture, so it emits
    /// [`ChangeEvent::EntriesUpdated`] (entry detail panes refresh).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   row matches the uuid.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn clear_entry_last_access(&mut self, entry_uuid: Uuid) -> Result<(), EngineError> {
        mutations::clear_entry_last_access(&mut self.conn, entry_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Fetch the raw bytes for a custom icon by UUID.
    ///
    /// Returns `Ok(None)` if no icon with that UUID is in the pool —
    /// callers should treat that as "icon no longer registered", not
    /// an error. Stale references can survive in caches /
    /// snapshots, and propagating a `NotFound` here would force
    /// every renderer to handle that case as an exception path.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn custom_icon_bytes(&self, uuid: Uuid) -> Result<Option<Vec<u8>>, EngineError> {
        crate::meta::read_custom_icon_bytes(&self.conn, uuid)
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

    /// Return the parent group's UUID for `child_uuid`, or `Ok(None)`
    /// if `child_uuid` is the root group (which has no parent).
    ///
    /// Trivial single-row `SELECT` against `group.parent_uuid` — much
    /// cheaper than fetching the whole tree just to read one edge.
    /// Mirrors the legacy `Vault::group_parent` shape so consumer
    /// migration off the in-memory `Vault` is a direct call swap.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group
    ///   with `child_uuid` exists.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn group_parent_uuid(&self, child_uuid: Uuid) -> Result<Option<Uuid>, EngineError> {
        crate::reads::group_parent_uuid(&self.conn, child_uuid)
    }

    /// Return `true` if `group_uuid` is at any depth inside the subtree
    /// rooted at `ancestor_uuid`. **Not inclusive** — a group is not
    /// its own descendant, so `is_descendant_of(g, g)` returns `false`
    /// (provided `g` exists).
    ///
    /// Implementation walks `parent_uuid` up from `group_uuid` until
    /// it either hits `ancestor_uuid` (true), reaches the root with no
    /// match (false), or trips the defensive iteration cap (false —
    /// guards against a `parent_uuid` cycle in a malformed user vault).
    ///
    /// `ancestor_uuid` is not validated separately: if it doesn't
    /// match any group, the walk simply terminates at root with
    /// `false`, which is the natural answer.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if `group_uuid`
    ///   doesn't match any group row.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn is_descendant_of(
        &self,
        group_uuid: Uuid,
        ancestor_uuid: Uuid,
    ) -> Result<bool, EngineError> {
        crate::reads::is_descendant_of(&self.conn, group_uuid, ancestor_uuid)
    }

    /// Full-text search across title / username / URL / notes, with
    /// a tag-substring fallback.
    ///
    /// Backed by the FTS5 virtual table built in migration 0001.
    /// Case-insensitive substring search across entry fields, scoped
    /// by `scope`.
    ///
    /// The query is split on whitespace into tokens; an entry matches
    /// when every token appears as a substring of at least one
    /// in-scope field (tokens AND, fields OR). Scope controls which
    /// fields participate: [`SearchScope::AnyField`] matches title,
    /// username, url, notes, and tags; [`SearchScope::TitleOnly`] and
    /// [`SearchScope::NotesOnly`] restrict to a single field.
    ///
    /// Results are alphabetised by title (case-insensitive) with uuid
    /// as a deterministic tie-breaker, then paginated by `page`.
    ///
    /// Empty / whitespace-only queries return an empty Vec without
    /// touching the database.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn search(
        &self,
        query: &str,
        scope: SearchScope,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::search(&self.conn, query, scope, page)
    }

    /// Find entries matching an `AutoFill` service identifier.
    ///
    /// Powers the `AutoFill` extension's lookup path: given a service
    /// identifier (typically a domain like `google.com` or a full URL
    /// like `https://accounts.google.com/signin`), return the entries
    /// most likely to match, in best-match-first order.
    ///
    /// # Matching tiers
    ///
    /// 1. Exact `url_host` match (case-insensitive).
    /// 2. eTLD+1 match — covers `accounts.google.com` finding
    ///    entries saved as `google.com` and vice versa. Uses a
    ///    hand-rolled two-label suffix list (no Public Suffix List
    ///    dependency in v1).
    /// 3. Substring match — the identifier appears anywhere inside
    ///    `entry.url`. Last-resort tier for unparseable URLs.
    ///
    /// Recycled entries are excluded. Results dedupe by uuid (best
    /// tier wins) and sort by tier, then `last_used_at` desc, then
    /// `modified_at` desc. Capped at `limit` rows.
    ///
    /// Empty / whitespace identifiers and `limit = 0` return an empty
    /// `Vec` without touching the database.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn search_by_service(
        &self,
        identifier: &str,
        limit: usize,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::reads::search_by_service(&self.conn, identifier, limit)
    }

    /// Evaluate a smart folder and return its matching entries.
    ///
    /// Looks the folder up by id, compiles its
    /// [`crate::predicate::Predicate`] to SQL via
    /// [`crate::predicate_sql::compile`], and runs the result against
    /// the entry table. Ordering and pagination semantics match
    /// [`Engine::list_entries`] (most-recently-modified first, `uuid`
    /// as a deterministic tie breaker).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::NotEvaluable`] if the persisted predicate
    ///   contains a [`Predicate::Unknown`] node (i.e. the row's
    ///   `evaluable` column is `false`).
    /// - [`EngineError::Sqlite`] on any other query failure.
    pub fn smart_folder_entries(
        &self,
        folder_id: i64,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::smart_folder::smart_folder_entries(&self.conn, folder_id, page)
    }

    /// Count entries matching a smart folder.
    ///
    /// Same evaluation rules as [`Engine::smart_folder_entries`];
    /// cheaper than fetching rows when the caller only needs the badge
    /// count.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::NotEvaluable`] if the folder is not evaluable.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn smart_folder_count(&self, folder_id: i64) -> Result<u64, EngineError> {
        crate::smart_folder::smart_folder_count(&self.conn, folder_id)
    }

    /// Evaluate an arbitrary [`Predicate`] and return matching entries.
    ///
    /// Direct-predicate variant of [`Engine::smart_folder_entries`].
    /// Intended for built-in smart folders (see
    /// [`crate::predicate_builtin`]) and any other call site that
    /// holds a predicate but no persisted `smart_folder` row.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotEvaluable`] if the predicate contains a
    ///   [`Predicate::Unknown`] node or an empty `And` / `Or` /
    ///   tag-set.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn entries_matching(
        &self,
        predicate: &Predicate,
        page: Pagination,
    ) -> Result<Vec<EntrySummary>, EngineError> {
        crate::smart_folder::entries_matching(&self.conn, predicate, page)
    }

    /// Count entries matching an arbitrary [`Predicate`].
    ///
    /// Direct-predicate variant of [`Engine::smart_folder_count`].
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotEvaluable`] if the predicate is not
    ///   evaluable.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn count_matching(&self, predicate: &Predicate) -> Result<u64, EngineError> {
        crate::smart_folder::count_matching(&self.conn, predicate)
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
        let id = crate::smart_folder::create(&mut self.conn, name, predicate)?;
        self.emit(ChangeEvent::SmartFolderCreated(id));
        Ok(id)
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
        crate::smart_folder::update(&mut self.conn, id, name, predicate)?;
        self.emit(ChangeEvent::SmartFolderUpdated(id));
        Ok(())
    }

    /// Delete a smart folder by id.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "smart_folder"`) if no
    ///   row with the given id exists.
    /// - [`EngineError::Sqlite`] on `DELETE` failure.
    pub fn delete_smart_folder(&mut self, id: i64) -> Result<(), EngineError> {
        crate::smart_folder::delete(&mut self.conn, id)?;
        self.emit(ChangeEvent::SmartFolderDeleted(id));
        Ok(())
    }

    /// Test-only helper: compile `predicate` against `now_ms` and
    /// return the UUIDs of matching entries.
    ///
    /// Exists so the predicate-SQL compiler's integration test can
    /// run a compiled fragment against the real schema without 3.8's
    /// `Engine::smart_folder_entries` being in place yet. Hidden from
    /// the public docs to keep the surface clean; not intended for
    /// production callers — 3.8's `smart_folder_entries` is the
    /// real surface.
    #[doc(hidden)]
    pub fn compiled_predicate_uuids_for_test(
        &self,
        predicate: &Predicate,
        now_ms: i64,
    ) -> Result<Vec<Uuid>, EngineError> {
        let compiled = crate::predicate_sql::compile(predicate, now_ms).map_err(|e| {
            EngineError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        let sql = format!(
            "SELECT uuid FROM entry WHERE {} ORDER BY uuid ASC",
            compiled.where_sql
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(compiled.params), |r| {
                let s: String = r.get(0)?;
                Uuid::parse_str(&s).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
