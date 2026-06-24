//! `Engine` mutation methods — entry / group / smart-folder / settings /
//! attachment CRUD plus the history operations. Every method runs inside
//! a transaction, refreshes the relevant `modified_at`, maintains
//! derived columns, and on commit invokes [`Engine::emit`] with a
//! [`ChangeEvent`] so observers see events only for successful
//! mutations.

use secrecy::SecretString;
use uuid::Uuid;

use crate::error::EngineError;
use crate::events::{ChangeEvent, EntryDeletionInfo, EntryMove, GroupDeletionInfo, GroupMove};
use crate::model::{
    EntrySave, EntryUpdate, GroupUpdate, HistoricEntry, NewEntryFields, NewGroupFields,
};
use crate::mutations;
use crate::portable::PortableEntry;

use super::Engine;

impl Engine {
    // ────────────────────────────────────────────────────────────────────
    // Mutation API — Phase 4 tasks 4.1 / 4.3.
    //
    // Every mutation runs inside a single transaction, refreshes the
    // relevant `modified_at`, and maintains derived columns. After the
    // commit returns, each method invokes [`Engine::emit`] with the
    // appropriate [`ChangeEvent`]; observers see events only for
    // successful mutations (failed mutations roll back and never emit).
    // ────────────────────────────────────────────────────────────────────

    /// Create a new entry in `group_uuid`. Returns the new entry's
    /// freshly-generated UUID.
    ///
    /// `created_at`, `modified_at`, and `accessed_at` are all set to the
    /// current wall-clock time. The canonical Password slot is
    /// AES-GCM-sealed under a fresh session key from the configured
    /// [`keepass_core::protector::FieldProtector`] and stored in `entry_protected`. Protected
    /// custom fields take the same path; non-protected ones land in
    /// `entry_custom_field`. Tags are trimmed + de-duplicated before
    /// insert.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group with
    ///   `group_uuid` exists.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure.
    /// - [`EngineError::Sqlite`] on insert failure.
    pub fn create_entry(
        &mut self,
        group_uuid: Uuid,
        fields: NewEntryFields,
    ) -> Result<Uuid, EngineError> {
        let now = self.now_ms();
        let new_uuid = self.next_uuid();
        let result = mutations::create_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            group_uuid,
            fields,
            now,
            new_uuid,
        )?;
        self.emit(ChangeEvent::EntriesAdded(vec![result]));
        Ok(result)
    }

    /// Serialise an entry into a [`PortableEntry`] suitable for
    /// importing into a different (or the same) database via
    /// [`Engine::import_entry`].
    ///
    /// Read-only on the source: reveals every protected field through
    /// this engine's [`keepass_core::protector::FieldProtector`], copies attachment bytes out of
    /// the content-addressed pool, and — when the entry references a
    /// custom icon — pulls the icon's PNG bytes so the target can
    /// rehome it under its own UUID rather than inheriting a dangling
    /// reference into a pool it doesn't share.
    ///
    /// The carrier is **in-process only**: it isn't serialised across
    /// the wire and the protected-field plaintext sits in
    /// [`SecretString`]s that zero on drop. The
    /// expected flow is
    /// `source.export_entry(uuid)` → `target.import_entry(carrier, …)` →
    /// `source.delete_entry(uuid)` in one breath.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row
    ///   matches.
    /// - [`EngineError::Reveal`] if any protected-field unwrap fails.
    /// - [`EngineError::Sqlite`] on query failure.
    pub fn export_entry(&self, entry_uuid: Uuid) -> Result<PortableEntry, EngineError> {
        crate::portable::export_entry(&self.conn, &*self.field_protector, entry_uuid)
    }

    /// Insert a [`PortableEntry`] (produced by [`Engine::export_entry`])
    /// under `target_group_uuid` as a brand new entry. Returns the
    /// freshly-minted UUID.
    ///
    /// Goes through the regular [`Engine::create_entry`] +
    /// [`Engine::attach_file`] paths on the target so derived columns
    /// (URL host, password strength, fingerprint, `has_totp`) are
    /// recomputed against the target's per-vault fingerprint key and
    /// every protected slot is re-sealed under the target's
    /// [`keepass_core::protector::FieldProtector`].
    ///
    /// **Custom-icon rehoming.** If the carrier ferries
    /// `custom_icon_png` bytes, they land in the target's icon pool
    /// via SHA-256 dedup ([`Engine::add_custom_icon`]); the resulting
    /// entry's `icon_custom_uuid` points at the target's pool. A
    /// carrier with `IconRef::Custom` but no PNG is rejected with
    /// [`EngineError::NotFound`] (`entity = "custom_icon"`) — silently
    /// downgrading would corrupt the user's intent.
    ///
    /// **Timestamps.** `created_at` / `modified_at` / `accessed_at`
    /// stamp `now` (matching `create_entry`'s usual semantics);
    /// `expires_at` is preserved when present.
    ///
    /// Emits [`ChangeEvent::EntriesAdded`] for the new uuid (via the
    /// underlying `create_entry`), and — when the icon pool grew —
    /// [`ChangeEvent::MetaUpdated`] for `meta.custom_icons`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if
    ///   `target_group_uuid` doesn't match a group row in the target.
    /// - [`EngineError::NotFound`] (`entity = "custom_icon"`) if the
    ///   carrier promised a custom icon but didn't supply its bytes.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure.
    /// - [`EngineError::Sqlite`] on insert failure.
    pub fn import_entry(
        &mut self,
        portable: PortableEntry,
        target_group_uuid: Uuid,
    ) -> Result<Uuid, EngineError> {
        let now = self.now_ms();
        let entry_uuid = self.next_uuid();
        let (new_uuid, icon_inserted) = crate::portable::import_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            target_group_uuid,
            portable,
            now,
            entry_uuid,
        )?;
        self.emit(ChangeEvent::EntriesAdded(vec![new_uuid]));
        if icon_inserted {
            self.emit(ChangeEvent::MetaUpdated {
                keys: vec![crate::meta::KEY_CUSTOM_ICONS.to_string()],
            });
        }
        Ok(new_uuid)
    }

    /// Update an existing entry. Each field of `update` is `Option`:
    /// `None` leaves it alone, `Some(value)` writes it.
    ///
    /// Setting `password` re-wraps the canonical Password slot and
    /// refreshes `password_strength_bucket`, `password_entropy`, and
    /// `password_fingerprint`. Setting `url` refreshes `url_host`.
    /// `modified_at` is always bumped to now.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure (only when `password` is updated).
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn update_entry(&mut self, uuid: Uuid, update: EntryUpdate) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::update_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            uuid,
            update,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Save the full desired state of an entry in ONE transaction with
    /// EXACTLY ONE history snapshot.
    ///
    /// The single funnel for the entry editor's "Save": it replaces the
    /// old sequence of per-field engine mutations (each of which pushed
    /// its own `<History>` snapshot) so one logical save archives one
    /// history record regardless of how many custom fields the entry
    /// carries. Standard fields, icon, expiry, the canonical Password
    /// slot, the full custom-field set (replace-all), and tags
    /// (set-semantics) are all applied; `password_strength_bucket`,
    /// `password_entropy`, `password_fingerprint`, `url_host`, and
    /// `has_totp` are recomputed. `modified_at` is bumped.
    ///
    /// Every call archives exactly one snapshot and bumps `modified_at`
    /// — it does not diff against the current state. See
    /// [`crate::EntrySave`] for the field contract.
    ///
    /// Emits [`ChangeEvent::EntriesUpdated`] for `uuid`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`] on wrap
    ///   failure.
    /// - [`EngineError::Sqlite`] on storage failure.
    pub fn save_entry(&mut self, uuid: Uuid, save: EntrySave) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::save_entry(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            uuid,
            save,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Soft-delete an entry: set `is_recycled = 1` and move to the
    /// recycle bin group (if one exists).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn recycle_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        let bin_uuid = self.next_uuid();
        mutations::recycle_entry(&mut self.conn, uuid, now, bin_uuid)?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesRecycled(vec![uuid]));
        Ok(())
    }

    /// Ensure a recycle bin group exists when the bin is enabled but none
    /// is present — call this once when a vault is first added so Keys
    /// never carries an enabled-but-binless vault into use or sync.
    /// Idempotent: a no-op when a bin already exists or the bin is
    /// disabled. Returns the bin uuid if one exists/was created.
    ///
    /// # Errors
    ///
    /// - [`EngineError::Sqlite`] on insert/update failure.
    pub fn ensure_recycle_bin(&mut self) -> Result<Option<String>, EngineError> {
        let before = self.recycle_bin_uuid()?;
        let now = self.now_ms();
        let bin_uuid = self.next_uuid();
        let bin = mutations::ensure_recycle_bin(&mut self.conn, now, bin_uuid)?;
        // Emit only when we actually created the group (it was absent before).
        if before.is_none() {
            if let Some(uuid) = bin.as_deref().and_then(|s| Uuid::parse_str(s).ok()) {
                self.emit(ChangeEvent::GroupsAdded(vec![uuid]));
            }
        }
        Ok(bin)
    }

    /// Restore a recycled entry: clear `is_recycled` AND move it out of
    /// the Trash, back to its recorded previous parent (KDBX 4.1
    /// `<PreviousParentGroup>`) when that group still exists outside the
    /// bin subtree, else to the vault root — `KeePassXC`'s semantics. A
    /// no-op (bar clearing a stale flag) on an entry that is not in the
    /// Trash: restoring a live entry must never relocate it.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn restore_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::restore_entry(&mut self.conn, uuid, now)?;
        self.emit(ChangeEvent::EntriesRestored(vec![uuid]));
        Ok(())
    }

    /// Hard-delete an entry. Cascades remove all `entry_protected`,
    /// `entry_attachment`, `entry_custom_field`, `entry_history`, and
    /// `entry_tag` rows (per schema FK `ON DELETE CASCADE`).
    /// Attachment blobs in `attachment_blob` are content-addressed and
    /// shared; they're not garbage-collected here.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches.
    /// - [`EngineError::Sqlite`] on delete failure.
    pub fn delete_entry(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        let outcome = mutations::delete_entry(&mut self.conn, uuid, now)?;
        // Entry gone → its parked conflict rows are orphans (Finding #11);
        // reconcile drops them so the badge doesn't haunt a deleted entry.
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesDeleted(vec![EntryDeletionInfo {
            uuid,
            previous_group: outcome.previous_group,
        }]));
        Ok(())
    }

    /// Move an entry to a different group.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"` or `"group"`).
    /// - [`EngineError::Sqlite`] on update failure.
    pub fn move_entry(&mut self, uuid: Uuid, new_group_uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        let outcome = mutations::move_entry(&mut self.conn, uuid, new_group_uuid, now)?;
        self.emit(ChangeEvent::EntriesMoved(vec![EntryMove {
            uuid,
            from_group: outcome.from_group,
            to_group: outcome.to_group,
        }]));
        Ok(())
    }

    /// Set the value of a protected field (canonical `Password` slot
    /// or a named protected custom field). UPSERTs `entry_protected`.
    /// When `field_name == "Password"`, refreshes strength / entropy /
    /// fingerprint columns.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Wrap`] / [`EngineError::SessionKey`].
    pub fn set_protected_field(
        &mut self,
        uuid: Uuid,
        field_name: &str,
        plaintext: SecretString,
    ) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::set_protected_field(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            uuid,
            field_name,
            plaintext,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::ProtectedFieldChanged {
            entry_uuid: uuid,
            field_name: field_name.to_owned(),
        });
        Ok(())
    }

    /// Set the value of a non-protected custom field. UPSERTs
    /// `entry_custom_field`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn set_non_protected_custom_field(
        &mut self,
        uuid: Uuid,
        field_name: &str,
        value: &str,
    ) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::set_non_protected_custom_field(
            &mut self.conn,
            &*self.field_protector,
            uuid,
            field_name,
            value,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Remove a custom field by name. Deletes from whichever of
    /// `entry_protected` / `entry_custom_field` the field lives in.
    /// No error if the field doesn't exist (idempotent removal).
    ///
    /// Refuses to delete the canonical `Password` slot — that would
    /// leave reveal callers with no row to read.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no row matches,
    ///   or `entity = "custom_field"` if `field_name == "Password"`.
    /// - [`EngineError::Sqlite`].
    pub fn remove_custom_field(&mut self, uuid: Uuid, field_name: &str) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::remove_custom_field(
            &mut self.conn,
            &*self.field_protector,
            uuid,
            field_name,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Replace the entry's tags wholesale. Inputs are trimmed and
    /// de-duplicated.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn set_tags(&mut self, uuid: Uuid, tags: Vec<String>) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::set_tags(&mut self.conn, &*self.field_protector, uuid, tags, now)?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        // Two events: the tag set changed (`TagsChanged`), and the
        // entry's `modified_at` was bumped (`EntriesUpdated`). Frontends
        // that only care about tag indices subscribe to the first;
        // entry-row observers subscribe to the second. Cheap to fire
        // both, no need to make the observer reason about overlap.
        self.emit(ChangeEvent::TagsChanged(vec![uuid]));
        self.emit(ChangeEvent::EntriesUpdated(vec![uuid]));
        Ok(())
    }

    /// Attach a file. Bytes are SHA-256 hashed and stored
    /// content-addressed in `attachment_blob`; the link row in
    /// `entry_attachment` upserts on `(entry_uuid, attachment_name)`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn attach_file(
        &mut self,
        uuid: Uuid,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::attach_file(
            &mut self.conn,
            &*self.field_protector,
            uuid,
            name,
            bytes,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::AttachmentsChanged(vec![uuid]));
        Ok(())
    }

    /// Add or replace an attachment by name. The blob lands in the
    /// content-addressed pool (dedup'd by SHA-256); re-using a name
    /// re-points the link at the new bytes. History snapshots first,
    /// like every entry mutation.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn set_attachment(
        &mut self,
        uuid: Uuid,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::set_attachment(
            &mut self.conn,
            &*self.field_protector,
            uuid,
            name,
            bytes,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::AttachmentsChanged(vec![uuid]));
        Ok(())
    }

    /// Remove an attachment by name. The underlying `attachment_blob`
    /// row is left in place (content-addressed and potentially shared).
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`).
    /// - [`EngineError::Sqlite`].
    pub fn remove_attachment(&mut self, uuid: Uuid, name: &str) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::remove_attachment(&mut self.conn, &*self.field_protector, uuid, name, now)?;
        crate::reconcile::reconcile_conflict_rows(self, uuid)?;
        self.emit(ChangeEvent::AttachmentsChanged(vec![uuid]));
        Ok(())
    }

    /// Create a new group under `parent_uuid`. Returns the new uuid.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if the parent
    ///   doesn't exist.
    /// - [`EngineError::Sqlite`].
    pub fn create_group(
        &mut self,
        parent_uuid: Uuid,
        fields: NewGroupFields,
    ) -> Result<Uuid, EngineError> {
        let now = self.now_ms();
        let new_uuid = self.next_uuid();
        let uuid = mutations::create_group(&mut self.conn, parent_uuid, fields, now, new_uuid)?;
        self.emit(ChangeEvent::GroupsAdded(vec![uuid]));
        Ok(uuid)
    }

    /// Update an existing group. Patch shape: `None` leaves alone,
    /// `Some(value)` writes.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::Sqlite`].
    pub fn update_group(&mut self, uuid: Uuid, update: GroupUpdate) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::update_group(&mut self.conn, uuid, update, now)?;
        self.emit(ChangeEvent::GroupsUpdated(vec![uuid]));
        Ok(())
    }

    /// Soft-recycle a group: move it under the database's recycle bin
    /// group. KDBX UX is "move, not delete"; this matches that.
    ///
    /// If no recycle-bin group exists, returns
    /// [`EngineError::NotFound`] (`entity = "recycle_bin"`). The engine
    /// deliberately does not auto-create a bin — that's a frontend
    /// decision. Callers wanting hard removal use [`Engine::delete_group`].
    ///
    /// Direct child entries of this group are not touched; they're
    /// implicitly recycled by virtue of having a recycled ancestor.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"` or
    ///   `"recycle_bin"`).
    /// - [`EngineError::CycleDetected`] if the caller passes the bin's
    ///   own uuid.
    /// - [`EngineError::Sqlite`].
    pub fn recycle_group(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::recycle_group(&mut self.conn, uuid, now)?;
        // Only the group event fires — descendant entries and groups
        // are implicitly recycled by sitting under a recycled ancestor.
        // Frontends listening on group events know to re-query their
        // subtree views; emitting per-descendant events would force
        // every observer to consume them even when they don't care.
        self.emit(ChangeEvent::GroupsRecycled(vec![uuid]));
        Ok(())
    }

    /// Restore a recycled group by moving it to `new_parent_uuid`.
    /// KDBX itself doesn't track the original location, so the caller
    /// supplies the destination.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::CycleDetected`] if the destination is the group
    ///   itself or a descendant.
    /// - [`EngineError::Sqlite`].
    pub fn restore_group(&mut self, uuid: Uuid, new_parent_uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        mutations::restore_group(&mut self.conn, uuid, new_parent_uuid, now)?;
        // Same shape as recycle — emit only the group event. Descendant
        // recycle status is determined by ancestor walk, not a column,
        // so there's nothing to fan out per row.
        self.emit(ChangeEvent::GroupsRestored(vec![uuid]));
        Ok(())
    }

    /// Hard-delete a group and every descendant group + entry.
    ///
    /// The schema does not declare `ON DELETE CASCADE` on the group
    /// self-FK or on `entry.group_uuid`, so the engine walks the
    /// subtree itself. Entry child tables cascade off `entry`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::Sqlite`].
    pub fn delete_group(&mut self, uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        let outcome = mutations::delete_group(&mut self.conn, uuid, now)?;
        // One combined `EntriesDeleted` and one combined `GroupsDeleted`
        // covering the entire cascade. Order: entries first, then
        // groups — leaves-up, mirroring the delete order inside the
        // transaction. Frontends get all the info in two events.
        if !outcome.deleted_entries.is_empty() {
            let entries = outcome
                .deleted_entries
                .into_iter()
                .map(|(uuid, previous_group)| EntryDeletionInfo {
                    uuid,
                    previous_group,
                })
                .collect();
            self.emit(ChangeEvent::EntriesDeleted(entries));
        }
        let groups = outcome
            .deleted_groups
            .into_iter()
            .map(|(uuid, previous_parent)| GroupDeletionInfo {
                uuid,
                previous_parent,
            })
            .collect();
        self.emit(ChangeEvent::GroupsDeleted(groups));
        Ok(())
    }

    /// Move a group to a new parent. Rejects cycles: the new parent
    /// cannot be the group itself or any descendant.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`).
    /// - [`EngineError::CycleDetected`].
    /// - [`EngineError::Sqlite`].
    pub fn move_group(&mut self, uuid: Uuid, new_parent_uuid: Uuid) -> Result<(), EngineError> {
        let now = self.now_ms();
        let outcome = mutations::move_group(&mut self.conn, uuid, new_parent_uuid, now)?;
        self.emit(ChangeEvent::GroupsMoved(vec![GroupMove {
            uuid,
            from_parent: outcome.from_parent,
            to_parent: outcome.to_parent,
        }]));
        Ok(())
    }

    /// Reorder `uuid` within its current parent's child list.
    /// `new_position` is the 0-based final index in the sibling
    /// sequence; values past the last index clamp to the end.
    ///
    /// Cross-parent moves use [`Engine::move_group`] instead — that
    /// path appends to the new parent. `reorder_group` only rewrites
    /// `sort_order` values; it never changes parentage.
    ///
    /// Emits [`ChangeEvent::GroupsReordered`] carrying the full ordered
    /// sibling list under the parent.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "group"`) if no group
    ///   with that UUID exists or the target is the root group.
    /// - [`EngineError::Sqlite`].
    pub fn reorder_group(&mut self, uuid: Uuid, new_position: u32) -> Result<(), EngineError> {
        let now = self.now_ms();
        let outcome = mutations::reorder_group(&mut self.conn, uuid, new_position, now)?;
        self.emit(ChangeEvent::GroupsReordered(outcome.siblings_in_order));
        Ok(())
    }

    /// Return the historical snapshots of an entry.
    ///
    /// Ordered oldest-first (`history_index` ascending). Empty vector
    /// for entries that exist but have no history snapshots. Protected
    /// field values are not included; fetch via
    /// [`Engine::reveal_history_field`].
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with that UUID exists.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn history(&self, uuid: Uuid) -> Result<Vec<HistoricEntry>, EngineError> {
        crate::reads::history(&self.conn, uuid)
    }

    /// Delete a single history snapshot from an entry without touching
    /// the live entry. Surviving snapshots are renumbered so
    /// `history_index` stays a dense `0..N` sequence.
    ///
    /// Mirrors the legacy `Vault::delete_history_at` contract: the live
    /// entry's `modified_at` is **not** bumped (deleting a history
    /// record is metadata, not a content edit). Emits
    /// [`ChangeEvent::EntriesUpdated`] so detail views re-pull the
    /// history listing.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with that uuid exists.
    /// - [`EngineError::NotFound`] (`entity = "history_snapshot"`) if
    ///   `history_index` is outside `0..N` for that entry's history.
    /// - [`EngineError::Sqlite`] on storage failure.
    pub fn delete_history_at(
        &mut self,
        entry_uuid: Uuid,
        history_index: u32,
    ) -> Result<(), EngineError> {
        // Write a history tombstone BEFORE dropping the row, so the deletion
        // PROPAGATES cross-peer. The cross-peer history merge is lossless (it
        // unions histories), so a bare local DELETE either resurrects from the
        // peer or diverges forever — only a `keys.history_tombstones.v1` record
        // (which the merge prunes against) makes a "remove this old version"
        // stick on every device (a privacy obligation). Reuses keepass-merge's
        // canonical tombstone construction — keyed by the record's
        // content-hash + mtime — via a one-entry projection.
        let vault = self.project_to_vault()?;
        let entry = vault
            .iter_entries()
            .find(|e| e.id == keepass_core::model::EntryId(entry_uuid))
            .ok_or(EngineError::NotFound { entity: "entry" })?;
        let record = entry
            .history
            .get(history_index as usize)
            .ok_or(EngineError::NotFound {
                entity: "history_snapshot",
            })?;
        let now =
            chrono::DateTime::from_timestamp_millis(self.now_ms()).unwrap_or_else(chrono::Utc::now);
        let mut tomb_entry = entry.clone();
        keepass_merge::add_history_tombstone(
            &mut tomb_entry,
            record,
            &vault.binaries,
            keepass_merge::TombstoneReason::UserDelete,
            None,
            now,
        )
        .map_err(|e| EngineError::Serialise(format!("add_history_tombstone: {e}")))?;
        // Persist the merged tombstone list onto the entry's custom_data so it
        // survives reconcile→project→save and is unioned on the peer's ingest.
        if let Some(item) = tomb_entry
            .custom_data
            .iter()
            .find(|c| c.key == keepass_merge::TOMBSTONE_CUSTOM_DATA_KEY)
        {
            self.conn.execute(
                "INSERT OR REPLACE INTO entry_custom_data \
                 (entry_uuid, key, value, last_modified_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    entry_uuid.to_string(),
                    item.key,
                    item.value,
                    item.last_modified.map(|d| d.timestamp_millis()),
                ],
            )?;
        }
        // Drop the local row + repack indices (the pre-existing behaviour).
        mutations::delete_history_at(&mut self.conn, entry_uuid, history_index)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }

    /// Restore an entry to the state captured in one of its history
    /// snapshots, preserving the snapshot in the history list and
    /// pushing the pre-restore live state as a new snapshot at the
    /// tail.
    ///
    /// Semantics match the legacy
    /// `Vault::restore_entry_from_history` /
    /// `keepass_core::Kdbx::restore_entry_from_history` contract under
    /// `HistoryPolicy::Snapshot`: the snapshot at `history_index` is
    /// **not consumed** — the entry's history grows by one record, the
    /// targeted snapshot stays at its original index, and a fresh
    /// snapshot of the pre-restore live state is appended so the
    /// restore is itself reversible via a subsequent call.
    ///
    /// `entry.modified_at` is bumped to `now()` (the restore is a real
    /// content edit). `created_at`, `accessed_at`, `last_used_at`, and
    /// `expires_at` are restored verbatim from the snapshot, and
    /// derived columns (`password_strength_bucket`, `password_entropy`,
    /// `password_fingerprint`, `url_host`, `has_totp`) are recomputed
    /// from the restored content. Tags, attachments (resolved via the
    /// snapshot's `sha256_hex`), custom fields, and protected fields
    /// are replaced wholesale.
    ///
    /// If the resulting history list exceeds the vault's
    /// `meta.history_max_items` budget, the oldest snapshots are
    /// dropped inline (matching the item-budget pass of
    /// `keepass_core::truncate_history`). The `history_max_size` byte
    /// budget is left to the next save round-trip through keepass-core.
    ///
    /// Emits [`ChangeEvent::EntriesUpdated`] for `entry_uuid`.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "entry"`) if no entry
    ///   with that uuid exists.
    /// - [`EngineError::NotFound`] (`entity = "history_snapshot"`) if
    ///   `history_index` is outside `0..N` for that entry's history.
    /// - [`EngineError::Reveal`] / [`EngineError::Wrap`] /
    ///   [`EngineError::SessionKey`] on protector failure.
    /// - [`EngineError::Sqlite`] on storage failure.
    pub fn restore_entry_from_history(
        &mut self,
        entry_uuid: Uuid,
        history_index: u32,
    ) -> Result<(), EngineError> {
        let max_items = crate::meta::read_history_max_items(&self.conn)?;
        let now = self.now_ms();
        mutations::restore_entry_from_history(
            &mut self.conn,
            &self.fingerprint_key,
            &*self.field_protector,
            entry_uuid,
            history_index,
            max_items,
            now,
        )?;
        crate::reconcile::reconcile_conflict_rows(self, entry_uuid)?;
        self.emit(ChangeEvent::EntriesUpdated(vec![entry_uuid]));
        Ok(())
    }
}
