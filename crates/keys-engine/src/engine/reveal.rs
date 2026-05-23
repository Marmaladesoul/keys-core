//! `Engine` reveal methods — fetch the cleartext of a protected
//! field (canonical Password, custom field, history snapshot field)
//! or an attachment payload by asking the configured
//! [`crate::key_provider::FieldProtector`] for a fresh session key
//! and AES-GCM-opening the wrapped blob in process. Results live in
//! [`secrecy::SecretString`] so they zero on drop.

use secrecy::SecretString;
use uuid::Uuid;

use crate::error::EngineError;

use super::Engine;

impl Engine {
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

    /// Read the value of a non-protected custom field by name.
    ///
    /// Counterpart to [`Engine::reveal_custom_field`] for fields stored
    /// in the `entry_custom_field` table (migration 0002) — values are
    /// plaintext and no AES-GCM unwrap is involved. Returns `None` if
    /// the entry has no matching row (i.e. the field is protected, or
    /// doesn't exist at all).
    ///
    /// `EntryFull::custom_fields` lists every custom field's `name` and
    /// `is_protected`, but doesn't carry values; callers fetch values
    /// on demand via this method (non-protected) or
    /// [`Engine::reveal_custom_field`] (protected).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Sqlite`] on query failure.
    pub fn non_protected_custom_field(
        &self,
        uuid: Uuid,
        field_name: &str,
    ) -> Result<Option<String>, EngineError> {
        crate::reads::non_protected_custom_field(&self.conn, uuid, field_name)
    }

    /// Reveal the cleartext value of a field in a historic snapshot of
    /// an entry.
    ///
    /// **Symmetric with the live-reveal paths.** Protected fields
    /// inside a history snapshot (the canonical `password` slot and any
    /// custom field with `protected: true`) are AES-GCM-sealed under
    /// the same session key as the live `entry_protected.wrapped_blob`
    /// rows, then base64-encoded into the snapshot JSON. This method
    /// deserialises the JSON, base64-decodes the wrapped bytes for the
    /// requested field, acquires a fresh session key via the
    /// [`keepass_core::protector::FieldProtector`], and AES-GCM-opens.
    /// Non-protected custom fields (`protected: false`) skip the unwrap
    /// and return the plaintext from the JSON directly — no session-key
    /// fetch in that case.
    ///
    /// `field_name = "Password"` reads the historic password;
    /// any other name reads from the snapshot's `custom_fields` map.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "history_snapshot"` or
    ///   `"history_field"`) if the snapshot or named field is missing.
    /// - [`EngineError::Reveal`] for session-key acquisition failure,
    ///   base64-decode failure, or AES-GCM unwrap failure; or wrapping
    ///   [`RevealError::Json`](crate::RevealError::Json) if the
    ///   `snapshot_json` is malformed.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn reveal_history_field(
        &self,
        uuid: Uuid,
        history_index: u32,
        field_name: &str,
    ) -> Result<SecretString, EngineError> {
        crate::reveal::reveal_history_field(
            &self.conn,
            &*self.field_protector,
            uuid,
            history_index,
            field_name,
        )
    }

    /// Fetch the bytes of an entry attachment by attachment name.
    ///
    /// Returns the raw blob from `attachment_blob` joined through
    /// `entry_attachment`. Conceptually a query method, so it lands in
    /// 3.1 alongside the rest of the entry-surface implementation.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "attachment"`) if no
    ///   `entry_attachment` row matches the `(uuid, attachment_name)`
    ///   pair. Covers both the missing-entry and missing-name cases.
    /// - [`EngineError::Sqlite`] for query failure.
    pub fn attachment_bytes(
        &self,
        uuid: Uuid,
        attachment_name: &str,
    ) -> Result<Vec<u8>, EngineError> {
        crate::reads::attachment_bytes(&self.conn, uuid, attachment_name)
    }

    /// Fetch the bytes of an attachment as it existed in a specific
    /// history snapshot of an entry.
    ///
    /// Resolves the snapshot's `attachments` list to find the named
    /// attachment's content-addressed SHA-256, then joins through
    /// `attachment_blob` for the raw bytes. The blob row survives even
    /// if later edits to the live entry replace or drop the attachment,
    /// so a snapshot's bytes remain retrievable as long as some entry
    /// (live or historical) still references that SHA.
    ///
    /// # Errors
    ///
    /// - [`EngineError::NotFound`] (`entity = "attachment"`) for every
    ///   miss along the chain: missing entry, missing history index,
    ///   missing attachment name in the snapshot, pre-widening snapshot
    ///   that didn't record the SHA-256, or dangling blob reference.
    /// - [`EngineError::Sqlite`] for query failure.
    /// - [`EngineError::Reveal`] (`Json`) if the snapshot JSON fails
    ///   to deserialise — shouldn't happen for engine-written rows.
    pub fn history_attachment_bytes(
        &self,
        uuid: Uuid,
        history_index: u32,
        attachment_name: &str,
    ) -> Result<Vec<u8>, EngineError> {
        crate::reads::history_attachment_bytes(&self.conn, uuid, history_index, attachment_name)
    }
}
