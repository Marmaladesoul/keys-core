//! Helpers shared across the mirror-facing modules (`ingest`,
//! `mutations`, `reads`, `projection`, `reveal`, `conflict_rows`,
//! `conflict_resolution`).
//!
//! Every item here previously existed as two or more independent
//! copies kept aligned by "mirrors …" doc comments. That is a drift
//! hazard with teeth: the copies are used on *different* write paths
//! against the *same* columns, so a normalisation applied to one and
//! not its twin silently produces two generations of rows. The worked
//! example is [`sql::parse_host`] — it feeds the indexed `url_host`
//! column from both ingest and edit, and a one-sided change there
//! would desync the two, breaking `search_by_service` for whichever
//! rows went through the other path.
//!
//! The rule for this module: a helper earns a place here the moment a
//! second module needs it. Nothing here holds policy — these are
//! codecs, existence checks, and tree walks.

pub(crate) mod codec;
pub(crate) mod sql;
pub(crate) mod tree;

/// The canonical KDBX name of the password field.
///
/// KDBX models the password as a *named* standard field rather than a
/// dedicated slot, so both the `SQLite` mirror (`entry_protected.field_name`)
/// and the `keepass-core` model (`Entry::password` vs `custom_fields`)
/// key off this exact string. Every module that decides "is this the
/// password or a custom field?" compares against it, which is why it
/// is declared once here rather than per-module.
pub(crate) const PASSWORD_FIELD: &str = "Password";
