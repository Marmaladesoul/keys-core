//! The test-vault marker: the one rule for "is this a test vault?".
//!
//! A vault is a **test vault** iff its Meta `CustomData` holds the item
//! [`MARKER_KEY`] with the value exactly [`MARKER_VALUE`]. Any other value,
//! or no item, is an ordinary vault — so a mistyped marker fails closed.
//! The marker lives inside the KDBX, so renaming or moving the file can't
//! give it to a vault or take it away.
//!
//! **A mirror's kind changes only when it is rebuilt from its file.** A test
//! vault and an ordinary vault never merge, and no write puts one kind's
//! contents over the other's file — even when they are replicas of one vault
//! (the identity gate, [`crate::identity`], can't tell: a copy of a vault
//! *is* that vault). [`crate::Engine::ensure_same_replica`] enforces both
//! gates together: on every replica [`crate::Engine::ingest_peer`] folds in
//! — peer blobs and the file on disk alike — and on the file a save or
//! re-key is about to overwrite. The engine has no setter, so to change a
//! vault's kind, mark the *file* ([`set_marked`] on a decoded vault, then
//! save it) and rebuild its mirror with a full ingest (a client re-adds the
//! vault), which replaces the mirror wholesale and merges nothing.
//!
//! Peer ingest merges Meta scalars and conflict-resolution records only,
//! never general `CustomData`, so the marker never spreads by syncing.

use keepass_core::model::{CustomDataItem, Vault};

/// Meta `CustomData` key carrying the marker.
pub const MARKER_KEY: &str = "KeysTestVault";

/// The only value that marks a vault as a test vault.
pub const MARKER_VALUE: &str = "1";

/// Is the Meta `CustomData` item `key` = `value` the marker?
fn is_marker_item(key: &str, value: &str) -> bool {
    key == MARKER_KEY && value == MARKER_VALUE
}

/// Is a vault whose Meta `CustomData` is `custom_data` a test vault?
#[must_use]
pub fn is_marked(custom_data: &[CustomDataItem]) -> bool {
    custom_data
        .iter()
        .any(|item| is_marker_item(&item.key, &item.value))
}

/// Mark `vault` as a test vault, or (`marked == false`) remove the marker.
/// For a vault decoded from a file that is about to be saved back — never
/// for a live mirror (see the module docs).
pub fn set_marked(vault: &mut Vault, marked: bool) {
    let custom_data = &mut vault.meta.custom_data;
    custom_data.retain(|item| item.key != MARKER_KEY);
    if marked {
        custom_data.push(CustomDataItem::new(
            MARKER_KEY.to_owned(),
            MARKER_VALUE.to_owned(),
            None,
        ));
    }
}

/// How an error message names a vault's kind.
fn kind_name(is_test: bool) -> &'static str {
    if is_test {
        "a test vault"
    } else {
        "an ordinary vault"
    }
}

/// The message for a refused kind mismatch, shared by keys-engine's and
/// keys-ffi's `TestVaultMarkerMismatch`.
#[must_use]
pub fn mismatch_message(local_is_test: bool, replica_is_test: bool) -> String {
    format!(
        "the replica is {}, this vault is {}; a test vault and an ordinary vault never merge",
        kind_name(replica_is_test),
        kind_name(local_is_test)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, value: &str) -> CustomDataItem {
        CustomDataItem::new(key.to_owned(), value.to_owned(), None)
    }

    #[test]
    fn only_the_exact_marker_counts() {
        assert!(is_marked(&[
            item("Other", "x"),
            item(MARKER_KEY, MARKER_VALUE)
        ]));
        assert!(!is_marked(&[]));
        assert!(!is_marked(&[item(MARKER_KEY, "0")]));
        assert!(!is_marked(&[item(MARKER_KEY, "true")]));
        assert!(!is_marked(&[item(MARKER_KEY, "")]));
        assert!(!is_marked(&[item("keystestvault", MARKER_VALUE)]));
    }

    #[test]
    fn set_marked_adds_one_marker_and_removes_it() {
        let mut vault = Vault::empty(keepass_core::model::GroupId(uuid::Uuid::nil()));
        vault.meta.custom_data.push(item("Other", "x"));
        set_marked(&mut vault, true);
        set_marked(&mut vault, true);
        assert!(is_marked(&vault.meta.custom_data));
        assert_eq!(
            vault.meta.custom_data.len(),
            2,
            "marking twice adds one item"
        );
        vault.meta.custom_data.push(item(MARKER_KEY, "0"));
        set_marked(&mut vault, false);
        assert!(!is_marked(&vault.meta.custom_data));
        assert_eq!(
            vault.meta.custom_data.len(),
            1,
            "unmarking removes every marker-keyed item"
        );
    }
}
