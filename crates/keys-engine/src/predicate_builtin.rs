//! Built-in smart folders (task 3.7).
//!
//! Canned [`Predicate`] values the frontend can show as default smart
//! folders without the user having to author them: weak passwords,
//! recently modified, expired, expiring soon, all entries, recycle bin
//! contents.
//!
//! These are pure data — no rows in the `smart_folder` table. They
//! live as constants/functions so the frontend can iterate
//! [`BUILTIN_SMART_FOLDERS`], render a sidebar, and call the engine's
//! smart-folder evaluation API (3.8) with the predicate the folder's
//! `kind` resolves to.
//!
//! ## Design decisions
//!
//! 1. **`all_entries`**: special-cased. There is no `Predicate::All`
//!    variant — adding one would touch the versioned predicate enum,
//!    the JSON wire format and the SQL compiler for a value the
//!    frontend can trivially translate to "call `list_entries(None,
//!    page)` instead of `smart_folder_entries`". The
//!    [`BuiltinSmartFolderKind::AllEntries`] arm carries no predicate
//!    and the caller is expected to route it through the unfiltered
//!    listing path.
//! 2. **`recycle_bin_contents`**: parameterised. The recycle bin's
//!    group UUID is per-vault and is already returned by
//!    [`crate::Engine::group_tree`], so adding a
//!    `Predicate::RecycleBinContents` variant just to push that
//!    lookup into the compiler would duplicate logic the caller
//!    already has. [`recycle_bin_contents`] takes a [`Uuid`] and
//!    returns [`Predicate::Group`].
//! 3. **"Weak" bucket boundary**: [`weak_password`] compiles to
//!    `StrengthBelow { bucket: Reasonable }` — i.e. `VeryWeak` and
//!    `Weak` only. `Reasonable` is by definition acceptable; a
//!    folder titled "Weak Passwords" should not nag the user about
//!    those.
//! 4. **"Recently modified" window**: fixed at 30 days, matching the
//!    project plan. A configurable window would belong to a
//!    user-defined smart folder, not a built-in.

use std::time::Duration;

use uuid::Uuid;

use crate::model::StrengthBucket;
use crate::predicate::Predicate;

/// Window length for [`recently_modified`]: 30 days.
pub const RECENTLY_MODIFIED_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Window length for [`expiring_soon`]: 7 days.
pub const EXPIRING_SOON_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// "Weak Passwords" — entries whose password strength bucket is
/// strictly below `Reasonable` (i.e. `VeryWeak` or `Weak`).
#[must_use]
pub fn weak_password() -> Predicate {
    Predicate::StrengthBelow {
        bucket: StrengthBucket::Reasonable,
    }
}

/// "Recently Modified" — entries modified within the last 30 days.
#[must_use]
pub fn recently_modified() -> Predicate {
    Predicate::ModifiedWithin {
        duration: RECENTLY_MODIFIED_WINDOW,
    }
}

/// "Expired" — entries whose expiry is in the past.
#[must_use]
pub fn expired() -> Predicate {
    Predicate::Expired
}

/// "Expiring Soon" — entries that expire within the next 7 days.
#[must_use]
pub fn expiring_soon() -> Predicate {
    Predicate::ExpiringWithin {
        duration: EXPIRING_SOON_WINDOW,
    }
}

/// "Recycle Bin" — entries whose parent group is the recycle bin.
///
/// The recycle bin's UUID is per-vault; callers obtain it from
/// [`crate::Engine::group_tree`] (or the cached `recycle_bin_uuid`
/// engine field once 3.8 lands) and pass it here.
#[must_use]
pub fn recycle_bin_contents(recycle_bin_uuid: Uuid) -> Predicate {
    Predicate::Group {
        uuid: recycle_bin_uuid,
    }
}

/// Hint to the frontend about which glyph to render for a builtin
/// folder. The engine doesn't render anything; this is a stable enum
/// so all UI surfaces agree on iconography.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BuiltinFolderIcon {
    /// Attention-grabbing icon — used for "weak" and "expired".
    Warning,
    /// Clock icon — used for time-windowed folders.
    Clock,
    /// Trash / recycle bin icon.
    Trash,
    /// Star or favourite icon (reserved; not currently used).
    Star,
    /// Catch-all "everything" icon — used for "All Entries".
    All,
}

/// What kind of builtin folder this is — drives how the caller
/// evaluates it.
///
/// Most builtins boil down to a [`Predicate`] the caller compiles
/// and runs. Two are special:
///
/// - [`BuiltinSmartFolderKind::AllEntries`] has no predicate; the
///   caller should list all entries (or all non-recycled entries,
///   per UX) without a `WHERE` filter.
/// - [`BuiltinSmartFolderKind::RecycleBin`] needs the vault's
///   recycle-bin UUID, which the caller knows; it materialises into
///   a [`Predicate::Group`] via [`recycle_bin_contents`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BuiltinSmartFolderKind {
    /// All entries; evaluate by listing without a predicate.
    AllEntries,
    /// Resolves to [`weak_password`].
    WeakPassword,
    /// Resolves to [`recently_modified`].
    RecentlyModified,
    /// Resolves to [`expired`].
    Expired,
    /// Resolves to [`expiring_soon`].
    ExpiringSoon,
    /// Resolves to [`recycle_bin_contents`] once the caller supplies
    /// the recycle bin UUID.
    RecycleBin,
}

impl BuiltinSmartFolderKind {
    /// Materialise the predicate for this kind, if any.
    ///
    /// Returns `None` for [`Self::AllEntries`] (caller should list
    /// without a filter) and for [`Self::RecycleBin`] (caller must
    /// use [`recycle_bin_contents`] with the vault's recycle bin
    /// UUID).
    #[must_use]
    pub fn predicate(self) -> Option<Predicate> {
        match self {
            Self::AllEntries | Self::RecycleBin => None,
            Self::WeakPassword => Some(weak_password()),
            Self::RecentlyModified => Some(recently_modified()),
            Self::Expired => Some(expired()),
            Self::ExpiringSoon => Some(expiring_soon()),
        }
    }
}

/// Descriptor for one builtin smart folder.
///
/// All fields are `'static` so the entire [`BUILTIN_SMART_FOLDERS`]
/// table is a `const`. The frontend iterates the table to render
/// the sidebar; each `id` is a stable string the UI can use as a
/// selection key and the analytics layer can log.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinSmartFolder {
    /// Stable, namespaced identifier — e.g. `"builtin.weak_password"`.
    /// Must be unique across [`BUILTIN_SMART_FOLDERS`].
    pub id: &'static str,
    /// Default user-facing label. Frontends may localise.
    pub display_name: &'static str,
    /// Icon hint.
    pub icon: BuiltinFolderIcon,
    /// What kind of folder this is. Drives evaluation.
    pub kind: BuiltinSmartFolderKind,
}

/// Canonical list of builtin smart folders, in display order.
pub const BUILTIN_SMART_FOLDERS: &[BuiltinSmartFolder] = &[
    BuiltinSmartFolder {
        id: "builtin.all_entries",
        display_name: "All Entries",
        icon: BuiltinFolderIcon::All,
        kind: BuiltinSmartFolderKind::AllEntries,
    },
    BuiltinSmartFolder {
        id: "builtin.weak_password",
        display_name: "Weak Passwords",
        icon: BuiltinFolderIcon::Warning,
        kind: BuiltinSmartFolderKind::WeakPassword,
    },
    BuiltinSmartFolder {
        id: "builtin.recently_modified",
        display_name: "Recently Modified",
        icon: BuiltinFolderIcon::Clock,
        kind: BuiltinSmartFolderKind::RecentlyModified,
    },
    BuiltinSmartFolder {
        id: "builtin.expired",
        display_name: "Expired",
        icon: BuiltinFolderIcon::Warning,
        kind: BuiltinSmartFolderKind::Expired,
    },
    BuiltinSmartFolder {
        id: "builtin.expiring_soon",
        display_name: "Expiring Soon",
        icon: BuiltinFolderIcon::Clock,
        kind: BuiltinSmartFolderKind::ExpiringSoon,
    },
    BuiltinSmartFolder {
        id: "builtin.recycle_bin",
        display_name: "Recycle Bin",
        icon: BuiltinFolderIcon::Trash,
        kind: BuiltinSmartFolderKind::RecycleBin,
    },
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn weak_password_predicate_is_evaluable() {
        assert!(weak_password().is_evaluable());
    }

    #[test]
    fn recently_modified_is_30_days() {
        let Predicate::ModifiedWithin { duration } = recently_modified() else {
            panic!("expected ModifiedWithin");
        };
        assert_eq!(duration, Duration::from_secs(30 * 24 * 60 * 60));
    }

    #[test]
    fn expiring_soon_is_7_days() {
        let Predicate::ExpiringWithin { duration } = expiring_soon() else {
            panic!("expected ExpiringWithin");
        };
        assert_eq!(duration, Duration::from_secs(7 * 24 * 60 * 60));
    }

    #[test]
    fn weak_password_is_below_reasonable() {
        let Predicate::StrengthBelow { bucket } = weak_password() else {
            panic!("expected StrengthBelow");
        };
        assert_eq!(bucket, StrengthBucket::Reasonable);
    }

    #[test]
    fn recycle_bin_contents_returns_group_predicate() {
        let uuid = Uuid::nil();
        let Predicate::Group { uuid: got } = recycle_bin_contents(uuid) else {
            panic!("expected Group");
        };
        assert_eq!(got, uuid);
    }

    #[test]
    fn all_entries_kind_has_no_predicate() {
        assert!(BuiltinSmartFolderKind::AllEntries.predicate().is_none());
    }

    #[test]
    fn recycle_bin_kind_has_no_predicate() {
        // Caller must use `recycle_bin_contents(uuid)` instead.
        assert!(BuiltinSmartFolderKind::RecycleBin.predicate().is_none());
    }

    #[test]
    fn builtin_folders_have_unique_stable_ids() {
        let mut seen = HashSet::new();
        for f in BUILTIN_SMART_FOLDERS {
            assert!(seen.insert(f.id), "duplicate builtin id: {}", f.id);
        }
    }

    #[test]
    fn builtin_folder_ids_use_builtin_namespace() {
        for f in BUILTIN_SMART_FOLDERS {
            assert!(
                f.id.starts_with("builtin."),
                "id should be namespaced: {}",
                f.id
            );
        }
    }
}
