//! Read-only navigation over a `keepass-core` group tree.
//!
//! The model layer exports almost no navigation, so each module that
//! needed to answer "where does this entry live?" grew its own
//! recursion — one returning the parent group, one the entry, one just
//! a bool. All three are the same depth-first walk with different
//! projections, so they are one walk here ([`find_entry_with_parent`])
//! plus three one-liners.
//!
//! These are the *read* walks. The write-side walk that projects a
//! tree into the mirror stays in `ingest`, where the SQL it emits
//! lives.

use keepass_core::model::{Entry, EntryId, Group, GroupId};

/// Depth-first search for the entry `target`, returning it alongside
/// the id of the group that holds it. `None` if the entry lives
/// nowhere in the subtree rooted at `group`.
///
/// An entry lives in exactly one group, so the first hit is the only
/// hit and the walk stops there.
pub(crate) fn find_entry_with_parent(group: &Group, target: EntryId) -> Option<(&Entry, GroupId)> {
    if let Some(entry) = group.entries.iter().find(|e| e.id == target) {
        return Some((entry, group.id));
    }
    group
        .groups
        .iter()
        .find_map(|child| find_entry_with_parent(child, target))
}

/// The entry `target`, wherever it lives under `group`.
pub(crate) fn find_entry(group: &Group, target: EntryId) -> Option<&Entry> {
    find_entry_with_parent(group, target).map(|(entry, _)| entry)
}

/// The id of the group holding `target`, wherever it lives under
/// `group`.
pub(crate) fn find_entry_parent_group(group: &Group, target: EntryId) -> Option<GroupId> {
    find_entry_with_parent(group, target).map(|(_, parent)| parent)
}

/// Whether `group` or any descendant holds the entry `target`.
pub(crate) fn contains_entry(group: &Group, target: EntryId) -> bool {
    find_entry_with_parent(group, target).is_some()
}

/// Depth-first collection of every entry under `root`, each paired
/// with the id of the group holding it.
pub(crate) fn collect_entries_with_parent(root: &Group) -> Vec<(&Entry, GroupId)> {
    fn walk<'a>(group: &'a Group, out: &mut Vec<(&'a Entry, GroupId)>) {
        out.extend(group.entries.iter().map(|entry| (entry, group.id)));
        for child in &group.groups {
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// Depth-first collection of every entry under `root`.
pub(crate) fn collect_entries(root: &Group) -> Vec<&Entry> {
    collect_entries_with_parent(root)
        .into_iter()
        .map(|(entry, _)| entry)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// A group with its own fresh id, holding entries with the given ids.
    fn group(entry_ids: &[EntryId]) -> Group {
        let mut g = Group::empty(GroupId(Uuid::new_v4()));
        g.entries = entry_ids.iter().map(|id| Entry::empty(*id)).collect();
        g
    }

    /// root[a] → child[b] → grandchild[c]
    fn tree(a: EntryId, b: EntryId, c: EntryId) -> Group {
        let mut root = group(&[a]);
        let mut child = group(&[b]);
        child.groups.push(group(&[c]));
        root.groups.push(child);
        root
    }

    fn ids() -> (EntryId, EntryId, EntryId) {
        (
            EntryId(Uuid::from_u128(1)),
            EntryId(Uuid::from_u128(2)),
            EntryId(Uuid::from_u128(3)),
        )
    }

    #[test]
    fn finds_entry_and_parent_at_every_depth() {
        let (a, b, c) = ids();
        let root = tree(a, b, c);
        let child = &root.groups[0];
        let grandchild = &child.groups[0];

        for (target, expected_parent) in [(a, root.id), (b, child.id), (c, grandchild.id)] {
            let (entry, parent) = find_entry_with_parent(&root, target).expect("entry found");
            assert_eq!(entry.id, target);
            assert_eq!(parent, expected_parent);
        }
    }

    #[test]
    fn absent_entry_is_none_everywhere() {
        let (a, b, c) = ids();
        let root = tree(a, b, c);
        let absent = EntryId(Uuid::from_u128(99));

        assert!(find_entry_with_parent(&root, absent).is_none());
        assert!(find_entry(&root, absent).is_none());
        assert!(find_entry_parent_group(&root, absent).is_none());
        assert!(!contains_entry(&root, absent));
    }

    #[test]
    fn contains_entry_sees_descendants() {
        let (a, b, c) = ids();
        let root = tree(a, b, c);
        assert!(contains_entry(&root, c));
        // ...but a subtree only sees its own.
        assert!(!contains_entry(&root.groups[0].groups[0], a));
    }

    #[test]
    fn collect_entries_gathers_the_whole_tree_depth_first() {
        let (a, b, c) = ids();
        let root = tree(a, b, c);
        let collected: Vec<_> = collect_entries(&root).iter().map(|e| e.id).collect();
        assert_eq!(collected, vec![a, b, c]);
    }

    #[test]
    fn collect_entries_with_parent_pairs_each_entry_with_its_group() {
        let (a, b, c) = ids();
        let root = tree(a, b, c);
        let child = &root.groups[0];
        let grandchild = &child.groups[0];

        let collected: Vec<_> = collect_entries_with_parent(&root)
            .into_iter()
            .map(|(e, g)| (e.id, g))
            .collect();
        assert_eq!(
            collected,
            vec![(a, root.id), (b, child.id), (c, grandchild.id)]
        );
    }
}
