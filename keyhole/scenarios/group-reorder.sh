#!/usr/bin/env bash
#
# Scenario: `reorder_group(uuid, new_position)` — what the index means,
# and that the order survives the KDBX round-trip.
#
# Pinned semantics: `new_position` is the moved group's 0-based index in
# its parent's sibling list AFTER the move. The engine removes the group
# from its old slot first, then inserts it at `new_position`; values
# past the end clamp to last. So with siblings [A B C D E]:
#
#   reorder B → 3   gives [A C D B E]  (not [A C B D E]: the index is
#                                       NOT a pre-removal insertion gap)
#
# A client whose drop gesture yields a pre-removal insertion gap (an
# outline view's "insert before row N", counted with the dragged row
# still in place) must subtract one for a downward move before calling
# `reorder_group`; for an upward move the two coincide.
#
# Each step is asserted from disk (mirror nuked → fresh ingest), so the
# sibling order is proven to live in the KDBX, not just the mirror.
# Covers: down by several, down by one (the classic off-by-one case),
# up, last → first, first → exact last index, clamp past the end, and a
# same-position no-op.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/group-reorder.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null

# A dedicated parent keeps the recycle bin (a root child) out of the
# sibling list under test.
"$KEYHOLE" create-group "$VAULT" "Shelf" >/dev/null
shelf="$("$KEYHOLE" child-groups "$VAULT" | awk '$2 == "Shelf" {print $1; exit}')"
for n in A B C D E; do
    "$KEYHOLE" create-group "$VAULT" "$n" --parent "$shelf" >/dev/null
done

uuid_of() { "$KEYHOLE" child-groups "$VAULT" --parent "$shelf" | awk -v n="$1" '$2 == n {print $1; exit}'; }
# Sibling order from disk, as one space-separated line of names.
order() {
    rm -rf "$VAULT.mirror"
    "$KEYHOLE" child-groups "$VAULT" --parent "$shelf" | awk '{print $2}' | paste -sd' ' -
}
expect() {
    local got
    got="$(order)"
    [ "$got" = "$1" ] || { echo "FAIL: $2: order after reopen is [$got], want [$1]"; exit 1; }
}
reorder() { "$KEYHOLE" reorder-group "$VAULT" "$(uuid_of "$1")" --position "$2" >/dev/null; }

expect "A B C D E" "creation order"

reorder B 3; expect "A C D B E" "down by two (B 1 → 3; post-removal index)"
reorder B 1; expect "A B C D E" "up by two (B 3 → 1)"
reorder E 0; expect "E A B C D" "last → first (E → 0)"
reorder E 4; expect "A B C D E" "first → last (E → 4, the exact last index)"
reorder A 99; expect "B C D E A" "clamp past the end (A → 99)"
reorder C 1; expect "B C D E A" "same-position no-op (C already at 1)"
reorder D 3; expect "B C E D A" "down by one (D 2 → 3)"
reorder D 2; expect "B C D E A" "up by one (D 3 → 2)"

echo "PASS: reorder_group's new_position is the post-removal final index (clamped), up and down, first and last, and the order survives the KDBX round-trip"
