#!/usr/bin/env bash
#
# Scenario: `group_tree` direct entry counts are attributed by LOCATION,
# never the per-entry `is_recycled` flag.
#
# What's proven:
#
#   1. A group recycled with entries inside keeps its own direct count —
#      in the WARM mirror right after the move (where the buried entry's
#      `is_recycled` flag is still 0; a group recycle re-parents without
#      cascading the flag) AND across a `rm -rf "$VAULT.mirror"` fresh
#      ingest (where ingest re-derives the flag to 1 from ancestry).
#      The cold read is the discriminating half: a flag-filtered count
#      reported the group empty after reopen — the same vault counting
#      differently warm vs cold, and entries buried in the bin subtree
#      counting NOWHERE (their group excluded them, the bin root never
#      held them).
#   2. The bin root's own count stays "what sits directly in it": the
#      directly-recycled entry, not the buried one.
#
# Sums over the bin subtree (a client's "how much is in the Trash?")
# are the consumer's job; the seam guarantees each group's direct count
# is honest wherever the group lives.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# Direct count for the group whose list-groups line matches $1.
count_of() {
    "$KEYHOLE" list-groups "$VAULT" | grep -F -- "$1" \
        | sed -n 's/.*(\([0-9][0-9]*\) entries).*/\1/p' | head -n 1
}
cold() { rm -rf "$VAULT.mirror"; }

# --- seed: two root entries, bin materialised by a direct recycle ------
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username a "$VAULT" "Alpha" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username b "$VAULT" "Bravo" >/dev/null

bravo="$("$KEYHOLE" list "$VAULT" | awk '/Bravo/ {print $1; exit}')"
[ -n "$bravo" ] || { echo "FAIL: could not find Bravo"; exit 1; }
"$KEYHOLE" recycle "$VAULT" "$bravo" >/dev/null   # lazily creates the bin

"$KEYHOLE" create-group "$VAULT" "Doomed" >/dev/null
doomed="$("$KEYHOLE" list-groups "$VAULT" | awk '/Doomed/ {print $1; exit}')"
bin="$(   "$KEYHOLE" list-groups "$VAULT" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$doomed" ] || { echo "FAIL: could not find Doomed group"; exit 1; }
[ -n "$bin" ]    || { echo "FAIL: could not find bin group"; exit 1; }

"$KEYHOLE" create-entry "$VAULT" "Buried" --group "$doomed" >/dev/null

n="$(count_of Doomed)"
[ "$n" = "1" ] || { echo "FAIL: live Doomed counts $n, want 1"; exit 1; }

# --- recycle the group; warm mirror, buried entry's flag is still 0 ---
"$KEYHOLE" move-group "$VAULT" "$doomed" --to "$bin" >/dev/null

n="$(count_of Doomed)"
[ "$n" = "1" ] || { echo "FAIL: warm recycled Doomed counts $n, want 1"; exit 1; }
n="$(count_of '[bin]')"
[ "$n" = "1" ] || { echo "FAIL: warm bin counts $n, want 1 (Bravo only)"; exit 1; }

# --- the teeth: fresh ingest re-derives the flag to 1 from ancestry ---
# A flag-filtered count reads Doomed as empty here; location keeps the
# buried entry counted on its group.
cold
n="$(count_of Doomed)"
[ "$n" = "1" ] || { echo "FAIL: cold recycled Doomed counts $n, want 1 (flag-count regression?)"; exit 1; }
n="$(count_of '[bin]')"
[ "$n" = "1" ] || { echo "FAIL: cold bin counts $n, want 1 (Bravo only)"; exit 1; }

echo "PASS: group_tree direct counts follow location — a recycled group keeps its count warm and across a fresh ingest, and the bin counts only its direct contents"
