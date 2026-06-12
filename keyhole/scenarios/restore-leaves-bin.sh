#!/usr/bin/env bash
#
# Scenario: "restore takes the entry OUT of the recycle bin" — recycle
# an entry, restore it, and assert (from disk) that it is no longer in
# the bin group and is listable at the root again.
#
# This pins down the suspicion recorded in DESIGN.md when the recycle
# verbs first landed: keys-engine::restore_entry looked like it cleared
# `is_recycled` without moving the entry out of the bin *group*, which
# would leave a "restored" entry still sitting in the Trash as far as
# every group-scoped view (and every other KDBX client) is concerned.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/restore.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Phoenix" --username rise >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Phoenix/ {print $1; exit}')"
root="$("$KEYHOLE" list-groups "$VAULT" | awk 'NR==1 {print $1}')"

# From-disk bin count (mirror nuked first — see DESIGN.md).
bin_count() { rm -rf "$VAULT.mirror"; "$KEYHOLE" inspect "$VAULT" | awk '/^recycled:/ {print $2}'; }

"$KEYHOLE" recycle "$VAULT" "$uuid" >/dev/null
[ "$(bin_count)" = "1" ] || { echo "FAIL: recycle did not land in the bin"; exit 1; }

"$KEYHOLE" restore "$VAULT" "$uuid" >/dev/null

n="$(bin_count)"
[ "$n" = "0" ] || { echo "FAIL: restored entry still counted in the bin ($n) — restore didn't move it out of the bin group"; exit 1; }

# And it must be back in a *visible* group (root), not merely flagged.
"$KEYHOLE" list "$VAULT" --group "$root" | grep -q "$uuid" \
    || { echo "FAIL: restored entry not listed under the root group"; exit 1; }

# --- the sharper half: restore returns to the ORIGINAL group ---------
# (KDBX 4.1 PreviousParentGroup, recorded by recycle.) An entry that
# lived in a subfolder must come back to that subfolder, not to root.
"$KEYHOLE" create-group "$VAULT" "Nest" >/dev/null
nest="$("$KEYHOLE" list-groups "$VAULT" | awk '/Nest/ {print $1; exit}')"
"$KEYHOLE" create-entry "$VAULT" "Nested" --username egg --group "$nest" >/dev/null
nuuid="$("$KEYHOLE" list "$VAULT" | awk '/Nested/ {print $1; exit}')"

"$KEYHOLE" recycle "$VAULT" "$nuuid" >/dev/null

# Force PreviousParentGroup through the FULL KDBX round-trip: nuke the
# mirror so restore must read the origin from a fresh ingest of the
# file. A warm mirror would pass even if projection/ingest dropped the
# element (adversarial-review catch: half the fix would be untested).
rm -rf "$VAULT.mirror"

# Double-recycle regression: recycling an already-binned entry must be
# a no-op, NOT clobber the recorded origin with the bin itself (which
# would make restore "restore" the entry into the Trash).
"$KEYHOLE" recycle "$VAULT" "$nuuid" >/dev/null

"$KEYHOLE" restore "$VAULT" "$nuuid" >/dev/null
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" --group "$nest" | grep -q "$nuuid" \
    || { echo "FAIL: restored entry did not return to its original subfolder (PreviousParentGroup lost in round-trip or clobbered by double-recycle)"; exit 1; }

# Restore-of-live-entry regression: restoring an entry that is NOT in
# the Trash must not relocate it.
"$KEYHOLE" restore "$VAULT" "$nuuid" >/dev/null
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" --group "$nest" | grep -q "$nuuid" \
    || { echo "FAIL: restore of a live entry relocated it out of its group"; exit 1; }

echo "PASS: restore exits the bin to the original group (via full KDBX round-trip); double-recycle and live-restore are safe no-ops"
