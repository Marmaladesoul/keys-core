#!/usr/bin/env bash
#
# RED → GREEN (Finding #11, cascade path): deleting a GROUP that holds a
# conflicted entry must clear that entry's badge too — the cascade must not
# leave an orphan conflict_entry row haunting a now-deleted entry.
#
# Pre-fix behaviour: delete_group hard-deleted the group and cascade-deleted
# its descendant entries, but never reconciled those entries' parked conflict
# rows. There is no FK cascade onto conflict_entry (it is keyed by
# (owner, entry_uuid), not a child of entry), so the cascade removed each
# entry's own child tables but left its parked rows behind, and
# `entries_with_parked_conflict` kept reporting a uuid with no live entry
# behind it — a ghost badge for something that no longer exists.
#
# Fix: delete_group reconciles each cascade-deleted entry's conflict rows
# after the cascade commits, the same "entry gone locally → drop all its
# rows" step already wired into delete_entry / empty_recycle_bin.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
# Seed an entry INSIDE a child group, so deleting the group cascades the
# entry (a root-group entry can't be reached by delete-group).
group="$("$KEYHOLE" --at 1000000 create-group "$A" "G" | awk '/^created group/ {print $3}')"
uuid="$("$KEYHOLE" --at 1000000 create-entry "$A" "E" --username V0 --group "$group" \
    | awk '/^created entry/ {print $3}')"
cp "$A" "$B"

badge() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }

# Park a genuine conflict on E.
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username Va >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username Vb >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ "$(badge "$A")" = 1 ] || { echo "FAIL(setup): A did not park the clash"; exit 1; }

# Delete the conflicted entry's GROUP — the cascade removes E, and its badge
# must clear with it (no orphan conflict rows).
"$KEYHOLE" --at 3000000 delete-group "$A" "$group" >/dev/null
[ "$(badge "$A")" = 0 ] \
    || { echo "FAIL: ghost badge — a cascade-deleted entry still reports a parked conflict"; exit 1; }

# Survives a fresh disk read.
rm -rf "$A.mirror"
[ "$(badge "$A")" = 0 ] || { echo "FAIL: orphan conflict badge resurrected after reopen"; exit 1; }

echo "PASS: deleting a group clears its cascade-deleted entries' badges (no orphan conflict rows)"
