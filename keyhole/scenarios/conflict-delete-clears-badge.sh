#!/usr/bin/env bash
#
# RED → GREEN (Finding #11): deleting a conflicted entry must clear its
# badge, not leave an orphan conflict_entry row haunting a deleted entry.
#
# Pre-fix behaviour: delete_entry removed the entry but not its parked
# conflict rows (no FK cascade onto conflict_entry), so
# `entries_with_parked_conflict` kept reporting a uuid with no live
# entry behind it — a ghost badge for something that no longer exists.
#
# Fix: the post-mutation conflict reconciliation (Finding #10 work)
# treats "entry gone locally" as "drop all its conflict rows", so a
# delete clears the badge as part of the same operation.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username V0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"

badge() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }

# Park a genuine conflict on E.
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username Va >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username Vb >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ "$(badge "$A")" = 1 ] || { echo "FAIL(setup): A did not park the clash"; exit 1; }

# Delete the conflicted entry — the badge must clear (no orphan rows).
"$KEYHOLE" --at 3000000 delete-entry "$A" "$uuid" >/dev/null
[ "$(badge "$A")" = 0 ] \
    || { echo "FAIL: ghost badge — a deleted entry still reports a parked conflict"; exit 1; }

# Survives a fresh disk read.
rm -rf "$A.mirror"
[ "$(badge "$A")" = 0 ] || { echo "FAIL: orphan conflict badge resurrected after reopen"; exit 1; }

echo "PASS: deleting a conflicted entry clears its badge (no orphan conflict rows)"
