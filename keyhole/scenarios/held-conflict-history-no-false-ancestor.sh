#!/usr/bin/env bash
#
# A HELD conflict must not fold the peer's history into local's. classify finds
# the common ancestor by content across each side's <History>, so the peer's
# intermediate versions — versions this replica never incorporated — would read
# as a later, false common ancestor. Against it, a peer edit to a NON-clashing
# field looks like this replica's change, and is silently reverted the moment
# the clash goes away.
#
# The history merge is otherwise lossless (see history-propagates-after-fork.sh):
# a replica folds the peer's snapshots in once its live entry incorporates the
# peer's version (InSync / auto-merged / adopted). This scenario pins the one
# exception.
#
# Shape: A retitles (E → TA) then changes the username (u0 → uA); B changes the
# username (u0 → uB). The username clash parks on both; B pulls again while it
# is held. Then B sets its username to uA too, dissolving the clash without a
# resolve. The merge must still take A's title: the true ancestor is the
# pre-fork (E, u0), from which only A changed the title.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

# `<uuid>  <title>  <username>` for entry $2 in vault $1.
live() { "$KEYHOLE" list "$1" | awk -v u="$2" '$1==u {print $2, $3}'; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"

"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --title TA >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username uA >/dev/null
"$KEYHOLE" --at 2500000 update-entry "$B" "$uuid" --username uB >/dev/null

# The clash parks; B pulls a second time while it is held.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list-conflicts "$B" | grep -q "$uuid" || { echo "FAIL(setup): B did not park the username clash"; exit 1; }

# B converges on A's username by hand; the clash dissolves on the next pulls.
"$KEYHOLE" --at 4000000 update-entry "$B" "$uuid" --username uA >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
rm -rf "$A.mirror" "$B.mirror"   # honest disk read

la="$(live "$A" "$uuid")"; lb="$(live "$B" "$uuid")"
[ "$lb" = "TA <uA>" ] || { echo "FAIL: B ended at [$lb], expected [TA <uA>] — A's non-clashing title edit was reverted"; exit 1; }
[ "$la" = "TA <uA>" ] || { echo "FAIL: A ended at [$la], expected [TA <uA>] — A's own title edit was reverted"; exit 1; }

echo "PASS: a held conflict keeps the peer's history out of local's lineage, so a non-clashing peer edit survives the clash dissolving"
