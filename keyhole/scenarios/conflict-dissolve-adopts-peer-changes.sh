#!/usr/bin/env bash
#
# A held conflict that dissolves must not strand the peer's other changes.
#
# A held conflict parks the peer's whole entry; local stays untouched, so the
# peer's NON-clashing edits riding alongside the clash wait in the peer row.
# When local then converges on the clashing field, the conflict dissolves —
# and those waiting edits must land on local, as a clean pull would land
# them. Dropping the row without adopting them leaves the peer's edit
# nowhere locally, and the next save overwrites the copy it came from.
#
# Shape: A and B fork; B renames the entry and changes the username, A
# changes the username too (the clash). A ingests B (conflict held), then
# sets its username to B's. Read back after `rm -rf "$A.mirror"` (the
# mirror persists state across processes like a real client's local store,
# so only a fresh re-ingest is honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

fail() { echo "FAIL: $1" >&2; exit 1; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username uA >/dev/null
"$KEYHOLE" --at 2100000 update-entry "$B" "$uuid" --title "E-peer" --username uB >/dev/null
"$KEYHOLE" --at 3000000 ingest-peer "$A" "$B" --owner b >/dev/null
grep -q "$uuid" <<<"$("$KEYHOLE" list-conflicts "$A")" || fail "no conflict held"
grep -q "E-peer" <<<"$("$KEYHOLE" list "$A")" && fail "a held conflict adopted the peer's title early"

# Local converges on the clashing field: the conflict dissolves.
"$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username uB >/dev/null

rm -rf "$A.mirror"
listing="$("$KEYHOLE" list "$A")"
grep -q "E-peer" <<<"$listing" \
    || fail "the peer's non-clashing title edit was stranded by the dissolve: [$listing]"
grep -q "$uuid" <<<"$("$KEYHOLE" list-conflicts "$A")" && fail "the dissolved conflict is still held"

echo "PASS conflict-dissolve-adopts-peer-changes"
