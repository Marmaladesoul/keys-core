#!/usr/bin/env bash
#
# RED (pre-correct-fix) → GREEN: a local edit that dissolves ONE peer's
# parked conflict must NOT un-badge a DIFFERENT peer's still-genuine
# conflict on the same entry. Multi-peer (3 devices), the case the
# single-peer Finding #10 scenario can't reach.
#
# This guards the over-clear the adversarial review caught: the first
# #10 fix cleared conflict rows owner-AGNOSTICALLY in `bump_modified`
# (`drop_conflict_rows` deletes WHERE entry_uuid=?, no owner filter), so
# editing toward peer B's value also wiped peer C's unresolved row — and
# a bare local edit, unlike a resolve, writes no propagation record, so
# C's divergence would silently vanish from the badge.
#
# Correct semantics (owner-aware): editing A's entry to match B's parked
# value dissolves the A-vs-B conflict (drop that owner's row) but leaves
# the A-vs-C conflict parked (it still genuinely diverges) — so the
# entry stays badged for C.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"
C="$TMP/device-c.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username V0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"; cp "$A" "$C"

# Badge count via list-conflicts ONLY (show-conflict would self-heal).
badge() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }

# Three-way divergence on the same field.
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username Va >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username Vb >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$C" "$uuid" --username Vc >/dev/null

# A parks a conflict against BOTH peers (two owner-tagged rows on E).
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$A" "$C" --owner device-c >/dev/null
[ "$(badge "$A")" = 1 ] || { echo "FAIL(setup): A did not park the multi-peer clash"; exit 1; }

# A's user locally edits E to MATCH peer B's value (Vb). The A-vs-B
# conflict dissolves; the A-vs-C conflict (Vb vs Vc) does NOT.
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username Vb >/dev/null

# THE BUG (over-clear): the entry must stay badged — peer C is still
# unresolved. The owner-agnostic clear wrongly drops C's row too → badge 0.
[ "$(badge "$A")" = 1 ] \
    || { echo "FAIL: over-clear — a local edit toward peer B un-badged the still-unresolved peer-C conflict"; exit 1; }

echo "PASS: local edit dissolves only the matched peer's conflict; other peers stay badged"
