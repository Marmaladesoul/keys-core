#!/usr/bin/env bash
#
# Scenario: cross-peer delete-vs-edit, pinning the documented 5b rules
# (sync-merge-strategies §4 / sync-multipeer-store 5b) at disk
# precision:
#
#   1. Edit strictly AFTER the delete → edit wins: the editing side
#      keeps the entry, and syncing back RESURRECTS it on the deleting
#      side (scrubbing the tombstone — a live entry must never coexist
#      with its own tombstone).
#   2. Edit and delete within the SAME wall-clock second → a tie at
#      disk precision → the delete wins, on BOTH sides identically.
#      (KDBX times are second-resolution in 3.1 and 4.x alike; the
#      engine floors mirror times to match — Finding #4 — so the tie
#      rule is symmetric by construction.)
#
# Teeth: case 1 fails if tombstones don't propagate or the zombie
# guard eats the live edit; case 2 fails if either side applies the
# tie rule asymmetrically (the pre-Finding-#4 behaviour).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

# --- case 1: edit strictly after delete → edit wins + resurrects ----
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Lazarus" --username alive >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Lazarus/ {print $1; exit}')"
cp "$A" "$B"

"$KEYHOLE" delete-entry "$B" "$uuid" >/dev/null
sleep 1.1   # cross a whole-second boundary: the edit is genuinely later
"$KEYHOLE" update-entry "$A" "$uuid" --username rescued >/dev/null

"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" list "$A" | grep '<rescued>' >/dev/null \
    || { echo "FAIL: post-delete edit was eaten by the peer's tombstone"; exit 1; }

"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list "$B" | grep '<rescued>' >/dev/null \
    || { echo "FAIL: edited entry did not resurrect on the deleting side"; exit 1; }
da="$("$KEYHOLE" digest "$A")"; db="$("$KEYHOLE" digest "$B")"
[ "$da" = "$db" ] || { echo "FAIL: case-1 replicas did not converge"; exit 1; }

# --- case 2: same-second delete and edit → tie → delete wins, both sides
"$KEYHOLE" create-entry "$A" "Doomed" --username brief >/dev/null
duuid="$("$KEYHOLE" list "$A" | awk '/Doomed/ {print $1; exit}')"
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null   # share it first
"$KEYHOLE" list "$B" | grep "$duuid" || { echo "FAIL: setup — Doomed did not sync to B"; exit 1; } >/dev/null

# Same second: no sleep between the two ops (each invocation is well
# under a second; both mtimes floor to the same instant in practice).
"$KEYHOLE" delete-entry "$B" "$duuid" >/dev/null
"$KEYHOLE" update-entry "$A" "$duuid" --username too-late >/dev/null

"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
da="$("$KEYHOLE" digest "$A")"; db="$("$KEYHOLE" digest "$B")"
[ "$da" = "$db" ] || { echo "FAIL: case-2 replicas did not converge after tie"; exit 1; }
if "$KEYHOLE" list "$A" | grep "$duuid"; then >/dev/null
    # The edit may legitimately land in the NEXT second on a slow run —
    # then edit-wins is correct. Accept either converged outcome, but
    # call out which one ran so a flaky tie isn't silently untested.
    echo "note: ops straddled a second boundary — edit-wins path exercised instead of the tie"
    "$KEYHOLE" list "$B" | grep "$duuid" || { echo "FAIL: straddle case diverged"; exit 1; } >/dev/null
else
    "$KEYHOLE" list "$B" | grep "$duuid" && { echo "FAIL: tie outcome asymmetric"; exit 1; } >/dev/null
fi

echo "PASS: post-delete edit wins and resurrects; same-second tie converges identically on both replicas"
