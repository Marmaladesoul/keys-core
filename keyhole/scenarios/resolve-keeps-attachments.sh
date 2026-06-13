#!/usr/bin/env bash
#
# Scenario: Finding #7 — resolving a parked conflict must NOT drop
# attachments added since the fork.
#
# Shape of the bug: the resolver's "theirs" is reconstructed from the
# conflict_* owner rows; if those rows carry no attachment state, the
# rebuilt remote entry has no attachments, the local-vs-theirs merge
# reads that as "remote removed every attachment", and a choose-remote
# resolution wipes the local links (bytes survive unreferenced in the
# pool; the peer keeps its copy → replicas diverge).
#
# Teeth: both resolution sides are exercised. choose-remote is the red
# case; choose-local is the symmetric guarantee the fix must also hold.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Carrier" --username orig-user >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Carrier/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# A adds an attachment after the fork; B adopts it (proven one-sided
# propagation). Both replicas now carry doc.txt.
"$KEYHOLE" set-attachment "$A" "$uuid" doc.txt --text "precious" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
[ "$("$KEYHOLE" cat-attachment "$B" "$uuid" doc.txt)" = "precious" ] \
    || { echo "FAIL(precondition): attachment did not propagate to B"; exit 1; }

# Both sides edit the SAME field → A parks a conflict on ingest.
"$KEYHOLE" update-entry "$A" "$uuid" --username a-user >/dev/null
"$KEYHOLE" update-entry "$B" "$uuid" --username b-user >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" list-conflicts "$A" | grep -q "$uuid" \
    || { echo "FAIL(precondition): expected a held conflict on A"; exit 1; }

# --- THE BUG: resolve choosing remote must keep the attachment --------
# B's copy genuinely has doc.txt, so "take theirs" must not drop it.
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose remote >/dev/null
got="$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt 2>/dev/null || echo MISSING)"
[ "$got" = "precious" ] \
    || { echo "FAIL: choose-remote resolve dropped the attachment (got: $got)"; exit 1; }
"$KEYHOLE" list "$A" | grep -q '<b-user>' \
    || { echo "FAIL: choose-remote resolve did not take the remote field"; exit 1; }

# The resolution converges: B adopts, replicas agree, attachment intact.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
converged || { echo "FAIL: replicas diverged after choose-remote resolve"; exit 1; }

# --- Symmetric leg: choose local must keep it too ----------------------
# Cross a second boundary first: KDBX times floor to seconds (Finding #4),
# so a re-edit within the same second as leg 1's resolution record would
# not post-date it and the resolution would (correctly) hold instead of
# re-parking.
sleep 1.1
"$KEYHOLE" update-entry "$A" "$uuid" --username a-user2 >/dev/null
"$KEYHOLE" update-entry "$B" "$uuid" --username b-user2 >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose local >/dev/null
got="$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt 2>/dev/null || echo MISSING)"
[ "$got" = "precious" ] \
    || { echo "FAIL: choose-local resolve dropped the attachment (got: $got)"; exit 1; }
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
converged || { echo "FAIL: replicas diverged after choose-local resolve"; exit 1; }

# --- and the resolved state survives a fresh disk read -----------------
rm -rf "$A.mirror" "$B.mirror"
[ "$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt)" = "precious" ] \
    || { echo "FAIL: attachment did not persist to the KDBX"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: resolving a parked conflict preserves attachments on both resolution sides"
