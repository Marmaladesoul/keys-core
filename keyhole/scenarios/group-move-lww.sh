#!/usr/bin/env bash
#
# Scenario: 5d group MOVE — a one-sided group re-parent propagates, and
# a both-sided re-parent resolves last-writer-wins, converging on both
# replicas. A group's parent is part of the convergence digest, so a
# re-parent that doesn't propagate diverges the replicas.
#
# Oracle is the digest (it covers each group's parent): after a
# one-sided move, B must converge to A; if B didn't adopt the move the
# digests differ. The both-sided leg asserts LWW convergence after a
# bidirectional exchange.
#
# Pre-slice behaviour (the red): reconcile_peer_groups reconciles group
# METADATA (name/notes/icon) but never `parent_uuid`, so a re-parent on
# one side never reaches the other — permanent structural divergence.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
for n in Home Parent-X Parent-Y; do "$KEYHOLE" create-group "$A" "$n" >/dev/null; done
home="$("$KEYHOLE" list-groups "$A" | awk '/Home/ {print $1}' | head -1)"
px="$("$KEYHOLE" list-groups "$A" | awk '/Parent-X/ {print $1}' | head -1)"
py="$("$KEYHOLE" list-groups "$A" | awk '/Parent-Y/ {print $1}' | head -1)"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# --- one-sided move on A → B must adopt the re-parent ---------------
sleep 1.1
"$KEYHOLE" move-group "$A" "$home" --to "$px" >/dev/null
[ "$("$KEYHOLE" digest "$A")" != "$("$KEYHOLE" digest "$B")" ] \
    || { echo "FAIL(precondition): move did not change A's digest"; exit 1; }
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
converged || { echo "FAIL: one-sided group move did not propagate"; exit 1; }

# --- both-sided move → newer wins, converge on both ----------------
"$KEYHOLE" move-group "$B" "$home" --to "$py" >/dev/null
sleep 1.1
"$KEYHOLE" move-group "$A" "$home" --to "$py" >/dev/null  # A newer, also → Y
# Re-diverge cleanly: B back to X (older), A to Y (newer).
"$KEYHOLE" move-group "$B" "$home" --to "$px" >/dev/null
sleep 1.1
"$KEYHOLE" move-group "$A" "$home" --to "$py" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
converged || { echo "FAIL: replicas diverged after both-sided move (LWW)"; exit 1; }

# --- and the LWW result survives a fresh disk read ------------------
da_before="$("$KEYHOLE" digest "$A")"
rm -rf "$A.mirror" "$B.mirror"
[ "$("$KEYHOLE" digest "$A")" = "$da_before" ] \
    || { echo "FAIL: A's group structure did not persist"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: group move propagates one-sided and resolves both-sided by LWW, surviving reopen"
