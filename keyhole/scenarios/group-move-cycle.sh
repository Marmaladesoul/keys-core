#!/usr/bin/env bash
#
# Scenario: 5d concurrent MUTUAL group move — A moves X under Y while B
# moves Y under X (same round, both legal on their own side). Naive
# parent-LWW would build a cycle X→Y→X; the cycle guard prevents the
# corrupt tree but, applied on both sides, leaves the replicas
# DISAGREEING on that edge (A keeps X under Y, B keeps Y under X) —
# divergence. A deterministic cycle-break must make BOTH replicas
# resolve to the same acyclic tree.
#
# The break is a pure function of the converged parent map (re-root the
# cycle's smallest-uuid member to root), so both sides compute it
# identically → convergence. The oracle is the digest (covers parent).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "GX" >/dev/null
"$KEYHOLE" create-group "$A" "GY" >/dev/null
gx="$("$KEYHOLE" list-groups "$A" | awk '/GX/ {print $1}' | head -1)"
gy="$("$KEYHOLE" list-groups "$A" | awk '/GY/ {print $1}' | head -1)"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# Mutual move, same round: A puts GX under GY; B puts GY under GX.
sleep 1.1
"$KEYHOLE" move-group "$A" "$gx" --to "$gy" >/dev/null
"$KEYHOLE" move-group "$B" "$gy" --to "$gx" >/dev/null

# Exchange both ways. Each side's own move is older-or-equal; the point
# is they must CONVERGE on one acyclic tree, not keep their own edge.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

# No cycle on either side (a cyclic mirror would corrupt the projection;
# list-groups must still enumerate all groups cleanly) and converged.
"$KEYHOLE" list-groups "$A" | grep -q "$gx" || { echo "FAIL: A's group tree broke"; exit 1; }
"$KEYHOLE" list-groups "$B" | grep -q "$gx" || { echo "FAIL: B's group tree broke"; exit 1; }
converged || { echo "FAIL: mutual move did not converge (divergent cycle edge)"; exit 1; }

# Survives reopen.
rm -rf "$A.mirror" "$B.mirror"
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: concurrent mutual group move converges to one acyclic tree on both replicas"
