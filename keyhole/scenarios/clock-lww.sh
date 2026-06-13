#!/usr/bin/env bash
#
# Scenario: the injectable engine clock (`--at <epoch-ms>`) makes
# timestamp-driven LWW reconciliation DETERMINISTIC — no `sleep`
# between processes, no wall-clock race.
#
# Two facets, both on a group both replicas already hold:
#
#   1. Distinct stamps → exact winner. B renames at t=3s, A renames at
#      t=5s. A is strictly newer, so A's name wins on BOTH replicas
#      regardless of ingest direction. (With the old wall-clock + sleep
#      approach this was only "probably" A; here it's pinned.)
#
#   2. Same-second tie → still converges. Both rename at the SAME
#      instant. LWW can't separate them, so the deterministic,
#      replica-symmetric tiebreak decides — we don't assert WHICH name
#      wins, only that both replicas AGREE (digest equal). A tie that
#      diverged would be the bug.
#
# This is the controllable-clock counterpart to group-rename-lww.sh:
# same policy, but the timing is an input rather than a sleep.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Shared" >/dev/null
g="$("$KEYHOLE" list-groups "$A" | awk '/Shared/ {print $1}' | head -1)"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
name_on() { "$KEYHOLE" list-groups "$1" | awk -v u="$g" '$1==u {print $2}'; }

# --- 1. distinct stamps: the strictly-newer write wins both ways -----
"$KEYHOLE" --at 3000 rename-group "$B" "$g" "from-B-older" >/dev/null
"$KEYHOLE" --at 5000 rename-group "$A" "$g" "from-A-newer" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
[ "$(name_on "$A")" = "from-A-newer" ] \
    || { echo "FAIL: A lost its strictly-newer rename (got: $(name_on "$A"))"; exit 1; }
[ "$(name_on "$B")" = "from-A-newer" ] \
    || { echo "FAIL: B did not adopt A's strictly-newer rename (got: $(name_on "$B"))"; exit 1; }
converged || { echo "FAIL: replicas diverged after distinct-stamp rename"; exit 1; }

# --- 2. same-second tie: tiebreak decides, replicas must agree -------
# Both rename to different names at the SAME pinned instant.
"$KEYHOLE" --at 8000 rename-group "$A" "$g" "tie-A" >/dev/null
"$KEYHOLE" --at 8000 rename-group "$B" "$g" "tie-B" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
[ "$(name_on "$A")" = "$(name_on "$B")" ] \
    || { echo "FAIL: same-second tie diverged (A=$(name_on "$A") B=$(name_on "$B"))"; exit 1; }
converged || { echo "FAIL: replicas diverged after same-second tie"; exit 1; }

# --- both outcomes survive a fresh disk read ------------------------
rm -rf "$A.mirror" "$B.mirror"
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: --at pins LWW direction (strictly-newer wins both ways) and same-second ties converge"
