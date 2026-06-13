#!/usr/bin/env bash
#
# Scenario: the parked-conflict SET is convergent across peers — both
# replicas surface the SAME held conflicts, and a resolution on one
# clears the badge on both.
#
# This is the owner-rows store's headline promise and the headless twin
# of soak Bug D ("conflict surfaced on only one device, its Resolve
# button dead"). The content digest does NOT cover conflict rows, so a
# divergent or ghost badge is invisible to the fuzzer's digest oracle —
# this scenario asserts conflict-set PARITY directly.
#
# Teeth: assertions run on BOTH replicas, not just the one that ingested
# first; a conflict that parks on A-only (or a badge that fails to clear
# on B after A resolves) fails parity even though the merged content
# converges.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Shared" --username base >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Shared/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
# Sorted parked-conflict uuid set for a vault ('' when none held).
# list-conflicts prints one uuid per line plus a count footer; keep only
# the uuid lines.
conflicts_on() {
    "$KEYHOLE" list-conflicts "$1" \
        | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        | sort | tr '\n' ',' || true
}
parity() { [ "$(conflicts_on "$A")" = "$(conflicts_on "$B")" ]; }

# --- both sides edit the SAME field differently → genuine clash ------
# Pinned to the same instant via --at: a same-field clash parks
# regardless of LWW, and pinning keeps the run deterministic.
"$KEYHOLE" --at 5000000 update-entry "$A" "$uuid" --username from-a >/dev/null
"$KEYHOLE" --at 5000000 update-entry "$B" "$uuid" --username from-b >/dev/null

# Exchange BOTH ways — each replica must independently park the clash.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

[ "$(conflicts_on "$A")" = "$uuid," ] \
    || { echo "FAIL: A did not park the clash (got: $(conflicts_on "$A"))"; exit 1; }
[ "$(conflicts_on "$B")" = "$uuid," ] \
    || { echo "FAIL: B did not park the clash (got: $(conflicts_on "$B"))"; exit 1; }
parity || { echo "FAIL: conflict sets differ across peers (A=$(conflicts_on "$A") B=$(conflicts_on "$B"))"; exit 1; }

# --- A resolves (keep local 'from-a'); badge clears on A -------------
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose local >/dev/null
[ -z "$(conflicts_on "$A")" ] \
    || { echo "FAIL: A's badge did not clear after resolve"; exit 1; }

# --- resolution propagates: B adopts, its badge clears too ----------
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ -z "$(conflicts_on "$B")" ] \
    || { echo "FAIL: B kept a ghost conflict after A resolved (got: $(conflicts_on "$B"))"; exit 1; }
parity || { echo "FAIL: conflict sets differ post-resolution (A=$(conflicts_on "$A") B=$(conflicts_on "$B"))"; exit 1; }
converged || { echo "FAIL: replicas diverged after resolution"; exit 1; }

# --- parity survives a fresh disk read on both sides ----------------
rm -rf "$A.mirror" "$B.mirror"
parity || { echo "FAIL: persisted conflict sets differ"; exit 1; }
[ -z "$(conflicts_on "$A")" ] && [ -z "$(conflicts_on "$B")" ] \
    || { echo "FAIL: a resolved conflict resurrected after reopen"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: parked-conflict set is convergent across both peers, through park → resolve → reopen"
