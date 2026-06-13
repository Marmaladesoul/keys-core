#!/usr/bin/env bash
#
# Scenario: conflict-set parity across THREE peers — the owner-rows
# store's actual N-peer promise (5e). Two devices diverge on the same
# field; a third device that has never touched the entry must, after a
# full-mesh sync, derive the SAME parked conflict as the other two —
# and one peer's resolution must converge all three to the chosen value
# with no ghost badges anywhere.
#
# Why three: the 2-peer case (conflict-set-parity.sh) is symmetric by
# construction. Three peers is where ingest order, owner-row indexing,
# and resolution-record propagation actually have to be path- and
# peer-independent. This is the headless twin of "conflict surfaced on
# only one device" (soak Bug D) at multi-peer scale.
#
# Oracles: (1) the parked-conflict uuid set is identical on all three
# replicas; (2) after one peer resolves, all three converge — empty
# conflict set + identical content digest equal to the resolver's.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"
C="$TMP/device-c.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Shared" --username base >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Shared/ {print $1; exit}')"
cp "$A" "$B"
cp "$A" "$C"

conflicts_on() {
    "$KEYHOLE" list-conflicts "$1" \
        | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        | sort | tr '\n' ',' || true
}
# One full-mesh sync round: every device ingests the other two, under
# the peer's stable owner id. Two rounds reach quiescence (a resolution
# record recorded in round N is consumed by the others in round N+1).
mesh_round() {
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$A" "$C" --owner device-c >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$C" --owner device-c >/dev/null
    "$KEYHOLE" ingest-peer "$C" "$A" --owner device-a >/dev/null
    "$KEYHOLE" ingest-peer "$C" "$B" --owner device-b >/dev/null
}
mesh_sync() { mesh_round; mesh_round; }
all_converged() {
    local da db dc
    da="$("$KEYHOLE" digest "$A")"; db="$("$KEYHOLE" digest "$B")"; dc="$("$KEYHOLE" digest "$C")"
    [ "$da" = "$db" ] && [ "$db" = "$dc" ]
}

# --- A and B diverge on the same field; C stays untouched -----------
"$KEYHOLE" --at 5000000 update-entry "$A" "$uuid" --username from-a >/dev/null
"$KEYHOLE" --at 5000000 update-entry "$B" "$uuid" --username from-b >/dev/null

mesh_sync

# All three must surface the identical parked-conflict set {E}.
ca="$(conflicts_on "$A")"; cb="$(conflicts_on "$B")"; cc="$(conflicts_on "$C")"
[ "$ca" = "$uuid," ] || { echo "FAIL: A did not park (got: $ca)"; exit 1; }
[ "$cb" = "$uuid," ] || { echo "FAIL: B did not park (got: $cb)"; exit 1; }
[ "$cc" = "$uuid," ] || { echo "FAIL: C (never edited) did not derive the conflict (got: $cc)"; exit 1; }

# --- one peer resolves; all three must converge ---------------------
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose local >/dev/null  # keep from-a
[ -z "$(conflicts_on "$A")" ] || { echo "FAIL: A's badge did not clear after resolve"; exit 1; }
resolved_digest="$("$KEYHOLE" digest "$A")"

mesh_sync

for v in "$A" "$B" "$C"; do
    [ -z "$(conflicts_on "$v")" ] \
        || { echo "FAIL: ghost conflict after 3-way resolution on $v (got: $(conflicts_on "$v"))"; exit 1; }
done
all_converged || { echo "FAIL: three replicas did not converge after resolution"; exit 1; }
[ "$("$KEYHOLE" digest "$B")" = "$resolved_digest" ] && [ "$("$KEYHOLE" digest "$C")" = "$resolved_digest" ] \
    || { echo "FAIL: peers converged to a value other than the resolver's (from-a)"; exit 1; }

# --- parity + content survive a fresh disk read on all three --------
rm -rf "$A.mirror" "$B.mirror" "$C.mirror"
for v in "$A" "$B" "$C"; do
    [ -z "$(conflicts_on "$v")" ] || { echo "FAIL: conflict resurrected on reopen for $v"; exit 1; }
done
all_converged || { echo "FAIL: three replicas diverged after reopen"; exit 1; }

echo "PASS: a same-field clash parks identically on all three peers and one resolution converges all three"
