#!/usr/bin/env bash
#
# Scenario: both-sided same-name attachment divergence PARKS and
# RESOLVES — the remaining 5c surface. Both devices replace the same
# attachment name with different bytes off a shared base; that is a
# genuine conflict only the user can settle, so it must hold open
# (badge + resolver), then converge to the chosen side on both
# replicas.
#
# Pre-slice behaviour (the red this scenario was written against):
# classify kept attachment conflicts OUT of the verdict — no park, no
# auto-pick — so each replica kept its own bytes indefinitely with no
# badge: a silent, permanent divergence.
#
# Teeth: the resolution must also propagate — B adopts A's pick via the
# synced resolution record rather than re-parking.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Carrier" --username c >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Carrier/ {print $1; exit}')"
"$KEYHOLE" set-attachment "$A" "$uuid" doc.txt --text "base" >/dev/null
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# Both sides replace the SAME name with different bytes (a second
# boundary past the shared base, so neither side reads as the base).
sleep 1.1
"$KEYHOLE" set-attachment "$A" "$uuid" doc.txt --text "from-a" >/dev/null
"$KEYHOLE" set-attachment "$B" "$uuid" doc.txt --text "from-b" >/dev/null

# --- THE SLICE: the divergence must PARK, not silently coexist -------
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null \
    || { echo "FAIL: both-sided attachment divergence did not park"; exit 1; }
# Local value untouched while held (hold-open keeps local).
[ "$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt)" = "from-a" ] \
    || { echo "FAIL: hold-open must keep local bytes"; exit 1; }

# The resolver surfaces the attachment delta and can take theirs.
"$KEYHOLE" show-conflict "$A" --entry "$uuid" | grep -i "attachment doc.txt" >/dev/null \
    || { echo "FAIL: resolver payload lacks the attachment delta"; exit 1; }
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose remote >/dev/null
[ "$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt)" = "from-b" ] \
    || { echo "FAIL: choose-remote did not adopt the peer bytes"; exit 1; }
"$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
    || { echo "FAIL: badge did not clear after resolve"; exit 1; }

# The resolution propagates: B adopts A's pick, no re-park.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list-conflicts "$B" | grep '(no held conflicts)' >/dev/null \
    || { echo "FAIL: B re-parked a resolved conflict"; exit 1; }
[ "$("$KEYHOLE" cat-attachment "$B" "$uuid" doc.txt)" = "from-b" ] \
    || { echo "FAIL: resolution did not propagate to B"; exit 1; }
converged || { echo "FAIL: replicas diverged after resolve"; exit 1; }

# And it all survives a fresh disk read.
rm -rf "$A.mirror" "$B.mirror"
[ "$("$KEYHOLE" cat-attachment "$A" "$uuid" doc.txt)" = "from-b" ] \
    || { echo "FAIL: resolved bytes did not persist"; exit 1; }
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: both-sided same-name attachment divergence parks, resolves, propagates, and persists"
