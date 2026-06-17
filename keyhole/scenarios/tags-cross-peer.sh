#!/usr/bin/env bash
#
# Tags converge cross-peer by 3-way SET semantics — distinct from the per-field
# LWW the rest of an entry uses. keyhole previously couldn't author tags at all
# (`create-entry`/`update-entry` hardcode an empty tag set), so tag convergence
# was untested — the same coverage hole custom-fields and recycle-bin/meta were.
# The new `set-tags` verb closes it; this pins the behaviour.
#
# The interesting case is a concurrent add on BOTH sides PLUS a removal: the
# merge is a true 3-way against the shared LCA tag set —
#   union the adds, and a tag removed on one side (relative to the LCA) loses,
#   while a tag merely untouched on one side survives.
# A bare union (no LCA) would WRONGLY resurrect the removed tag, so this has
# teeth for the set semantics, not just "tags propagate".

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

tags_on() { "$KEYHOLE" tags "$1" "$2" | tr '\n' ' ' | sed 's/ $//'; }
converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"

# --- 1. one-sided add propagates -----------------------------------------
"$KEYHOLE" --at 1500000 set-tags "$A" "$uuid" "alpha, beta" >/dev/null
cp "$A" "$B"   # B forks from the {alpha,beta} base (the shared LCA)

"$KEYHOLE" --at 1600000 set-tags "$A" "$uuid" "alpha, beta, gamma" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$B.mirror"
[ "$(tags_on "$B" "$uuid")" = "alpha beta gamma" ] \
    || { echo "FAIL: B did not adopt A's one-sided tag add (got: [$(tags_on "$B" "$uuid")])"; exit 1; }

# Reset both to the shared base for the 3-way case (re-sync so the LCA is
# {alpha,beta,gamma} on both).
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
converged || { echo "FAIL: replicas diverged after the one-sided add"; exit 1; }

# --- 2. 3-way set merge: concurrent add on both + a removal vs the LCA ----
# LCA = {alpha, beta, gamma}.
#   A: adds a-only, keeps the rest        → {alpha, beta, gamma, a-only}
#   B: adds b-only, REMOVES beta          → {alpha, gamma, b-only}
# Expected merge on both: {alpha, gamma, a-only, b-only}
#   - a-only / b-only: added on one side (not in LCA) → kept
#   - beta: in LCA, removed by B, untouched by A      → removal wins → gone
#   - alpha, gamma: in LCA, untouched by B            → kept
"$KEYHOLE" --at 2000000 set-tags "$A" "$uuid" "alpha, beta, gamma, a-only" >/dev/null
"$KEYHOLE" --at 2000000 set-tags "$B" "$uuid" "alpha, gamma, b-only" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$A.mirror" "$B.mirror"

EXPECT="a-only alpha b-only gamma"   # sorted
[ "$(tags_on "$A" "$uuid")" = "$EXPECT" ] \
    || { echo "FAIL: A's 3-way tag merge wrong. got [$(tags_on "$A" "$uuid")], want [$EXPECT]"; exit 1; }
[ "$(tags_on "$B" "$uuid")" = "$EXPECT" ] \
    || { echo "FAIL: B's 3-way tag merge wrong. got [$(tags_on "$B" "$uuid")], want [$EXPECT]"; exit 1; }
converged || { echo "FAIL: digests diverge after the 3-way tag merge"; exit 1; }

echo "PASS: tags converge cross-peer by 3-way set semantics (union of adds, removal-vs-LCA wins), survives a fresh disk read"
