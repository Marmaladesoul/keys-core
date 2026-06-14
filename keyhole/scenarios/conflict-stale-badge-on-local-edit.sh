#!/usr/bin/env bash
#
# RED → GREEN (Finding #10): a parked conflict whose divergence DISSOLVES
# must not leave a ghost badge. Local converges to the parked peer value
# via an ordinary local edit (no resolve, no re-ingest); the badge query
# (`entries_with_parked_conflict`) must stop reporting it.
#
# Pre-fix behaviour (the red): the conflict_entry row outlived the
# divergence it recorded. `list-conflicts` (the cheap badge query) kept
# reporting the entry; the row only cleared lazily if a resolver-open
# happened to run the merge-backed dissolve check
# (`held_conflict_payload`). Net: a phantom badge / dead resolver entry
# — the deterministic, hand-isolated core of the fuzzer's intermittent
# ghost-conflict / parity failures.
#
# NB: the badge MUST be read with `list-conflicts` only. `show-conflict`
# triggers the lazy heal, so calling it would erase the very evidence
# under test (that mistake masked the bug on the first draft).
#
# Fix (semantics, option A): a local CONTENT edit supersedes a parked
# conflict — the parked peer snapshot is stale and any genuine remaining
# divergence re-derives on the next sync — so it clears the entry's
# conflict rows (engine: keys_engine `bump_modified`).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username V0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"

# Badge count via list-conflicts ONLY (no show-conflict — it self-heals).
badge() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }

# --- park a genuine same-field conflict; A holds B's value -----------
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username Va >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username Vb >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ "$(badge "$A")" = 1 ] || { echo "FAIL(setup): A did not park the clash"; exit 1; }

# --- local edit makes A match the parked peer value → DISSOLVED ------
# No resolve, no re-ingest. The badge must clear.
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username Vb >/dev/null
[ "$(badge "$A")" = 0 ] \
    || { echo "FAIL: ghost badge — list-conflicts still reports a dissolved conflict"; exit 1; }

# --- survives a fresh disk read (the clear persisted) ----------------
rm -rf "$A.mirror"
[ "$(badge "$A")" = 0 ] || { echo "FAIL: ghost badge resurrected after reopen"; exit 1; }

# --- a genuine fresh divergence still parks (clear isn't a blanket mute)
# A and B are now both at Vb; have each edit to a DIFFERENT new value so
# it's a true two-sided clash (not a one-sided advance that auto-merges).
"$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username Vc >/dev/null
"$KEYHOLE" --at 4000000 update-entry "$B" "$uuid" --username Vd >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ "$(badge "$A")" = 1 ] || { echo "FAIL: a fresh genuine divergence did not park"; exit 1; }

echo "PASS: a local edit clears a dissolved parked conflict (no ghost badge), fresh divergence still parks"
