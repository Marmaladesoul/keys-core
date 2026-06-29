#!/usr/bin/env bash
#
# Scenario: two devices each ADD a custom (string) field to the SAME entry
# while offline, then sync. The two axes a field-level merge must honour:
#
#   1. DIFFERENT field names  → set-union: BOTH fields survive on BOTH
#      replicas (an additive, non-conflicting merge).
#   2. SAME field name, diff value → a genuine clash: parks a held
#      conflict on BOTH replicas (never a silent last-write-wins).
#
# Teeth: an entry-level last-write-wins merge — replace the whole entry
# with whichever side has the newer LastModificationTime — keeps only one
# side's field in case 1 (the other vanishes, not even in history) and
# silently drops the loser with no badge in case 2. That is exactly the
# pre-per-field-merge behaviour; this scenario is red on such a build and
# green once the merge is field-level. Existing conflict scenarios only
# edit the standard UserName/Notes fields — custom-field ADD is its own
# code path, uncovered until here.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Pin every mutation to one instant so the run is deterministic and the
# expected-state vault digests identically to the merged replicas.
AT=5000000

conflicts_on() {
    "$KEYHOLE" list-conflicts "$1" \
        | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        | sort | tr '\n' ',' || true
}

# ── Case 1: different field names → union, both survive ──────────────
A="$TMP/a.kdbx"; B="$TMP/b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Shared" --username base >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Shared/ {print $1; exit}')"
cp "$A" "$B"
# Snapshot the pre-divergence base so the expected-state oracle shares
# the entry's uuid + creation time with the real replicas (a fresh
# `create` would differ on those vault-identity bits, not just content).
BASE="$TMP/base.kdbx"; cp "$A" "$BASE"

"$KEYHOLE" --at "$AT" set-field "$A" "$uuid" "MacField"     "mac-val"     >/dev/null
"$KEYHOLE" --at "$AT" set-field "$B" "$uuid" "AirminiField" "airmini-val" >/dev/null

# Exchange both ways — each replica adopts the other's field.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

# Different field names are NOT a clash — neither side may park.
[ -z "$(conflicts_on "$A")" ] && [ -z "$(conflicts_on "$B")" ] \
    || { echo "FAIL: a non-overlapping field add parked a spurious conflict (A=$(conflicts_on "$A") B=$(conflicts_on "$B"))"; exit 1; }

# Build the expected state from the shared base — one entry carrying
# BOTH fields at the same instant — and prove the merged replicas digest
# identically. An entry-level LWW merge would carry only one field here.
EXPECT="$TMP/expect.kdbx"; cp "$BASE" "$EXPECT"
"$KEYHOLE" --at "$AT" set-field "$EXPECT" "$uuid" "MacField"     "mac-val"     >/dev/null
"$KEYHOLE" --at "$AT" set-field "$EXPECT" "$uuid" "AirminiField" "airmini-val" >/dev/null

# Fresh disk reads on every side: the only honest "did it persist?".
rm -rf "$A.mirror" "$B.mirror" "$EXPECT.mirror"
da="$("$KEYHOLE" digest "$A")"
db="$("$KEYHOLE" digest "$B")"
de="$("$KEYHOLE" digest "$EXPECT")"
[ "$da" = "$db" ] \
    || { echo "FAIL: replicas diverged after concurrent field add (A=$da B=$db)"; exit 1; }
[ "$da" = "$de" ] \
    || { echo "FAIL: merged state lost a field — expected both MacField+AirminiField (merged=$da both=$de)"; exit 1; }

# ── Case 2: same field name, different value → parks, no silent LWW ──
C="$TMP/c.kdbx"; D="$TMP/d.kdbx"
"$KEYHOLE" create "$C" >/dev/null
"$KEYHOLE" create-entry "$C" "Clash" --username base >/dev/null
cuuid="$("$KEYHOLE" list "$C" | awk '/Clash/ {print $1; exit}')"
cp "$C" "$D"

"$KEYHOLE" --at "$AT" set-field "$C" "$cuuid" "Note" "from-mac"     >/dev/null
"$KEYHOLE" --at "$AT" set-field "$D" "$cuuid" "Note" "from-airmini" >/dev/null

"$KEYHOLE" ingest-peer "$C" "$D" --owner device-d >/dev/null
"$KEYHOLE" ingest-peer "$D" "$C" --owner device-c >/dev/null

[ "$(conflicts_on "$C")" = "$cuuid," ] \
    || { echo "FAIL: same-name custom-field clash did not park on C (got: $(conflicts_on "$C"))"; exit 1; }
[ "$(conflicts_on "$D")" = "$cuuid," ] \
    || { echo "FAIL: same-name custom-field clash did not park on D (got: $(conflicts_on "$D"))"; exit 1; }
"$KEYHOLE" show-conflict "$C" --entry "$cuuid" | grep -i "field Note" >/dev/null \
    || { echo "FAIL: expected a 'Note' field delta in the parked conflict"; exit 1; }

# Resolving keeps a side and converges — the loser is not stranded.
"$KEYHOLE" resolve "$C" --entry "$cuuid" --choose local >/dev/null
"$KEYHOLE" ingest-peer "$D" "$C" --owner device-c >/dev/null
"$KEYHOLE" ingest-peer "$C" "$D" --owner device-d >/dev/null
rm -rf "$C.mirror" "$D.mirror"
[ -z "$(conflicts_on "$C")" ] && [ -z "$(conflicts_on "$D")" ] \
    || { echo "FAIL: conflict lingered after resolution (C=$(conflicts_on "$C") D=$(conflicts_on "$D"))"; exit 1; }
[ "$("$KEYHOLE" digest "$C")" = "$("$KEYHOLE" digest "$D")" ] \
    || { echo "FAIL: replicas diverged after resolving the field clash"; exit 1; }

echo "PASS: concurrent custom-field add unions on distinct names and parks (no silent LWW) on a same-name clash"
