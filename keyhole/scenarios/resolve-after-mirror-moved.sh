#!/usr/bin/env bash
#
# Scenario: THE MIRROR MOVES WHILE THE RESOLVER IS OPEN. Opening the resolver
# stashes a snapshot of the vault, and nothing stops the mirror changing while
# the user decides. Applying the choice over that snapshot would discard the
# change, so the apply is refused and the user goes back through the resolver.
#
# keyhole's `resolve` holds the resolver open across `--while-open-create` and
# `--while-open-notes`. Every data assertion reads from a fresh ingest of the
# file (`rm -rf "$VAULT.mirror"`), because surviving in the mirror proves
# nothing about surviving on disk.
#
# Assertions, for another entry saved meanwhile and for the entry in conflict
# changing meanwhile:
#   1. REFUSED → `ResolutionMismatch`, the conflict stays held, and the change
#      that moved the mirror survives in the file.
#   2. NOT STUCK → reopening the resolver and choosing again works, clears the
#      conflict, lands the choice and keeps that change.
#
# Self-contained: keyhole's own verbs; throwaway vaults.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

# Two replicas holding a conflict on the notes of one entry, parked in $1's
# mirror. Sets $uuid.
park_notes_conflict() {
    local vault="$1" peer="$2"
    "$KEYHOLE" create "$vault" >/dev/null || fail "create $vault"
    "$KEYHOLE" create-entry "$vault" "Shared" --username orig-user >/dev/null || fail "seed"
    uuid="$("$KEYHOLE" list "$vault" | awk '/Shared/ {print $1; exit}')"
    cp "$vault" "$peer"
    "$KEYHOLE" update-entry "$vault" "$uuid" --notes localnotes >/dev/null || fail "local edit"
    "$KEYHOLE" update-entry "$peer" "$uuid" --notes peernotes >/dev/null || fail "peer edit"
    "$KEYHOLE" ingest-peer "$vault" "$peer" --owner device-b >/dev/null || fail "ingest-peer"
    "$KEYHOLE" list-conflicts "$vault" | grep "$uuid" >/dev/null || fail "no conflict parked"
}

# Whether a fresh ingest of $1 finds $2 in any entry's text.
file_holds() {
    local probe="$TMP/probe.kdbx"
    cp "$1" "$probe"
    rm -rf "$probe.mirror"
    "$KEYHOLE" search "$probe" "$2" --bin exclude | grep Shared >/dev/null
}

# Check a `resolve` run refused: $1 is its exit status, $2 its output.
assert_refused() {
    [ "$1" -ne 0 ] || fail "a resolution was applied over a change made while the resolver was open"
    echo "$2" | grep ResolutionMismatch >/dev/null || fail "expected ResolutionMismatch, got: $2"
}

# ── Another entry saved while the resolver is open ────────────────────────
A="$TMP/a.kdbx"
park_notes_conflict "$A" "$TMP/a-peer.kdbx"
out="$("$KEYHOLE" resolve "$A" --entry "$uuid" --choose remote \
    --while-open-create "Saved meanwhile" 2>&1)"
assert_refused $? "$out"
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null \
    || fail "a refused resolution must leave the conflict held"
"$KEYHOLE" resolve "$A" --entry "$uuid" --choose remote >/dev/null \
    || fail "the conflict can't be resolved after a refusal"
"$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
    || fail "the conflict should have cleared on the second try"
rm -rf "$A.mirror"
"$KEYHOLE" list "$A" | grep "Saved meanwhile" >/dev/null \
    || fail "the entry saved while the resolver was open was lost"
file_holds "$A" peernotes || fail "the resolution itself didn't land"

# ── The entry in conflict changes while the resolver is open ──────────────
B="$TMP/b.kdbx"
park_notes_conflict "$B" "$TMP/b-peer.kdbx"
out="$("$KEYHOLE" resolve "$B" --entry "$uuid" --choose remote \
    --while-open-notes newernotes 2>&1)"
assert_refused $? "$out"
"$KEYHOLE" list-conflicts "$B" | grep "$uuid" >/dev/null \
    || fail "a refused resolution must leave the conflict held"
file_holds "$B" newernotes || fail "the newer edit didn't survive the refusal"
"$KEYHOLE" resolve "$B" --entry "$uuid" --choose local >/dev/null \
    || fail "the conflict can't be resolved after a refusal"
"$KEYHOLE" list-conflicts "$B" | grep '(no held conflicts)' >/dev/null \
    || fail "the conflict should have cleared on the second try"
file_holds "$B" newernotes || fail "the newer edit didn't survive the second try"

echo "PASS: a resolution is refused if the mirror moved after the resolver opened"
