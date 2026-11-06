#!/usr/bin/env bash
#
# Scenario: THE VAULT FILE CHANGES BETWEEN THE READ AND THE RECORD. Bringing a
# mirror current reads the file, derives its key (which can take seconds) and
# ingests it. The signature the mirror then records says "this is the file I
# hold", so it must describe the bytes that were read. Recording whatever sits
# at the path by then marks an unread change as merged: nothing merges it, and
# the next save writes over it.
#
# `KEYHOLE_LAND_FILE_AFTER_READ` renames a file over the vault after the sync
# has read it, at the session key request that follows. That is the same place
# for a real writer landing during the derive, and is exact where a race
# against a slow KDF would not be.
#
# Assertions, each read from a fresh ingest of the file:
#   1. FRESH MIRROR → a change landing during the first ingest isn't lost: the
#      next verb sees the file as changed and merges it before saving.
#   2. WARM MIRROR → the same for a change landing during a reconcile that
#      settles (the digest-equal adoption that records a signature).
#   3. CONTROL → with nothing landing, the signature matches and the next open
#      skips the merge.
#
# Self-contained: keyhole's own verbs; throwaway vaults.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

RECONCILED="reconciled"

fail() { echo "FAIL: $*"; exit 1; }

# What another writer holds: a copy of $1 with an entry titled $3, at $2.
another_writer() {
    local from="$1" to="$2" title="$3"
    cp "$from" "$to"
    "$KEYHOLE" create-entry "$to" "$title" >/dev/null || fail "another writer's edit"
    rm -rf "$to.mirror"
}

# Whether a fresh ingest of $1 lists an entry titled $2.
file_lists() {
    local probe="$TMP/probe.kdbx"
    cp "$1" "$probe"
    rm -rf "$probe.mirror"
    "$KEYHOLE" list "$probe" | grep "$2" >/dev/null
}

# ── 1. Fresh mirror ───────────────────────────────────────────────────────
A="$TMP/a.kdbx"
"$KEYHOLE" create "$A" >/dev/null || fail "create"
"$KEYHOLE" create-entry "$A" "Original" >/dev/null || fail "seed"
another_writer "$A" "$TMP/a-landing.kdbx" "Landed during read"
rm -rf "$A.mirror"

KEYHOLE_LAND_FILE_AFTER_READ="$TMP/a-landing.kdbx" "$KEYHOLE" list "$A" >/dev/null \
    || fail "open with a file landing"
[ ! -e "$TMP/a-landing.kdbx" ] || fail "the landing never happened, so this tested nothing"

"$KEYHOLE" create-entry "$A" "Saved next" >/dev/null || fail "next save"
file_lists "$A" "Landed during read" \
    || fail "fresh mirror: the next save overwrote a change the mirror never read"
file_lists "$A" "Saved next" || fail "fresh mirror: the next save didn't land"

# ── 2. Warm mirror, settling reconcile ────────────────────────────────────
B="$TMP/b.kdbx"
"$KEYHOLE" create "$B" >/dev/null || fail "create"
"$KEYHOLE" create-entry "$B" "Original" >/dev/null || fail "seed"
# The file moves on while the mirror stands still: that is what's reconciled.
another_writer "$B" "$TMP/b-moved.kdbx" "Read by the reconcile"
another_writer "$TMP/b-moved.kdbx" "$TMP/b-landing.kdbx" "Landed during reconcile"
mv "$TMP/b-moved.kdbx" "$B"

KEYHOLE_LAND_FILE_AFTER_READ="$TMP/b-landing.kdbx" "$KEYHOLE" list "$B" >/dev/null \
    || fail "reconcile with a file landing"
[ ! -e "$TMP/b-landing.kdbx" ] || fail "the landing never happened, so this tested nothing"

"$KEYHOLE" create-entry "$B" "Saved next" >/dev/null || fail "next save"
file_lists "$B" "Landed during reconcile" \
    || fail "warm mirror: the next save overwrote a change the mirror never read"
file_lists "$B" "Read by the reconcile" || fail "warm mirror: the reconciled change was lost"
file_lists "$B" "Saved next" || fail "warm mirror: the next save didn't land"

# ── 3. Control ────────────────────────────────────────────────────────────
C="$TMP/c.kdbx"
"$KEYHOLE" create "$C" >/dev/null || fail "create"
"$KEYHOLE" create-entry "$C" "Original" >/dev/null || fail "seed"
rm -rf "$C.mirror"
"$KEYHOLE" list "$C" >/dev/null || fail "first open"
if "$KEYHOLE" list "$C" 2>&1 >/dev/null | grep "$RECONCILED" >/dev/null; then
    fail "control: an unchanged file was reconciled, so the recorded signature is wrong"
fi

echo "PASS: a recorded signature describes the bytes that were read"
