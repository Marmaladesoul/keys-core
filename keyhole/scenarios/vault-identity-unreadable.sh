#!/usr/bin/env bash
#
# Scenario: VAULT-IDENTITY VERIFICATION of a DAMAGED file — a KDBX4 file
# damaged past its keyed header HMAC (which proves the key) must be reported
# as `unreadable`, never as `undecryptable`.
#
# `undecryptable` means "the supplied key material didn't open this file", and
# a consumer acts on it by re-prompting for the current credential (the vault
# may have been re-keyed elsewhere). A file that the right key opens but whose
# payload is truncated or corrupt can't be fixed by re-prompting: telling the
# user "that password doesn't open it" is false and sends them round in a loop.
# Only a genuine key refusal may produce `undecryptable`; damage past the key
# check is its own verdict. (KDBX4 only: a KDBX3 file proves the key by
# decrypting its payload, so its payload damage is `undecryptable` by design;
# that side is pinned in keys-ffi's tests/verify_vault_identity.rs.)
#
# Assertions (all against a fresh KDBX4 vault in a temp dir):
#   1. CONTROL — the intact file, right password → match.
#   2. CORRUPT PAYLOAD — one byte flipped inside the first payload block,
#      right password → unreadable (NOT undecryptable, NOT mismatch).
#   3. TRUNCATED — the end-of-payload block cut off, right password →
#      unreadable.
#   4. WRONG PASSWORD — intact file → undecryptable; and on the damaged files
#      too, because the header HMAC is checked before the payload is read, so
#      payload damage is only ever reported once the key has been accepted.
#
# Self-contained: keyhole's own create / root-uuid / verify-identity.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-identity-unreadable-pw"
WRONG="keyhole-identity-unreadable-WRONG-pw"

# A KDBX4 payload is a stream of HMAC'd blocks ending in an empty block:
# a 32-byte HMAC-SHA-256 tag plus a 4-byte zero length.
BLOCK_HMAC_BYTES=32
BLOCK_LENGTH_BYTES=4
END_BLOCK_BYTES=$((BLOCK_HMAC_BYTES + BLOCK_LENGTH_BYTES))
# XOR mask that flips every bit of one byte, so the corrupt byte always differs.
EVERY_BIT_OF_A_BYTE=255

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VAULT="$TMP/genuine.kdbx"
CORRUPT="$TMP/corrupt.kdbx"
TRUNCATED="$TMP/truncated.kdbx"

fail() { echo "FAIL: $*"; exit 1; }

# Run verify-identity and report "<verdict>:<exit-code>" (see
# vault-identity-verify.sh).
verify() { # <picked> <expected-uuid> [password]
    local pw="${3:-$PW}" out rc
    out=$(KEYHOLE_PASSWORD="$pw" "$KEYHOLE" verify-identity "$1" --expect "$2" 2>/dev/null); rc=$?
    printf '%s:%s' "$out" "$rc"
}

KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$VAULT" >/dev/null || fail "create vault"
ROOT="$(KEYHOLE_PASSWORD="$PW" "$KEYHOLE" root-uuid "$VAULT" 2>/dev/null)"
[ -n "$ROOT" ] || fail "could not read the vault's root-group UUID"
SIZE="$(wc -c <"$VAULT" | tr -d ' ')"

# --- 1: CONTROL — intact file, right password → match ----------------
[ "$(verify "$VAULT" "$ROOT")" = "match:0" ] || fail "control: the intact vault did not match"

# --- 2: CORRUPT PAYLOAD — flip the last byte of the first block ------
# The byte just before the end block is the last ciphertext byte of the
# first payload block: well past the header, so the header HMAC still passes
# and only that block's HMAC catches the damage.
cp "$VAULT" "$CORRUPT"
FLIP_AT=$((SIZE - END_BLOCK_BYTES - 1))
ORIG="$(od -An -tu1 -j "$FLIP_AT" -N1 "$CORRUPT" | tr -d ' ')"
FLIPPED=$((ORIG ^ EVERY_BIT_OF_A_BYTE))
printf "$(printf '\\%03o' "$FLIPPED")" \
    | dd of="$CORRUPT" bs=1 seek="$FLIP_AT" count=1 conv=notrunc 2>/dev/null \
    || fail "could not corrupt the payload byte"
cmp -s "$VAULT" "$CORRUPT" && fail "the corrupted copy is byte-identical to the original"
[ "$(verify "$CORRUPT" "$ROOT")" = "unreadable:1" ] \
    || fail "a corrupt payload under the RIGHT password was not unreadable (got $(verify "$CORRUPT" "$ROOT"))"

# --- 3: TRUNCATED — cut off the end block and one data byte ----------
head -c $((SIZE - END_BLOCK_BYTES - 1)) "$VAULT" >"$TRUNCATED"
[ "$(verify "$TRUNCATED" "$ROOT")" = "unreadable:1" ] \
    || fail "a truncated file under the RIGHT password was not unreadable (got $(verify "$TRUNCATED" "$ROOT"))"

# --- 4: WRONG PASSWORD → undecryptable, damaged or not ---------------
[ "$(verify "$VAULT" "$ROOT" "$WRONG")" = "undecryptable:1" ] \
    || fail "the intact vault under a WRONG password was not undecryptable"
[ "$(verify "$CORRUPT" "$ROOT" "$WRONG")" = "undecryptable:1" ] \
    || fail "the corrupt vault under a WRONG password was not undecryptable"
[ "$(verify "$TRUNCATED" "$ROOT" "$WRONG")" = "undecryptable:1" ] \
    || fail "the truncated vault under a WRONG password was not undecryptable"

echo "PASS: a KDBX4 file damaged past its header HMAC is unreadable under the right password, while only a wrong password is undecryptable"
