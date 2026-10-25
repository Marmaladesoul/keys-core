#!/usr/bin/env bash
#
# Scenario: a full re-ingest never destroys changes the vault file
# doesn't have yet.
#
# `ingest_from_kdbx` REPLACES the mirror with the file's contents. That
# is lossless only when the mirror owes the file nothing — yet a client
# can reach the ingest path while the mirror is dirty: an edit committed
# to the mirror but not yet flushed (a debounce window, a save still
# retrying, a lock that closed the engine without flushing), followed by
# an unlock that re-ingests to verify the password. Unguarded, that
# sequence silently discards the edit.
#
# Proves, in order:
#   1. an unsaved mutation (`recycle --no-save`) leaves the mirror dirty;
#   2. `reingest` over that dirty mirror is REFUSED ("mirror owes") and
#      the mirror is untouched — still dirty;
#   3. the refusal comes only AFTER the file decrypts: with a wrong
#      password the same call fails closed on the key instead, never
#      with the mirror-owes refusal. So a client that sees the refusal
#      also knows the password was right;
#   4. the owed write survives the refusal: `flush` persists it —
#      asserted honestly via a wiped mirror + a fresh from-disk ingest;
#   5. over a clean mirror `reingest` proceeds — the guard is scoped to
#      the dirty case, not a blanket ban on re-ingest.
#
# NB ordering: read verbs (`inspect`, `list`, …) flush leftover dirt at
# session teardown, so every dirty-state assertion uses the exempt
# `persistence-state` and runs before the first read verb.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/reingest.kdbx"

fail() { echo "FAIL: $*"; exit 1; }
state() { "$KEYHOLE" persistence-state "$VAULT"; }
recycled() { "$KEYHOLE" inspect "$VAULT" | awk '/^recycled:/ {print $2}'; }

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Keeper" --username keep >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Binned" --username bin >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Binned/ {print $1; exit}')"
[ -n "$uuid" ] || fail "could not find seeded entry"

# 1. Unsaved mutation → dirty mirror, file untouched.
"$KEYHOLE" recycle "$VAULT" "$uuid" --no-save >/dev/null
[[ "$(state)" == *"dirty=true"* ]] || fail "expected dirty after --no-save mutation"

# 2. Re-ingest over the dirty mirror must be refused, mirror untouched.
if out="$("$KEYHOLE" reingest "$VAULT" 2>&1)"; then
    fail "reingest over a dirty mirror succeeded — it discarded the unsaved recycle: $out"
fi
[[ "$out" == *"mirror owes"* ]] || fail "expected a mirror-owes refusal, got: $out"
[[ "$(state)" == *"dirty=true"* ]] || fail "refused reingest changed the watermark"

# 3. Wrong password over the same dirty mirror: fails on the key, never
#    with the mirror-owes refusal (decrypt runs first).
if out="$(KEYHOLE_PASSWORD="not-the-password" "$KEYHOLE" reingest "$VAULT" 2>&1)"; then
    fail "reingest under a wrong password succeeded: $out"
fi
[[ "$out" != *"mirror owes"* ]] \
    || fail "wrong password produced the mirror-owes refusal — the refusal must imply a verified key: $out"
[[ "$out" == *"decryption failed"* ]] \
    || fail "wrong password should fail on the key (decrypt), got: $out"
[[ "$(state)" == *"dirty=true"* ]] || fail "wrong-password reingest changed the watermark"

# 4. The owed write survives: flush persists it to the file.
out="$("$KEYHOLE" flush "$VAULT")"
[ "$out" = "flushed" ] || fail "expected 'flushed' on the still-dirty vault, got: $out"
rm -rf "$VAULT.mirror"
[ "$(recycled)" = "1" ] || fail "the unsaved recycle did not survive to the KDBX"

# 5. Clean mirror → reingest proceeds, nothing lost, watermark settled.
[[ "$(state)" == *"dirty=false"* ]] || fail "expected clean before the control reingest"
out="$("$KEYHOLE" reingest "$VAULT")"
[ "$out" = "reingested" ] || fail "reingest over a clean mirror should proceed, got: $out"
[[ "$(state)" == *"dirty=false"* ]] || fail "a clean reingest left the watermark dirty"
[ "$(recycled)" = "1" ] || fail "clean reingest lost the persisted recycle"

echo "PASS: re-ingest refuses a dirty mirror (after verifying the key), the owed write survives to the KDBX, and a clean mirror re-ingests normally"
