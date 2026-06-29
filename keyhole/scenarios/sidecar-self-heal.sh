#!/usr/bin/env bash
#
# Scenario: a vault whose local SQLCipher *sidecar* can no longer be
# decrypted by the key the keystore now hands back self-heals on open —
# it discards the stale sidecar and re-ingests from the canonical KDBX
# (the source of truth), re-gating on the master password, then proceeds.
#
# Models the failure a keystore reset causes on a real client: the sidecar
# files survive (they live beside the vault, not in the keystore), but
# the key that decrypts them is gone, so the open that used to succeed
# now fails at the sidecar/key layer — before the KDBX is ever consulted.
# The sidecar is a disposable *derived cache*, so the safe remedy is to
# throw it away and rebuild it from the KDBX under the password the user
# is already supplying. keyhole reproduces the wiped-key state by
# reopening with a DIFFERENT mirror key (KEYHOLE_DB_KEY) than the one the
# sidecar was sealed under.
#
# Safety boundary — the whole point; every one of these MUST hold:
#   1. correct password + stale key  -> auto-heal, opens, content intact;
#   2. re-open under the now-current key -> NO second heal (one-shot, so a
#      recurring rebuild stays a loud, visible signal of a deeper problem);
#   3. WRONG password + stale key     -> the heal's re-ingest fails closed
#      at the KDBX unlock; the open fails and the KDBX is untouched. The
#      self-heal is NOT an auth bypass — it still gates on the password,
#      it just stops a dead cache from blocking a *correct* unlock;
#   4. CORRUPT kdbx + stale key       -> the heal fires AT MOST once, then
#      surfaces the real KDBX error (no rebuild loop, no masked corruption).
#
# Self-contained: drives keyhole's own create / create-entry / digest /
# list — no external tooling.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-self-heal-master-pw"
export KEYHOLE_PASSWORD="$PW"

# 64 hex chars (32 bytes), distinct from the adapter's default mirror key
# — standing in for "the keystore now returns a different/rotated key".
ALT_DB_KEY="$(printf 'a%.0s' {1..64})"
ALT_DB_KEY_2="$(printf 'b%.0s' {1..64})"
# Stable marker keyhole prints (stderr) when an open self-heals. A test
# that greps this is the canary if the wording ever drifts.
HEAL_NOTE='self-heal: rebuilt mirror from kdbx'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Seed a fresh vault with one entry, establishing a populated sidecar
# under the DEFAULT mirror key. Prints the vault path.
seed_vault() {
    local v="$1"
    "$KEYHOLE" create "$v" >/dev/null \
        || { echo "FAIL: could not create $v"; exit 1; }
    "$KEYHOLE" create-entry "$v" "Secret" \
        --username alice --entry-password "Tr0ub4dor&3" >/dev/null \
        || { echo "FAIL: could not seed entry in $v"; exit 1; }
    [ -f "$v.mirror/mirror.sqlite" ] \
        || { echo "FAIL: no sidecar after seeding $v"; exit 1; }
}

# ── 1. POSITIVE: stale db key + correct password -> auto-heal ──────────
VAULT="$TMP/heal.kdbx"
seed_vault "$VAULT"
baseline="$("$KEYHOLE" digest "$VAULT" 2>/dev/null)"
[ -n "$baseline" ] || { echo "FAIL: could not capture baseline digest"; exit 1; }

# Reopen with a DIFFERENT mirror key: the sidecar file survives but no
# longer decrypts, so the open must self-heal rather than fail.
out="$(KEYHOLE_DB_KEY="$ALT_DB_KEY" "$KEYHOLE" list "$VAULT" 2>&1)" \
    || { echo "FAIL: stale-key open did not self-heal (it errored)"; printf '%s\n' "$out" | sed 's/^/    /'; exit 1; }
printf '%s\n' "$out" | grep -q "$HEAL_NOTE" \
    || { echo "FAIL: open self-healed silently — the rebuild was not logged"; printf '%s\n' "$out" | sed 's/^/    /'; exit 1; }
printf '%s\n' "$out" | grep -q 'Secret' \
    || { echo "FAIL: the re-ingested vault is missing the Secret entry"; printf '%s\n' "$out" | sed 's/^/    /'; exit 1; }
after="$(KEYHOLE_DB_KEY="$ALT_DB_KEY" "$KEYHOLE" digest "$VAULT" 2>/dev/null)"
[ "$after" = "$baseline" ] \
    || { echo "FAIL: content digest changed across the self-heal (before=$baseline after=$after)"; exit 1; }
echo "note: stale db key triggered a self-heal; content digest preserved ($baseline)"

# ── 2. IDEMPOTENT: a second open under the now-current key must NOT heal
#       again — the rebuilt sidecar is sealed under ALT_DB_KEY, so opening
#       under ALT_DB_KEY is a healthy, signature-skip open. A heal here
#       would mean we rebuild on every launch (perf + a false alarm).
out2="$(KEYHOLE_DB_KEY="$ALT_DB_KEY" "$KEYHOLE" list "$VAULT" 2>&1)" \
    || { echo "FAIL: second open (healthy mirror) errored"; printf '%s\n' "$out2" | sed 's/^/    /'; exit 1; }
if printf '%s\n' "$out2" | grep -q "$HEAL_NOTE"; then
    echo "FAIL: self-heal fired again on a freshly-rebuilt mirror — not one-shot"
    exit 1
fi
echo "note: re-open under the rebuilt key did not re-heal (one-shot)"

# ── 3. NEGATIVE: stale db key + WRONG password -> fail closed ──────────
#    The heal discards the sidecar and tries to re-ingest, but re-ingest
#    must unlock the KDBX under the supplied password — a wrong one fails
#    closed there, so the open fails. Self-heal must never let a dead
#    cache convert into a successful unlock under the wrong password.
VAULT_WP="$TMP/wrongpw.kdbx"
seed_vault "$VAULT_WP"
wp_out="$(KEYHOLE_DB_KEY="$ALT_DB_KEY" KEYHOLE_PASSWORD="not-the-master-pw" "$KEYHOLE" list "$VAULT_WP" 2>&1)"
wp_rc=$?
if [ "$wp_rc" -eq 0 ]; then
    echo "FAIL: stale key + WRONG password unlocked the vault — self-heal became an auth bypass"
    printf '%s\n' "$wp_out" | sed 's/^/    /'
    exit 1
fi
# The surfaced error must be the KDBX unlock failure (the re-ingest), not
# a swallowed success.
printf '%s\n' "$wp_out" | grep -qi 'kdbx' \
    || { echo "FAIL: wrong-password failure did not surface a KDBX unlock error"; printf '%s\n' "$wp_out" | sed 's/^/    /'; exit 1; }
# The canonical KDBX is untouched: it still opens under the CORRECT
# password (a fresh re-ingest), proving the failed heal harmed nothing.
recover="$(KEYHOLE_DB_KEY="$ALT_DB_KEY" "$KEYHOLE" list "$VAULT_WP" 2>&1)" \
    || { echo "FAIL: vault did not re-open under the correct password after a failed heal"; printf '%s\n' "$recover" | sed 's/^/    /'; exit 1; }
printf '%s\n' "$recover" | grep -q 'Secret' \
    || { echo "FAIL: the Secret entry vanished after a failed heal — the KDBX was harmed"; exit 1; }
echo "note: wrong password + stale key failed closed; KDBX untouched and re-opens correctly"

# ── 4. NEGATIVE: stale db key + CORRUPT kdbx -> heal once, surface error
#    The heal fires (the sidecar genuinely won't decrypt), discards the
#    sidecar, then re-ingest hits the corrupt KDBX and surfaces the real
#    error. It must NOT loop: at most one heal attempt per open.
VAULT_CORRUPT="$TMP/corrupt.kdbx"
seed_vault "$VAULT_CORRUPT"
# Scribble over the KDBX header so the master-password unlock fails on a
# parse/format error rather than a wrong-key error.
dd if=/dev/zero of="$VAULT_CORRUPT" bs=1 count=64 conv=notrunc 2>/dev/null
cr_out="$(KEYHOLE_DB_KEY="$ALT_DB_KEY_2" "$KEYHOLE" list "$VAULT_CORRUPT" 2>&1)"
cr_rc=$?
if [ "$cr_rc" -eq 0 ]; then
    echo "FAIL: a corrupt KDBX opened successfully after a self-heal — corruption was masked"
    exit 1
fi
heal_count="$(printf '%s\n' "$cr_out" | grep -c "$HEAL_NOTE")"
if [ "$heal_count" -gt 1 ]; then
    echo "FAIL: self-heal fired $heal_count times on a corrupt KDBX — rebuild loop"
    printf '%s\n' "$cr_out" | sed 's/^/    /'
    exit 1
fi
printf '%s\n' "$cr_out" | grep -qi 'kdbx' \
    || { echo "FAIL: corrupt-KDBX failure did not surface a KDBX error"; printf '%s\n' "$cr_out" | sed 's/^/    /'; exit 1; }
echo "note: corrupt KDBX surfaced the real error after a single heal attempt (no loop)"

echo "PASS: sidecar self-heal recovers a stale-key vault, stays one-shot, and refuses both a wrong password and a corrupt KDBX"
