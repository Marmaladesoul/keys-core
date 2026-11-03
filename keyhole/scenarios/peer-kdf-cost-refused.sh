#!/usr/bin/env bash
#
# Scenario: A PEER BLOB CAN'T SET ITS READER'S KDF COST — a KDBX file's outer
# header names its own KDF parameters, and the KDF has to run before the
# header HMAC (KDBX4) or the payload (KDBX3) can be checked. So a peer blob
# with hostile parameters (gigabytes of Argon2 memory, billions of passes or
# AES rounds) would make `ingest-peer` allocate or spin without bound before
# learning anything about the file. Replicas of one vault share their KDF
# parameters — only the salt is per-envelope — so the peer ingest refuses a
# blob whose cost (parameters minus salt) differs from the local vault's,
# from the header alone, before deriving anything.
#
# The forged blobs come from `forge-kdf`: a real replica with only the
# header's KDF parameters rewritten. Its header HMAC no longer verifies, so
# no key could open it — what's under test is whether the reader runs the
# KDF before finding that out.
#
# Assertions:
#   1. HOSTILE ARGON2 → a replica demanding 6 GiB × u32::MAX passes is
#      refused with the KDF-cost error, well inside the time budget (the
#      derive itself would run for hours, or abort on the allocation); the
#      vault's file is byte-identical and the vault still opens.
#   2. EXACT MATCH → a cheap, benign difference (one more pass) is refused
#      too, as the KDF-cost error rather than a decrypt failure: adopting a
#      peer's changed KDF parameters is a re-key, which needs its own path.
#   3. HOSTILE AES-KDF (KDBX3) → a replica demanding u32::MAX AES rounds is
#      refused the same way.
#   4. SALT IS NOT COST → a peer that re-keyed under the same password
#      (fresh salt, same parameters) still merges.
#   5. CONTROL → an ordinary peer replica merges, and the merge persists
#      across a fresh re-ingest. The gate must not over-refuse.
#   6. AFTER A RESOLVE → resolving a held conflict re-ingests the mirror in
#      memory, with no file envelope; the vault's recorded KDF cost must
#      survive it, so the next peer ingest still passes the gate.
#
# Self-contained: keyhole's own create / create-entry / update-entry / list /
# ingest-peer / list-conflicts / resolve / rekey / forge-kdf verbs, plus the
# vendored KDBX3 fixture; throwaway vaults.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
KDBX3_FIXTURE="$HERE/fixtures/kdbx3-minimal.kdbx"
KDBX3_PW='tëst pässwörd 🔑/\'
export KEYHOLE_PASSWORD="keyhole-kdf-cost-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

LOCAL="$TMP/local.kdbx"     # the vault receiving peer blobs
PEER="$TMP/peer.kdbx"       # an honest replica of it
REFUSAL="KdfParametersMismatch"
# Seconds a refused ingest may take. The refusal reads one header; a derive
# at any of the forged costs runs for hours. The margin absorbs slow runners.
BUDGET_SECS=30
# What a process killed by the watchdog exits with (128 + SIGKILL).
KILLED_RC=137
U32_MAX=4294967295

fail() { echo "FAIL: $*"; exit 1; }

# Run a command, killing it if it outlives the budget; returns its exit
# status (KILLED_RC when the watchdog fired).
bounded() {
    "$@" &
    local pid=$!
    ( sleep "$BUDGET_SECS"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local dog=$!
    wait "$pid"
    local rc=$?
    # Reap the watchdog's own sleep too, or it outlives the scenario.
    pkill -P "$dog" 2>/dev/null
    kill "$dog" 2>/dev/null
    wait "$dog" 2>/dev/null
    return "$rc"
}

# Ingest a forged peer blob and assert the KDF-cost refusal: fast, typed,
# nothing written. $1 = vault, $2 = forged blob, $3 = label.
expect_refused() {
    local vault="$1" blob="$2" label="$3"
    cp "$vault" "$TMP/before.kdbx"
    bounded "$KEYHOLE" ingest-peer "$vault" "$blob" >"$TMP/out" 2>"$TMP/err"
    local rc=$?
    [ "$rc" -ne "$KILLED_RC" ] \
        || fail "$label: ingest outlived ${BUDGET_SECS}s — the reader ran the forged KDF"
    [ "$rc" -ne 0 ] && grep -q "$REFUSAL" "$TMP/err" \
        || { cat "$TMP/out" "$TMP/err"; fail "$label: not refused with the KDF-cost error (rc=$rc)"; }
    cmp -s "$TMP/before.kdbx" "$vault" || fail "$label: the refused ingest rewrote the vault's file"
}

# --- seed: a vault and an honest replica that has diverged ---------------
"$KEYHOLE" create "$LOCAL" >/dev/null || fail "create the vault"
"$KEYHOLE" create-entry "$LOCAL" "Local Login" --username local >/dev/null || fail "seed the vault"
cp "$LOCAL" "$PEER"
"$KEYHOLE" create-entry "$PEER" "Peer Login" --username peer >/dev/null || fail "seed the replica"

# --- 1: HOSTILE ARGON2 → refused before deriving ------------------------
"$KEYHOLE" forge-kdf "$PEER" "$TMP/hostile.kdbx" \
    --argon2-memory-mib 6144 --argon2-iterations "$U32_MAX" >/dev/null || fail "forge the hostile Argon2 blob"
expect_refused "$LOCAL" "$TMP/hostile.kdbx" "hostile Argon2"
"$KEYHOLE" list "$LOCAL" >"$TMP/p1-list.out" || fail "the vault no longer opens after the refusal"
grep -q "Peer Login" "$TMP/p1-list.out" && fail "the forged blob's entry leaked into the vault"

echo "note: a blob demanding 6 GiB × u32::MAX Argon2 passes is refused before deriving"

# --- 2: EXACT MATCH → a benign change is refused too ---------------------
"$KEYHOLE" forge-kdf "$PEER" "$TMP/one-more-pass.kdbx" --argon2-iterations 3 >/dev/null \
    || fail "forge the one-more-pass blob"
expect_refused "$LOCAL" "$TMP/one-more-pass.kdbx" "one more Argon2 pass"

echo "note: any change of KDF cost is refused — adopting one is a re-key"

# --- 3: HOSTILE AES-KDF (KDBX3) → refused before deriving -----------------
K3="$TMP/k3.kdbx"
cp "$KDBX3_FIXTURE" "$K3"
KEYHOLE_PASSWORD="$KDBX3_PW" "$KEYHOLE" list "$K3" >/dev/null || fail "open the KDBX3 fixture"
"$KEYHOLE" forge-kdf "$K3" "$TMP/k3-hostile.kdbx" --aes-rounds "$U32_MAX" >/dev/null \
    || fail "forge the hostile AES-KDF blob"
KEYHOLE_PASSWORD="$KDBX3_PW" expect_refused "$K3" "$TMP/k3-hostile.kdbx" "hostile AES-KDF"

echo "note: a KDBX3 blob demanding u32::MAX AES-KDF rounds is refused before deriving"

# --- 4: SALT IS NOT COST → a re-keyed peer (fresh salt) merges ----------
cp "$PEER" "$TMP/peer-before-rekey.kdbx"
KEYHOLE_NEW_PASSWORD="$KEYHOLE_PASSWORD" "$KEYHOLE" rekey "$PEER" >/dev/null \
    || fail "re-key the replica under the same password"
# forge-kdf with no override is an identity rewrite; its report shows the KDF.
kdf_of() { "$KEYHOLE" forge-kdf "$1" "$TMP/probe.kdbx" | sed 's/.*(KDF: //'; }
salt_of() { kdf_of "$1" | sed 's/.*salt: \[\([^]]*\)\].*/\1/'; }
cost_of() { kdf_of "$1" | sed 's/salt: \[[^]]*\], //'; }
[ "$(salt_of "$PEER")" != "$(salt_of "$TMP/peer-before-rekey.kdbx")" ] \
    || fail "the re-key kept the salt, so this step proves nothing"
[ "$(cost_of "$PEER")" = "$(cost_of "$TMP/peer-before-rekey.kdbx")" ] \
    || fail "the re-key changed the KDF cost"
"$KEYHOLE" ingest-peer "$LOCAL" "$PEER" >"$TMP/p4.out" 2>"$TMP/p4.err" \
    || { cat "$TMP/p4.err"; fail "a replica with a fresh salt and the same KDF cost was refused"; }

echo "note: a re-keyed replica (fresh salt, same cost) still merges"

# --- 5: CONTROL → the merge persists ------------------------------------
"$KEYHOLE" create-entry "$PEER" "Peer Later" --username later >/dev/null || fail "edit the replica"
"$KEYHOLE" ingest-peer "$LOCAL" "$PEER" >"$TMP/p5.out" 2>"$TMP/p5.err" \
    || { cat "$TMP/p5.err"; fail "an ordinary replica was refused"; }
rm -rf "$LOCAL.mirror"
"$KEYHOLE" list "$LOCAL" >"$TMP/p5-list.out" || fail "fresh re-ingest after the merge"
grep -q "Peer Login" "$TMP/p5-list.out" || fail "the replica's first entry didn't persist"
grep -q "Peer Later" "$TMP/p5-list.out" || fail "the replica's later entry didn't persist"
grep -q "Local Login" "$TMP/p5-list.out" || fail "the vault lost its own entry in the merge"

# --- 6: AFTER A RESOLVE → the recorded cost survives ---------------------
uuid="$("$KEYHOLE" list "$LOCAL" | awk '/Local Login/ {print $1; exit}')"
[ -n "$uuid" ] || fail "find the entry to put in conflict"
cp "$LOCAL" "$PEER"
"$KEYHOLE" update-entry "$LOCAL" "$uuid" --username local-side >/dev/null || fail "edit locally"
"$KEYHOLE" update-entry "$PEER" "$uuid" --username peer-side >/dev/null || fail "edit on the replica"
"$KEYHOLE" ingest-peer "$LOCAL" "$PEER" >/dev/null 2>"$TMP/p6a.err" \
    || { cat "$TMP/p6a.err"; fail "the clashing replica was refused"; }
"$KEYHOLE" list-conflicts "$LOCAL" | grep -q "$uuid" || fail "the clash didn't park a conflict"
"$KEYHOLE" resolve "$LOCAL" --entry "$uuid" --choose remote >/dev/null || fail "resolve the conflict"
"$KEYHOLE" create-entry "$PEER" "Peer After Resolve" --username after >/dev/null || fail "edit the replica again"
"$KEYHOLE" ingest-peer "$LOCAL" "$PEER" >/dev/null 2>"$TMP/p6b.err" \
    || { cat "$TMP/p6b.err"; fail "the first peer ingest after a resolve was refused"; }
"$KEYHOLE" list "$LOCAL" | grep -q "Peer After Resolve" || fail "the post-resolve merge didn't land"

echo "note: a resolved conflict keeps the vault's recorded KDF cost"

echo "PASS: a peer blob whose KDF cost differs from the vault's — hostile Argon2, hostile AES-KDF, or a benign change — is refused from its header before any derive and writes nothing; a fresh salt at the same cost, an ordinary replica, and a replica after a resolve, merge normally"
