#!/usr/bin/env bash
#
# Scenario: VAULT-IDENTITY VERIFICATION — a consumer re-anchoring a vault to
# a user-picked KDBX file must REJECT the wrong file, while NOT false-rejecting
# the genuine vault after it has been re-keyed elsewhere.
#
# A "Locate…" recovery flow (the vault's .kdbx went missing; the user points
# at a replacement) is path-based and trusting. Without an identity check it
# silently re-points a vault's stable identity (and its local store) at a
# DIFFERENT vault's file, and the next unlock ingests the wrong contents. A
# vault's identity is its root-group UUID — minted once and preserved across
# every save / sync / RE-KEY — so "same vault?" == "same root-group UUID?".
#
# The verb returns a THREE-WAY verdict (stdout + exit code), so a consumer
# keying off either can't read a reject as success:
#   * match         (exit 0) — same vault; proceed.
#   * mismatch      (exit 1) — decrypts but a DIFFERENT vault; reject.
#   * undecryptable (exit 1) — won't open under the supplied credential.
#                              AMBIGUOUS: wrong file, corrupt, OR the genuine
#                              vault re-keyed since the credential was cached —
#                              so a real consumer re-derives, it is NOT a
#                              "different vault" verdict.
#
# Assertions:
#   1. SAME vault → match.
#   2. PATH-AGNOSTIC → the same vault at a NEW path still matches (the point of
#      recovery), and the picked read creates NO mirror (pure read).
#   3. DIFFERENT vault that decrypts under the same password → mismatch.
#   4. WRONG password → undecryptable (NOT mismatch).
#   5. SYMMETRY → a different vault matches its OWN identity (mismatch is real).
#   6. RE-KEY (the load-bearing case): after the vault is re-keyed, the GENUINE
#      file under the STALE (old) credential is `undecryptable`, NOT `mismatch`
#      — so a consumer re-derives instead of rejecting its own vault; under the
#      NEW credential it is `match` (identity preserved across re-key).
#   7. KEYFILE vault → matches WITH its keyfile; WITHOUT it → undecryptable.
#
# Self-contained: keyhole's own create / root-uuid / rekey / verify-identity.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-identity-master-pw"
NEWPW="keyhole-identity-rekeyed-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VAULT_A="$TMP/genuine.kdbx"      # the vault being recovered
VAULT_B="$TMP/other.kdbx"        # a DIFFERENT vault, same password
MOVED="$TMP/genuine-moved.kdbx"  # the genuine vault's bytes at a new path

fail() { echo "FAIL: $*"; exit 1; }

# Run verify-identity and report "<verdict>:<exit-code>" so an assertion pins
# BOTH the stdout verdict and the exit code in one comparison.
verify() { # <picked> <expected-uuid> [password] [keyfile]
    local pw="${3:-$PW}" out rc
    if [ -n "${4:-}" ]; then
        out=$(KEYHOLE_PASSWORD="$pw" "$KEYHOLE" verify-identity "$1" --expect "$2" --keyfile "$4" 2>/dev/null); rc=$?
    else
        out=$(KEYHOLE_PASSWORD="$pw" "$KEYHOLE" verify-identity "$1" --expect "$2" 2>/dev/null); rc=$?
    fi
    printf '%s:%s' "$out" "$rc"
}

# --- seed two distinct vaults under the SAME master password ----------
# Same password is the honest "different vault" case: the picked file is
# decrypted with the cached master password, so a different file that decrypts
# but is a different vault is exactly the dangerous case to catch.
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$VAULT_A" >/dev/null || fail "create genuine vault A"
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$VAULT_B" >/dev/null || fail "create other vault B"

A_ROOT="$(KEYHOLE_PASSWORD="$PW" "$KEYHOLE" root-uuid "$VAULT_A" 2>/dev/null)"
B_ROOT="$(KEYHOLE_PASSWORD="$PW" "$KEYHOLE" root-uuid "$VAULT_B" 2>/dev/null)"
[ -n "$A_ROOT" ] || fail "could not read genuine vault A's root-group UUID"
[ -n "$B_ROOT" ] || fail "could not read other vault B's root-group UUID"
[ "$A_ROOT" != "$B_ROOT" ] || fail "two independently-created vaults share a root-group UUID ($A_ROOT)"

# --- 1: SAME vault → match -------------------------------------------
[ "$(verify "$VAULT_A" "$A_ROOT")" = "match:0" ] || fail "genuine file did not match its own identity"

# --- 2: PATH-AGNOSTIC → identity holds across a move; pure read -------
cp "$VAULT_A" "$MOVED"
[ "$(verify "$MOVED" "$A_ROOT")" = "match:0" ] || fail "genuine vault at a new path did not match"
[ ! -e "$MOVED.mirror" ] || fail "verify-identity created a mirror for the picked file — must be a pure read"

# --- 3: DIFFERENT vault (decrypts, different root) → mismatch ---------
[ "$(verify "$VAULT_B" "$A_ROOT")" = "mismatch:1" ] || fail "a DIFFERENT vault was not rejected as mismatch (exit 1)"

# --- 4: WRONG password → undecryptable (NOT mismatch) ----------------
[ "$(verify "$VAULT_A" "$A_ROOT" "keyhole-WRONG-pw")" = "undecryptable:1" ] \
    || fail "a wrong-password file was not undecryptable (exit 1)"

# --- 5: SYMMETRY teeth → B matches its OWN identity ------------------
[ "$(verify "$VAULT_B" "$B_ROOT")" = "match:0" ] || fail "vault B did not match its OWN identity — 'mismatch' may be always-fail"

echo "note: guard accepts genuine (even moved), rejects different vault (A=$A_ROOT B=$B_ROOT) and wrong password"

# --- 6: RE-KEY — genuine-but-re-keyed must be undecryptable, not mismatch
# Re-key A's master credential. The root-group UUID (identity) is preserved, so
# A_ROOT still names this vault — but the file no longer opens under the OLD
# credential a stale device cached. The guard must report `undecryptable`
# (re-derive), NOT `mismatch` (reject the user's own vault).
KEYHOLE_PASSWORD="$PW" KEYHOLE_NEW_PASSWORD="$NEWPW" "$KEYHOLE" rekey "$VAULT_A" >/dev/null \
    || fail "could not re-key vault A"
[ "$(verify "$VAULT_A" "$A_ROOT" "$PW")" = "undecryptable:1" ] \
    || fail "re-keyed genuine vault under the STALE credential must be undecryptable, not mismatch"
[ "$(verify "$VAULT_A" "$A_ROOT" "$NEWPW")" = "match:0" ] \
    || fail "re-keyed vault under the NEW credential must match (identity preserved across re-key)"

echo "note: after re-key, the genuine file is undecryptable under the old credential (re-derive) and matches under the new (identity preserved)"

# --- 7: KEYFILE vault → match WITH keyfile, undecryptable WITHOUT -----
VAULT_K="$TMP/keyed.kdbx"
KF="$TMP/keyed.keyx"
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$VAULT_K" --keyfile "$KF" >/dev/null || fail "create keyfile vault"
K_ROOT="$(KEYHOLE_PASSWORD="$PW" "$KEYHOLE" root-uuid "$VAULT_K" --keyfile "$KF" 2>/dev/null)"
[ -n "$K_ROOT" ] || fail "could not read keyfile vault's root-group UUID"

[ "$(verify "$VAULT_K" "$K_ROOT" "$PW" "$KF")" = "match:0" ] \
    || fail "keyfile vault did not match its own identity WITH its keyfile"
[ "$(verify "$VAULT_K" "$K_ROOT" "$PW")" = "undecryptable:1" ] \
    || fail "keyfile vault WITHOUT its keyfile must be undecryptable"

echo "PASS: vault-identity verify accepts the genuine (even relocated) file, rejects a different vault, and — crucially — reports a re-keyed genuine vault as undecryptable (re-derive) rather than mismatch"
