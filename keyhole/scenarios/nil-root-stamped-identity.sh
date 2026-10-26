#!/usr/bin/env bash
#
# Scenario: NIL-ROOT STAMPED IDENTITY — a vault file whose root group has no
# UUID (keepass-core decodes an absent root <UUID> as nil) is given one.
#
# A vault's identity is its root-group UUID, and the identity guard refuses
# to reconcile with or write over a file whose root differs from the mirror's.
# A nil root never matches anything — so without an identity of its own, such
# a vault could be opened but never saved or synced. The engine instead stamps
# one on first ingest, derived from the file's master seed: deterministic, so
# every device ingesting the same unstamped bytes mints the same identity.
# The ingest leaves the mirror owing the file a write; that first write is let
# through only onto the very file the stamp came from.
#
# Assertions:
#   1. A fresh ingest of a nil-root file leaves the mirror DIRTY (it owes the
#      file its identity) and writes nothing.
#   2. Every mirror ingesting the same bytes stamps the SAME identity, and the
#      flush writes it into the file (an independent pure read now matches).
#   3. The stamped file then behaves as any identified vault: a fresh
#      re-ingest keeps the identity and settles clean.
#   4. A DIFFERENT nil-root vault swapped in at the path is refused by
#      reconcile, save and re-key (VaultIdentityMismatch), its bytes untouched,
#      and the original file still takes the owed stamp afterwards.
#   5. The other vault stamps its own, different identity.
#
# Fixtures: two keepass-core-written KDBX 4 vaults with a nil root UUID and
# one entry each ("Alpha Login" / "Bravo Login"), under a public test
# password (a test credential, not a secret).

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX_A="$HERE/fixtures/nil-root-a.kdbx"
FIX_B="$HERE/fixtures/nil-root-b.kdbx"
export KEYHOLE_PASSWORD="keyhole-nil-root-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

REFUSAL="VaultIdentityMismatch"

fail() { echo "FAIL: $*"; exit 1; }

# A rewrite must land in a later mtime second than the recorded signature.
swap_in() { sleep 1; cp "$1" "$2"; }

# Pure read of the FILE's identity (no mirror): "match" iff it carries $2.
file_identity() { "$KEYHOLE" verify-identity "$1" --expect "$2" 2>/dev/null; }

# --- 1 + 2: stamp on ingest, owed until flushed, deterministic -------------
VAULT="$TMP/vault.kdbx"
SIBLING="$TMP/sibling.kdbx"   # another device's copy of the same bytes
cp "$FIX_A" "$VAULT"
cp "$FIX_A" "$SIBLING"

state="$("$KEYHOLE" persistence-state "$VAULT")" || fail "fresh ingest of a nil-root vault"
[[ "$state" == *"dirty=true"* ]] || fail "a stamped ingest must leave the mirror owing a write (got: $state)"
cmp -s "$FIX_A" "$VAULT" || fail "the ingest alone wrote the file"

STAMP="$("$KEYHOLE" root-uuid "$SIBLING")" || fail "stamp the sibling copy"
[ -n "$STAMP" ] || fail "no stamped identity"
[ "$STAMP" != "00000000-0000-0000-0000-000000000000" ] || fail "the stamped identity is nil"
[ "$(file_identity "$SIBLING" "$STAMP")" = "match" ] || fail "the sibling's flush did not write its stamp"

[ "$(file_identity "$VAULT" "$STAMP")" = "mismatch" ] || fail "the vault file carries an identity before any flush"
flushed="$("$KEYHOLE" flush "$VAULT")" || fail "flush the owed stamp"
[ "$flushed" = "flushed" ] || fail "the owed stamp was not flushed (got: $flushed)"
[ "$(file_identity "$VAULT" "$STAMP")" = "match" ] \
    || fail "the vault's mirror stamped a different identity than its sibling's (not deterministic)"

echo "note: stamped identity $STAMP — owed by the ingest, written by the flush, same on every copy"

# --- 3: the stamped file is an ordinary identified vault -------------------
rm -rf "$VAULT.mirror"
state="$("$KEYHOLE" persistence-state "$VAULT")" || fail "fresh re-ingest of the stamped file"
[[ "$state" == *"dirty=false"* ]] || fail "an identified file's ingest must settle clean (got: $state)"
[ "$("$KEYHOLE" root-uuid "$VAULT")" = "$STAMP" ] || fail "the identity changed across a fresh re-ingest"
"$KEYHOLE" list "$VAULT" >"$TMP/list.out" || fail "list the stamped vault"
grep -q "Alpha Login" "$TMP/list.out" || fail "the vault's entry is missing after stamping"

echo "note: the stamped file re-ingests with the same identity, clean"

# --- 4: a different nil-root vault is refused ------------------------------
BOUND="$TMP/bound.kdbx"
cp "$FIX_A" "$BOUND"
"$KEYHOLE" persistence-state "$BOUND" >/dev/null || fail "bind a mirror to vault A (stamp owed)"
swap_in "$FIX_B" "$BOUND"

if "$KEYHOLE" list "$BOUND" >"$TMP/sync.out" 2>"$TMP/sync.err"; then
    cat "$TMP/sync.out" "$TMP/sync.err"; fail "reconcile against a different nil-root vault succeeded"
fi
grep -q "$REFUSAL" "$TMP/sync.err" || { cat "$TMP/sync.err"; fail "reconcile failed, but not with $REFUSAL"; }

if KEYHOLE_SKIP_OPEN_SYNC=1 "$KEYHOLE" flush "$BOUND" >"$TMP/save.out" 2>"$TMP/save.err"; then
    cat "$TMP/save.out" "$TMP/save.err"; fail "the owed stamp was written over a different nil-root vault"
fi
grep -q "$REFUSAL" "$TMP/save.err" || { cat "$TMP/save.err"; fail "the save failed, but not with $REFUSAL"; }

if KEYHOLE_SKIP_OPEN_SYNC=1 KEYHOLE_NEW_PASSWORD="keyhole-nil-root-new-pw" \
        "$KEYHOLE" rekey "$BOUND" >"$TMP/rekey.out" 2>"$TMP/rekey.err"; then
    cat "$TMP/rekey.out" "$TMP/rekey.err"; fail "a re-key over a different nil-root vault succeeded"
fi
grep -q "$REFUSAL" "$TMP/rekey.err" || { cat "$TMP/rekey.err"; fail "the re-key failed, but not with $REFUSAL"; }
cmp -s "$FIX_B" "$BOUND" || fail "a refused write changed the other vault's file"

swap_in "$FIX_A" "$BOUND"
flushed="$(KEYHOLE_SKIP_OPEN_SYNC=1 "$KEYHOLE" flush "$BOUND")" || fail "the original file no longer takes the owed stamp"
[ "$flushed" = "flushed" ] || fail "the owed stamp did not survive the refusals (got: $flushed)"
[ "$(file_identity "$BOUND" "$STAMP")" = "match" ] || fail "the original file did not take the stamp"

echo "note: a different nil-root vault refused ($REFUSAL) by reconcile, save and re-key; bytes untouched"

# --- 5: the other vault stamps its own identity ----------------------------
OTHER="$TMP/other.kdbx"
cp "$FIX_B" "$OTHER"
OTHER_STAMP="$("$KEYHOLE" root-uuid "$OTHER")" || fail "stamp the other vault"
[ "$OTHER_STAMP" != "$STAMP" ] || fail "two different nil-root vaults stamped the same identity"
"$KEYHOLE" list "$OTHER" >"$TMP/other.out" || fail "list the other vault"
grep -q "Bravo Login" "$TMP/other.out" || fail "the other vault's entry is missing"
grep -q "Alpha Login" "$TMP/other.out" && fail "vault A's entry reached the other vault"

echo "note: the other nil-root vault stamped its own identity $OTHER_STAMP"
echo "PASS: nil-root vaults are stamped an identity, written once onto their own file only"
