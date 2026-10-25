#!/usr/bin/env bash
#
# Scenario: REFUSE A DIFFERENT VAULT — when the file at a warm mirror's
# path is replaced by a *different* vault (a swapped / relinked file that
# happens to decrypt under the same password), every path that crosses the
# mirror↔file boundary — reconcile, peer ingest, save, re-key — must REFUSE
# rather than merge it in or write over it, touching neither the mirror nor
# the file.
#
# A vault's identity is its root-group UUID (see `vault-identity-verify.sh`):
# minted once, preserved across every save / sync / re-key. The mirror
# carries the identity of the vault it was ingested from, so "is the file
# still my vault?" == "same root-group UUID?". Without the check, reconcile
# has no notion of "different vault": a stranger whose groups/entries hang off
# its own root dies mid-merge on a foreign-key violation (rolled back, but
# surfaced as an opaque internal error a client can't act on), and a stranger
# with nothing under its root "reconciles" as no-change — silently accepted as
# this vault's file, to be overwritten by the next save (that shape is pinned
# by the engine test `reconcile_refuses_an_empty_different_vault`; keyhole's
# `create` always mints a bin group, so it can't build a root-only vault).
# The refusal must be deliberate, named, and all-or-nothing.
#
# Assertions:
#   1. SWAP → the open-time reconcile (`sync_with_disk`) fails with the
#      identity-mismatch error, and the file at the path is byte-identical
#      afterwards (no write-back over the stranger's file).
#   2. MIRROR UNTOUCHED → restoring A's file, the warm mirror still holds
#      exactly A's entries (none of B's leaked in), and that survives a
#      mirror nuke + fresh-process re-ingest of A.
#   3. PEER-BLOB PATH → `ingest-peer` with a different vault's blob is
#      refused the same way, and leaves A's file byte-identical.
#   4. B UNPOLLUTED → B's own file, re-ingested from disk in a fresh
#      process, holds only B's entries.
#   5. CONTROL → an externally edited copy of A (same vault, new content) at
#      the path still reconciles, and the edit persists across a mirror
#      nuke + fresh-process re-ingest. The guard must not over-refuse.
#   6. SAVE / RE-KEY → with the engine already open when B is swapped in
#      (no open-time sync), a save and a re-key are refused and B's bytes
#      are untouched; the owed edit stays in the mirror and lands on A's
#      own file once it is back (across a fresh re-ingest).
#
# Self-contained: keyhole's own create / create-entry / update-entry / list /
# ingest-peer / rekey verbs (+ KEYHOLE_SKIP_OPEN_SYNC), throwaway vaults only.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-reconcile-identity-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VAULT="$TMP/vault.kdbx"      # the path the mirror is bound to (vault A)
A_COPY="$TMP/a-pristine.kdbx" # A's bytes, kept aside to restore
B_FILE="$TMP/b.kdbx"          # a DIFFERENT vault, same password
B_COPY="$TMP/b-pristine.kdbx" # B's bytes, for the byte-identity checks
PEER="$TMP/a-peer.kdbx"       # an externally edited copy of A (control)

# The identity-mismatch refusal, as keyhole renders the FFI error.
REFUSAL="VaultIdentityMismatch"

fail() { echo "FAIL: $*"; exit 1; }

# Overwrite the bound path. sleep 1 so the new mtime is strictly newer than
# the mirror's recorded signature (a file-mtime wait, not an LWW stamp), so
# the next open sees "the file changed" and reconciles.
swap_in() { sleep 1; cp "$1" "$VAULT"; }

# --- seed: vault A (bound to the mirror) and a different vault B ---------
"$KEYHOLE" create "$VAULT" >/dev/null || fail "create vault A"
"$KEYHOLE" create-entry "$VAULT" "Alpha Login" --username alpha >/dev/null || fail "seed A"
"$KEYHOLE" create "$B_FILE" >/dev/null || fail "create vault B"
"$KEYHOLE" create-entry "$B_FILE" "Bravo Login" --username bravo >/dev/null || fail "seed B"
cp "$VAULT" "$A_COPY"
cp "$B_FILE" "$B_COPY"
rm -rf "$B_FILE.mirror" # B's own mirror plays no part below

# Warm A's mirror (any verb opens a Session, which records the signature).
"$KEYHOLE" list "$VAULT" >"$TMP/seed.out" || fail "warm A's mirror"
grep -q "Alpha Login" "$TMP/seed.out" || fail "A's mirror did not warm with its own entry"

# --- 1: SWAP → reconcile refused, file left byte-identical --------------
swap_in "$B_COPY"
if "$KEYHOLE" list "$VAULT" >"$TMP/swap.out" 2>"$TMP/swap.err"; then
    echo "--- stdout"; cat "$TMP/swap.out"; echo "--- stderr"; cat "$TMP/swap.err"
    fail "reconcile against a DIFFERENT vault succeeded — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/swap.err" \
    || { cat "$TMP/swap.err"; fail "the swap failed, but not with the identity-mismatch refusal"; }
cmp -s "$B_COPY" "$VAULT" \
    || fail "the refused reconcile rewrote the file at the path (merged A into the stranger's vault)"

echo "note: swapped-in vault refused ($REFUSAL), file byte-identical"

# --- 2: MIRROR UNTOUCHED → A's mirror holds only A ----------------------
swap_in "$A_COPY"
"$KEYHOLE" list "$VAULT" >"$TMP/warm.out" 2>"$TMP/warm.err" \
    || { cat "$TMP/warm.err"; fail "A's own file no longer reconciles after the refusal"; }
grep -q "Alpha Login" "$TMP/warm.out" || fail "A's entry missing from the warm mirror after the refusal"
grep -q "Bravo Login" "$TMP/warm.out" && fail "B's entry leaked into A's mirror despite the refusal"

rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" >"$TMP/fresh.out" || fail "fresh re-ingest of A"
grep -q "Alpha Login" "$TMP/fresh.out" || fail "A's entry missing after a fresh re-ingest"
grep -q "Bravo Login" "$TMP/fresh.out" && fail "B's entry reached A's file"

echo "note: A's mirror and file hold only A after the refusal (warm + fresh re-ingest)"

# --- 3: PEER-BLOB PATH → ingest-peer refuses a different vault ----------
cp "$VAULT" "$TMP/a-before-peer.kdbx"
if "$KEYHOLE" ingest-peer "$VAULT" "$B_COPY" >"$TMP/peer.out" 2>"$TMP/peer.err"; then
    cat "$TMP/peer.out"; cat "$TMP/peer.err"
    fail "ingest-peer with a DIFFERENT vault's blob succeeded — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/peer.err" \
    || { cat "$TMP/peer.err"; fail "ingest-peer failed, but not with the identity-mismatch refusal"; }
cmp -s "$TMP/a-before-peer.kdbx" "$VAULT" || fail "the refused peer ingest rewrote A's file"
"$KEYHOLE" list "$VAULT" >"$TMP/after-peer.out" || fail "A no longer opens after the refused peer ingest"
grep -q "Alpha Login" "$TMP/after-peer.out" || fail "A's entry missing after the refused peer ingest"
grep -q "Bravo Login" "$TMP/after-peer.out" && fail "B's entry leaked into A's mirror via ingest-peer"

echo "note: peer-blob ingest of a different vault refused"

# --- 4: B UNPOLLUTED → B's file holds only B ----------------------------
cmp -s "$B_COPY" "$B_FILE" || fail "B's own file changed"
"$KEYHOLE" list "$B_FILE" >"$TMP/b.out" || fail "fresh ingest of B"
grep -q "Bravo Login" "$TMP/b.out" || fail "B's entry missing from B"
grep -q "Alpha Login" "$TMP/b.out" && fail "A's entry reached B's file"

# --- 5: CONTROL → an externally edited copy of A still reconciles -------
uuid="$(awk '/Alpha Login/ {print $1; exit}' "$TMP/after-peer.out")"
[ -n "$uuid" ] || fail "could not find A's seeded entry"
cp "$VAULT" "$PEER"
rm -rf "$PEER.mirror"
"$KEYHOLE" update-entry "$PEER" "$uuid" --title "Alpha Edited Elsewhere" >/dev/null || fail "edit A's peer copy"
swap_in "$PEER"
"$KEYHOLE" list "$VAULT" >"$TMP/ctl.out" 2>"$TMP/ctl.err" \
    || { cat "$TMP/ctl.err"; fail "an externally edited copy of the SAME vault was refused"; }
grep -q "reconciled" "$TMP/ctl.err" || { cat "$TMP/ctl.err"; fail "the edited copy did not go through reconcile"; }
grep -q "Alpha Edited Elsewhere" "$TMP/ctl.out" || fail "the external edit was not adopted"

rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" >"$TMP/ctl-fresh.out" || fail "fresh re-ingest after the control edit"
grep -q "Alpha Edited Elsewhere" "$TMP/ctl-fresh.out" \
    || fail "the adopted edit did not persist across a fresh re-ingest"

echo "note: an externally edited copy of the same vault still reconciles"

# --- 6: SAVE / RE-KEY → refused over a different vault's file -----------
# The window a reconcile can't cover: the engine is already open when the
# file is swapped, so the next thing to touch the file is a WRITE.
# KEYHOLE_SKIP_OPEN_SYNC opens over the mirror as it stands (no open-time
# sync), modelling exactly that. The verb's mutation lands in the mirror,
# then its save must be refused — B's bytes untouched — and a re-key too.
cp "$VAULT" "$TMP/a-current.kdbx"
swap_in "$B_COPY"
if KEYHOLE_SKIP_OPEN_SYNC=1 "$KEYHOLE" create-entry "$VAULT" "Charlie Login" --username charlie \
        >"$TMP/save.out" 2>"$TMP/save.err"; then
    cat "$TMP/save.out"; cat "$TMP/save.err"
    fail "a save over a DIFFERENT vault's file succeeded — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/save.err" \
    || { cat "$TMP/save.err"; fail "the save failed, but not with the identity-mismatch refusal"; }
cmp -s "$B_COPY" "$VAULT" || fail "the refused save overwrote the other vault's file"

if KEYHOLE_SKIP_OPEN_SYNC=1 KEYHOLE_NEW_PASSWORD="keyhole-reconcile-identity-new-pw" \
        "$KEYHOLE" rekey "$VAULT" >"$TMP/rekey.out" 2>"$TMP/rekey.err"; then
    cat "$TMP/rekey.out"; cat "$TMP/rekey.err"
    fail "a re-key over a DIFFERENT vault's file succeeded — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/rekey.err" \
    || { cat "$TMP/rekey.err"; fail "the re-key failed, but not with the identity-mismatch refusal"; }
cmp -s "$B_COPY" "$VAULT" || fail "the refused re-key rewrote the other vault's file"

# The refused save kept the edit in the mirror (still owed), so once A's
# own file is back the next open reconciles and lands it on the RIGHT file.
swap_in "$TMP/a-current.kdbx"
"$KEYHOLE" list "$VAULT" >"$TMP/back.out" 2>"$TMP/back.err" \
    || { cat "$TMP/back.err"; fail "A's own file no longer opens after the refused save"; }
grep -q "Charlie Login" "$TMP/back.out" || fail "the edit made while the stranger sat at the path was lost"
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" >"$TMP/back-fresh.out" || fail "fresh re-ingest of A after the refused save"
grep -q "Charlie Login" "$TMP/back-fresh.out" || fail "the owed edit never reached A's file"
grep -q "Bravo Login" "$TMP/back-fresh.out" && fail "B's entry reached A's file"

echo "PASS: a different vault at the bound path is refused by reconcile, peer-blob ingest, save and re-key — mirror and the other vault's file untouched — while a genuine external edit still reconciles and an owed edit lands on the right file"
