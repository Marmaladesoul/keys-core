#!/usr/bin/env bash
#
# Scenario: TEST VAULTS ONLY SYNC WITH TEST VAULTS — a vault carrying the
# test-vault marker (Meta CustomData `KeysTestVault` = `1`) and one that
# doesn't are different kinds of vault, even when they are replicas of the
# same vault (same root-group UUID, same password). Every path that folds a
# replica into the mirror — the peer-blob ingest and the open-time reconcile
# against the file on disk — must REFUSE a replica whose marker differs from
# the mirror's, touching neither the mirror nor the file. Otherwise a marked
# copy of an ordinary vault would keep receiving that vault's live edits (and
# send its own back) for as long as the two stay paired.
#
# The identity gate (`reconcile-refuses-different-vault.sh`) can't catch this:
# a copy of a vault IS that vault. So the marker check runs alongside it, on
# the write paths too, and a mirror's kind never changes in place: kind is
# set on the FILE (`mark-test-vault`, the way an external client would edit
# it) and a warm mirror refuses the changed file until it is rebuilt.
#
# Assertions:
#   1. MARKER VERBS → `mark-test-vault` marks the file, a fresh ingest
#      carries it (it's in the KDBX), and `is-test-vault` reports it; the
#      unmarked original reports false.
#   2. UNMARKED ← MARKED → `ingest-peer` of the marked copy into the
#      unmarked vault is refused with the marker-mismatch error; the
#      unmarked vault's file is byte-identical and none of the copy's
#      entries reached it.
#   3. MARKED ← UNMARKED → the reverse direction is refused the same way.
#   4. DISK PATH → the marked copy swapped in at the unmarked vault's path
#      is refused by the open-time reconcile; the file is left byte-identical.
#   5. SAVE PATH → with the engine already open when the marked copy lands
#      at the path (no open-time sync), the save is refused and the marked
#      file is untouched.
#   6. NO KIND CHANGE IN PLACE → marking the ordinary vault's own file makes
#      its warm mirror refuse it; once the mirror is rebuilt from the file,
#      it opens as a test vault.
#   7. CONTROL → once both sides carry the marker, the same peer ingest
#      merges, and the merged edit persists across a fresh re-ingest. The
#      guard must not over-refuse.
#
# Self-contained: keyhole's own create / create-entry / update-entry / list /
# ingest-peer / mark-test-vault / is-test-vault verbs, throwaway vaults only.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-test-marker-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PLAIN="$TMP/plain.kdbx"         # an ordinary (unmarked) vault
MARKED="$TMP/marked.kdbx"       # a replica of the same vault, then marked
REFUSAL="TestVaultMarkerMismatch"

fail() { echo "FAIL: $*"; exit 1; }

# --- seed: an ordinary vault, and a marked copy of it -------------------
"$KEYHOLE" create "$PLAIN" >/dev/null || fail "create the ordinary vault"
"$KEYHOLE" create-entry "$PLAIN" "Plain Login" --username plain >/dev/null || fail "seed the ordinary vault"
cp "$PLAIN" "$MARKED"
"$KEYHOLE" mark-test-vault "$MARKED" >/dev/null || fail "mark the copy"
"$KEYHOLE" create-entry "$MARKED" "Marked Only" --username marked >/dev/null || fail "seed the marked copy"

# --- 1: MARKER VERBS → set, persisted in the KDBX, reported ------------
rm -rf "$MARKED.mirror"
[ "$("$KEYHOLE" is-test-vault "$MARKED")" = "true" ] \
    || fail "the marker didn't survive a save + fresh re-ingest of the marked copy"
[ "$("$KEYHOLE" is-test-vault "$PLAIN")" = "false" ] \
    || fail "the ordinary vault reports itself as a test vault"

echo "note: marker set, persisted in the KDBX, and reported"

# --- 2: UNMARKED ← MARKED → refused ------------------------------------
cp "$PLAIN" "$TMP/plain-before.kdbx"
if "$KEYHOLE" ingest-peer "$PLAIN" "$MARKED" >"$TMP/p2.out" 2>"$TMP/p2.err"; then
    cat "$TMP/p2.out"; cat "$TMP/p2.err"
    fail "an ordinary vault merged a marked replica — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/p2.err" \
    || { cat "$TMP/p2.err"; fail "the ingest failed, but not with the marker-mismatch refusal"; }
cmp -s "$TMP/plain-before.kdbx" "$PLAIN" || fail "the refused ingest rewrote the ordinary vault's file"
"$KEYHOLE" list "$PLAIN" >"$TMP/p2-list.out" || fail "the ordinary vault no longer opens"
grep -q "Marked Only" "$TMP/p2-list.out" && fail "the marked copy's entry leaked into the ordinary vault"

echo "note: an ordinary vault refuses a marked replica"

# --- 3: MARKED ← UNMARKED → refused ------------------------------------
cp "$MARKED" "$TMP/marked-before.kdbx"
"$KEYHOLE" create-entry "$PLAIN" "Plain Later" --username later >/dev/null || fail "edit the ordinary vault"
if "$KEYHOLE" ingest-peer "$MARKED" "$PLAIN" >"$TMP/p3.out" 2>"$TMP/p3.err"; then
    cat "$TMP/p3.out"; cat "$TMP/p3.err"
    fail "a test vault merged an ordinary replica — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/p3.err" \
    || { cat "$TMP/p3.err"; fail "the reverse ingest failed, but not with the marker-mismatch refusal"; }
cmp -s "$TMP/marked-before.kdbx" "$MARKED" || fail "the refused ingest rewrote the test vault's file"
"$KEYHOLE" list "$MARKED" >"$TMP/p3-list.out" || fail "the test vault no longer opens"
grep -q "Plain Later" "$TMP/p3-list.out" && fail "the ordinary vault's entry leaked into the test vault"

echo "note: a test vault refuses an ordinary replica"

# --- 4: DISK PATH → the open-time reconcile refuses the swap -----------
# sleep 1 so the swapped file's mtime is strictly newer than the mirror's
# recorded signature, and the next open reconciles.
"$KEYHOLE" list "$PLAIN" >/dev/null || fail "warm the ordinary vault's mirror"
cp "$PLAIN" "$TMP/plain-current.kdbx"
sleep 1; cp "$MARKED" "$PLAIN"
cp "$PLAIN" "$TMP/swapped.kdbx"
if "$KEYHOLE" list "$PLAIN" >"$TMP/p4.out" 2>"$TMP/p4.err"; then
    cat "$TMP/p4.out"; cat "$TMP/p4.err"
    fail "the open-time reconcile accepted a marked file over an ordinary mirror"
fi
grep -q "$REFUSAL" "$TMP/p4.err" \
    || { cat "$TMP/p4.err"; fail "the reconcile failed, but not with the marker-mismatch refusal"; }
cmp -s "$TMP/swapped.kdbx" "$PLAIN" || fail "the refused reconcile rewrote the file at the path"
echo "note: the disk reconcile refuses a marker change at the path"

# --- 5: SAVE PATH → a save over the marked copy is refused --------------
# KEYHOLE_SKIP_OPEN_SYNC opens over the mirror as it stands, modelling an
# engine already open when the file changed: the next thing to touch the
# file is a WRITE, which must be refused.
if KEYHOLE_SKIP_OPEN_SYNC=1 "$KEYHOLE" create-entry "$PLAIN" "Plain Save" --username save \
        >"$TMP/p5.out" 2>"$TMP/p5.err"; then
    cat "$TMP/p5.out"; cat "$TMP/p5.err"
    fail "an ordinary mirror saved over a marked file — it must be refused"
fi
grep -q "$REFUSAL" "$TMP/p5.err" \
    || { cat "$TMP/p5.err"; fail "the save failed, but not with the marker-mismatch refusal"; }
cmp -s "$TMP/swapped.kdbx" "$PLAIN" || fail "the refused save overwrote the marked file"
sleep 1; cp "$TMP/plain-current.kdbx" "$PLAIN"
"$KEYHOLE" list "$PLAIN" >"$TMP/p5-back.out" 2>"$TMP/p5-back.err" \
    || { cat "$TMP/p5-back.err"; fail "the ordinary vault no longer opens once its own file is back"; }
grep -q "Plain Save" "$TMP/p5-back.out" || fail "the edit owed by the refused save was lost"

echo "note: a save refuses to put an ordinary mirror over a marked file"

# --- 6: NO KIND CHANGE IN PLACE → marking a warm vault's file ------------
"$KEYHOLE" mark-test-vault "$PLAIN" >/dev/null || fail "mark the ordinary vault's file"
if "$KEYHOLE" list "$PLAIN" >"$TMP/p6.out" 2>"$TMP/p6.err"; then
    cat "$TMP/p6.out"; cat "$TMP/p6.err"
    fail "a warm ordinary mirror accepted its file turning into a test vault"
fi
grep -q "$REFUSAL" "$TMP/p6.err" \
    || { cat "$TMP/p6.err"; fail "the kind change failed, but not with the marker-mismatch refusal"; }
rm -rf "$PLAIN.mirror"
[ "$("$KEYHOLE" is-test-vault "$PLAIN")" = "true" ] \
    || fail "a mirror rebuilt from the marked file isn't a test vault"

echo "note: a mirror's kind never changes in place; a rebuilt mirror takes the file's"

# --- 7: CONTROL → both marked, the same ingest merges -------------------
"$KEYHOLE" ingest-peer "$MARKED" "$PLAIN" >"$TMP/p7.out" 2>"$TMP/p7.err" \
    || { cat "$TMP/p7.err"; fail "two test-vault replicas refused to merge"; }
rm -rf "$MARKED.mirror"
"$KEYHOLE" list "$MARKED" >"$TMP/p7-list.out" || fail "fresh re-ingest after the control merge"
grep -q "Plain Later" "$TMP/p7-list.out" || fail "the merged entry didn't persist to the test vault's file"
grep -q "Marked Only" "$TMP/p7-list.out" || fail "the test vault lost its own entry in the merge"
[ "$("$KEYHOLE" is-test-vault "$MARKED")" = "true" ] || fail "the merge dropped the marker"

echo "PASS: a test vault and an ordinary vault never merge or overwrite each other — peer blob, disk reconcile or save, either direction — a mirror's kind never changes in place, and two test vaults sync normally"
