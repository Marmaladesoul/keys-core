#!/usr/bin/env bash
#
# Scenario: `search` with an explicit recycle-bin filter — bin inclusion
# is the CALLER's choice on the seam, never an implicit policy. A search
# box over live entries passes `exclude`; a "Deleted items" view
# searching *inside* the bin passes `only`; `include` disables the
# filter entirely.
#
# What's proven:
#
#   1. A recycled entry drops out of `--bin exclude` results, appears in
#      `--bin only` results, and `--bin include` spans both — the same
#      query, three caller choices, three result sets.
#   2. The exclusion survives a close+reopen from disk (mirror nuked →
#      fresh ingest — the only honest "did it hit the KDBX?").
#   3. An entry BURIED in a group that is then moved under the bin also
#      filters correctly — the discriminating case, asserted against the
#      WARM live mirror. A group recycle re-parents the group but leaves
#      its descendant entries' `is_recycled` flag at 0 until the next
#      ingest re-derives it from ancestry; a flag-based filter would
#      leak the buried entry into live results (and hide it from
#      bin-only results) in exactly the in-session state a client
#      searches right after the mutation. The filter decides by
#      bin-subtree MEMBERSHIP. (Regress it to the flag and this step
#      goes red — a cold re-ingested read would NOT catch it, since
#      ingest normalises the flag.)
#   4. With the bin DISABLED there is no live/binned distinction:
#      `exclude` and `include` match every entry, `only` matches none.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# --- seed: an enabled-bin vault with three matching root entries ------
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g "$VAULT" "Alpha-login"   >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g "$VAULT" "Bravo-login"   >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g "$VAULT" "Charlie-login" >/dev/null

# Warm search: the live mirror a client reads in-session (where a group
# move hasn't been re-ingested yet — step 3's teeth live here). Cold
# search: nuke the mirror first, forcing a fresh ingest from the KDBX.
hits_warm() {                         "$KEYHOLE" search "$VAULT" "$1" --bin "$2" | { grep -c -- "-login" || true; } }
hits_cold() { rm -rf "$VAULT.mirror"; "$KEYHOLE" search "$VAULT" "$1" --bin "$2" | { grep -c -- "-login" || true; } }
# Full-read grep (never grep -q — an early-closed pipe SIGPIPEs keyhole
# and pipefail misreads it; see DESIGN.md).
has_warm() { "$KEYHOLE" search "$VAULT" "$1" --bin "$2" | grep -- "$3" >/dev/null; }

[ "$(hits_cold login exclude)" = "3" ] || { echo "FAIL: fresh vault exclude hits $(hits_warm login exclude), want 3"; exit 1; }

# --- 1) recycle Bravo: one query, three caller choices ----------------
bravo="$("$KEYHOLE" list "$VAULT" | awk '/Bravo/ {print $1; exit}')"
[ -n "$bravo" ] || { echo "FAIL: could not find Bravo-login"; exit 1; }
"$KEYHOLE" recycle "$VAULT" "$bravo" >/dev/null

[ "$(hits_warm login exclude)" = "2" ] || { echo "FAIL: exclude after recycle: $(hits_warm login exclude), want 2"; exit 1; }
! has_warm login exclude "Bravo"      || { echo "FAIL: recycled Bravo leaked into exclude results"; exit 1; }
[ "$(hits_warm login only)" = "1" ]   || { echo "FAIL: bin-only after recycle: $(hits_warm login only), want 1"; exit 1; }
has_warm login only "Bravo"           || { echo "FAIL: bin-only search did not find recycled Bravo"; exit 1; }
[ "$(hits_warm login include)" = "3" ] || { echo "FAIL: include after recycle: $(hits_warm login include), want 3"; exit 1; }

# --- 2) the exclusion survives a fresh ingest from disk ---------------
[ "$(hits_cold login exclude)" = "2" ] || { echo "FAIL: exclude lost across reopen: $(hits_warm login exclude), want 2"; exit 1; }

# --- 3) the discriminating case: an entry buried under a recycled group ---
"$KEYHOLE" create-group "$VAULT" "Doomed" >/dev/null
doomed="$("$KEYHOLE" list-groups "$VAULT" | awk '/Doomed/ {print $1; exit}')"
bin="$(   "$KEYHOLE" list-groups "$VAULT" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$doomed" ] || { echo "FAIL: could not find Doomed group"; exit 1; }
[ -n "$bin" ]    || { echo "FAIL: could not find bin group"; exit 1; }

"$KEYHOLE" create-entry "$VAULT" "Buried-login" --group "$doomed" >/dev/null
[ "$(hits_warm login exclude)" = "3" ] || { echo "FAIL: buried-in-live-group entry should match exclude: $(hits_warm login exclude), want 3"; exit 1; }

"$KEYHOLE" move-group "$VAULT" "$doomed" --to "$bin" >/dev/null
# WARM: Buried-login still carries is_recycled = 0 — only its ancestry
# says "binned". Membership must decide.
[ "$(hits_warm login exclude)" = "2" ] || { echo "FAIL: buried entry not excluded warm — $(hits_warm login exclude), want 2 (flag-filter regression?)"; exit 1; }
! has_warm login exclude "Buried"      || { echo "FAIL: buried-under-bin entry leaked into exclude results warm"; exit 1; }
[ "$(hits_warm login only)" = "2" ]    || { echo "FAIL: bin-only should see Bravo + Buried warm: $(hits_warm login only), want 2"; exit 1; }
has_warm login only "Buried"           || { echo "FAIL: bin-only search did not find buried entry warm"; exit 1; }

# --- 4) bin disabled: no live/binned distinction ----------------------
"$KEYHOLE" set-bin "$VAULT" off >/dev/null
[ "$(hits_warm login exclude)" = "4" ] || { echo "FAIL: bin-off exclude: $(hits_warm login exclude), want 4 (everything is live)"; exit 1; }
[ "$(hits_warm login include)" = "4" ] || { echo "FAIL: bin-off include: $(hits_warm login include), want 4"; exit 1; }
[ "$(hits_warm login only)" = "0" ]    || { echo "FAIL: bin-off bin-only: $(hits_warm login only), want 0"; exit 1; }

echo "PASS: search bin filter is an explicit caller choice (exclude/only/include), excludes by subtree membership (direct + buried-in-recycled-group, warm), survives reopen, and degrades correctly with the bin disabled"
