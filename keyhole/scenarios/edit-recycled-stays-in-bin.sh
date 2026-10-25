#!/usr/bin/env bash
#
# Scenario: "editing a recycled entry applies the edit IN PLACE, in the
# bin" — mutation and relocation are orthogonal. Recycle an entry that
# lives in a subfolder, then edit it through every content verb (title,
# custom field, tags, attachment add). After each edit, re-read the KDBX
# from a FRESH process (mirror nuked — the only honest "what is on disk")
# and assert the entry is still in the bin, still counted as recycled,
# NOT back in its original group, and that the edit itself landed. A
# second leg runs every edit on the WARM mirror `recycle` left behind
# (no nuke in between), then checks once from disk.
#
# In KDBX the bin is an ordinary group, so an in-place edit inside it is
# format-legal; nothing about an edit implies a restore. Only the explicit
# `restore` verb relocates — the closing teeth check proves the placement
# predicate can fail, and that `restore` still honours the recorded
# PreviousParentGroup after the in-bin edits.
#
# Teeth were also proven by mutation: appending this statement just before
# the commit in keys-engine `mutations::update_entry` (relocate-on-edit)
# turns the scenario red at the first `update-entry` step:
#   UPDATE entry SET is_recycled = 0, previous_parent_uuid = group_uuid,
#     group_uuid = COALESCE(previous_parent_uuid, group_uuid)
#   WHERE uuid = ?1 AND is_recycled = 1
#
# Membership reads capture keyhole's output before grepping: under
# `pipefail`, an early-exiting `grep -q` would SIGPIPE keyhole and turn a
# match into a false negative.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/edit-recycled.kdbx"

fail() { echo "FAIL: $*"; exit 1; }

# --- seed: two entries living in a subfolder -------------------------
"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-group "$VAULT" "Home" >/dev/null
home="$("$KEYHOLE" list-groups "$VAULT" | awk '/Home/ {print $1; exit}')"
[ -n "$home" ] || fail "could not find seeded group"
"$KEYHOLE" create-entry "$VAULT" "Cold" --username u --group "$home" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Warm" --username u --group "$home" >/dev/null
cold="$("$KEYHOLE" list "$VAULT" | awk '/Cold/ {print $1; exit}')"
warm="$("$KEYHOLE" list "$VAULT" | awk '/Warm/ {print $1; exit}')"
[ -n "$cold" ] && [ -n "$warm" ] || fail "could not find seeded entries"

# All reads below come from a fresh ingest of the KDBX.
cold_read() { rm -rf "$VAULT.mirror"; "$KEYHOLE" "$@"; }

# Is entry $1 anywhere in group $2's subtree, as written to disk?
in_subtree() {
    local out
    out="$(cold_read entries-in-subtree "$VAULT" "$2")"
    grep -qx "$1" <<<"$out"
}

recycled_count() { cold_read inspect "$VAULT" | awk '/^recycled:/ {print $2}'; }

# $1 = entry uuid, $2 = step label, $3 = expected bin population.
assert_in_bin() {
    in_subtree "$1" "$bin" || fail "after $2: entry left the recycle bin (silent restore)"
    if in_subtree "$1" "$home"; then fail "after $2: entry is back in its original group (silent restore)"; fi
    [ "$(recycled_count)" = "$3" ] || fail "after $2: recycled count is $(recycled_count), want $3 (flag cleared?)"
}

# --- cold leg: each verb, asserted in place across a fresh reopen ----
"$KEYHOLE" recycle "$VAULT" "$cold" >/dev/null
bin="$("$KEYHOLE" list-groups "$VAULT" | awk '/Recycle Bin/ {print $1; exit}')"
[ -n "$bin" ] || fail "recycle did not produce a bin group"
assert_in_bin "$cold" "recycle" 1

"$KEYHOLE" update-entry "$VAULT" "$cold" --title "Cold-edited" >/dev/null
assert_in_bin "$cold" "update-entry" 1
listing="$(cold_read list "$VAULT" --group "$bin")"
grep -q "Cold-edited" <<<"$listing" || fail "update-entry did not land on the binned entry"

"$KEYHOLE" set-field "$VAULT" "$cold" "Probe" "in-bin" >/dev/null
assert_in_bin "$cold" "set-field" 1
probe="$(printf '%s\n' "$PW" | keepassxc-cli show -q -a Probe "$VAULT" "Recycle Bin/Cold-edited")"
[ "$probe" = "in-bin" ] || fail "set-field did not land on the binned entry (got '$probe')"

"$KEYHOLE" set-tags "$VAULT" "$cold" "binned-tag" >/dev/null
assert_in_bin "$cold" "set-tags" 1
[ "$(cold_read tags "$VAULT" "$cold")" = "binned-tag" ] \
    || fail "set-tags did not land on the binned entry"

"$KEYHOLE" set-attachment "$VAULT" "$cold" probe.txt --text "attached-in-bin" >/dev/null
assert_in_bin "$cold" "set-attachment" 1
[ "$(cold_read cat-attachment "$VAULT" "$cold" probe.txt)" = "attached-in-bin" ] \
    || fail "set-attachment did not land on the binned entry"

# --- warm leg: every verb on the mirror recycle left, no nukes -------
"$KEYHOLE" recycle "$VAULT" "$warm" >/dev/null
"$KEYHOLE" update-entry "$VAULT" "$warm" --title "Warm-edited" >/dev/null
"$KEYHOLE" set-field "$VAULT" "$warm" "Probe" "warm" >/dev/null
"$KEYHOLE" set-tags "$VAULT" "$warm" "warm-tag" >/dev/null
"$KEYHOLE" set-attachment "$VAULT" "$warm" warm.txt --text "warm-attach" >/dev/null
assert_in_bin "$warm" "warm-mirror edits" 2
assert_in_bin "$cold" "warm-mirror edits" 2

# --- teeth: the explicit verb DOES relocate, to the recorded origin --
"$KEYHOLE" restore "$VAULT" "$cold" >/dev/null
in_subtree "$cold" "$home" || fail "restore after in-bin edits did not return the entry to its original group"
if in_subtree "$cold" "$bin"; then fail "restore after in-bin edits left the entry in the bin"; fi
[ "$(recycled_count)" = "1" ] || fail "restore did not clear the recycled flag"

echo "PASS: edits to a recycled entry (title, field, tags, attachment — cold and warm mirror) apply in place in the bin across a fresh reopen; only restore relocates"
