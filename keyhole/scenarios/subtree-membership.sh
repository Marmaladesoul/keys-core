#!/usr/bin/env bash
#
# Scenario: subtree membership (`groups_in_subtree` / `entries_in_subtree`)
# is derived from live group ancestry, so it is correct the instant a
# group is re-parented — it never waits on the per-entry `is_recycled`
# flag, which lags a warm group recycle.
#
# What's proven:
#
#   1. Both queries are ROOT-INCLUSIVE: the bin root itself appears in
#      its own group subtree.
#   2. A warm group recycle (move a group, with a nested subgroup and
#      buried entries, under the bin) is reflected IMMEDIATELY: the whole
#      moved subtree — parent group, nested subgroup, and every buried
#      entry — reports as members in the warm mirror, before any
#      close/reopen re-derives the `is_recycled` flag. This is the exact
#      case the flag lags, and where a walker that seeds an un-lowercased
#      root (or filters on the flag) silently misses the nested subgroup.
#   3. The same membership holds across `rm -rf "$VAULT.mirror"` — a
#      fresh ingest that re-derives the flag from ancestry. Warm and cold
#      agree, because neither answer is computed from the flag.
#   4. A non-existent root is a NotFound error (non-zero exit), not an
#      empty set — the ownership-probe contract a multi-vault caller
#      relies on.
#
# One ancestry-derived subtree primitive, proven at the seam, is what the
# client walkers collapse onto.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

cold() { rm -rf "$VAULT.mirror"; }

# Trailing "N group(s) in subtree" / "N entry(ies) in subtree" count.
gcount() { "$KEYHOLE" groups-in-subtree "$VAULT" "$1" | sed -n 's/^\([0-9][0-9]*\) group(s) in subtree/\1/p'; }
ecount() { "$KEYHOLE" entries-in-subtree "$VAULT" "$1" | sed -n 's/^\([0-9][0-9]*\) entry(ies) in subtree/\1/p'; }
# Is $2 (a uuid) present in the subtree listing of root $1? Capture the
# full listing before grepping — piping straight into `grep -q` lets grep
# close the pipe on first match, killing keyhole with SIGPIPE, which
# `set -o pipefail` would then read as a scenario failure.
groups_have() { local out; out="$("$KEYHOLE" groups-in-subtree "$VAULT" "$1")"; grep -qiF -- "$2" <<<"$out"; }
entries_have() { local out; out="$("$KEYHOLE" entries-in-subtree "$VAULT" "$1")"; grep -qiF -- "$2" <<<"$out"; }

# --- seed: a root entry, bin materialised by a direct recycle ----------
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username a "$VAULT" "Bravo" >/dev/null

bravo="$("$KEYHOLE" list "$VAULT" | awk '/Bravo/ {print $1; exit}')"
[ -n "$bravo" ] || { echo "FAIL: could not find Bravo"; exit 1; }
"$KEYHOLE" recycle "$VAULT" "$bravo" >/dev/null   # lazily creates the bin

bin="$("$KEYHOLE" list-groups "$VAULT" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$bin" ] || { echo "FAIL: could not find bin group"; exit 1; }

# --- build a nested subtree OUTSIDE the bin: Attic > Cellar ------------
"$KEYHOLE" create-group "$VAULT" "Attic" >/dev/null
attic="$("$KEYHOLE" list-groups "$VAULT" | awk '/Attic/ {print $1; exit}')"
[ -n "$attic" ] || { echo "FAIL: could not find Attic group"; exit 1; }
"$KEYHOLE" create-group "$VAULT" "Cellar" --parent "$attic" >/dev/null
cellar="$("$KEYHOLE" list-groups "$VAULT" | awk '/Cellar/ {print $1; exit}')"
[ -n "$cellar" ] || { echo "FAIL: could not find Cellar group"; exit 1; }

"$KEYHOLE" create-entry "$VAULT" "BuriedAttic" --group "$attic" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "BuriedCellar" --group "$cellar" >/dev/null
buried_attic="$("$KEYHOLE" list "$VAULT" | awk '/BuriedAttic/ {print $1; exit}')"
buried_cellar="$("$KEYHOLE" list "$VAULT" | awk '/BuriedCellar/ {print $1; exit}')"
[ -n "$buried_attic" ] && [ -n "$buried_cellar" ] || { echo "FAIL: could not find buried entries"; exit 1; }

# --- (1) root-inclusive, and the bin holds only its direct recycle ----
groups_have "$bin" "$bin" || { echo "FAIL: bin subtree does not include the bin root itself (not inclusive)"; exit 1; }
n="$(gcount "$bin")"; [ "$n" = "1" ] || { echo "FAIL: pre-move bin group-subtree is $n, want 1 (bin only)"; exit 1; }
n="$(ecount "$bin")"; [ "$n" = "1" ] || { echo "FAIL: pre-move bin entry-subtree is $n, want 1 (Bravo only)"; exit 1; }

# --- (2) warm group recycle: move Attic (with Cellar + buried) into bin
"$KEYHOLE" move-group "$VAULT" "$attic" --to "$bin" >/dev/null

# Warm mirror — the buried entries' `is_recycled` flag still lags here.
n="$(gcount "$bin")"; [ "$n" = "3" ] || { echo "FAIL: warm bin group-subtree is $n, want 3 (bin, Attic, Cellar)"; exit 1; }
n="$(ecount "$bin")"; [ "$n" = "3" ] || { echo "FAIL: warm bin entry-subtree is $n, want 3 (Bravo, BuriedAttic, BuriedCellar)"; exit 1; }
# The nested subgroup + its buried entry are the teeth — a walker that
# never recurses past the root (casing seed bug) misses exactly these.
groups_have "$bin" "$cellar"        || { echo "FAIL: warm bin group-subtree omits the nested Cellar group"; exit 1; }
entries_have "$bin" "$buried_cellar" || { echo "FAIL: warm bin entry-subtree omits the entry buried in Cellar"; exit 1; }

# --- (3) cold reopen: fresh ingest, flag re-derived; membership holds --
cold
n="$(gcount "$bin")"; [ "$n" = "3" ] || { echo "FAIL: cold bin group-subtree is $n, want 3"; exit 1; }
n="$(ecount "$bin")"; [ "$n" = "3" ] || { echo "FAIL: cold bin entry-subtree is $n, want 3"; exit 1; }
groups_have "$bin" "$cellar"        || { echo "FAIL: cold bin group-subtree omits the nested Cellar group"; exit 1; }
entries_have "$bin" "$buried_cellar" || { echo "FAIL: cold bin entry-subtree omits the entry buried in Cellar"; exit 1; }

# --- (4) NotFound root is an error, not an empty set ------------------
bogus="00000000-0000-0000-0000-000000000000"
if "$KEYHOLE" groups-in-subtree "$VAULT" "$bogus" >/dev/null 2>&1; then
    echo "FAIL: groups-in-subtree on a non-existent root should error, not return empty"; exit 1
fi

echo "PASS: subtree membership is ancestry-derived — inclusive of the root, correct warm (before the is_recycled flag catches up) and cold, and a missing root is NotFound not an empty set"
