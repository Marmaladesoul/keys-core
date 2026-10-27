#!/usr/bin/env bash
#
# When peer ingest adopts the peer's newer version of an entry, the receiver's
# live entry must carry that version's `LastModificationTime`, not keep its own
# older one. keepass-merge's auto-merge result inherits local's timestamps by
# contract; the engine owns advancing them. Left alone, the receiver's file
# shows current content stamped with the time of an older version — older than
# its own history snapshots — and a time-based merge (other KeePass clients
# pick the newer `LastModificationTime`) can then prefer a stale copy.
#
# Three shapes, each in its own throwaway pair:
#   one     A edits after the fork; B adopts. Both must end on A's time.
#   both    A and B edit DIFFERENT fields; each auto-merges the other's edit.
#           The merged version is new, so it must be strictly newer than both
#           edits (one second past the later), and both replicas must land on
#           the same time, so the pair settles instead of each side stamping
#           its own merge.
#   behind  only B edits; B pulls A, which is behind. B keeps its own time.
#
# Read after `rm -rf "$VAULT.mirror"` (the mirror persists state across
# processes like a real client's local store, so only a fresh re-ingest from
# the KDBX is honest). The content digest excludes timestamps, so compare
# `times` directly.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL($1): $2"; exit 1; }
# Live modified_at (ms) of entry $2 in vault $1, after an honest disk read.
mtime() { rm -rf "$1.mirror"; "$KEYHOLE" times "$1" "$2" | sed -n 's/^modified_at=//p'; }
# Two-way sync at clock $3: $2 pulls $1, then $1 pulls $2.
sync_pair() {
    "$KEYHOLE" --at "$3" ingest-peer "$2" "$1" --owner a >/dev/null
    "$KEYHOLE" --at "$(($3 + 100))" ingest-peer "$1" "$2" --owner b >/dev/null
}

# ── one: B adopts A's post-fork edits ──
A="$TMP/one-a.kdbx" B="$TMP/one-b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
cp "$A" "$B"
"$KEYHOLE" --at 1000000 create-entry "$A" "J" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/J/ {print $1; exit}')"
sync_pair "$A" "$B" 1500000
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --title J2 >/dev/null
sync_pair "$A" "$B" 2500000
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --title J3 >/dev/null
sync_pair "$A" "$B" 3500000
[ "$(mtime "$A" "$uuid")" = "3000000" ] || fail one "A's own edit time is $(mtime "$A" "$uuid"), expected 3000000"
[ "$(mtime "$B" "$uuid")" = "3000000" ] || fail one "B adopted J3 but reads modified at $(mtime "$B" "$uuid"), expected A's 3000000"

# ── both: non-overlapping edits on each side converge on the later time ──
A="$TMP/both-a.kdbx" B="$TMP/both-b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "K" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/K/ {print $1; exit}')"
cp "$A" "$B"
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username u1 >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$B" "$uuid" --notes "from b" >/dev/null
sync_pair "$A" "$B" 4000000
sync_pair "$A" "$B" 5000000
[ "$(mtime "$A" "$uuid")" = "3001000" ] || fail both "A reads $(mtime "$A" "$uuid"), expected one second past the later edit, 3001000"
[ "$(mtime "$B" "$uuid")" = "3001000" ] || fail both "B reads $(mtime "$B" "$uuid"), expected one second past the later edit, 3001000"

# ── behind: pulling a peer that is behind leaves local's time alone ──
A="$TMP/behind-a.kdbx" B="$TMP/behind-b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "L" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/L/ {print $1; exit}')"
cp "$A" "$B"
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username u1 >/dev/null
"$KEYHOLE" --at 3000000 ingest-peer "$B" "$A" --owner a >/dev/null
[ "$(mtime "$B" "$uuid")" = "2000000" ] || fail behind "B reads $(mtime "$B" "$uuid"), expected its own 2000000"

echo "PASS adopted-edit-advances-mtime"
