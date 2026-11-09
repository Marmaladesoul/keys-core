#!/usr/bin/env bash
#
# The lossless history fold must keep each replica's version order within one
# second. classify finds the common ancestor by content across both sides'
# <History>, reading a later position as a later generation. KDBX times are
# whole seconds, so when a replica's edit, the merge that took it, and a later
# edit all share a second, the order of the history list is the only record of
# which came first. A fold that places a peer's older version AFTER a version
# that descends from it hands classify a stale ancestor: against it, a clean
# one-sided change reads as a both-sided clash and parks a conflict on one
# replica only, while the other auto-merges (the two then hold different
# content and different badges).
#
# Two shapes, one entry each, every write on a pinned clock (`--at`, ms):
#
#   alpha — the peer's version is in the peer's HISTORY. A and B each add an
#   attachment (s0, s1), sync (s1), then A replaces its attachment (s1) and B
#   adds another (s2). On the second sync B must take A's replacement.
#
#   beta — the peer's version is the peer's CURRENT. A adds an attachment
#   (s0), B adds one (s1), they sync (s1), then only A replaces its attachment
#   (s1). B must fast-forward to A's version, not park. With B's snapshot
#   misplaced, B's version and the merge tie as candidate ancestors and the
#   content hash breaks the tie, so the payloads are chosen to be the pair that
#   tied the wrong way before the fold kept the order.
#
# Both replicas must end with no held conflict and identical content.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

# Whole-second boundaries are what matter; S is the start of second 0.
S=1799999000000

sync_pair() { # $1 = epoch-ms of the first pull; the second is 1 ms later
    "$KEYHOLE" --at "$1" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" --at "$(($1 + 1))" ingest-peer "$B" "$A" --owner device-a >/dev/null
}
no_conflicts() { # $1 = vault, $2 = label
    "$KEYHOLE" list-conflicts "$1" | grep '(no held conflicts)' >/dev/null \
        || { echo "FAIL: $2 parked a conflict for one-sided attachment changes"; exit 1; }
}
att() { "$KEYHOLE" cat-attachment "$1" "$2" "$3"; }

"$KEYHOLE" --at "$S" create "$A" >/dev/null
"$KEYHOLE" --at "$((S + 100))" create-entry "$A" alpha --username u-alpha >/dev/null
"$KEYHOLE" --at "$((S + 200))" create-entry "$A" beta --username u-beta >/dev/null
alpha="$("$KEYHOLE" list "$A" | awk '$2=="alpha" {print $1}')"
beta="$("$KEYHOLE" list "$A" | awk '$2=="beta" {print $1}')"
cp "$A" "$B"

# Round 1: on both entries A writes in s0 and B in s1; they sync in s1.
"$KEYHOLE" --at "$((S + 300))" set-attachment "$A" "$alpha" a-att --text a-1 >/dev/null
"$KEYHOLE" --at "$((S + 400))" set-attachment "$A" "$beta" a-att --text a-1 >/dev/null
"$KEYHOLE" --at "$((S + 1100))" set-attachment "$B" "$alpha" b-att --text b-1 >/dev/null
"$KEYHOLE" --at "$((S + 1150))" set-attachment "$B" "$beta" b-att --text b-2 >/dev/null
sync_pair "$((S + 1200))"
no_conflicts "$A" "A (round 1)"
no_conflicts "$B" "B (round 1)"

# Round 2. A replaces its attachment on both entries in s1; B adds one to
# alpha in s2 and leaves beta alone.
"$KEYHOLE" --at "$((S + 1500))" set-attachment "$A" "$alpha" a-att --text a-2 >/dev/null
"$KEYHOLE" --at "$((S + 1600))" set-attachment "$A" "$beta" a-att --text a-2 >/dev/null
"$KEYHOLE" --at "$((S + 2100))" set-attachment "$B" "$alpha" b-att-2 --text b-2 >/dev/null
sync_pair "$((S + 2200))"
no_conflicts "$A" "A (round 2)"
no_conflicts "$B" "B (round 2)"

# Honest disk read: drop both mirrors and re-ingest from the KDBX files.
rm -rf "$A.mirror" "$B.mirror"
for v in "$A" "$B"; do
    for e in "$alpha" "$beta"; do
        [ "$(att "$v" "$e" a-att)" = a-2 ] \
            || { echo "FAIL: $(basename "$v") lost A's attachment replacement on $e"; exit 1; }
    done
    [ "$(att "$v" "$alpha" b-att-2)" = b-2 ] \
        || { echo "FAIL: $(basename "$v") lost B's added attachment on alpha"; exit 1; }
done
da="$("$KEYHOLE" digest "$A")"; db="$("$KEYHOLE" digest "$B")"
[ "$da" = "$db" ] || { echo "FAIL: digest divergence: A=$da B=$db"; exit 1; }

# One order, settled: the digest excludes history, and the fold reports a
# reorder as a change, so replicas that never agreed on a same-second order
# would rewrite a file on every pass. A pair's first puller can be a step
# behind the second, so allow one catch-up pass; after it, a pass must write
# nothing.
sync_pair "$((S + 3200))"
before="$(cksum "$A" "$B")"
sync_pair "$((S + 4200))"
[ "$(cksum "$A" "$B")" = "$before" ] \
    || { echo "FAIL: a sync pass after catch-up rewrote a vault (history orders not settled)"; exit 1; }

echo "PASS: same-second history keeps each replica's version order, so one-sided attachment changes merge on both replicas"
