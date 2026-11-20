#!/usr/bin/env bash
#
# An OLDER copy of the vault file put back underneath a warm mirror (a sync
# tool or file-hosting client restoring a previous version, a backup restore)
# must not undo what the mirror holds beyond it. The open-time reconcile merges
# the old file in, and wherever the mirror is AHEAD of that file it must write
# the merged state back, so the KDBX (what other apps, other devices and the
# next rebuild read) holds it again.
#
# The write-back decision has to ask "does the file lack what the mirror
# holds?", not "did this pass change the mirror?": merging an ancestor changes
# nothing locally, so a pass that only rewrites the file when local advanced
# leaves the old copy in place, and a recycle or permanent delete made since
# that copy silently comes back on the next fresh read.
#
# Shapes (each its own throwaway vault): an edit, a recycle, a permanent
# delete, an entry move. Each: snapshot the file, mutate (saved), put the
# snapshot back with a new mtime, open (reconcile), then `rm -rf` the mirror and
# compare a fresh read against the pre-put-back digest.
#
# Control: with the mutation reverted in the put-back copy's favour — nothing
# local beyond the file — the open must NOT rewrite the file.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL($1): $2"; exit 1; }

# Seed $1 with entries E and F and a group G; echo "E F G" uuids.
seed() {
    "$KEYHOLE" create "$1" >/dev/null
    "$KEYHOLE" --at 1000000 create-entry "$1" E --username e0 >/dev/null
    "$KEYHOLE" --at 1100000 create-entry "$1" F --username f0 >/dev/null
    "$KEYHOLE" create-group "$1" G >/dev/null
    local e f g
    e="$("$KEYHOLE" list "$1" | awk '$2=="E" {print $1; exit}')"
    f="$("$KEYHOLE" list "$1" | awk '$2=="F" {print $1; exit}')"
    g="$("$KEYHOLE" list-groups "$1" | awk '$2=="G" {print $1; exit}')"
    echo "$e $f $g"
}

# $1 label; remaining args: a mutation command with V, E, F, G in its env.
putback() {
    local label="$1"; shift
    local V="$TMP/$label.kdbx" e f g
    read -r e f g < <(seed "$V")
    cp -p "$V" "$TMP/$label.old"
    V="$V" E="$e" F="$f" G="$g" "$@" >/dev/null
    local want; want="$("$KEYHOLE" digest "$V")"
    cp "$TMP/$label.old" "$V"
    touch -t 203001010000 "$V"   # an older copy, put back with a new mtime
    "$KEYHOLE" inspect "$V" >/dev/null 2>&1
    rm -rf "$V.mirror"           # honest disk read
    [ "$("$KEYHOLE" digest "$V")" = "$want" ] \
        || fail "$label" "the put-back older file was not rewritten: a fresh read lost the local $label"
    echo "  ok($label): the file holds the mirror's state again after the open"
}

putback edit    sh -c '"$0" --at 2000000 update-entry "$V" "$E" --username e1' "$KEYHOLE"
putback recycle sh -c '"$0" --at 2000000 recycle "$V" "$F"' "$KEYHOLE"
putback delete  sh -c '"$0" --at 2000000 delete-entry "$V" "$F"' "$KEYHOLE"
putback move    sh -c '"$0" --at 2000000 move-entry "$V" "$E" --to "$G"' "$KEYHOLE"

# Control: the put-back copy is the SAME content the mirror holds → no rewrite.
V="$TMP/control.kdbx"
seed "$V" >/dev/null
cp -p "$V" "$TMP/control.copy"
cp "$TMP/control.copy" "$V"
touch -t 203001010000 "$V"
before="$(md5 -q "$V" 2>/dev/null || md5sum "$V" | cut -d' ' -f1)"
"$KEYHOLE" inspect "$V" >/dev/null 2>&1
after="$(md5 -q "$V" 2>/dev/null || md5sum "$V" | cut -d' ' -f1)"
[ "$before" = "$after" ] || fail "control" "an identical copy put back was rewritten (nothing local was beyond it)"
echo "  ok(control): an identical copy put back is left alone"

echo "PASS: an older vault file put back under a warm mirror is rewritten with the mirror's state (edit, recycle, delete, move); an identical one is not"
