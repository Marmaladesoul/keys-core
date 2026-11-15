#!/usr/bin/env bash
#
# Replicas of one vault that each create its recycle bin must create the SAME
# group, so a merge holds one bin, not two. A vault handed over
# enabled-but-binless (keepassxc-cli makes them) gets its bin per replica —
# `ensure-bin` when a vault is added, or the lazy create on first recycle — and
# with a fresh random uuid per mint, two copies made two groups called
# "Recycle Bin": the meta merge settled on one as the bin and the other stayed
# behind as an ordinary folder on both peers.
#
# The bin's uuid is therefore the first of a sequence of uuids derived from the
# vault's root-group uuid (the vault's identity) that no group holds and no
# tombstone names, so replicas in the same state mint the same group. Cases:
#
#   1. both replicas run ensure-bin at different instants;
#   2. one runs ensure-bin, the other mints lazily by recycling first;
#   3. bin disabled then re-enabled on both replicas: the kept group stays an
#      ordinary group (never silently made the bin again — it may hold live
#      entries by then), and both mint the same NEW bin beside it;
#   4. the bin is deleted, the deletion reaches the peer, then a recycle mints
#      a bin again: a fresh uuid (a deleted bin's uuid is never reused), and
#      the peer keeps it;
#   5. the bin is deleted and an empty one minted before the deletion syncs:
#      the merge drops the old bin and keeps the new one on both;
#   6. the bin is deleted, the deletion syncs, then BOTH replicas mint an
#      empty bin: same uuid on both, and the next merge keeps it (reusing the
#      deleted uuid would put the bin under its own tombstone, which deletes
#      an empty group on every replica that holds the tombstone).
#
# Every assertion reads the files fresh (mirrors removed). Seeded via
# keepassxc-cli on purpose (independent implementation = honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fresh()     { rm -rf "$1.mirror"; }
field()     { fresh "$1"; "$KEYHOLE" inspect "$1" | awk -F': *' -v k="$2" '$1 == k {print $2}'; }
bin_count() { fresh "$1"; "$KEYHOLE" list-groups "$1" | grep -c '  Recycle Bin  ' || true; }
digest()    { fresh "$1"; "$KEYHOLE" digest "$1"; }
entry_id()  { fresh "$1"; "$KEYHOLE" list "$1" | awk -v t="$2" '$2 == t {print $1}'; }
exchange()  { # <A> <B>
    "$KEYHOLE" ingest-peer "$1" "$2" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$2" "$1" --owner device-a >/dev/null
}
fail() { echo "FAIL($1): $2"; exit 1; }

seed() { # <dir> — a binless vault with one entry, copied to a.kdbx + b.kdbx
    mkdir -p "$1"
    printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$1/v.kdbx" >/dev/null 2>&1
    printf '%s\n' "$PW" | keepassxc-cli add -q "$1/v.kdbx" e1
    [ "$(field "$1/v.kdbx" 'bin group')" = absent ] || fail setup "expected no bin group"
    cp "$1/v.kdbx" "$1/a.kdbx"; cp "$1/v.kdbx" "$1/b.kdbx"
}

one_bin_each() { # <case> <A> <B>
    [ "$(bin_count "$2")" = 1 ] || fail "$1" "A holds $(bin_count "$2") Recycle Bin groups"
    [ "$(bin_count "$3")" = 1 ] || fail "$1" "B holds $(bin_count "$3") Recycle Bin groups"
    [ "$(field "$2" 'bin uuid')" = "$(field "$3" 'bin uuid')" ] \
        || fail "$1" "peers designate different bins"
    [ "$(digest "$2")" = "$(digest "$3")" ] || fail "$1" "digests diverge"
}

T=$(( ($(date +%s) + 3600) * 1000 ))

# --- 1. both replicas ensure-bin, at different instants ----------------------
seed "$TMP/1"
"$KEYHOLE" --at "$T"              ensure-bin "$TMP/1/a.kdbx" >/dev/null
"$KEYHOLE" --at "$(( T + 1000 ))" ensure-bin "$TMP/1/b.kdbx" >/dev/null
[ "$(field "$TMP/1/a.kdbx" 'bin uuid')" = "$(field "$TMP/1/b.kdbx" 'bin uuid')" ] \
    || fail ensure "replicas minted different bin uuids before any exchange"
exchange "$TMP/1/a.kdbx" "$TMP/1/b.kdbx"
one_bin_each ensure "$TMP/1/a.kdbx" "$TMP/1/b.kdbx"

# --- 2. one ensure-bin, the other mints lazily on its first recycle ----------
seed "$TMP/2"
"$KEYHOLE" --at "$T" ensure-bin "$TMP/2/a.kdbx" >/dev/null
"$KEYHOLE" --at "$(( T + 1000 ))" recycle "$TMP/2/b.kdbx" "$(entry_id "$TMP/2/b.kdbx" e1)" >/dev/null
[ "$(field "$TMP/2/a.kdbx" 'bin uuid')" = "$(field "$TMP/2/b.kdbx" 'bin uuid')" ] \
    || fail lazy "ensure-bin and the lazy mint made different bin uuids"
exchange "$TMP/2/a.kdbx" "$TMP/2/b.kdbx"
one_bin_each lazy "$TMP/2/a.kdbx" "$TMP/2/b.kdbx"
[ "$(field "$TMP/2/a.kdbx" recycled)" = 1 ] || fail lazy "B's recycle didn't reach A's bin"

# --- 3. disable, then re-enable, on both replicas ---------------------------
seed "$TMP/3"
"$KEYHOLE" --at "$T" ensure-bin "$TMP/3/a.kdbx" >/dev/null
exchange "$TMP/3/a.kdbx" "$TMP/3/b.kdbx"
kept="$(field "$TMP/3/a.kdbx" 'bin uuid')"
for v in a b; do
    "$KEYHOLE" --at "$(( T + 1000 ))" set-bin "$TMP/3/$v.kdbx" off >/dev/null
    "$KEYHOLE" --at "$(( T + 2000 ))" set-bin "$TMP/3/$v.kdbx" on >/dev/null
done
new3="$(field "$TMP/3/a.kdbx" 'bin uuid')"
[ "$new3" != "$kept" ] || fail re-enable "re-enabling made the kept group the bin again"
[ "$(field "$TMP/3/b.kdbx" 'bin uuid')" = "$new3" ] || fail re-enable "replicas minted different new bins"
exchange "$TMP/3/a.kdbx" "$TMP/3/b.kdbx"
for v in a b; do
    [ "$(field "$TMP/3/$v.kdbx" 'bin uuid')" = "$new3" ] || fail re-enable "$v lost the new bin"
    [ "$(bin_count "$TMP/3/$v.kdbx")" = 2 ] \
        || fail re-enable "$v holds $(bin_count "$TMP/3/$v.kdbx") Recycle Bin groups (want the kept one + the bin)"
done
[ "$(digest "$TMP/3/a.kdbx")" = "$(digest "$TMP/3/b.kdbx")" ] || fail re-enable "digests diverge"

# --- 4. bin deleted (deletion synced), then minted again by a recycle --------
seed "$TMP/4"
"$KEYHOLE" --at "$T" ensure-bin "$TMP/4/a.kdbx" >/dev/null
exchange "$TMP/4/a.kdbx" "$TMP/4/b.kdbx"
bin4="$(field "$TMP/4/a.kdbx" 'bin uuid')"
"$KEYHOLE" --at "$(( T + 1000 ))" delete-group "$TMP/4/a.kdbx" "$bin4" >/dev/null
exchange "$TMP/4/a.kdbx" "$TMP/4/b.kdbx"
[ "$(field "$TMP/4/b.kdbx" 'bin group')" = absent ] || fail remint "B kept the bin A deleted"
"$KEYHOLE" --at "$(( T + 2000 ))" recycle "$TMP/4/a.kdbx" "$(entry_id "$TMP/4/a.kdbx" e1)" >/dev/null
[ "$(field "$TMP/4/a.kdbx" 'bin uuid')" != "$bin4" ] || fail remint "the deleted bin's uuid was reused"
exchange "$TMP/4/a.kdbx" "$TMP/4/b.kdbx"
one_bin_each remint "$TMP/4/a.kdbx" "$TMP/4/b.kdbx"
[ "$(field "$TMP/4/b.kdbx" recycled)" = 1 ] || fail remint "the recycled entry didn't survive on B"

# --- 5. bin deleted, an empty one minted, before the deletion syncs ----------
seed "$TMP/5"
"$KEYHOLE" --at "$T" ensure-bin "$TMP/5/a.kdbx" >/dev/null
exchange "$TMP/5/a.kdbx" "$TMP/5/b.kdbx"
bin5="$(field "$TMP/5/a.kdbx" 'bin uuid')"
"$KEYHOLE" --at "$(( T + 1000 ))" delete-group "$TMP/5/a.kdbx" "$bin5" >/dev/null
"$KEYHOLE" --at "$(( T + 2000 ))" ensure-bin "$TMP/5/a.kdbx" >/dev/null
exchange "$TMP/5/a.kdbx" "$TMP/5/b.kdbx"
one_bin_each unsynced-delete "$TMP/5/a.kdbx" "$TMP/5/b.kdbx"
[ "$(field "$TMP/5/b.kdbx" 'bin uuid')" != "$bin5" ] || fail unsynced-delete "B kept the deleted bin"

# --- 6. bin deleted, deletion synced, then both mint an empty bin ------------
seed "$TMP/6"
"$KEYHOLE" --at "$T" ensure-bin "$TMP/6/a.kdbx" >/dev/null
exchange "$TMP/6/a.kdbx" "$TMP/6/b.kdbx"
"$KEYHOLE" --at "$(( T + 1000 ))" delete-group "$TMP/6/a.kdbx" "$(field "$TMP/6/a.kdbx" 'bin uuid')" >/dev/null
exchange "$TMP/6/a.kdbx" "$TMP/6/b.kdbx"
"$KEYHOLE" --at "$(( T + 2000 ))" ensure-bin "$TMP/6/a.kdbx" >/dev/null
"$KEYHOLE" --at "$(( T + 3000 ))" ensure-bin "$TMP/6/b.kdbx" >/dev/null
[ "$(field "$TMP/6/a.kdbx" 'bin uuid')" = "$(field "$TMP/6/b.kdbx" 'bin uuid')" ] \
    || fail synced-delete "replicas minted different bins after a synced delete"
exchange "$TMP/6/a.kdbx" "$TMP/6/b.kdbx"
[ "$(field "$TMP/6/a.kdbx" 'bin group')" = present ] || fail synced-delete "the merge deleted the new empty bin"
one_bin_each synced-delete "$TMP/6/a.kdbx" "$TMP/6/b.kdbx"

echo "PASS: replicas of one vault mint the same recycle bin (ensure, lazy, re-enable, re-mint after a synced or unsynced delete), one bin after merging, survives a fresh disk read"
