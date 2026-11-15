#!/usr/bin/env bash
#
# Two peers that each designate a different recycle-bin group must settle on
# the same one. A vault handed over enabled-but-binless (keepassxc-cli makes
# them) gets its bin group created per replica — `ensure-bin` on add, or the
# lazy create on first recycle — per replica. Replicas now mint the same group
# (its uuid derives from the root's; see replicas-mint-one-bin.sh), but two
# DIFFERENT bin groups still meet whenever one bin predates that or came from
# another client. The bin pointer is LWW-arbitrated by `recycle_bin_changed`, so:
#
#   1. The engine's bin creation must stamp `recycle_bin_changed`. It didn't:
#      both replicas kept the timestamp the file arrived with, the meta merge
#      saw a tie, kept each side's own pointer, and the pair diverged for good
#      (each treating the other's bin as an ordinary group, so one side's
#      deletes showed as live entries on the other).
#   2. An exact tie (same instant on both, pinned here with --at) must still
#      converge — the meta merge breaks timestamp ties on the value.
#
# Replicas in the same state mint the same bin, so each case gives B a
# different history first: B disables its bin (keeping that group as an
# ordinary one) and re-enables, minting the next bin, while A keeps the first.
#
# Seeded via keepassxc-cli on purpose (independent implementation = honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

field()  { "$KEYHOLE" inspect "$1" | awk -F': *' -v k="$2" '$1 == k {print $2}'; }
digest() { "$KEYHOLE" digest "$1"; }

# Later than the file's own RecycleBinChanged (keepassxc stamps creation time).
T=$(( ($(date +%s) + 3600) * 1000 ))

check_pair() { # <case> <A> <B>
    local a="$2" b="$3"
    "$KEYHOLE" ingest-peer "$a" "$b" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$b" "$a" --owner device-a >/dev/null
    rm -rf "$a.mirror" "$b.mirror"   # honest disk read
    local ua ub
    ua="$(field "$a" 'bin uuid')"; ub="$(field "$b" 'bin uuid')"
    [ "$ua" != none ] || { echo "FAIL($1): A has no bin after the exchange"; exit 1; }
    [ "$ua" = "$ub" ] \
        || { echo "FAIL($1): peers designate different bins (A=$ua B=$ub)"; exit 1; }
    [ "$(digest "$a")" = "$(digest "$b")" ] \
        || { echo "FAIL($1): digests diverge (A=$(digest "$a") B=$(digest "$b"))"; exit 1; }
}

seed() { # <path>
    printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$1" >/dev/null
    [ "$(field "$1" 'bin group')" = absent ] || { echo "FAIL(setup): expected no bin group"; exit 1; }
}

# B designates its second bin at <at>; A designates the first at <a_at>.
diverge() { # <A> <B> <a_at> <at>
    "$KEYHOLE" --at "$3" ensure-bin "$1" >/dev/null
    "$KEYHOLE" --at "$(( $4 - 2000 ))" ensure-bin "$2" >/dev/null
    "$KEYHOLE" --at "$(( $4 - 1000 ))" set-bin "$2" off >/dev/null
    "$KEYHOLE" --at "$4" set-bin "$2" on >/dev/null
    [ "$(field "$1" 'bin uuid')" != "$(field "$2" 'bin uuid')" ] \
        || { echo "FAIL(setup): replicas designate the same bin"; exit 1; }
}

# --- 1. the peers designate different bins at different instants -----------
seed "$TMP/v1.kdbx"
cp "$TMP/v1.kdbx" "$TMP/a1.kdbx"; cp "$TMP/v1.kdbx" "$TMP/b1.kdbx"
diverge "$TMP/a1.kdbx" "$TMP/b1.kdbx" "$T" "$(( T + 3000 ))"
b_bin="$(field "$TMP/b1.kdbx" 'bin uuid')"
check_pair "stamped" "$TMP/a1.kdbx" "$TMP/b1.kdbx"
[ "$(field "$TMP/a1.kdbx" 'bin uuid')" = "$b_bin" ] \
    || { echo "FAIL(stamped): the later-designated bin (B's) did not win"; exit 1; }

# --- 2. both designate at the same instant: the tie still converges ---------
seed "$TMP/v2.kdbx"
cp "$TMP/v2.kdbx" "$TMP/a2.kdbx"; cp "$TMP/v2.kdbx" "$TMP/b2.kdbx"
diverge "$TMP/a2.kdbx" "$TMP/b2.kdbx" "$T" "$T"
check_pair "tie" "$TMP/a2.kdbx" "$TMP/b2.kdbx"

echo "PASS: peers that each mint a recycle bin converge on one (later stamp wins; exact tie broken deterministically), survives a fresh disk read"
