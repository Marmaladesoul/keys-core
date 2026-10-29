#!/usr/bin/env bash
#
# A held conflict's peer row must rebuild the peer's EXACT entry — tags,
# custom_data (tag / attachment / history tombstones) and <History> included.
# The resolver merges local against that rebuilt "theirs", so a facet the row
# drops is a facet the merge decides wrongly:
#   - without tags, the history record of a rejected peer version is
#     unfaithful (it loses the tags the peer's copy carried);
#   - without <History>, the tag merge has no shared ancestor and falls back
#     to a union, so neither side's tag deletion since the fork is honoured.
#
# Every shape forks A and B from one base (tags {alpha, beta}, username u0),
# optionally edits tags, then makes a clashing username edit on each side, so
# A holds a conflict after ingesting B. Each shape runs in its own throwaway
# pair and reads back after `rm -rf "$VAULT.mirror"` (the mirror persists
# state across processes like a real client's local store, so only a fresh
# re-ingest is honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL($1): $2" >&2; exit 1; }
tags_on() { "$KEYHOLE" tags "$1" "$2" | tr '\n' ' ' | sed 's/ $//'; }

# $1 = label, $2 = A's tags after the fork, $3 = B's tags after the fork
# (empty = leave the base tags alone). Leaves the conflict held on A and
# prints the entry uuid.
setup() {
    local a="$TMP/$1-a.kdbx" b="$TMP/$1-b.kdbx" uuid
    "$KEYHOLE" create "$a" >/dev/null
    "$KEYHOLE" --at 1000000 create-entry "$a" "E" --username u0 >/dev/null
    uuid="$("$KEYHOLE" list "$a" | awk '/E/ {print $1; exit}')"
    "$KEYHOLE" --at 1500000 set-tags "$a" "$uuid" "alpha, beta" >/dev/null
    cp "$a" "$b"
    [ -z "$2" ] || "$KEYHOLE" --at 1800000 set-tags "$a" "$uuid" "$2" >/dev/null
    [ -z "$3" ] || "$KEYHOLE" --at 1900000 set-tags "$b" "$uuid" "$3" >/dev/null
    "$KEYHOLE" --at 2000000 update-entry "$a" "$uuid" --username uA >/dev/null
    "$KEYHOLE" --at 2100000 update-entry "$b" "$uuid" --username uB >/dev/null
    "$KEYHOLE" --at 3000000 ingest-peer "$a" "$b" --owner b >/dev/null
    grep -q "$uuid" <<<"$("$KEYHOLE" list-conflicts "$a")" || fail "$1,setup" "no conflict held"
    echo "$uuid"
}

# $1 = label, $2 = side. Resolves, then drops the mirror so every read below
# re-ingests from the KDBX alone.
resolve() {
    local a="$TMP/$1-a.kdbx"
    "$KEYHOLE" --at 4000000 resolve "$a" --entry "$uuid" --choose "$2" >/dev/null
    rm -rf "$a.mirror"
}

# ── 1. keep-local records the rejected version WITH its tags ──
uuid="$(setup record "" "")"
resolve record local
rejected="$("$KEYHOLE" history "$TMP/record-a.kdbx" "$uuid" --tags | awk '$2 == "uB"')"
[ -n "$rejected" ] || fail record "the rejected version (uB) is not in history"
[ "$(awk '{print $3}' <<<"$rejected")" = "[alpha,beta]" ] \
    || fail record "the rejected version was recorded without its tags: [$rejected]"

# ── 2. keep-local leaves the live tags exactly as local had them ──
# A dropped beta and added mine; B left the base tags alone. A union with B's
# copy would bring beta back.
uuid="$(setup keep "alpha, mine" "")"
resolve keep local
[ "$(tags_on "$TMP/keep-a.kdbx" "$uuid")" = "alpha mine" ] \
    || fail keep "keep-local changed local's tags to [$(tags_on "$TMP/keep-a.kdbx" "$uuid")]"

# ── 3. a tag deleted locally after the fork does not resurrect ──
# A dropped beta; choosing B's side (which still carries beta, untouched since
# the fork) must still honour that deletion.
uuid="$(setup local-del "alpha" "")"
resolve local-del remote
grep -q "<uB>" <<<"$("$KEYHOLE" list "$TMP/local-del-a.kdbx")" || fail local-del "theirs (uB) was not adopted"
[ "$(tags_on "$TMP/local-del-a.kdbx" "$uuid")" = "alpha" ] \
    || fail local-del "the locally deleted tag resurrected: [$(tags_on "$TMP/local-del-a.kdbx" "$uuid")]"

# ── 4. a tag the peer deleted is honoured when choosing the peer's side ──
uuid="$(setup peer-del "" "alpha")"
resolve peer-del remote
[ "$(tags_on "$TMP/peer-del-a.kdbx" "$uuid")" = "alpha" ] \
    || fail peer-del "the peer's tag deletion was lost: [$(tags_on "$TMP/peer-del-a.kdbx" "$uuid")]"

# ── 5. choose-remote keeps a tag neither side removed ──
uuid="$(setup remote "" "")"
resolve remote remote
grep -q "<uB>" <<<"$("$KEYHOLE" list "$TMP/remote-a.kdbx")" || fail remote "theirs (uB) was not adopted"
[ "$(tags_on "$TMP/remote-a.kdbx" "$uuid")" = "alpha beta" ] \
    || fail remote "adopting theirs changed the tags to [$(tags_on "$TMP/remote-a.kdbx" "$uuid")]"

echo "PASS conflict-row-exact-peer-entry"
