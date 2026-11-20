#!/usr/bin/env bash
#
# Ingesting a peer copy that is merely BEHIND (an ancestor of the local state:
# the local replica forked from it and then edited) changes nothing locally, so
# it must be a no-op: no entry reported updated, no mirror mutation, no save —
# on a warm mirror and on one rebuilt from the KDBX alone. A peer that's behind
# catches up by pulling the local head itself; re-saving local on every pull of
# its stale copy only churns the file and the transport.
#
# The trap: field-granular classify verdicts "local edited, peer didn't" as an
# auto-merge whose result IS local. Advancing local with that result counts the
# entry as updated and bumps the mutation watermark, so every pull of the stale
# copy saves again and never settles.
#
# Controls, so the no-op can't be bought by ignoring the peer: a peer that is
# genuinely ahead on a field local didn't touch, and one that only changed the
# icon, must still apply and save.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL($1): $2"; exit 1; }
sum() { md5 -q "$1" 2>/dev/null || md5sum "$1" | cut -d' ' -f1; }

# Fork A from B, A then edits E (and with a history cap of 2, trims it), so B's
# copy is a strict ancestor of A's.
A="$TMP/a.kdbx"
B="$TMP/b.kdbx"
"$KEYHOLE" create "$B" >/dev/null
"$KEYHOLE" set-history-max "$B" 2 >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$B" E --username v0 >/dev/null
uuid="$("$KEYHOLE" list "$B" | awk '$2=="E" {print $1; exit}')"
"$KEYHOLE" --at 1200000 update-entry "$B" "$uuid" --username v1 >/dev/null
cp "$B" "$A"
"$KEYHOLE" ingest-peer "$A" "$B" --owner b >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username v2 >/dev/null
"$KEYHOLE" --at 2100000 update-entry "$A" "$uuid" --username v3 >/dev/null

behind_is_noop() {
    local label="$1" before out
    before="$(sum "$A")"
    out="$("$KEYHOLE" ingest-peer "$A" "$B" --owner b)"
    case "$out" in *"ingested peer 'b': no change"*) : ;; *) fail "$label" "ingesting the stale peer was not a no-op: $out";; esac
    case "$out" in *"no local advance"*) : ;; *) fail "$label" "ingesting the stale peer left the mirror owing a write: $out";; esac
    [ "$(sum "$A")" = "$before" ] || fail "$label" "ingesting the stale peer rewrote the file"
    "$KEYHOLE" persistence-state "$A" | grep -q 'dirty=false' \
        || fail "$label" "the mirror is dirty after ingesting the stale peer"
    echo "  ok($label): pulling the stale peer is a no-op"
}
behind_is_noop warm
behind_is_noop warm-again
rm -rf "$A.mirror"     # the local mirror rebuilt from the KDBX alone
behind_is_noop rebuilt
[ "$("$KEYHOLE" list "$A" | awk -v u="$uuid" '$1==u' | sed -n 's/.*<\(.*\)>.*/\1/p')" = "v3" ] \
    || fail "rebuilt" "A's live value changed"

# Control 1: B advances a field A never touched → A must take it and save.
"$KEYHOLE" --at 3000000 update-entry "$B" "$uuid" --notes from-b >/dev/null
out="$("$KEYHOLE" ingest-peer "$A" "$B" --owner b)"
case "$out" in *"merged state saved to disk"*) : ;; *) fail "ahead" "a peer ahead on another field was not applied: $out";; esac
echo "  ok(ahead): a peer ahead on another field still applies and saves"

# Control 2: a fresh pair where the peer only changed the icon (cosmetic, so
# not a new version) — the merge differs from local, so it must still apply.
C="$TMP/c.kdbx"
D="$TMP/d.kdbx"
"$KEYHOLE" create "$C" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$C" I --username i0 >/dev/null
iu="$("$KEYHOLE" list "$C" | awk '$2=="I" {print $1; exit}')"
cp "$C" "$D"
"$KEYHOLE" ingest-peer "$C" "$D" --owner d >/dev/null
"$KEYHOLE" --at 2000000 add-custom-icon "$D" "$iu" icon-bytes >/dev/null
out="$("$KEYHOLE" ingest-peer "$C" "$D" --owner d)"
case "$out" in *"merged state saved to disk"*) : ;; *) fail "icon" "a peer's icon-only change was not applied: $out";; esac
echo "  ok(icon): a peer's icon-only change still applies and saves"

echo "PASS: ingesting a peer that is merely behind is a no-op (warm and rebuilt mirror); genuine peer changes still apply"
