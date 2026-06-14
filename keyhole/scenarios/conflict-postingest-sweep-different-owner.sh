#!/usr/bin/env bash
#
# Task #31: the post-ingest dissolve sweep clears a DIFFERENT owner's parked
# conflict than the one being ingested — eagerly, at ingest time, not lazily
# on the next resolver-open.
#
# Finding #10's reconcile runs at three sites; this exercises the post-INGEST
# one (`reconcile_all_conflict_rows` at the tail of `Engine::ingest_peer`).
# The ingest arms are owner-SCOPED — ingesting peer P only clears P's own
# conflict row. But adopting P's value can ALSO converge the local entry onto
# a THIRD peer's parked value, dissolving that third owner's conflict as a
# side effect. Only the whole-set sweep catches it; without it the third
# owner's row lingers as a ghost badge until a resolver-open heals it lazily.
#
# Why this needs an owner-introspection verb (and the single-peer Finding #10
# scenarios can't reach it): a genuinely-divergent fourth peer keeps the entry
# BADGED throughout, so the owner-agnostic badge (`list-conflicts`) reads 1
# both when the sweep correctly dropped the dissolved owner AND when it wrongly
# left it. Only `conflict-owners` — which peers does this entry still diverge
# from — can tell "swept" from "ghost". It's a pure SELECT (like
# `list-conflicts`, unlike `show-conflict`), so reading it right after the
# ingest proves the drop was EAGER, not a lazy heal triggered by the read.
#
# Cast (all start from a shared E=V0, all diverge at the same instant):
#   hub  = Vh    the inspected device; parks against p1, p2, p3
#   p1   = Vp    resolves its own hub-clash toward Vp, propagating a resolution
#   p2   = Vp    holds the SAME value p1 resolves to (the DIFFERENT owner the
#                sweep dissolves when hub adopts p1's resolution)
#   p3   = Vp3   a genuinely distinct value — stays parked, keeps hub badged
#
# hub ingests p1's resolution → adopts Vp →
#   p1: cleared by the ingest arm (owner-scoped);
#   p2: dissolved by the SWEEP (hub now == p2's Vp, p2 != the ingested p1);
#   p3: kept (Vp3 still diverges).
# Expected owners(hub,E) = {p3}.  A missing sweep would leave {p2, p3} — same
# badge (1), different owner set.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
HUB="$TMP/hub.kdbx"
P1="$TMP/p1.kdbx"
P2="$TMP/p2.kdbx"
P3="$TMP/p3.kdbx"

# Sorted, space-joined conflict-owner set for an entry — '' when none.
# conflict-owners is a pure SELECT (no lazy heal), so this never perturbs the
# state it measures.
owners() { "$KEYHOLE" conflict-owners "$1" "$2" \
    | grep -v '(no parked conflict)' | sort | tr '\n' ' ' | sed 's/ $//'; }
# Owner-agnostic badge count (list-conflicts only — show-conflict would heal).
badge() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }
field() { "$KEYHOLE" list "$1" | awk -v u="$2" '$1==u {print $3}'; }

"$KEYHOLE" create "$HUB" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$HUB" "E" --username V0 >/dev/null
uuid="$("$KEYHOLE" list "$HUB" | awk '/E/ {print $1; exit}')"
cp "$HUB" "$P1"; cp "$HUB" "$P2"; cp "$HUB" "$P3"

# Four-way same-instant divergence (genuine clashes; p1 and p2 land on Vp).
"$KEYHOLE" --at 2000000 update-entry "$HUB" "$uuid" --username Vh  >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$P1"  "$uuid" --username Vp  >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$P2"  "$uuid" --username Vp  >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$P3"  "$uuid" --username Vp3 >/dev/null

# hub parks against all three peers.
"$KEYHOLE" ingest-peer "$HUB" "$P1" --owner p1 >/dev/null
"$KEYHOLE" ingest-peer "$HUB" "$P2" --owner p2 >/dev/null
"$KEYHOLE" ingest-peer "$HUB" "$P3" --owner p3 >/dev/null
[ "$(owners "$HUB" "$uuid")" = "p1 p2 p3" ] \
    || { echo "FAIL(setup): hub did not park all three peers (owners=[$(owners "$HUB" "$uuid")])"; exit 1; }
[ "$(badge "$HUB")" = 1 ] || { echo "FAIL(setup): hub entry not badged"; exit 1; }

# p1 resolves its own hub-clash toward its local value Vp (a clean second
# later), which writes a propagatable resolution record.
"$KEYHOLE" ingest-peer "$P1" "$HUB" --owner hub >/dev/null
"$KEYHOLE" --at 3000000 resolve "$P1" --entry "$uuid" --choose local >/dev/null
[ "$(field "$P1" "$uuid")" = "<Vp>" ] \
    || { echo "FAIL(setup): p1 resolution did not land on Vp (got: $(field "$P1" "$uuid"))"; exit 1; }

# THE TEST: hub ingests p1's resolution. hub adopts Vp; the post-ingest sweep
# must dissolve p2 (now matched, a DIFFERENT owner than the ingested p1) while
# leaving p3 (still divergent) parked.
"$KEYHOLE" ingest-peer "$HUB" "$P1" --owner p1 >/dev/null

[ "$(field "$HUB" "$uuid")" = "<Vp>" ] \
    || { echo "FAIL: hub did not adopt p1's resolution (username: $(field "$HUB" "$uuid"))"; exit 1; }

got="$(owners "$HUB" "$uuid")"
[ "$got" = "p3" ] \
    || { echo "FAIL: post-ingest sweep did not dissolve the different-owner conflict. owners=[$got], expected [p3] (a lingering p2 = ghost the badge can't see)"; exit 1; }

# The entry is STILL badged (p3 is genuine) — proving the owner-agnostic badge
# alone cannot distinguish the swept state from the ghost-p2 state.
[ "$(badge "$HUB")" = 1 ] \
    || { echo "FAIL: hub entry lost its badge though p3 still genuinely diverges"; exit 1; }

echo "PASS: post-ingest sweep dissolves a different-owner conflict (p2) eagerly while keeping a genuine peer (p3) parked"
