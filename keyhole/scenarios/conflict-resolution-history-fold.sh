#!/usr/bin/env bash
#
# Resolving a held conflict must CONVERGE the entry's <History> across both
# replicas — not just its live value. A resolution snapshots the LOSER (the
# rejected value — an old, scrubbed-but-recoverable secret) into the
# resolver's history. If that snapshot, and each side's own pre-conflict
# history, don't fold together cross-peer, the two devices end up holding
# DIFFERENT history sets: a "removed" old password lingers on one and not the
# other. That's the privacy gap this pins.
#
# Why the steady-state paths miss it: a resolution makes the live values
# match, so the very next pull classifies the entry InSync (keep-theirs) or
# AutoMerges one way then InSync on the bounce-back (keep-mine). The InSync
# arm folds nothing additive — it only reconciles history TOMBSTONES (replicas
# may legitimately differ in plain history DEPTH; see
# history-quota-trim-propagates.sh). So a resolution's loser snapshot, and any
# pre-conflict snapshot unique to one side, never reach the peer. The fold has
# to be triggered by the resolution itself (a resolution record on either
# side), which is exactly the gate the fix adds.
#
# Teeth, per direction: each replica grows a history snapshot the other never
# sees (`amid` on A, `bmid` on B) BEFORE the clash. After resolve+sync the two
# replicas must agree on the full snapshot set — which forces both the
# cross-pollination of `amid`/`bmid` AND the convergence of the loser. The
# digest is no oracle here (it excludes history by design), so we compare the
# snapshot sets directly via the `history` verb across a fresh disk read
# (`rm -rf "$VAULT.mirror"` — the mirror persists state across processes like a
# real client's local store, so only a fresh re-ingest from the KDBX is honest).
#
# Covers BOTH resolution directions: keep-mine (`--choose local`) and
# keep-theirs (`--choose remote`).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

# The set of usernames across an entry's history snapshots, sorted+joined.
hist_users() { "$KEYHOLE" history "$1" "$2" | awk 'NF==2 && $1 ~ /^[0-9]+$/ && $2 !~ /snapshot/ {print $2}' | sort | tr '\n' ' ' | sed 's/ $//'; }

# Drive one resolution direction end-to-end in its own throwaway vault pair.
#   $1 = --choose side: "local" (keep-mine) or "remote" (keep-theirs)
#   $2 = the loser username expected to land in BOTH histories after resolve
#        (keep-mine drops the peer's value; keep-theirs drops our own)
run_direction() {
    local choose="$1" loser="$2"
    local TMP A B uuid
    TMP="$(mktemp -d)"
    A="$TMP/device-a.kdbx"
    B="$TMP/device-b.kdbx"

    "$KEYHOLE" create "$A" >/dev/null
    "$KEYHOLE" --at 1000000 create-entry "$A" "E" --username base >/dev/null
    uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
    # Shared snapshot {base} before the fork (live m1 on both).
    "$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username m1 >/dev/null
    cp "$A" "$B"

    # Each replica grows a snapshot the other never sees: A pushes m1→amid,
    # B pushes m1→bmid. So A's history gains `amid`, B's gains `bmid`.
    "$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username amid >/dev/null
    "$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username afin >/dev/null
    "$KEYHOLE" --at 3000000 update-entry "$B" "$uuid" --username bmid >/dev/null
    "$KEYHOLE" --at 4000000 update-entry "$B" "$uuid" --username bfin >/dev/null
    [ "$(hist_users "$A" "$uuid")" = "amid base m1" ] || { echo "FAIL(setup,$choose): A base history [$(hist_users "$A" "$uuid")]"; rm -rf "$TMP"; exit 1; }
    [ "$(hist_users "$B" "$uuid")" = "base bmid m1" ] || { echo "FAIL(setup,$choose): B base history [$(hist_users "$B" "$uuid")]"; rm -rf "$TMP"; exit 1; }

    # The live username (afin vs bfin) clashes → both PARK on sync.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" list-conflicts "$B" | grep "$uuid" >/dev/null || { echo "FAIL(setup,$choose): B did not park the clash"; rm -rf "$TMP"; exit 1; }

    # B resolves the held conflict. The loser is snapshotted into B's history
    # and a resolution record is written into B's vault meta.
    "$KEYHOLE" --at 5000000 resolve "$B" --entry "$uuid" --choose "$choose" >/dev/null

    # Sync both ways. The resolution must converge the HISTORY, not just the
    # live value: the loser snapshot + each side's unique snapshot fold so both
    # replicas hold the same set.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    rm -rf "$A.mirror" "$B.mirror"   # honest disk read

    local ha hb expected
    ha="$(hist_users "$A" "$uuid")"; hb="$(hist_users "$B" "$uuid")"
    # union of both sides' pre-conflict snapshots {amid,base,m1,bmid} plus the
    # resolution loser, sorted.
    expected="$(printf '%s\n' amid base bmid m1 "$loser" | sort | tr '\n' ' ' | sed 's/ $//')"

    [ "$ha" = "$hb" ] \
        || { echo "FAIL($choose): replicas diverge on history after resolve — A=[$ha] B=[$hb] (the resolution didn't fold history)"; rm -rf "$TMP"; exit 1; }
    # The loser (an old secret) must live on BOTH replicas, not just the resolver.
    case " $ha " in *" $loser "*) : ;; *) echo "FAIL($choose): the resolution loser '$loser' is missing from the converged history [$ha]"; rm -rf "$TMP"; exit 1 ;; esac
    # And each side's unique pre-conflict snapshot must have crossed over.
    case " $ha " in *" amid "* ) : ;; *) echo "FAIL($choose): A's unique snapshot 'amid' lost in the fold [$ha]"; rm -rf "$TMP"; exit 1 ;; esac
    case " $ha " in *" bmid "* ) : ;; *) echo "FAIL($choose): B's unique snapshot 'bmid' did not reach A [$ha]"; rm -rf "$TMP"; exit 1 ;; esac
    [ "$ha" = "$expected" ] \
        || { echo "FAIL($choose): converged history is [$ha], expected [$expected]"; rm -rf "$TMP"; exit 1; }

    rm -rf "$TMP"
    echo "  ok($choose): history converged to {$ha} on both replicas, loser '$loser' retained on both"
}

# keep-mine: B keeps its own value (bfin); the peer's value (afin) is the loser.
run_direction local afin
# keep-theirs: B adopts the peer's value (afin); B's own value (bfin) is the loser.
run_direction remote bfin

echo "PASS: a resolved conflict folds <History> so both replicas converge on the same snapshot set, loser included, for keep-mine and keep-theirs"
