#!/usr/bin/env bash
#
# History-snapshot deletion must propagate cleanly even when it RIDES the
# conflict adopt-peer arm — and must NOT clobber the peer history that arm just
# adopted. This is the corner the plain history-delete-propagates.sh (an InSync
# path) doesn't reach.
#
# Reaching the adopt-peer arm takes care: if B simply resolves a clash, the
# resolution snapshots A's losing value into B's history, so A's live value
# becomes a shared ancestor and the next ingest is an AutoMerge (which keeps
# A's own history), NOT an adopt. To get a genuine Conflict-with-peer-resolution
# at adopt time, A must RE-EDIT after parking to a value B never sees — then
# classify still sees a clash, and because A's re-edit predates B's resolution,
# A adopts B's resolved value (design §5.3).
#
# Sequence: A and B fork from a shared base; B grows a B-only history snapshot
# ("bx") A never sees; both edit the SAME field to distinct values (a genuine
# clash) and sync → both PARK. A re-edits ("a2"). Then B scrubs an old snapshot
# ("h1") AND resolves the clash to its own value — so B's pull carries a FRESH
# tombstone + a resolution record. A then ingests B: A adopts B's resolved value
# (the adopt-peer arm rebuilds A's entry, history and all, from B's copy), and
# the history-tombstone reconcile must run against THAT adopted (peer) history.
#
# Teeth: if the reconcile bases on A's stale local history instead, it overwrites
# the just-adopted B history — dropping B's legitimate "bx" snapshot (silent
# cross-peer history loss + permanent depth divergence). The assertions pin both
# that the scrub ("h1") propagated AND that "bx" survived, across a fresh disk
# read, and that the replicas converge on the same history set.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

# The set of usernames across an entry's history snapshots, sorted+joined.
hist_users() { "$KEYHOLE" history "$1" "$2" | awk 'NF==2 && $1 ~ /^[0-9]+$/ && $2 !~ /snapshot/ {print $2}' | sort | tr '\n' ' ' | sed 's/ $//'; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username h0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
# Shared history {h0, h1} (live h2) before the fork.
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username h1 >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username h2 >/dev/null
cp "$A" "$B"   # B forks with history {h0, h1} (live h2)
[ "$(hist_users "$A" "$uuid")" = "h0 h1" ] || { echo "FAIL(setup): base history [$(hist_users "$A" "$uuid")]"; exit 1; }

# B grows a B-only snapshot: pushes h2 into history, live becomes bx.
"$KEYHOLE" --at 4000000 update-entry "$B" "$uuid" --username bx >/dev/null
# Both devices now clash on the SAME field (username) to distinct values.
"$KEYHOLE" --at 5000000 update-entry "$A" "$uuid" --username afin >/dev/null  # A: hist {h0,h1,h2}
"$KEYHOLE" --at 5000000 update-entry "$B" "$uuid" --username bfin >/dev/null  # B: hist {h0,h1,h2,bx}
[ "$(hist_users "$B" "$uuid")" = "bx h0 h1 h2" ] || { echo "FAIL(setup): B base history [$(hist_users "$B" "$uuid")]"; exit 1; }

# Sync both ways → the username clash PARKS on both (no tombstones yet).
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null || { echo "FAIL(setup): A did not park the clash"; exit 1; }

# A re-edits to a value B never sees, so the entry stays a genuine Conflict at
# adopt time (not an AutoMerge against a resolution-snapshot ancestor).
"$KEYHOLE" --at 5500000 update-entry "$A" "$uuid" --username a2 >/dev/null
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null || { echo "FAIL(setup): A's re-edit dissolved the clash"; exit 1; }

# B scrubs an OLD snapshot (h1) AND resolves the clash to its own value. So B's
# next sync carries a FRESH tombstone A hasn't seen + a resolution record. The
# resolve snapshots A's parked value (afin) into B's history. B's resolution at
# 6000000 post-dates A's re-edit (5500000), so A adopts (design §5.3).
"$KEYHOLE" --at 6000000 delete-history "$B" "$uuid" 1 >/dev/null   # drop h1 from B's {h0,h1,h2,bx}
"$KEYHOLE" --at 6000000 resolve "$B" --entry "$uuid" --choose local >/dev/null

# A ingests B: adopts B's resolved value (adopt-peer arm) AND learns the
# tombstone in the same pull — the history reconcile must run over the adopted
# PEER history, not A's stale local one.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
rm -rf "$A.mirror"   # honest disk read

# A must have adopted B's resolved value.
"$KEYHOLE" list "$A" | grep "$uuid" | grep '<bfin>' >/dev/null \
    || { echo "FAIL(setup): A did not adopt B's resolved value (not the adopt-peer arm)"; exit 1; }

ha="$(hist_users "$A" "$uuid")"
case " $ha " in
    *" h1 "*) echo "FAIL: the scrub did not propagate — h1 survives on A (got [$ha])"; exit 1 ;;
esac
case " $ha " in
    *" bx "*) : ;;
    *) echo "FAIL: adopt-peer history clobbered — B's 'bx' snapshot lost on A (got [$ha]); reconcile based on stale local history?"; exit 1 ;;
esac
# B's resolve snapshotted A's parked value (afin) into history, so the adopted
# set is {afin, bx, h0, h2} with h1 scrubbed.
[ "$ha" = "afin bx h0 h2" ] || { echo "FAIL: A's history after adoption is not {afin,bx,h0,h2} (got [$ha])"; exit 1; }

# Converge: B adopts nothing new, both agree on the surviving history set.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$B.mirror"
hb="$(hist_users "$B" "$uuid")"
[ "$ha" = "$hb" ] || { echo "FAIL: replicas diverge on history after adopt — A=[$ha] B=[$hb]"; exit 1; }

echo "PASS: a history scrub riding the conflict adopt-peer arm propagates (h1 gone) without clobbering adopted peer history (bx kept), and converges"
