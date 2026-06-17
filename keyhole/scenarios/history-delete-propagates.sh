#!/usr/bin/env bash
#
# Deleting a history snapshot must PROPAGATE cross-peer. The user action is
# "scrub this old version" — e.g. removing a leaked/old password from an
# entry's history. If it doesn't propagate, the snapshot lives on (with its
# old secret) on every other device — a real privacy gap.
#
# The cross-peer history merge is deliberately LOSSLESS (it unions histories),
# so a bare local DELETE can't survive a sync: the peer either resurrects the
# record, or — as seen here — the two replicas simply diverge on history depth
# forever. A deletion only propagates if it leaves a `keys.history_tombstones`
# record that the lossless merge then prunes against. This scenario pins that.
#
# NB the convergence digest is NO oracle here — it deliberately EXCLUDES
# history (replicas may legitimately differ in depth), so we compare the
# snapshot sets directly via the `history` verb across a fresh disk read.

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
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username v0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
# Three edits → history snapshots v0, v1, v2 (live entry is v3).
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username v1 >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username v2 >/dev/null
"$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username v3 >/dev/null
cp "$A" "$B"   # B forks with the full history {v0,v1,v2}
[ "$(hist_users "$A" "$uuid")" = "v0 v1 v2" ] || { echo "FAIL(setup): unexpected base history [$(hist_users "$A" "$uuid")]"; exit 1; }

# A scrubs the middle snapshot (v1).
"$KEYHOLE" --at 5000000 delete-history "$A" "$uuid" 1 >/dev/null
[ "$(hist_users "$A" "$uuid")" = "v0 v2" ] || { echo "FAIL(setup): A's local delete didn't drop v1 (got [$(hist_users "$A" "$uuid")])"; exit 1; }

# Sync both ways. The deletion must propagate to B, and the replicas must
# AGREE on the resulting history — not diverge, not resurrect v1.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
rm -rf "$A.mirror" "$B.mirror"   # honest disk read

ha="$(hist_users "$A" "$uuid")"; hb="$(hist_users "$B" "$uuid")"
[ "$ha" = "$hb" ] \
    || { echo "FAIL: replicas diverge on history after a deletion — A=[$ha] B=[$hb] (the deletion didn't propagate)"; exit 1; }
[ "$ha" = "v0 v2" ] \
    || { echo "FAIL: history deletion did not converge to {v0,v2} — got [$ha] (v1 resurrected?)"; exit 1; }

echo "PASS: a history-snapshot deletion propagates and converges cross-peer ({v0,v2} on both), survives a fresh disk read"
