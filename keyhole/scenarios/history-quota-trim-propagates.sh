#!/usr/bin/env bash
#
# Quota-trim of an entry's history must PROPAGATE cross-peer as a deletion. When
# an edit pushes history past the vault's `<HistoryMaxItems>` cap, the oldest
# snapshot is dropped. Without a tombstone that drop is invisible to a peer: a
# replica that still holds the trimmed snapshot keeps it forever, so a
# quota-trimmed OLD SECRET silently lives on the other device — a privacy gap,
# the exact analogue of the user "delete this version" gap.
#
# Like that delete (see history-delete-propagates.sh), the only thing that makes
# a quota drop STICK cross-peer is a `keys.history_tombstones` record (reason
# `quota_trim`) that ingest prunes against. The privacy-delete fix proved the
# *user_delete* half on the Engine path; this pins the *quota_trim* half.
#
# What we assert: the trimmed snapshot (v0) is PURGED from the peer that held it
# and never resurrects on the trimmer. NB the owner-rows ingest path PRUNES local
# history against the unioned tombstone set — it doesn't union the peer's history
# IN (replicas may legitimately differ in history depth; the convergence digest
# excludes history for exactly that reason). So the guarantee under test is "the
# trimmed secret is gone everywhere", not full depth equality. We read the
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
# Cap history at 2 snapshots so a single extra edit trips the quota trim.
"$KEYHOLE" set-history-max "$A" 2 >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username v0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
# Two edits → history snapshots v0, v1 (live entry is v2); still at the cap.
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username v1 >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username v2 >/dev/null
[ "$(hist_users "$A" "$uuid")" = "v0 v1" ] || { echo "FAIL(setup): unexpected base history [$(hist_users "$A" "$uuid")] (expected v0 v1)"; exit 1; }

# B forks here, holding the full at-cap history {v0, v1}.
cp "$A" "$B"

# One more edit on A pushes v2 onto history → [v0, v1, v2], over the cap of 2,
# so the oldest (v0) is quota-trimmed. The Engine path must tombstone v0.
"$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username v3 >/dev/null
[ "$(hist_users "$A" "$uuid")" = "v1 v2" ] || { echo "FAIL(setup): A's quota trim didn't drop v0 (got [$(hist_users "$A" "$uuid")], expected v1 v2)"; exit 1; }

# Sync both ways. The trim's tombstone must reach B (which still holds v0) and
# prune v0 there; the trimmer A must not have v0 resurrected.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
rm -rf "$A.mirror" "$B.mirror"   # honest disk read

ha="$(hist_users "$A" "$uuid")"; hb="$(hist_users "$B" "$uuid")"
# The privacy guarantee: the quota-trimmed v0 lives on NEITHER replica.
case " $hb " in *" v0 "*) echo "FAIL: the quota-trimmed v0 still lives on peer B — B=[$hb] (the trim didn't propagate as a deletion)"; exit 1;; esac
case " $ha " in *" v0 "*) echo "FAIL: the quota-trimmed v0 resurrected on the trimmer A — A=[$ha]"; exit 1;; esac
# No over-purge: A keeps its post-trim set; B keeps everything except v0.
[ "$ha" = "v1 v2" ] || { echo "FAIL: A's post-trim history changed unexpectedly — A=[$ha] (expected v1 v2)"; exit 1; }
[ "$hb" = "v1" ]    || { echo "FAIL: B did not converge to the de-v0'd set — B=[$hb] (expected v1)"; exit 1; }

echo "PASS: a quota-trimmed snapshot propagates as a deletion (v0 purged from both replicas), survives a fresh disk read"
