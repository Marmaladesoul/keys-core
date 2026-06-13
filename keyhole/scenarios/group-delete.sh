#!/usr/bin/env bash
#
# Scenario: 5d cross-peer group DELETE — a group deleted on one side is
# removed on the other (its `<DeletedObjects>` tombstone is consumed),
# and the replicas converge. A group's presence is in the convergence
# digest, so a delete that doesn't propagate diverges the replicas.
#
# Pre-slice behaviour (the red): delete_group records a group tombstone
# (since 5b) but ingest_peer never CONSUMES it — reconcile_peer_groups
# only walks groups the peer still HOLDS, so a peer-deleted group was
# invisible and lingered locally forever.
#
# Two legs: an EMPTY shared group (clean delete), and a shared group
# whose ENTRY is deleted by the same side (the entry tombstone + the
# group tombstone must both propagate, leaving B's group empty then
# removed).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Empty" >/dev/null
"$KEYHOLE" create-group "$A" "Full" >/dev/null
empty="$("$KEYHOLE" list-groups "$A" | awk '/Empty/ {print $1}' | head -1)"
full="$("$KEYHOLE" list-groups "$A" | awk '/Full/ {print $1}' | head -1)"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
has_group() { "$KEYHOLE" list-groups "$1" | grep "$2" >/dev/null; }

# --- leg 1: delete an EMPTY shared group on A → B removes it --------
sleep 1.1
"$KEYHOLE" delete-group "$A" "$empty" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
if has_group "$B" "$empty"; then
    echo "FAIL: peer-deleted empty group was not removed on B"; exit 1
fi
converged || { echo "FAIL: replicas diverged after empty-group delete"; exit 1; }

# --- leg 2: delete a NON-empty group (cascade) → B converges -------
# Put an entry into Full on BOTH (shared base had Full empty; create the
# entry on A, sync so B has it too), then A deletes Full.
"$KEYHOLE" create-entry "$A" "Doomed" --username d >/dev/null
ent="$("$KEYHOLE" list "$A" | awk '/Doomed/ {print $1; exit}')"
"$KEYHOLE" move-entry "$A" "$ent" --to "$full" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
converged || { echo "FAIL(precondition): B did not pick up the entry in Full"; exit 1; }

sleep 1.1
"$KEYHOLE" delete-group "$A" "$full" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
if has_group "$B" "$full"; then
    echo "FAIL: peer-deleted non-empty group was not removed on B"; exit 1
fi
"$KEYHOLE" list "$B" | grep "$ent" >/dev/null \
    && { echo "FAIL: cascade-deleted entry still present on B"; exit 1; } || true
converged || { echo "FAIL: replicas diverged after non-empty-group delete"; exit 1; }

# --- and the deletions survive a fresh disk read -------------------
rm -rf "$A.mirror" "$B.mirror"
has_group "$B" "$empty" && { echo "FAIL: empty-group delete did not persist"; exit 1; } || true
has_group "$B" "$full" && { echo "FAIL: full-group delete did not persist"; exit 1; } || true
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: cross-peer group delete (empty + cascade) propagates and converges, surviving reopen"
