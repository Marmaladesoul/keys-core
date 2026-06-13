#!/usr/bin/env bash
#
# Scenario: 5d cross-peer group delete, option-2 semantics (CONTENT
# SAVES THE GROUP). When one device deletes a group while another adds
# content into it, the group SURVIVES with the content (the delete is
# overridden — the deleter wouldn't have deleted a group someone was
# actively filling), and the replicas converge. A truly-empty group
# that's deleted with no content anywhere still gets deleted.
#
# Convergence relies on deciding group liveness from the MERGED tree
# (does the tombstoned group have a live descendant?), computed
# identically on both devices — not from transient ingest-time
# emptiness (the ~5% divergence the prior empty-only rule produced).
#
# Non-sticky: content resurrects the group permanently (the delete is
# forgotten); a later emptying leaves an ordinary empty group, it does
# NOT re-delete. See DESIGN.md.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Box" >/dev/null
"$KEYHOLE" create-group "$A" "Empty" >/dev/null
"$KEYHOLE" create-entry "$A" "Loose" --username l >/dev/null
box="$("$KEYHOLE" list-groups "$A" | awk '/Box/ {print $1}' | head -1)"
empty="$("$KEYHOLE" list-groups "$A" | awk '/Empty/ {print $1}' | head -1)"
ent="$("$KEYHOLE" list "$A" | awk '/Loose/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
has_group() { "$KEYHOLE" list-groups "$1" | grep "$2" >/dev/null; }

# --- content saves the group: A deletes Box, B fills it -------------
sleep 1.1
"$KEYHOLE" delete-group "$A" "$box" >/dev/null
"$KEYHOLE" move-entry "$B" "$ent" --to "$box" >/dev/null

"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

has_group "$A" "$box" || { echo "FAIL: Box deleted on A despite B's content (delete should lose)"; exit 1; }
has_group "$B" "$box" || { echo "FAIL: Box not present on B"; exit 1; }
[ "$("$KEYHOLE" list "$A" --group "$box" | grep -c "$ent")" = 1 ] \
    || { echo "FAIL: the entry isn't in the resurrected Box on A"; exit 1; }
converged || { echo "FAIL: replicas diverged after delete-vs-fill"; exit 1; }

# --- truly-empty delete still stands --------------------------------
sleep 1.1
"$KEYHOLE" delete-group "$A" "$empty" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
if has_group "$B" "$empty"; then
    echo "FAIL: empty deleted group should be removed on B"; exit 1
fi
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
converged || { echo "FAIL: replicas diverged after empty-group delete"; exit 1; }

# --- survives reopen ------------------------------------------------
rm -rf "$A.mirror" "$B.mirror"
has_group "$A" "$box" || { echo "FAIL: resurrected Box did not persist"; exit 1; }
has_group "$A" "$empty" && { echo "FAIL: empty-group delete did not persist"; exit 1; } || true
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: content saves a deleted group (converges); a truly-empty deleted group stays deleted"
