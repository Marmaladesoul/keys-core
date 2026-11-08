#!/usr/bin/env bash
#
# Scenario: organising INSIDE the recycle bin. A recycled entry and a
# recycled group are moved (`move_entry` / `move_group`) from the bin's
# top level into a subfolder of the bin. Asserted from disk (mirror
# nuked → fresh ingest):
#
#   1. the parent changed — the entry is listed directly under the
#      subfolder, the group is a direct child of the subfolder, and
#      neither is still at the bin's top level;
#   2. both are STILL recycled — the entry (and an entry buried in the
#      moved group) match `search --bin only`, drop out of
#      `search --bin exclude`, and are absent from the live count; the
#      moved group is still inside the bin's subtree;
#   3. the entry's recorded origin (KDBX 4.1 <PreviousParentGroup>)
#      survives the bin → bin move: restoring it afterwards returns it
#      to the live folder it was recycled FROM, not to the root. A
#      bin → bin move must not overwrite the origin with a bin group —
#      the same clobber a double-recycle is guarded against.
#
# Contract this pins for clients: a move whose source and destination
# are both inside the bin subtree is an ordinary re-parent that leaves
# the item recycled — not a restore, and not a no-op. (A move INTO the
# bin subtree is a recycle and a move OUT is a restore; this is the
# third case, bin → bin.)

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/move-within-bin.kdbx"

cold() { rm -rf "$VAULT.mirror"; "$KEYHOLE" "$@"; }

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" ensure-bin "$VAULT" >/dev/null
bin="$("$KEYHOLE" inspect "$VAULT" | awk '/^bin uuid:/ {print $3}')"
[ -n "$bin" ] && [ "$bin" != "none" ] || { echo "FAIL: no recycle bin group"; exit 1; }

# --- seed: one recycled entry, one recycled group (with an entry) -----
# The entry lives in a live subfolder first, so its recorded origin is
# distinguishable from restore's root fallback.
"$KEYHOLE" create-group "$VAULT" "Nest" >/dev/null
nest="$("$KEYHOLE" child-groups "$VAULT" | awk '$2 == "Nest" {print $1; exit}')"
"$KEYHOLE" create-entry "$VAULT" "Gull-login" --username gull --group "$nest" >/dev/null
gull="$("$KEYHOLE" list "$VAULT" | awk '/Gull-login/ {print $1; exit}')"
"$KEYHOLE" recycle "$VAULT" "$gull" >/dev/null

"$KEYHOLE" create-group "$VAULT" "Crate" >/dev/null
crate="$("$KEYHOLE" child-groups "$VAULT" | awk '$2 == "Crate" {print $1; exit}')"
"$KEYHOLE" create-entry "$VAULT" "Cargo-login" --username cargo --group "$crate" >/dev/null
cargo_uuid="$("$KEYHOLE" list "$VAULT" | awk '/Cargo-login/ {print $1; exit}')"
"$KEYHOLE" recycle-group "$VAULT" "$crate" >/dev/null

# The bin subfolder the user drops onto.
"$KEYHOLE" create-group "$VAULT" "Sorted" --parent "$bin" >/dev/null
sorted="$("$KEYHOLE" child-groups "$VAULT" --parent "$bin" | awk '$2 == "Sorted" {print $1; exit}')"
[ -n "$sorted" ] || { echo "FAIL: could not create a subfolder of the bin"; exit 1; }

# Preconditions, from disk: both start at the bin's top level.
cold list "$VAULT" --group "$bin" | grep "$gull" >/dev/null \
    || { echo "FAIL(setup): recycled entry not at the bin's top level"; exit 1; }
cold child-groups "$VAULT" --parent "$bin" | grep "$crate" >/dev/null \
    || { echo "FAIL(setup): recycled group not at the bin's top level"; exit 1; }
live_before="$(cold live-count "$VAULT")"
[ "$live_before" = "0" ] || { echo "FAIL(setup): live count $live_before, want 0"; exit 1; }

# --- the move: bin → bin subfolder ------------------------------------
"$KEYHOLE" move-entry "$VAULT" "$gull" --to "$sorted" >/dev/null
"$KEYHOLE" move-group "$VAULT" "$crate" --to "$sorted" >/dev/null

# --- 1) parent changed (from disk) ------------------------------------
cold list "$VAULT" --group "$sorted" | grep "$gull" >/dev/null \
    || { echo "FAIL: entry not under the bin subfolder after move + reopen"; exit 1; }
if cold list "$VAULT" --group "$bin" | grep "$gull" >/dev/null; then
    echo "FAIL: entry still at the bin's top level after move + reopen"; exit 1
fi
cold child-groups "$VAULT" --parent "$sorted" | grep "$crate" >/dev/null \
    || { echo "FAIL: group not under the bin subfolder after move + reopen"; exit 1; }
if cold child-groups "$VAULT" --parent "$bin" | grep "$crate" >/dev/null; then
    echo "FAIL: group still at the bin's top level after move + reopen"; exit 1
fi

# --- 2) still recycled (from disk) ------------------------------------
for name in Gull-login Cargo-login; do
    cold search "$VAULT" "$name" --bin only | grep -- "$name" >/dev/null \
        || { echo "FAIL: $name no longer in the bin after a bin → bin-subfolder move"; exit 1; }
    if cold search "$VAULT" "$name" --bin exclude | grep -- "$name" >/dev/null; then
        echo "FAIL: $name surfaced as live after a bin → bin-subfolder move"; exit 1
    fi
done
live_after="$(cold live-count "$VAULT")"
[ "$live_after" = "0" ] || { echo "FAIL: live count $live_after after the move, want 0 (something was restored)"; exit 1; }
cold groups-in-subtree "$VAULT" "$bin" | grep "$crate" >/dev/null \
    || { echo "FAIL: moved group left the bin subtree"; exit 1; }
cold entries-in-subtree "$VAULT" "$bin" | grep "$cargo_uuid" >/dev/null \
    || { echo "FAIL: entry inside the moved group left the bin subtree"; exit 1; }

# --- 3) the origin survives the bin → bin move -------------------------
rm -rf "$VAULT.mirror"
"$KEYHOLE" restore "$VAULT" "$gull" >/dev/null
cold list "$VAULT" --group "$nest" | grep "$gull" >/dev/null \
    || { echo "FAIL: restore after a bin → bin move did not return the entry to its original folder (origin clobbered by the move)"; exit 1; }

echo "PASS: bin → bin-subfolder moves re-parent the entry and the group, leave both recycled, and keep the entry's restore origin (via full KDBX round-trip)"
