#!/usr/bin/env bash
#
# Scenario: "two devices edit the same entry while apart; the conflict
# parks instead of clobbering, survives across separate keyhole
# processes, and resolves to convergence" — the headless encoding of
# the offline sync-divergence loop the GUI resolver handles.
#
# The persistent per-vault mirror is what's really under test here:
# every step runs in a FRESH keyhole process, so the held conflict that
# `ingest-peer` parks must be carried by `<vault>.mirror/` (exactly as
# a real client's local store carries it across relaunches) for
# `list-conflicts` / `resolve` to see it. An ephemeral mirror fails
# this scenario at the very first list-conflicts.
#
# Teeth: we assert the conflict IS held after ingest (a merge that
# silently clobbers one side would show zero conflicts and fail), and
# the final convergence is read after deleting the mirror — forcing a
# re-ingest from the KDBX, the only honest "did the resolution save?".

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/device-a.kdbx"
PEER="$TMP/device-b.kdbx"

# --- seed: one vault, one entry, then "sync" it to a second device ---
"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Shared Login" --username original >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Shared Login/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL: could not find seeded entry"; exit 1; }
cp "$VAULT" "$PEER"

# --- diverge while "offline": same entry, different edits ------------
"$KEYHOLE" update-entry "$VAULT" "$uuid" --username alice >/dev/null
"$KEYHOLE" update-entry "$PEER"  "$uuid" --username bob   >/dev/null

# --- device B's vault arrives at device A: park, don't clobber -------
"$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-b >/dev/null

# --- the fork-A assertion: a SEPARATE process sees the held conflict -
"$KEYHOLE" list-conflicts "$VAULT" | grep -q "$uuid" \
    || { echo "FAIL: conflict not held across invocations (persistent mirror broken?)"; exit 1; }

# --- the payload names the diverged field, both sides intact ---------
payload="$("$KEYHOLE" show-conflict "$VAULT" --entry "$uuid")"
echo "$payload" | grep -q 'field UserName' \
    || { echo "FAIL: expected a UserName field delta in:"; echo "$payload"; exit 1; }
echo "$payload" | grep -q 'username="alice"' \
    || { echo "FAIL: local side (alice) missing from payload"; exit 1; }
echo "$payload" | grep -q 'username="bob"' \
    || { echo "FAIL: remote side (bob) missing from payload"; exit 1; }

# --- resolve choosing the peer side, again in a fresh process --------
"$KEYHOLE" resolve "$VAULT" --entry "$uuid" --choose remote >/dev/null

"$KEYHOLE" list-conflicts "$VAULT" | grep -q '(no held conflicts)' \
    || { echo "FAIL: conflict still held after resolve"; exit 1; }

# --- convergence must be ON DISK: nuke the mirror, re-ingest, check --
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" | grep -q '<bob>' \
    || { echo "FAIL: resolved username (bob) did not persist to the KDBX"; exit 1; }

echo "PASS: offline divergence parks as a held conflict, survives process boundaries, and resolves to a converged on-disk vault"
