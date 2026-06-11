#!/usr/bin/env bash
#
# Scenario: "recycle moves the entry to the bin and that survives a
# close+reopen from disk" — the headless encoding of the Mac-app bug
# where deleting an entry was either lost on relaunch (no save) or, worse,
# a silent permanent delete (no bin group).
#
# The vault here has the recycle-bin flag enabled but NO bin group yet
# (the state keepassxc-cli — and, before the fix, a fresh Keys vault —
# leaves it in). Correct behaviour: the first recycle lazily creates the
# bin and soft-recycles into it. We assert that by re-opening the KDBX in
# a FRESH keyhole process (the only honest test of "did it hit disk") and
# counting the bin.
#
# Teeth: `--no-save` must NOT persist. A test that can't fail isn't a test.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# --- seed: an enabled-but-binless vault with two entries -------------
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username keep "$VAULT" "Keep Me"    >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username bin  "$VAULT" "Recycle Me" >/dev/null

uuid="$("$KEYHOLE" list "$VAULT" | awk '/Recycle Me/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL: could not find seeded entry"; exit 1; }

# Entries sitting in the recycle bin, as seen by a FRESH reopen from disk.
# The mirror is persistent (it carries unsaved state across processes,
# like a real client's local store), so the honest "did it hit the KDBX?"
# read must remove it first to force a re-ingest.
bin_count() { rm -rf "$VAULT.mirror"; "$KEYHOLE" inspect "$VAULT" | awk '/^recycled:/ {print $2}'; }

[ "$(bin_count)" = "0" ] || { echo "FAIL: expected an empty bin to start"; exit 1; }

# --- teeth check: --no-save must NOT persist across reopen -----------
"$KEYHOLE" recycle "$VAULT" "$uuid" --no-save >/dev/null
n="$(bin_count)"
[ "$n" = "0" ] || { echo "FAIL: --no-save persisted ($n in bin after reopen)"; exit 1; }

# --- the real assertion: recycle WITH save survives reopen ----------
"$KEYHOLE" recycle "$VAULT" "$uuid" >/dev/null
n="$(bin_count)"
[ "$n" = "1" ] || { echo "FAIL: recycle did not persist into the bin ($n after reopen, want 1)"; exit 1; }

echo "PASS: recycle lazily creates the bin + soft-recycles, and it survives reopen; --no-save does not"
