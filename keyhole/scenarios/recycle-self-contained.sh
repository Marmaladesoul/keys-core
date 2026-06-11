#!/usr/bin/env bash
#
# Scenario: the recycle-into-bin behaviour, seeded ENTIRELY through
# keyhole (create + create-entry) — no keepassxc-cli. A *Keys*-created
# vault has its bin eagerly created at birth, so this exercises a normal
# soft-recycle into the existing bin, surviving a from-disk reopen.
#
# Its sibling `recycle-persists.sh` seeds via keepassxc-cli on purpose: an
# independent implementation building the KDBX keeps us honest (and that
# vault is binless, so it also covers the lazy-create safety net). Keep both.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/self.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Keep Me"    --username keep >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Recycle Me" --username bin  >/dev/null

uuid="$("$KEYHOLE" list "$VAULT" | awk '/Recycle Me/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL: could not find seeded entry"; exit 1; }

# From-disk read: the persistent mirror would otherwise carry unsaved
# state across processes, so nuke it to force a re-ingest of the KDBX.
bin_count() { rm -rf "$VAULT.mirror"; "$KEYHOLE" inspect "$VAULT" | awk '/^recycled:/ {print $2}'; }

[ "$(bin_count)" = "0" ] || { echo "FAIL: expected an empty bin to start"; exit 1; }

"$KEYHOLE" recycle "$VAULT" "$uuid" --no-save >/dev/null
[ "$(bin_count)" = "0" ] || { echo "FAIL: --no-save persisted across reopen"; exit 1; }

"$KEYHOLE" recycle "$VAULT" "$uuid" >/dev/null
[ "$(bin_count)" = "1" ] || { echo "FAIL: recycle did not persist into the bin"; exit 1; }

echo "PASS: Keys-created vault soft-recycles into its (eagerly-created) bin, surviving reopen"
