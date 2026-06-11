#!/usr/bin/env bash
#
# Scenario: a vault handed to us enabled-but-binless (e.g. a keepassxc-cli
# import) gets its bin group created when added — the `ensure-bin` hook the
# GUI runs on first-add. After that we're never holding an enabled-but-binless
# vault, so the first recycle is an ordinary move into an existing bin (no lazy
# create, no cross-peer race).
#
# Seeded via keepassxc-cli on purpose (independent implementation = honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/imported.kdbx"

printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null

field() { "$KEYHOLE" inspect "$VAULT" | awk -F': *' -v k="$1" '$1 == k {print $2}'; }

# keepassxc leaves the flag enabled but no bin group.
[ "$(field 'recycle bin')" = "enabled" ] || { echo "FAIL: expected bin enabled"; exit 1; }
[ "$(field 'bin group')" = "absent" ]    || { echo "FAIL: expected no bin group yet"; exit 1; }

"$KEYHOLE" ensure-bin "$VAULT" >/dev/null

# Survives reopen from disk: nuke the persistent mirror to force a
# re-ingest of the KDBX — a warm mirror would pass even without a save.
rm -rf "$VAULT.mirror"
[ "$(field 'bin group')" = "present" ] || { echo "FAIL: ensure-bin did not persist a bin group"; exit 1; }

echo "PASS: ensure-bin creates + persists the bin group for an imported enabled-but-binless vault"
