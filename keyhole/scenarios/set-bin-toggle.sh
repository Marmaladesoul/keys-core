#!/usr/bin/env bash
#
# Scenario: the recycle-bin toggle — the behaviour behind the Vault
# Info on/off switch (agreed design from the KeysCore #136 review:
# respect the per-vault setting; bin disabled = permanent delete).
#
#   1. Disable (keep): designation cleared, the old group survives as
#      an ordinary group, and a recycle is now a PERMANENT tombstoned
#      delete.
#   2. Re-enable: a bin group is auto-created (no group picker) and
#      recycling is recoverable again.
#   3. Disable (--delete-bin-contents): the bin group AND its contents
#      are gone for good.
#
# Every persistence assertion crosses a mirror-nuked reopen.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/toggle.kdbx"

field() { rm -rf "$VAULT.mirror"; "$KEYHOLE" inspect "$VAULT" | awk -F': *' -v k="$1" '$1 == k {print $2}'; }

"$KEYHOLE" create "$VAULT" >/dev/null
for t in keeper victim-one victim-two; do
    "$KEYHOLE" create-entry "$VAULT" "$t" --username u >/dev/null
done
[ "$(field 'recycle bin')" = "enabled" ] || { echo "FAIL: new vault should have bin enabled"; exit 1; }

# --- 1. disable, keeping the group --------------------------------------
"$KEYHOLE" set-bin "$VAULT" off >/dev/null
[ "$(field 'recycle bin')" = "disabled" ] || { echo "FAIL: disable did not persist"; exit 1; }
[ "$(field 'bin group')" = "absent" ] || { echo "FAIL: designation not cleared"; exit 1; }
"$KEYHOLE" list-groups "$VAULT" | grep -q "Recycle Bin" \
    || { echo "FAIL: disable (keep) should leave the old group as an ordinary group"; exit 1; }
"$KEYHOLE" list-groups "$VAULT" | grep "Recycle Bin" | grep -q '\[bin\]' \
    && { echo "FAIL: kept group still flagged as the bin"; exit 1; }

# Bin off ⇒ recycling is PERMANENT (engine policy, tombstoned).
v1="$("$KEYHOLE" list "$VAULT" | awk '/victim-one/ {print $1; exit}')"
"$KEYHOLE" recycle "$VAULT" "$v1" >/dev/null
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" | grep -q "$v1" \
    && { echo "FAIL: bin-off recycle did not permanently delete"; exit 1; }
[ "$(field 'entries')" = "2" ] || { echo "FAIL: expected 2 entries after permanent delete"; exit 1; }

# --- 2. re-enable: auto-create, recoverable again ------------------------
"$KEYHOLE" set-bin "$VAULT" on >/dev/null
[ "$(field 'recycle bin')" = "enabled" ] || { echo "FAIL: enable did not persist"; exit 1; }
[ "$(field 'bin group')" = "present" ] || { echo "FAIL: enable did not auto-create/designate a bin"; exit 1; }

v2="$("$KEYHOLE" list "$VAULT" | awk '/victim-two/ {print $1; exit}')"
"$KEYHOLE" recycle "$VAULT" "$v2" >/dev/null
[ "$(field 'recycled')" = "1" ] || { echo "FAIL: bin-on recycle should be recoverable"; exit 1; }

# --- 3. disable, deleting bin + contents ---------------------------------
"$KEYHOLE" set-bin "$VAULT" off --delete-bin-contents >/dev/null
[ "$(field 'recycle bin')" = "disabled" ] || { echo "FAIL: disable(delete) did not persist"; exit 1; }
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" | grep -q "$v2" \
    && { echo "FAIL: bin contents survived --delete-bin-contents"; exit 1; }
[ "$(field 'entries')" = "1" ] || { echo "FAIL: expected only 'keeper' to remain"; exit 1; }

echo "PASS: bin toggle — disable keeps the group + makes deletes permanent; enable auto-creates; disable+delete removes bin and contents"
