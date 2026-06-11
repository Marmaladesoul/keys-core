#!/usr/bin/env bash
#
# Scenario: "a new Keys-created vault has the recycle bin enabled" — so a
# user's very first 'Move to Trash' is recoverable rather than a silent
# permanent delete. Drives keyhole's `create` (the same
# Vault::create_empty the GUI uses), then asserts the flag via a fresh
# reopen. Self-contained: no keepassxc-cli.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/fresh.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null

field() { "$KEYHOLE" inspect "$VAULT" | awk -F': *' -v k="$1" '$1 == k {print $2}'; }

state="$(field 'recycle bin')"
[ "$state" = "enabled" ] || { echo "FAIL: new vault recycle bin is '$state', want 'enabled'"; exit 1; }

# Eager-created: the bin *group* exists from birth (fixed UUID before any
# sync), not just the flag.
group="$(field 'bin group')"
[ "$group" = "present" ] || { echo "FAIL: new vault bin group is '$group', want 'present'"; exit 1; }

echo "PASS: new Keys-created vault has the recycle bin enabled AND the group eagerly created"
