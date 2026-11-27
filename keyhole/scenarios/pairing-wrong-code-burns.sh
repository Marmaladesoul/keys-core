#!/usr/bin/env bash
#
# Scenario: one run per code. A wrong code (a typo, or a stale code after
# "New Code") burns that code: the displaying side shows a new one, both
# sides lose one run of three, and the next, right code still verifies.
# "New Code" itself is a local re-roll and spends nothing.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# A typo, then the right code.
sim --typos 1
expect "display: run-failed failure=confirmation-failed runs-left=2"
expect "type: run-failed failure=refused-by-peer runs-left=2"
expect "display: showing reason=run-failed runs-left=2"
expect "display: verified kind=device"
expect "type: verified kind=device"
expect "result: verified"

# Two typos: two runs spent, the third verifies.
sim --typos 2
expect "display: run-failed failure=confirmation-failed runs-left=1"
expect "result: verified"

# The person reads the code, someone presses New Code, the old code is typed.
sim --reroll-then-type-stale
expect "display: new-code"
expect "display: run-failed failure=confirmation-failed runs-left=2"
expect "result: verified"

echo "PASS: a wrong or stale code burns one run and a fresh code; the right code then verifies"
