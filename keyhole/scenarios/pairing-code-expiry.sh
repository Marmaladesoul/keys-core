#!/usr/bin/env bash
#
# Scenario: codes expire and runs time out, on the sheet's injectable clock
# (no sleeps).
#
#   1. The code expires before it's typed and the sheet hasn't replaced it
#      yet: the displaying side refuses the Hello without a run (no run
#      spent on either side), shows a new code marked "expired", and that
#      code verifies.
#   2. The same, but the sheet has already replaced the expired code (its
#      status was polled, as a sheet on screen is): the stale code costs one
#      run on each side, like any wrong code.
#   3. A run stalls past the run timeout: it counts as a failed run on both
#      sides, a new code is shown, and the next run verifies. The displaying
#      side, which only polls its status, can still say what the run was
#      lost to.
#   4. Each of the typing side's two waits is timed from when it began: a
#      Share and then a Confirm that each arrive just inside the run
#      timeout verify, though the run took nearly twice the timeout.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

sim --expire-before-typing
expect "display: no-run reason=code-expired"
expect "type: no-run reason=code-expired"
expect "display: showing reason=expired runs-left=3"
expect "result: verified"
refute "display: run-failed failure=confirmation-failed runs-left=2"

# The realistic path: the sheet is on screen, so its status has been polled
# and the expired code already replaced when the stale one is typed. The
# Hello can't say which code it was typed from, so it meets the new code and
# fails like any wrong code: one run on each side.
sim --expire-then-poll
expect "display: showing reason=expired runs-left=3"
expect "display: run-failed failure=confirmation-failed runs-left=2"
expect "type: run-failed failure=refused-by-peer runs-left=2"
refute "display: no-run reason=code-expired"
expect "result: verified"

sim --stall
expect "type: run-failed failure=timed-out runs-left=2"
expect "display: showing reason=run-failed runs-left=2"
expect "display: lost-run failure=timed-out"
expect "result: verified"

sim --slow-legs
[ "$(count "clock: just under run timeout")" = 2 ] \
    || { echo "FAIL: expected two slow legs"; echo "$OUT"; exit 1; }
expect "type: verified kind=device"
expect "result: verified"
refute "display: showing reason=run-failed runs-left=2"

echo "PASS: an expired code is replaced; its Hello costs nothing before the replacement and one run after; a stalled run times out as a failure; each wait is timed afresh"
