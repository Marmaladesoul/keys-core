#!/usr/bin/env bash
#
# Scenario: active attacks on the exchange give an attacker nothing beyond
# the one counted guess a run costs.
#
# - A refusal can't hand a spent guess back. Once the typing side's Reply is
#   out, whoever holds it can test one guess at the code, so a forged "busy"
#   refusal in answer to it counts as a failed run: three, and the typing
#   side's sheet is a dead end.
# - The typing side listens only to the displaying side it was opened
#   against. A third endpoint's forged refusal or Share changes nothing.
#   The displaying side, mid-run, ignores a third endpoint's Reply and
#   turns its Hello away as busy; the run in flight still verifies.
# - A Hello the displaying side can't run (an unknown protocol version) is
#   refused without a run: the code showing survives and still verifies.
# - Giving up on a run in flight counts as a failed run on that side.
# - A Reply replayed from an earlier run fails the run it is replayed into,
#   even though it was made with a right code. (A run burns its code, so the
#   sheets can't show the session-id binding by itself; a unit test in
#   keys-pairing does, with one code across two runs.)
# - A code a failed run burnt doesn't work again.
# - Messages out of turn are ignored or turned away without disturbing a run
#   in flight, or fail the run they land in.
# - A Confirm that never arrives costs the typing side a run (its guess was
#   spent when its Reply left) and leaves the displaying side "verified,
#   awaiting peer": not paired, and its session unable to send.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# 1. An impostor at the displaying endpoint harvests Replies and refuses each.
sim --attack refuse-after-reply
expect "type: run-failed failure=refused-by-peer runs-left=2"
expect "type: run-failed failure=refused-by-peer runs-left=1"
expect "type: dead-end failure=refused-by-peer"
expect "type: status dead-end"
expect "result: not-verified"
refute "type: no-run reason=busy"
[ "$(count "wire: reply answered with a forged busy refusal")" = 3 ] \
    || { echo "FAIL: the typing side allowed other than three harvested Replies"; echo "$OUT"; exit 1; }

# 2. A stranger injects into the typing side mid-run; the run still verifies.
for kind in device person; do
    sim --kind "$kind" --attack stranger
    expect "type: stranger dead-end refusal ignored"
    expect "type: stranger share ignored"
    expect "display: stranger reply ignored"
    expect "display: stranger hello no-run reason=busy"
    expect "result: verified"
done

# 3. A replayed Reply.
sim --attack replay-reply
expect "wire: reply withheld"
expect "display: abandoned run-failed failure=abandoned runs-left=2"
expect "type: abandoned run-failed failure=abandoned runs-left=2"
expect "wire: replayed the first attempt's reply"
expect "display: run-failed failure=confirmation-failed runs-left=1"
expect "result: verified"

# 4. A burnt code, typed again.
sim --attack reuse-burnt-code
expect "type: retypes the burnt code"
expect "display: run-failed failure=confirmation-failed runs-left=1"
expect "result: verified"

# 5. Messages out of turn.
sim --attack out-of-order
expect "display: reply-before-hello ignored"
expect "display: second-hello no-run reason=busy"
expect "type: run-failed failure=malformed-message runs-left=2"
expect "result: verified"

# 6. The Confirm is lost.
sim --attack drop-confirm
expect "display: verified kind=device"
expect "type: lost-run failure=timed-out runs-left=2"
expect "display: verified-awaiting-peer"
expect "session: display peer-confirmed no"
expect "session: display-sends-first refused"
refute "display: verified"
expect "result: not-verified"

# 7. A Hello of a version the sheet doesn't run, before the genuine one.
sim --attack unusable-hello
expect "display: unusable-hello no-run reason=unsupported"
expect "display: code-kept yes"
expect "result: verified"
refute "display: showing reason=run-failed runs-left=2"

echo "PASS: forged refusals, strangers, replays, burnt codes, out-of-turn messages, a lost Confirm and an unusable Hello gain nothing"
