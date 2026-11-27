#!/usr/bin/env bash
#
# Scenario: a device takes part in a pairing only while its sheet is open,
# and the transport holds callers to its limits.
#
#  - With no sheet open a device accepts no call and no approach, of either
#    kind, and tells a knock for an id it never issued that nothing is
#    outstanding. A refused call costs the typing side nothing: nothing was
#    typed.
#  - An open sheet accepts only the greeting that fits it: the same kind of
#    pairing, from the opposite role.
#  - Closing the sheet closes what it accepted. A run in flight ends, and
#    each side counts it as a failed run.
#  - A message longer than any exchange message is refused by the
#    transport; the run it interrupted fails and the sheet goes on to its
#    next code.
#  - A second caller at a busy displaying sheet is turned away at no cost,
#    and its hanging up doesn't end the run in flight with the first.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# No sheet open.
net --attack no-sheet
[ "$(count "stranger: call not-listening")" = "2" ] || { echo "FAIL: a call of each kind should find nobody listening:"; echo "$OUT"; exit 1; }
[ "$(count "stranger: approach not-listening")" = "2" ] || { echo "FAIL: an approach of each kind should find nobody listening:"; echo "$OUT"; exit 1; }
refute "stranger: call accepted"
refute "stranger: approach accepted"
expect "stranger: knock not-outstanding"
expect "quiet: invites-outstanding=0"

# A displaying sheet for a Person pairing: a device call, a person approach
# and a device approach are all turned away; a person call is accepted; and
# after the sheet closes, that one isn't either.
net --attack wrong-kind
expect "bob: listening role=display kind=person"
[ "$(count "stranger: approach not-listening")" = "2" ] || { echo "FAIL: both approaches should be turned away:"; echo "$OUT"; exit 1; }
before "stranger: call not-listening" "stranger: call accepted"
expect "bob: link from=stranger"
# The last thing that happens is the call after the close, turned away.
before "bob: link from=stranger" "bob: sheet closed"
[ "$(tail -1 <<<"$OUT")" = "stranger: call not-listening" ] || { echo "FAIL: the call after the close should be turned away:"; echo "$OUT"; exit 1; }
[ "$(count "stranger: call not-listening")" = "2" ] || { echo "FAIL: one wrong-kind call and one after the close should be turned away:"; echo "$OUT"; exit 1; }
[ "$(count "stranger: call accepted")" = "1" ] || { echo "FAIL: exactly one call should be accepted:"; echo "$OUT"; exit 1; }

# The displaying side closes its sheet mid-run.
net --attack sheet-closed-mid-run
expect "type: call accepted"
before "type: submit" "display: sheet closed"
expect "display: abandoned run-failed failure=abandoned runs-left=2"
expect "type: transport closed -> run-failed failure=abandoned runs-left=2"
expect "type: status awaiting-code runs-left=2"
# And the closed sheet takes no new call.
expect "type: call not-listening"
expect "result: not-verified"

# An oversize message where a Reply belongs, then an oversize Hello.
net --attack oversize
expect "mallory: sent 2048 bytes where a reply belongs"
expect "display: transport too-large -> run-failed failure=abandoned runs-left=2"
expect "mallory: oversize hello too-large"
expect "display: showing-code=yes"
expect "result: not-verified"

# Two callers at one displaying sheet. The second is told the sheet is
# busy, which costs it nothing, and hangs up; its connection failing leaves
# the first caller's run alone, and that run verifies.
net --attack second-caller
expect "display: second-caller no-run reason=busy"
expect "stranger: no-run reason=busy"
expect "stranger: status awaiting-code runs-left=3"
expect "display: second-caller-gone transport closed -> ignored"
expect "display: verified kind=device"
expect "type: verified kind=device"
expect "result: verified"

echo "PASS: no sheet, no pairing: calls and approaches are refused unless a matching sheet is open, closing it ends the run in flight, and an oversize message fails its run"
