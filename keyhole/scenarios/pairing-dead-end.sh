#!/usr/bin/env bash
#
# Scenario: at most three runs per open sheet. Three failed runs, whoever
# made them, land both sides on the dead end and the sheet accepts nothing
# more.
#
#   1. The person mistypes three times: both sides dead-end.
#   2. An impostor on another endpoint makes three guesses before the genuine
#      typer gets a turn: the displaying sheet dead-ends, and when the
#      genuine typer then tries, it is told so and stops too. An impostor
#      gets three blind one-in-a-million guesses per sheet, no more.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

sim --typos 3
expect "display: run-failed failure=confirmation-failed runs-left=1"
expect "display: dead-end failure=confirmation-failed"
expect "type: dead-end failure=peer-dead-end"
expect "type: status dead-end"
expect "result: not-verified"
refute "display: verified kind=device"

sim --impostor-guesses 3
[ "$(count "display: impostor run-failed failure=confirmation-failed runs-left=2")" = 1 ] \
    || { echo "FAIL: first impostor guess"; echo "$OUT"; exit 1; }
expect "display: impostor dead-end failure=confirmation-failed"
expect "display: no-run reason=dead-end"
expect "type: dead-end failure=peer-dead-end"
expect "result: not-verified"

echo "PASS: three failed runs dead-end the sheet on both sides, impostor guesses included"
