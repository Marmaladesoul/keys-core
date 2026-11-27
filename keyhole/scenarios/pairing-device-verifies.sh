#!/usr/bin/env bash
#
# Scenario: a device pairing with the right code verifies on both sides and
# yields a session that carries an opaque payload both ways.
#
# Also pins the "nothing moves until both confirmations verify" rule at the
# session: the displaying side (the device already in the account) can't
# send until it has opened a frame from the typing side, which proves the
# typing side verified it. And frames can't be replayed. The code itself
# never appears in the driver's output.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

sim --kind device --payload "opaque bundle"
expect "display: showing reason=opened runs-left=3"
expect "display: verified kind=device"
expect "type: verified kind=device"
# Holding a session is not yet "paired" on the displaying side: its status
# turns from awaiting-peer to verified on the typing side's first frame.
expect "display: verified-awaiting-peer"
expect "display: verified"
expect "session: display-sends-first refused"
expect "session: stranger-frame ignored"
expect "session: stray-exchange-message ignored"
expect "session: type-to-display ok"
expect "session: display-to-type ok"
expect "session: replay rejected"
expect "session: after-rejection refuses-everything"
expect "result: verified"
if grep -qE '[0-9]{6}' <<<"$OUT"; then echo "FAIL: a six-digit run in the output:"; echo "$OUT"; exit 1; fi

echo "PASS: device pairing verifies both sides; the session speaks typer-first, listens only to its peer and refuses replays"
