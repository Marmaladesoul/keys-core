#!/usr/bin/env bash
#
# Scenario: a device pairing over the real transport, found three ways.
#
# Every party is a node of its own on the loopback interface, and the
# sheets are given the endpoint ids the transport authenticated. The device
# already in the account shows the code and the new one types it, except
# where the direction is flipped.
#
#  - nearby: the new device advertises while its sheet is open, and the
#    device in the account approaches the address it discovered;
#  - somewhere else: the new device shows a `keys://pair/device/…` link that
#    carries its endpoint id and nothing to dial directly;
#  - flipped: the new device shows the code and the other one calls it.
#
# Also pins: a wrong code costs one run and the next run is a fresh stream
# on the same connection; and a stranger on the network who reaches the new
# device first gets one failed run out of it, never a pairing, while the
# real device is told the new one is busy until the person turns the
# stranger away.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# Nearby: advertisement, approach, code, session.
net --flow device-nearby --payload "opaque bundle"
expect "new: listening role=type kind=device"
# A fresh loopback node has no relay: version and endpoint id, nothing else.
expect "new: advertising service=_keys-pair._udp txt-keys=v,id"
expect "trusted: discovered endpoint-matches=yes direct-addresses=1"
expect "trusted: approach accepted"
expect "new: approached by=trusted"
expect "trusted: verified kind=device"
expect "new: verified kind=device"
expect "session: type-to-display ok"
expect "session: display-to-type ok"
expect "result: verified"
no_code_in_output

# Somewhere else: the address link, and a typo on the way.
net --flow device-link --typos 1
expect "trusted: parsed device-link endpoint-matches=yes"
expect "trusted: run-failed failure=confirmation-failed runs-left=2"
expect "new: run-failed failure=refused-by-peer runs-left=2"
expect "trusted: verified kind=device"
expect "new: verified kind=device"
expect "result: verified"
[ "$(count "new: submit")" = "2" ] || { echo "FAIL: expected two typed codes:"; echo "$OUT"; exit 1; }
# The link is an endpoint id and an empty relay, with a version and a
# checksum: 38 bytes, so 76 hex characters after the path. Nothing else
# fits in it.
LINK="$(link_line)"
case "$LINK" in
    keys://pair/device/*) ;;
    *) echo "FAIL: not a device link: $LINK"; exit 1 ;;
esac
BODY="${LINK#keys://pair/device/}"
[ "${#BODY}" = "76" ] || { echo "FAIL: device link body is ${#BODY} characters, expected 76"; exit 1; }

# Three typos spend the sheet on both sides; nothing pairs.
net --flow device-nearby --typos 3
expect "trusted: dead-end failure=confirmation-failed"
expect "new: dead-end failure=peer-dead-end"
expect "new: status dead-end"
expect "result: not-verified"
refute "trusted: verified kind=device"

# Flipped: the new device shows the code, the device in the account calls.
net --flow device-flipped
expect "new: listening role=display kind=device"
expect "trusted: call accepted"
expect "trusted: submit"
expect "new: verified kind=device"
expect "trusted: verified kind=device"
expect "result: verified"

# A stranger gets there first.
net --flow device-nearby --attack stranger-first
expect "stranger: approach accepted"
expect "new: approached by=stranger"
expect "trusted: approach busy"
expect "stranger: run-failed failure=confirmation-failed runs-left=2"
expect "new: run-failed failure=refused-by-peer runs-left=2"
refute "stranger: verified kind=device"
before "new: dismissed stranger" "trusted: approach accepted"
expect "new: approached by=trusted"
expect "trusted: verified kind=device"
expect "new: verified kind=device"
expect "result: verified"

echo "PASS: a device pairing verifies over the transport by advertisement, address link and flipped direction; a stranger who approaches first gets a failed run and no pairing"
