#!/usr/bin/env bash
#
# Scenario: the confirmed transcript binds the endpoints and every message,
# and a Person pairing's account keys are signed over it, inside the
# session.
#
#   1. Spliced connection: the displaying side's transport reports a relay's
#      endpoint id, not the typer's. Even with the right code every run
#      fails, to the dead end.
#   2. Tampering with any one message fails that run: the displaying side's
#      nonce or its share (group element) in the Share, the typing side's
#      share in the Reply, the tag in the Confirm, a byte added to the end
#      of a Share or a Reply. A tampered confirm leaves the displaying side
#      holding a session the typer doesn't have; it reports "verified,
#      awaiting peer" and its session refuses to send.
#   3. Person pairing: each side ends up holding exactly the other's account
#      identity, recovery and encryption public keys, signed for this run.
#      They travel inside the verified session, after both confirmations:
#      the exchange's own messages are the same lengths as a device
#      pairing's and no account key appears in them, a wrong code ends the
#      run before any key set is sealed, and a key-set frame altered on the
#      wire fails the run on whichever side receives it.
#   4. Person pairing with a pinned identity (from an invite) that doesn't
#      match: every run fails on the side that pinned it. When that is the
#      typing side, the displaying side is left "verified, awaiting peer",
#      unable to send.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

sim --relay
expect "display: run-failed failure=confirmation-failed runs-left=2"
expect "display: dead-end failure=confirmation-failed"
expect "result: not-verified"

# The displaying side's nonce: the two sides' session ids differ, so the
# typing side's confirmation doesn't verify.
sim --tamper share
expect "wire: tampered share"
expect "display: run-failed failure=confirmation-failed runs-left=2"
expect "result: verified"

# The low bit of a share's first byte: every valid ristretto255 encoding has
# it clear, so the flipped share doesn't decode and the side that received
# it aborts. (A share altered into another valid point is a different key
# agreement; keys-pairing's unit tests cover that with the confirmation.)
sim --tamper share-point
expect "wire: tampered share point"
expect "type: run-failed failure=invalid-share runs-left=2"
expect "result: verified"

sim --tamper reply
expect "wire: tampered reply"
expect "display: run-failed failure=invalid-share runs-left=2"
expect "result: verified"

sim --tamper confirm
expect "wire: tampered confirm"
expect "type: run-failed failure=confirmation-failed runs-left=2"
expect "session: display-sends-first refused"
expect "display: verified-awaiting-peer"
expect "result: not-verified"

# The exchange has no associated data for either kind: a byte after a
# Share's share, or after a Reply's tag, is refused by whoever receives it.
for kind in device person; do
    sim --kind "$kind" --tamper share-trailing
    expect "wire: share with a trailing byte"
    expect "type: run-failed failure=malformed-message runs-left=2"
    expect "result: verified"

    sim --kind "$kind" --tamper reply-trailing
    expect "wire: reply with a trailing byte"
    expect "display: run-failed failure=malformed-message runs-left=2"
    expect "result: verified"
done

# What the exchange's four messages weigh, for a device pairing...
EXCHANGE_LENGTHS="wire: exchange-lengths hello=19 share=49 reply=97 confirm=65"
sim --kind device
expect "$EXCHANGE_LENGTHS"

# A Person pairing's exchange carries no account key: neither account's
# identity, recovery or encryption public key appears in the Hello, Share,
# Reply or Confirm. The key sets follow inside the session.
# ...and for a Person pairing: the same, so there is no room in them for a
# key set, a signature or anything derived from one. The displaying side,
# which sent its key set last, waits to hear it was accepted before it can
# send.
sim --kind person --pin right --type-pin right --payload "friendship bootstrap"
expect "$EXCHANGE_LENGTHS"
expect "wire: account-keys-in-exchange none"
refute "wire: account-keys-in-exchange LEAKED"
expect "display: verified-awaiting-peer"
expect "session: display-sends-first refused"
expect "display: verified"
expect "display: peer-keys-match=yes"
expect "type: peer-keys-match=yes"
expect "session: display-to-type ok"
expect "result: verified"

# A wrong code in a Person pairing ends at the confirmation, before any key
# set is sealed: the exchange that failed carried no account key either.
sim --kind person --typos 1
expect "display: run-failed failure=confirmation-failed runs-left=2"
[ "$(count "wire: account-keys-in-exchange none")" = 2 ] \
    || { echo "FAIL: expected both runs' exchanges checked for account keys"; echo "$OUT"; exit 1; }
refute "wire: account-keys-in-exchange LEAKED"
expect "result: verified"

# A key-set frame altered on the wire doesn't open: the displaying side
# fails the run and sends no key set of its own.
sim --kind person --tamper key-set
expect "wire: tampered key set"
expect "display: run-failed failure=invalid-peer-keys runs-left=2"
expect "type: run-failed failure=refused-by-peer runs-left=2"
expect "result: verified"

# A tampered Confirm in a Person pairing: the typing side fails the run
# before it has sealed its key set, so the displaying side never verifies.
sim --kind person --tamper confirm
expect "type: run-failed failure=confirmation-failed runs-left=2"
expect "display: abandoned run-failed failure=abandoned runs-left=2"
expect "result: verified"

# The displaying side's key-set frame altered on the wire: the typing side
# fails the run and records no account. The displaying side had verified
# and sent; it stays "verified, awaiting peer" and can't send.
sim --kind person --tamper display-key-set
expect "wire: tampered displaying side's key set"
expect "type: run-failed failure=invalid-peer-keys runs-left=2"
expect "session: display-sends-first refused"
expect "display: verified-awaiting-peer"
refute "type: peer-keys-match=yes"
expect "result: not-verified"

# The typing side pinned an identity the displaying side doesn't have.
sim --kind person --type-pin wrong
expect "type: run-failed failure=unexpected-peer-identity runs-left=2"
expect "session: display-sends-first refused"
expect "display: verified-awaiting-peer"
expect "result: not-verified"

sim --kind person --pin wrong
expect "display: run-failed failure=unexpected-peer-identity runs-left=2"
expect "display: dead-end failure=unexpected-peer-identity"
expect "result: not-verified"

echo "PASS: endpoints and messages are bound into the confirmed transcript; Person keys are signed over it and travel only inside the session"
