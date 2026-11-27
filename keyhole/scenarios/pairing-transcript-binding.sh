#!/usr/bin/env bash
#
# Scenario: the confirmed transcript binds the endpoints, every message and,
# for a Person pairing, each side's account keys.
#
#   1. Spliced connection: the displaying side's transport reports a relay's
#      endpoint id, not the typer's. Even with the right code every run
#      fails, to the dead end.
#   2. Tampering with any one message fails that run: the displaying side's
#      nonce or its share (group element) in the Share, the typing side's
#      share in the Reply, the tag in the Confirm. A tampered confirm leaves
#      the displaying side holding a session the typer doesn't have; it
#      reports "verified, awaiting peer" and its session refuses to send.
#   3. Person pairing: each side ends up holding exactly the other's account
#      identity, recovery and encryption public keys, signed for this run
#      and beside the share they travelled with.
#   4. Person pairing with a pinned identity (from an invite) that doesn't
#      match the typer: every run fails.

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

# In a Person pairing the same flipped share fails one step earlier: each
# side's key set is signed beside its own share, so the typing side finds
# the displaying side's keys weren't signed with the share that arrived.
sim --kind person --tamper share-point
expect "wire: tampered share point"
expect "type: run-failed failure=invalid-peer-keys runs-left=2"
expect "result: verified"

sim --tamper reply
expect "wire: tampered reply"
expect "display: run-failed failure=invalid-share runs-left=2"
expect "result: verified"

sim --tamper confirm
expect "wire: tampered confirm"
expect "type: run-failed failure=confirmation-failed runs-left=2"
expect "session: display-sends-first refused"
expect "result: not-verified"

sim --kind person --pin right --payload "friendship bootstrap"
expect "display: peer-keys-match=yes"
expect "type: peer-keys-match=yes"
expect "session: display-to-type ok"
expect "result: verified"

sim --kind person --pin wrong
expect "display: run-failed failure=unexpected-peer-identity runs-left=2"
expect "display: dead-end failure=unexpected-peer-identity"
expect "result: not-verified"

echo "PASS: endpoints, messages and Person keys are bound into the confirmed transcript"
