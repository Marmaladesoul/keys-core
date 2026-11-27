#!/usr/bin/env bash
#
# Scenario: a Person pairing from invite to verified, and what a knock will
# and won't do.
#
# Alice's Mac issues an invite. Bob's device opens it and knocks on the Mac,
# which has no pairing sheet open: the knock is answered all the same,
# records Bob's endpoint, and runs no exchange. Then Bob's device shows the
# code and one of Alice's devices calls it and types.
#
# The knock's rules, each pinned here:
#  - only an invite the device issued, still outstanding, is answered as
#    open; an unknown, cancelled or expired id all get the same answer;
#  - the first endpoint to knock is the opener; it may knock again (a lost
#    answer) and hears the same; any other endpoint is told nothing is
#    outstanding and changes nothing;
#  - while the issuing device is starting up and hasn't reloaded its
#    invites, a knock gets no answer (so it is tried again), and once it
#    has, the invite still answers;
#  - someone who knocks before the invited person locks them out and gains
#    nothing: the verification dead-ends against them;
#  - an invite that claims the inviter's identity but points at someone
#    else's device fails on that identity even when the code is right;
#  - once the pairing is over, the invite is spent.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# The whole flow, verified from another of Alice's devices.
net --flow person --payload "friendship bootstrap"
# The hostile padding, direction override and control character are gone
# from the name on both ends.
expect 'bob: parsed invite identity-matches=yes endpoint-matches=yes name="Alice"'
expect "bob: knock opened"
expect "alice-mac: invites-opened=1"
expect_re "alice-mac: invite id=[0-9a-f]{8} opened-by=bob"
# The knock opened no sheet: a call straight after it finds nobody listening.
before "bob: knock opened" "bob: call not-listening"
before "bob: call not-listening" "bob: listening role=display kind=person"
expect "alice-phone: call accepted"
expect_re "bob: verified kind=person peer-identity=[0-9a-f]{8}"
expect_re "alice-phone: verified kind=person peer-identity=[0-9a-f]{8}"
expect "bob: peer-keys-match=yes"
expect "alice-phone: peer-keys-match=yes"
expect "session: type-to-display ok"
expect "session: display-to-type ok"
expect "alice-mac: invite retired=yes"
before "alice-mac: invite retired=yes" "bob: knock not-outstanding"
expect "result: verified"
no_code_in_output
# The invite carries a version, two public keys' worth of ids (the identity
# key and the endpoint id), the invite id, the expiry, an empty relay, the
# five-letter name and a checksum: 100 bytes, 200 hex characters. No room
# for anything else.
LINK="$(link_line)"
BODY="${LINK#keys://pair/person/}"
[ "${#BODY}" = "200" ] || { echo "FAIL: invite body is ${#BODY} characters, expected 200"; exit 1; }

# The same, verified from the device that issued the invite, typo included.
net --flow person --verify-from issuer --typos 1
expect "alice-mac: call accepted"
expect "bob: run-failed failure=confirmation-failed runs-left=2"
expect_re "alice-mac: verified kind=person peer-identity=[0-9a-f]{8}"
expect "result: verified"

# A stranger knocks with an id nobody issued.
net --flow person --attack knock-unknown
expect "mallory: knock not-outstanding"
expect "alice-mac: invites-opened=0"
expect_re "alice-mac: invite id=[0-9a-f]{8} opened-by=nobody"

# A second endpoint knocks after the first; the first asks again.
net --flow person --attack knock-second-opener
expect "mallory: knock not-outstanding"
[ "$(count "bob: knock opened")" = "2" ] || { echo "FAIL: the opener's repeated knock should be answered the same:"; echo "$OUT"; exit 1; }
# Two knocks from the opener, one opening.
expect "alice-mac: invites-opened=1"
expect_re "alice-mac: invite id=[0-9a-f]{8} opened-by=bob"
expect "result: verified"

# Expired, and cancelled: the same answer as unknown, and nothing recorded.
for attack in knock-expired knock-cancelled; do
    net --flow person --attack "$attack"
    expect "bob: knock not-outstanding"
    expect "alice-mac: invites-opened=0"
    expect "alice-mac: no invites outstanding"
    expect "result: not-verified"
done

# The issuing device restarts. Until its client has handed the stored
# invites back, a knock gets no answer at all, never a wrong "nothing
# outstanding" that the invited device would take as final. Once the book is
# open the same knock is answered. A stored entry the book can't use is left
# out and doesn't hold the others up.
net --flow person --attack knock-relaunch
before "alice-mac: relaunched" "bob: knock unanswered"
before "bob: knock unanswered" "alice-mac: invite book open invites-outstanding=1 left-out=1"
before "alice-mac: invite book open invites-outstanding=1 left-out=1" "bob: knock opened"
# Bob's first knock is the unanswered one, and nothing told him the invite
# was gone before it was opened for him.
[ "$(grep -m1 '^bob: knock ' <<<"$OUT")" = "bob: knock unanswered" ] || { echo "FAIL: the knock before the book opened should go unanswered:"; echo "$OUT"; exit 1; }
before "bob: knock opened" "bob: knock not-outstanding"
expect_re "alice-mac: invite id=[0-9a-f]{8} opened-by=bob"
expect "result: verified"

# Someone who saw the invite knocks first.
net --flow person --attack knock-interceptor-first
before "mallory: knock opened" "bob: knock not-outstanding"
expect_re "alice-mac: invite id=[0-9a-f]{8} opened-by=mallory"
# Bob has no code to read out, so whatever Alice types is a guess at the
# interceptor's sheet: three failures and a dead end, nothing recorded.
expect "mallory: dead-end failure=confirmation-failed"
expect "alice-phone: dead-end failure=peer-dead-end"
expect "alice-phone: status dead-end"
refute "alice-phone: peer-keys-match=yes"
expect "result: not-verified"

# An invite that claims Alice's identity but names Mallory's device. Bob's
# sheet expects Alice's identity; Mallory types the right code and still
# fails, because she can't sign as Alice.
net --flow person --attack forged-invite
expect "bob: knock opened"
expect "mallory: call accepted"
expect "bob: run-failed failure=unexpected-peer-identity runs-left=2"
expect "bob: dead-end failure=unexpected-peer-identity"
refute "bob: peer-keys-match=yes"
expect "result: not-verified"

echo "PASS: an invite's knock is answered with the sheet closed, for its first opener only, runs no exchange and survives a restart; an interceptor and a forged invite both end without a pairing"
