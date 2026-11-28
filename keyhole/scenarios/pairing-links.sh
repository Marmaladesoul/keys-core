#!/usr/bin/env bash
#
# Scenario: the `keys://pair/…` links through the seam, and names from
# unverified sources.
#
# A link is public: it is read off a screen, pasted into a message,
# forwarded and stored. So it carries an address or an invite's public
# values and nothing else, and its parser has to cope with whatever comes
# back: a link cut short or altered on the way (caught by its checksum), a
# link of the other kind, a later version, and text that was never a link.
#
# A name in an invite or an advertisement is chosen by whoever sent it. It
# is shown as plain text only after losing its control characters and
# anything that reorders the text around it, and capped in length.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

# parse <text>: what pair-link makes of it, in $OUT.
parse() { OUT="$("$KEYHOLE" pair-link "$1")"; }
# name <text>: what pair-name makes of it, in $OUT.
name() { OUT="$("$KEYHOLE" pair-name "$1")"; }

# A device link, as a node made it.
net --flow device-link
DEVICE_LINK="$(link_line)"
parse "$DEVICE_LINK"
expect "link: device"
expect "relay: none"
expect_re "endpoint: [0-9a-f]{64}"
ENDPOINT="$(sed -n 's/^endpoint: //p' <<<"$OUT")"

# Case and surrounding whitespace don't matter: a link survives a channel
# that shouts it, and a paste that picks up a newline.
parse "  $(tr '[:lower:]' '[:upper:]' <<<"$DEVICE_LINK")
"
expect "link: device"
expect "endpoint: $ENDPOINT"

# Cut short by one character, and with one character changed: damaged.
parse "${DEVICE_LINK%?}"
expect "refused: the-pairing-link-is-damaged"
LAST="${DEVICE_LINK: -1}"
[ "$LAST" = "0" ] && SWAP="1" || SWAP="0"
parse "${DEVICE_LINK%?}$SWAP"
expect "refused: the-pairing-link-is-damaged"
MID=$(( ${#DEVICE_LINK} / 2 ))
AT="${DEVICE_LINK:$MID:1}"
[ "$AT" = "0" ] && SWAP="1" || SWAP="0"
parse "${DEVICE_LINK:0:$MID}$SWAP${DEVICE_LINK:$((MID + 1))}"
expect "refused: the-pairing-link-is-damaged"

# A device link's body under the invite's path doesn't check out either.
parse "keys://pair/person/${DEVICE_LINK#keys://pair/device/}"
expect "refused: the-pairing-link-is-damaged"

# An invite link, as a node made it.
net --flow person
INVITE_LINK="$(link_line)"
parse "$INVITE_LINK"
expect "link: person"
expect "relay: none"
expect 'name: "Alice"'
expect_re "identity: [0-9a-f]{64}"
expect_re "invite-id: [0-9a-f]{32}"
expect_re "expires-at: [0-9]+"
parse "${INVITE_LINK%??}"
expect "refused: the-pairing-link-is-damaged"

# Text that was never a pairing link.
for text in "" "keys://pair/" "keys://pair/vault/00" "https://example.com/" \
            "keys://vault/device/00" "hello"; do
    parse "$text"
    expect "refused: not-a-keys-pairing-link"
done

# Names.
name "  Mum  "
expect 'name: "Mum"'
# A right-to-left override that would show the name's tail reversed.
name "$(printf 'Jeff\xe2\x80\xaeexe.jpg')"
expect 'name: "Jeffexe.jpg"'
# Controls, including an escape sequence's lead byte and a newline.
name "$(printf 'a\x1b[31mb\nc')"
expect 'name: "a[31mbc"'
# Characters that show nothing: a zero-width space between letters goes, and
# a name made only of invisible characters is no name at all.
name "$(printf 'a\xe2\x80\x8bb')"
expect 'name: "ab"'
name "$(printf '\xe2\x80\x8b\xe3\x85\xa4')"
expect 'name: ""'
# Capped at 64 characters.
name "$(printf 'x%.0s' $(seq 1 100))"
[ "$(sed -n 's/^name: "\(.*\)"$/\1/p' <<<"$OUT" | tr -d '\n' | wc -c | tr -d ' ')" = "64" ] \
    || { echo "FAIL: a long name should be capped at 64 characters: $OUT"; exit 1; }

echo "PASS: pairing links parse strictly, damaged ones are caught by the checksum, and unverified names are sanitised and capped"
