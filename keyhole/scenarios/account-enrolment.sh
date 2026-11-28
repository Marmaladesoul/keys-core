#!/usr/bin/env bash
#
# Scenario: a device's enrolment, the account-signed statement that makes a
# device one of the account's.
#
# Holding an account document's secret is not enough to add a device: a
# roster entry counts only with the account identity key's signature over
# the device's public keys, its endpoint id and its author id. So the
# enrolment checks out against its own account and no other, every byte of
# it is covered (the version byte refuses as malformed instead), and it
# can't be cut short or padded.

set -euo pipefail
source "$(dirname "$0")/account-common.inc"

run account-create "$WORK/account" >/dev/null
run account-show "$WORK/account"
IDENTITY="$(field "account identity")"
run account-create "$WORK/stranger" >/dev/null
run account-show "$WORK/stranger"
STRANGER="$(field "account identity")"

# A new device, before pairing: keys only.
run account-device-keygen "$WORK/new"
NEW_ID="$(field "device id")"
NEW_RELAY="$(field "device relay")"
NEW_VAULT="$(field "device vault")"

ENDPOINT="$(printf '0b%.0s' {1..32})"
AUTHOR="$(printf 'c4%.0s' {1..32})"
run account-enrol "$WORK/account" --device "$WORK/new" \
    --endpoint "$ENDPOINT" --author "$AUTHOR" --out "$WORK/enrolment"
expect "enrolment: signed"
[ "$(wc -c <"$WORK/enrolment" | tr -d ' ')" = 225 ] || { echo "FAIL: enrolment is not 225 bytes"; exit 1; }

# It checks out against its account and says what it certifies.
run account-open-enrolment "$WORK/enrolment" --identity "$IDENTITY"
expect "enrolment: valid"
expect "device id $NEW_ID"
expect "device signing $NEW_ID"
expect "device relay $NEW_RELAY"
expect "device vault $NEW_VAULT"
expect "device endpoint $ENDPOINT"
expect "device author $AUTHOR"

# Not against another account.
run account-open-enrolment "$WORK/enrolment" --identity "$STRANGER"
expect "refused: enrolment enrolment-not-signed-by-account"

# Every byte after the version is covered by the signature: each key, and
# the signature itself.
for offset in 1 32 33 65 97 129 161 192 193 224; do
    cp "$WORK/enrolment" "$WORK/altered"
    flip "$WORK/altered" "$offset"
    run account-open-enrolment "$WORK/altered" --identity "$IDENTITY"
    expect "refused: enrolment enrolment-not-signed-by-account"
done
# Another version, cut short, padded.
cp "$WORK/enrolment" "$WORK/altered"; flip "$WORK/altered" 0
run account-open-enrolment "$WORK/altered" --identity "$IDENTITY"
expect "refused: enrolment enrolment-malformed"
cp "$WORK/enrolment" "$WORK/altered"; truncate_to "$WORK/altered" 224
run account-open-enrolment "$WORK/altered" --identity "$IDENTITY"
expect "refused: enrolment enrolment-malformed"
{ cat "$WORK/enrolment"; printf '\0'; } >"$WORK/altered"
run account-open-enrolment "$WORK/altered" --identity "$IDENTITY"
expect "refused: enrolment enrolment-malformed"

# A device can't be enrolled into an account by holding only the device's
# keys: a "device" directory has no account to sign with.
run account-enrol "$WORK/new" --device "$WORK/new" --out "$WORK/selfmade" 2>/dev/null || true
[ ! -e "$WORK/selfmade" ] || { echo "FAIL: a device enrolled itself without the account keys"; exit 1; }

echo "PASS: an enrolment checks out only against its own account, covers every byte, and refuses any other shape"
