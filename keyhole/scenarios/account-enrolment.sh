#!/usr/bin/env bash
#
# Scenario: a device's enrolment, the account-signed statement that makes a
# device one of the account's.
#
# Holding an account document's secret is not enough to add a device: a
# roster entry counts only with the account identity key's signature over
# the device's public keys, its endpoint id and its author id. So the
# enrolment checks out against its own account and no other, a changed bit
# in any key or in the signature is refused (a changed version byte is
# refused as malformed instead), it can't be cut short or padded, and the
# account won't sign for keys that can't be used.

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

# The transport's endpoint and author ids are Ed25519 keys; other devices'
# signing keys stand in for them.
run account-device-keygen "$WORK/endpoint"
ENDPOINT="$(field "device id")"
run account-device-keygen "$WORK/author"
AUTHOR="$(field "device id")"
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

# The signature covers each key and is itself checked: a flipped byte at
# the start and end of each field is refused.
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

# The account won't sign for keys that can't be used. A device whose vault
# key is its relay key would merge two protection classes into one:
rm -rf "$WORK/merged" && cp -R "$WORK/new" "$WORK/merged"
{ printf '\001V'; tail -c 32 "$WORK/new/device-sync.keys"; } >"$WORK/merged/device-vault.keys"
run account-enrol "$WORK/account" --device "$WORK/merged" \
    --endpoint "$ENDPOINT" --author "$AUTHOR" --out "$WORK/merged-enrolment"
expect "refused: enrolment enrolment-unusable-key"
[ ! -e "$WORK/merged-enrolment" ] || { echo "FAIL: an unusable enrolment was written"; exit 1; }
# Nor for one key in two roles (the device's own id, or the account's
# identity key, as its endpoint id), or an endpoint id that isn't a key.
for endpoint in "$NEW_ID" "$IDENTITY" "$(printf '00%.0s' {1..32})"; do
    rm -f "$WORK/unusable"
    run account-enrol "$WORK/account" --device "$WORK/new" \
        --endpoint "$endpoint" --author "$AUTHOR" --out "$WORK/unusable"
    expect "refused: enrolment enrolment-unusable-key"
    [ ! -e "$WORK/unusable" ] || { echo "FAIL: an unusable enrolment was written"; exit 1; }
done
# A device's stored form in the wrong place is refused, not read as keys.
rm -rf "$WORK/swapped" && cp -R "$WORK/new" "$WORK/swapped"
cp "$WORK/new/device-vault.keys" "$WORK/swapped/device-sync.keys"
run account-enrol "$WORK/account" --device "$WORK/swapped" \
    --endpoint "$ENDPOINT" --author "$AUTHOR" --out "$WORK/unusable"
expect "refused: device-sync.keys stored-keys-wrong-kind"

echo "PASS: an enrolment checks out only against its own account, every key and the signature are covered, other shapes and unusable keys are refused"
