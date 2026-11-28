#!/usr/bin/env bash
#
# Scenario: an account's keys survive the device's secure storage, one
# stored form per protection class, read back by a fresh process.
#
# A new account is the account keys (identity, recovery, encryption) and this
# device's keys (signing, relay, vault). Each goes into secure storage in its
# own protection class: the account keys and the device's vault key behind
# the app's unlock; the device's signing and relay keys readable after the
# device's first unlock, so a locked, unattended device can still sync. A
# locked device therefore reads its own id and relay key and nothing that
# opens a vault or acts as the account. A stored form put in the wrong place
# is refused as the wrong kind, and a damaged one as damaged; neither is ever
# read as keys.

set -euo pipefail
source "$(dirname "$0")/account-common.inc"

DEV="$WORK/device"
run account-create "$DEV"
CREATED="$OUT"
IDENTITY="$(field "account identity")"
DEVICE_ID="$(field "device id")"
for role in "account identity" "account recovery" "account encryption" \
            "device id" "device relay" "device vault"; do
    [[ "$(field "$role")" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: no $role in:"; echo "$OUT"; exit 1; }
done

# A fresh process, unlocked, reads back exactly the keys that were made.
run account-show "$DEV"
[ "$(sort <<<"$OUT")" = "$(sort <<<"$CREATED")" ] \
    || { echo "FAIL: read-back keys differ:"; echo "$CREATED"; echo "---"; echo "$OUT"; exit 1; }

# A locked device reads its id and relay key only.
run account-show "$DEV" --locked
expect "device id $DEVICE_ID"
expect "account: locked"
refute_re "^(account identity|account recovery|account encryption|device vault) "

# Each stored form in another's place is refused as the wrong kind.
swap() { # swap <file read> <file put in its place> <reported>
    rm -rf "$WORK/swapped" && cp -R "$DEV" "$WORK/swapped"
    cp "$DEV/$2" "$WORK/swapped/$1"
    run account-show "$WORK/swapped"
    expect "refused: $1 stored-keys-wrong-kind"
}
swap account.keys device-vault.keys
swap device-sync.keys account.keys
swap device-vault.keys device-sync.keys

# A damaged stored form is refused as damaged: cut short, another version,
# an unknown kind. (A changed secret byte is just another key and can't be
# told apart, so only the structure is checked.)
damage() { # damage <file> <how> <arg>
    rm -rf "$WORK/damaged" && cp -R "$DEV" "$WORK/damaged"
    "$2" "$WORK/damaged/$1" "$3"
    run account-show "$WORK/damaged"
    expect "refused: $1 stored-keys-damaged"
}
damage device-sync.keys truncate_to 65
damage device-vault.keys truncate_to 2
damage account.keys truncate_to 97
damage account.keys flip 0
damage device-sync.keys flip 1

# The recovery code written at creation is this account's, and another
# account's code isn't.
run account-recovery "$DEV/recovery-code" --dir "$DEV"
expect "recovery-code: valid"
run account-create "$WORK/other"
run account-recovery "$WORK/other/recovery-code" --dir "$DEV"
expect "recovery-code: not-this-account"

# This device's enrolment, written at creation, checks out against its own
# account and certifies this device.
run account-open-enrolment "$DEV/enrolment" --identity "$IDENTITY"
expect "enrolment: valid"
expect "device id $DEVICE_ID"

# The recovery code is never printed: no 7-group code in any output above.
grep -qE '([0-9A-Z]{4}-){6}[0-9A-Z]{4}' <<<"$CREATED" && { echo "FAIL: a recovery code was printed"; exit 1; }

echo "PASS: stored forms round-trip per protection class, wrong or damaged forms are refused, a locked device reads no account key"
