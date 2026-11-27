#!/usr/bin/env bash
#
# Scenario: pairing key generation. One call makes an account key set
# (identity, recovery, encryption) and a device key set (signing, relay,
# vault), all 32-byte public keys, all distinct, and fresh on every call.
# Only public halves cross the seam; nothing is stored.

set -euo pipefail
source "$(dirname "$0")/pairing-common.inc"

first="$("$KEYHOLE" pair-keygen)"
second="$("$KEYHOLE" pair-keygen)"

roles="account identity|account recovery|account encryption|device signing|device relay|device vault"
[ "$(wc -l <<<"$first" | tr -d ' ')" = 6 ] || { echo "FAIL: want 6 keys, got:"; echo "$first"; exit 1; }
while read -r set role key; do
    grep -qE "^($roles)$" <<<"$set $role" || { echo "FAIL: unexpected key '$set $role'"; exit 1; }
    [[ "$key" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: $set $role is not 32 bytes of hex: $key"; exit 1; }
done <<<"$first"

keys() { awk '{print $3}' <<<"$1"; }
[ "$(keys "$first" | sort -u | wc -l | tr -d ' ')" = 6 ] || { echo "FAIL: keys within one set repeat"; exit 1; }
[ "$( (keys "$first"; keys "$second") | sort -u | wc -l | tr -d ' ')" = 12 ] \
    || { echo "FAIL: a second generation repeated a key"; exit 1; }

echo "PASS: account and device key sets are complete, distinct and fresh"
