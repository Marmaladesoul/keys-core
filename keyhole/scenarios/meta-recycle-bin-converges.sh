#!/usr/bin/env bash
#
# Vault-meta convergence (pre-soak): a recycle-bin toggle on one peer must
# converge on the other. `ingest_peer` reconciles entries, groups, resolution
# records and (since #166) the custom-icon pool — but it ignored vault Meta
# entirely, so toggling the recycle bin on device A left B unchanged and the
# two replicas DIVERGED. The convergence digest covers `recycle_bin_enabled` +
# `recycle_bin_uuid`, so this is a genuine, permanent digest split — the kind
# of "stuck out of sync" a 2-Mac soak would otherwise burn an afternoon on.
# (The fuzzer never toggles the bin, so it sat in its blind spot.)
#
# Two cases:
#   1. one-sided disable — A turns the bin off, B adopts it on ingest;
#   2. LWW — both toggle at different instants, the newer wins on both sides.
# Recycle-bin state (enabled flag + bin-group pointer) is LWW-arbitrated by
# `recycle_bin_changed`, stamped from the engine clock (pinned here via --at).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

bin_state() { "$KEYHOLE" inspect "$1" | awk -F: '/recycle bin:/ {gsub(/ /,"",$2); print $2}'; }
digest()    { "$KEYHOLE" digest "$1"; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u >/dev/null
cp "$A" "$B"
[ "$(bin_state "$A")" = "enabled" ] || { echo "FAIL(setup): A's bin not enabled by default"; exit 1; }

# --- 1. one-sided disable: A turns the bin off; B must adopt it -----------
"$KEYHOLE" --at 2000000 set-bin "$A" off >/dev/null
[ "$(bin_state "$A")" = "disabled" ] || { echo "FAIL(setup): A did not disable its bin"; exit 1; }

"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$B.mirror"   # honest disk read

[ "$(bin_state "$B")" = "disabled" ] \
    || { echo "FAIL: B did not adopt A's recycle-bin disable (meta not reconciled on ingest)"; exit 1; }
[ "$(digest "$A")" = "$(digest "$B")" ] \
    || { echo "FAIL: digests diverge after a one-sided bin toggle (A=$(digest "$A") B=$(digest "$B"))"; exit 1; }

# --- 2. LWW: both toggle, the strictly-newer write wins on both sides ------
# A re-enables at t=4s; B disables at t=3s (older). A's enable must win on both.
"$KEYHOLE" --at 4000000 set-bin "$A" on  >/dev/null
"$KEYHOLE" --at 3000000 set-bin "$B" off >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$A.mirror" "$B.mirror"

[ "$(bin_state "$A")" = "enabled" ] \
    || { echo "FAIL: A lost its strictly-newer re-enable (got $(bin_state "$A"))"; exit 1; }
[ "$(bin_state "$B")" = "enabled" ] \
    || { echo "FAIL: B did not adopt A's strictly-newer re-enable (got $(bin_state "$B"))"; exit 1; }
[ "$(digest "$A")" = "$(digest "$B")" ] \
    || { echo "FAIL: digests diverge after LWW bin toggle (A=$(digest "$A") B=$(digest "$B"))"; exit 1; }

echo "PASS: recycle-bin toggle converges cross-peer (one-sided adopt + LWW), survives a fresh disk read"
