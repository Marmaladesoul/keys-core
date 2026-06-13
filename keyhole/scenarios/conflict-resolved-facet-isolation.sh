#!/usr/bin/env bash
#
# RED → GREEN (Finding #9): resolving ONE facet of an entry must not
# suppress a later, genuinely-divergent edit on a DIFFERENT facet of the
# same entry. The resolved-since gate has to be per-facet, not
# per-entry.
#
# Deterministic isolation (all stamps pinned via --at):
#   1. base entry with attachment att-1.
#   2. both sides edit the USERNAME differently → field conflict;
#      A resolves → the entry now carries a resolution record.
#   3. both sides replace att-1 with different bytes (usernames left
#      alone) → a genuine ATTACHMENT clash on the already-resolved
#      entry. It MUST park (and converge on resolve) — the field
#      resolution is unrelated to the attachment facet.
#
# Pre-fix behaviour (the red): the per-entry resolved_at made
# ingest_peer treat the whole entry as settled, so the new attachment
# divergence never parked — each side silently kept its own bytes (no
# badge, replicas diverged). Control: the SAME attachment clash on a
# FRESH entry parks correctly (attachment-both-sided-park.sh).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username base >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
"$KEYHOLE" --at 1000000 set-attachment "$A" "$uuid" att-1 --text base >/dev/null
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
held() { "$KEYHOLE" list-conflicts "$1" \
    | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' | tr '\n' ',' || true; }

# --- step 1: field conflict on the entry, A resolves ----------------
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username from-a >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$B" "$uuid" --username from-b >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" --at 2100000 resolve "$A" --entry "$uuid" --choose local >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
{ [ -z "$(held "$A")" ] && [ -z "$(held "$B")" ] && converged; } \
    || { echo "FAIL(setup): the field conflict did not converge"; exit 1; }

# --- step 2: attachment clash on the SAME (already-resolved) entry ---
"$KEYHOLE" --at 3000000 set-attachment "$A" "$uuid" att-1 --text bytes-a >/dev/null
"$KEYHOLE" --at 3000000 set-attachment "$B" "$uuid" att-1 --text bytes-b >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

# THE BUG: a real attachment divergence on a previously-resolved entry
# must still park on both sides (per-facet, not per-entry).
[ "$(held "$A")" = "$uuid," ] \
    || { echo "FAIL: attachment clash on a resolved entry did not park on A (silent divergence)"; exit 1; }
[ "$(held "$B")" = "$uuid," ] \
    || { echo "FAIL: attachment clash on a resolved entry did not park on B (silent divergence)"; exit 1; }

# --- step 3: resolve the attachment facet; both converge ------------
"$KEYHOLE" --at 3100000 resolve "$A" --entry "$uuid" --choose local >/dev/null  # keep bytes-a
[ -z "$(held "$A")" ] || { echo "FAIL: A's badge did not clear after attachment resolve"; exit 1; }
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
[ -z "$(held "$B")" ] || { echo "FAIL: B kept a ghost attachment conflict A resolved"; exit 1; }
[ -z "$(held "$A")" ] || { echo "FAIL: A re-parked the attachment conflict after B adopted"; exit 1; }
converged || { echo "FAIL: replicas diverged after attachment resolution"; exit 1; }

# --- survives reopen ------------------------------------------------
rm -rf "$A.mirror" "$B.mirror"
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: a resolution on one facet does not suppress a later clash on another facet"
