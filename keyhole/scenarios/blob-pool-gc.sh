#!/usr/bin/env bash
#
# Scenario: the mirror's content-addressed attachment blob pool must
# not retain garbage — and must never collect a parked conflict's
# divergent bytes (5c blob-pool GC).
#
# The KDBX file's binary pool is already GC'd at save by keepass-core
# (gc_binaries_pool); this pins the ENGINE MIRROR's `attachment_blob`
# table, which previously only ever grew: remove/replace left blobs in
# place, and deleting an entry cascaded away the links + history that
# referenced them while the bytes lingered forever.
#
# Reference roots the GC must honour: live entry_attachment links,
# history-snapshot shas, and conflict_entry_attachment (a parked
# conflict's peer bytes exist ONLY in the pool — Finding #7).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

pool_count() { # $1=vault → blob row count
    "$KEYHOLE" inspect "$1" | awk '/blob pool:/ {print $3}'
}

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Keeper" --username k >/dev/null
keeper="$("$KEYHOLE" list "$A" | awk '/Keeper/ {print $1; exit}')"
"$KEYHOLE" create-entry "$A" "Doomed" --username d >/dev/null
doomed="$("$KEYHOLE" list "$A" | awk '/Doomed/ {print $1; exit}')"

# Blobs across both entries; history snapshots hold replaced versions.
"$KEYHOLE" set-attachment "$A" "$keeper" keep.txt --text "keep-v1" >/dev/null
"$KEYHOLE" set-attachment "$A" "$doomed" gone.txt --text "gone-v1" >/dev/null
"$KEYHOLE" set-attachment "$A" "$doomed" gone.txt --text "gone-v2" >/dev/null
[ "$(pool_count "$A")" = "3" ] \
    || { echo "FAIL(precondition): expected 3 blobs, got $(pool_count "$A")"; exit 1; }

# --- THE SLICE: deleting the entry orphans its blobs; GC reaps them --
# (delete-entry saves; the save-time sweep is the GC hook.)
"$KEYHOLE" delete-entry "$A" "$doomed" >/dev/null
got="$(pool_count "$A")"
[ "$got" = "1" ] \
    || { echo "FAIL: orphaned blobs not collected (pool=$got, want 1)"; exit 1; }
# The live attachment is untouched.
[ "$("$KEYHOLE" cat-attachment "$A" "$keeper" keep.txt)" = "keep-v1" ] \
    || { echo "FAIL: GC collected a live blob"; exit 1; }

# --- A parked conflict's divergent peer bytes are a GC root ----------
cp "$A" "$B"
sleep 1.1
"$KEYHOLE" set-attachment "$A" "$keeper" keep.txt --text "keep-a" >/dev/null
"$KEYHOLE" set-attachment "$B" "$keeper" keep.txt --text "keep-b" >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" list-conflicts "$A" | grep "$keeper" >/dev/null \
    || { echo "FAIL(precondition): expected a held conflict"; exit 1; }
# Trigger saves (and thus GC sweeps) while the conflict is held.
"$KEYHOLE" create-entry "$A" "Churn" --username c >/dev/null
# Resolving remote must still find the peer bytes in the pool.
"$KEYHOLE" resolve "$A" --entry "$keeper" --choose remote >/dev/null
[ "$("$KEYHOLE" cat-attachment "$A" "$keeper" keep.txt)" = "keep-b" ] \
    || { echo "FAIL: parked peer blob was collected before resolve"; exit 1; }

# --- and the collected state is honest on disk -----------------------
rm -rf "$A.mirror"
[ "$("$KEYHOLE" cat-attachment "$A" "$keeper" keep.txt)" = "keep-b" ] \
    || { echo "FAIL: resolved bytes did not persist"; exit 1; }

echo "PASS: blob pool reaps orphans at save, spares live/history/parked-conflict roots"
