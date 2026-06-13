#!/usr/bin/env bash
#
# Scenario: Finding #8's user-facing guarantee — an attachment removal
# must not resurrect when the remover ingests a peer still carrying
# the attachment, and must propagate.
#
# The underlying bug: removing an attachment returns the entry to a
# content state identical to an OLDER shared snapshot, and the LCA
# matcher could alias to that ancient generation (fixed in
# keepass-merge by min-rank pair selection — see DESIGN.md Finding #8).
# Honesty note: this DETERMINISTIC case was shielded by attachment
# tombstones even before the matcher fix (a removal writes a tombstone
# the stale re-add can't beat), so the scenario pins the guarantee from
# two directions (tombstones + matcher) rather than red-proving the
# matcher; the authoritative matcher gate is fuzz-attachments.sh, which
# reproduced the aliasing ~1-in-7 pre-fix and soaks 30/30 post-fix.
#
# Sleeps separate the three generations into distinct seconds — KDBX
# times floor to seconds (Finding #4), so same-second ops would
# otherwise collapse into one generation timestamp.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Carrier" --username c >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/Carrier/ {print $1; exit}')"
cp "$A" "$B"

converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }
has_attachment() { # $1=vault
    "$KEYHOLE" cat-attachment "$1" "$uuid" doc.txt >/dev/null 2>&1
}

# Generation 1: A adds the attachment; B adopts it.
sleep 1.1
"$KEYHOLE" set-attachment "$A" "$uuid" doc.txt --text "transient" >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
has_attachment "$B" \
    || { echo "FAIL(precondition): attachment did not propagate to B"; exit 1; }

# Generation 2: A removes it — content returns to the pre-add state.
sleep 1.1
"$KEYHOLE" remove-attachment "$A" "$uuid" doc.txt >/dev/null

# --- THE BUG: A ingests B (which still carries the attachment). The
# removal is A's newest intent; B's copy is stale. It must NOT come back.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
if has_attachment "$A"; then
    echo "FAIL: removal resurrected — A re-adopted the stale peer attachment"; exit 1
fi

# And the removal propagates: B ingests A and drops it; replicas agree.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
if has_attachment "$B"; then
    echo "FAIL: removal did not propagate to B"; exit 1
fi
converged || { echo "FAIL: replicas diverged after the removal exchange"; exit 1; }

# The converged removal survives a fresh disk read.
rm -rf "$A.mirror" "$B.mirror"
if has_attachment "$A" || has_attachment "$B"; then
    echo "FAIL: removal did not persist to the KDBX"; exit 1
fi
converged || { echo "FAIL: persisted replicas diverged"; exit 1; }

echo "PASS: attachment removal survives ingesting a stale peer and propagates without resurrection"
