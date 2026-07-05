#!/usr/bin/env bash
#
# Scenario: the reconcile WRITE-BACK convergence guard.
#
# When the disk KDBX changes underneath a warm mirror, `keyhole`'s open
# path reconciles it (the disk-watcher `reconcile_with_disk_park_conflicts`
# seam) and then — per the reference-client policy — writes the merged
# projection back to disk ONLY when the merge left local holding content
# the file lacks. The engine reports that as `Applied.needs_write_back`.
#
# Two arms:
#   (a) A one-way disk edit (an external client changed an entry) is
#       adopted but NOT written back: rewriting a file that already holds
#       everything we do is pure byte-churn — it bumps the mtime for
#       every other watcher and, between two rewrite-on-ingest clients
#       sharing a vault over syncthing/rsync, ping-pongs forever. This is
#       the regression guard: a needless write-back here was surfacing a
#       spurious save-failure downstream.
#   (b) A genuine two-sided divergence (local holds a saved add that an
#       external overwrite clobbered off disk) IS written back exactly
#       once, and a second open does NOT write back again — the loop
#       terminates. Convergence is verified across a mirror-nuke re-ingest.
#
# Teeth: arm (a) asserts the on-disk bytes are UNCHANGED after reconcile
# (cmp), so a stray save fails the test; arm (b) asserts the bytes DID
# change, that the clobbered local entry was restored, and that the
# replica converged on a fresh disk read.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Arm (a): one-way disk edit → adopted, NOT written back ────────────
VAULT="$TMP/a.kdbx"
PEER="$TMP/a-peer.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Shared Login" --username original >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Shared Login/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL(a): could not find seeded entry"; exit 1; }

# An external client (peer copy) edits the title, then that file lands on
# our path — the disk-watcher case. sleep 1 so the overwrite's mtime is
# strictly newer than the warm mirror's recorded signature (a file-mtime
# wait, not an LWW stamp).
cp "$VAULT" "$PEER"
"$KEYHOLE" update-entry "$PEER" "$uuid" --title "Renamed Externally" >/dev/null
sleep 1
cp "$PEER" "$VAULT"

# Capture the exact on-disk bytes before the reconcile-on-open.
cp "$VAULT" "$TMP/a-before.kdbx"

# Any verb opens a Session, which reconciles when the signature differs.
# The reconcile note (incl. the write-back verdict) goes to stderr.
"$KEYHOLE" list "$VAULT" >"$TMP/a-list.txt" 2>"$TMP/a-err.txt"

grep -q "write-back not needed" "$TMP/a-err.txt" \
    || { echo "FAIL(a): expected 'write-back not needed' on a one-way disk edit:"; cat "$TMP/a-err.txt"; exit 1; }
grep -q "wrote back merged state" "$TMP/a-err.txt" \
    && { echo "FAIL(a): reconcile wrote back after a pure ingest (the churn/ping-pong bug):"; cat "$TMP/a-err.txt"; exit 1; }
cmp -s "$TMP/a-before.kdbx" "$VAULT" \
    || { echo "FAIL(a): the KDBX bytes changed — a needless write-back rewrote the file"; exit 1; }
grep -q "Renamed Externally" "$TMP/a-list.txt" \
    || { echo "FAIL(a): the external title edit was not ingested:"; cat "$TMP/a-list.txt"; exit 1; }

echo "PASS(a): one-way disk edit adopted, file left byte-identical (no write-back)"

# ── Arm (b): two-sided divergence → written back once, then settles ───
VAULT="$TMP/b.kdbx"
PEER="$TMP/b-peer.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Shared" --username base >/dev/null
cp "$VAULT" "$PEER"

# Local: a saved add (now in our mirror AND on disk).
"$KEYHOLE" create-entry "$VAULT" "LocalOnly" --username local >/dev/null
# External: an independent add on the peer copy, which then overwrites our
# file — clobbering LocalOnly off disk. Our mirror still holds it.
"$KEYHOLE" create-entry "$PEER" "PeerOnly" --username peer >/dev/null
sleep 1
cp "$PEER" "$VAULT"

cp "$VAULT" "$TMP/b-before.kdbx"

"$KEYHOLE" list "$VAULT" >/dev/null 2>"$TMP/b-err.txt"

grep -q "wrote back merged state" "$TMP/b-err.txt" \
    || { echo "FAIL(b): a two-sided merge did not write back the union:"; cat "$TMP/b-err.txt"; exit 1; }
if cmp -s "$TMP/b-before.kdbx" "$VAULT"; then
    echo "FAIL(b): the KDBX bytes are unchanged — the merged union was not persisted"; exit 1
fi

# Loop-termination: a SECOND open sees disk == merged and must NOT write
# back again (no rewrite ping-pong between converged peers).
"$KEYHOLE" list "$VAULT" >/dev/null 2>"$TMP/b-err2.txt"
grep -q "wrote back merged state" "$TMP/b-err2.txt" \
    && { echo "FAIL(b): reconcile wrote back a second time — the convergence loop does not terminate:"; cat "$TMP/b-err2.txt"; exit 1; }

# Convergence must be ON DISK: nuke the mirror, re-ingest, and confirm all
# three entries survived (the clobbered LocalOnly was restored by the
# write-back, the external PeerOnly was adopted).
rm -rf "$VAULT.mirror"
list="$("$KEYHOLE" list "$VAULT")"
for name in "Shared" "LocalOnly" "PeerOnly"; do
    echo "$list" | grep -q "$name" \
        || { echo "FAIL(b): '$name' missing after mirror-nuke re-ingest — write-back lost data:"; echo "$list"; exit 1; }
done

echo "PASS(b): two-sided merge written back once, loop terminates, all three entries converge on a fresh disk read"
echo "PASS: reconcile write-back guard holds both directions"
