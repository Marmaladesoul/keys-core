#!/usr/bin/env bash
#
# Scenario: the engine-owned persistence watermark (migration 0012) —
# "does the KDBX still owe a write?" answered below the seam instead of
# by per-call-site frontend convention.
#
# Proves, in order:
#   1. a freshly seeded vault reads back clean (save + post-ingest both
#      settle the watermark);
#   2. a mutation left unsaved (`--no-save`) reads back DIRTY from a
#      brand-new process — the crash-recovery signal: the watermark
#      lives in the persistent mirror, so a client that died between
#      mutation and save sees the owed write on next open;
#   3. `flush` (save-iff-dirty, the orchestrator primitive) writes the
#      owed bytes — asserted honestly by wiping the mirror and
#      re-ingesting from disk — and settles the watermark;
#   4. `flush` on a clean vault is a no-op (`clean`) — which also
#      proves a fresh from-disk ingest settles the watermark (else
#      every reopen would owe a phantom write);
#   5. the normal mutating-verb save tail settles the watermark.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/watermark.kdbx"

fail() { echo "FAIL: $*"; exit 1; }
state() { "$KEYHOLE" persistence-state "$VAULT"; }

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Sacrificial" --username bin >/dev/null

uuid="$("$KEYHOLE" list "$VAULT" | awk '/Sacrificial/ {print $1; exit}')"
[ -n "$uuid" ] || fail "could not find seeded entry"

# 1. Seeded and saved → clean.
s="$(state)"
[[ "$s" == *"dirty=false"* ]] || fail "expected clean after seeding, got: $s"

# 2. Mutate WITHOUT saving; a NEW keyhole process must read dirty back
#    from the mirror. This is the crash-recovery core: the unsaved
#    mutation is durable in the mirror, and the engine still remembers
#    the KDBX is owed a write.
"$KEYHOLE" recycle "$VAULT" "$uuid" --no-save >/dev/null
s="$(state)"
[[ "$s" == *"dirty=true"* ]] || fail "expected dirty after --no-save mutation, got: $s"

# 3. flush writes the owed bytes and settles the watermark.
out="$("$KEYHOLE" flush "$VAULT")"
[ "$out" = "flushed" ] || fail "expected 'flushed' on a dirty vault, got: $out"
s="$(state)"
[[ "$s" == *"dirty=false"* ]] || fail "expected clean after flush, got: $s"

# The honest "did it hit the KDBX?": wipe the mirror so nothing can
# carry over, re-ingest from disk, and the recycle must be there.
rm -rf "$VAULT.mirror"
recycled="$("$KEYHOLE" inspect "$VAULT" | awk '/^recycled:/ {print $2}')"
[ "$recycled" = "1" ] || fail "flush did not persist the mutation to the KDBX (recycled=$recycled)"

# 4. flush on a clean vault is a no-op — and since the mirror was just
#    rebuilt from disk, this also proves a fresh ingest settles the
#    watermark rather than leaving a phantom owed write.
out="$("$KEYHOLE" flush "$VAULT")"
[ "$out" = "clean" ] || fail "expected 'clean' on an already-persisted vault, got: $out"

# 5. A normal mutating verb (teardown flush included) leaves the vault clean.
"$KEYHOLE" create-entry "$VAULT" "Saved Normally" --username ok >/dev/null
s="$(state)"
[[ "$s" == *"dirty=false"* ]] || fail "expected clean after a saving verb, got: $s"

# 6. Loop-safety: ingesting an IDENTICAL peer advances nothing, so the
#    teardown writes nothing and the KDBX keeps its exact bytes+mtime —
#    a no-op sync must never churn the file (fresh mtimes restart the
#    reconcile ping-pong between two watching clients).
PEER="$TMP/identical-peer.kdbx"
cp "$VAULT" "$PEER"
before_stat="$(stat -f '%m %z' "$VAULT" 2>/dev/null || stat -c '%Y %s' "$VAULT")"
out="$("$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner twin)"
[[ "$out" == *"no local advance — nothing to save"* ]] \
    || fail "identical-peer ingest should report nothing to save, got: $out"
after_stat="$(stat -f '%m %z' "$VAULT" 2>/dev/null || stat -c '%Y %s' "$VAULT")"
[ "$before_stat" = "$after_stat" ] \
    || fail "identical-peer ingest rewrote the KDBX ($before_stat -> $after_stat) — mtime churn is the sync ping-pong class"

echo "PASS: engine-owned dirty watermark — unsaved mutations read back dirty across processes, flush persists + settles, saves/ingests settle, no-op peer ingest leaves the file untouched"
