#!/usr/bin/env bash
#
# Scenario: the engine's save_to_kdbx writes to whatever path the caller
# hands it — including a path that differs from the one ingest_from_kdbx
# was originally called with. The mirror is path-keyed (`<vault>.mirror/`),
# so to keep continuity across a move the caller carries it along.
#
# Why this exists: clients that follow a moved file (security-scoped
# bookmarks on macOS, file-watcher reattachment elsewhere) re-aim their
# next save at the new path. The engine must do the obvious thing — open
# the kdbx at the new path, splice the mirror in, write back at the new
# path — without latching onto the original ingest path internally.
# A regression here would mean a client correctly following a move would
# still write its bytes to the old location.
#
# Shape:
#   create A, add Foo  →  mv A B (and A.mirror B.mirror) →
#   add Bar against B  →  rm B.mirror → fresh reopen B → both visible.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/before-move.kdbx"
B="$TMP/after-move.kdbx"

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "Foo" --username foo >/dev/null

# Carry both the kdbx and its mirror across — that's what a real client
# effectively does when it follows a moved file (the mirror keyed-by-path
# is a local-store detail; what matters is mirror state survives the move).
mv "$A" "$B"
mv "$A.mirror" "$B.mirror"

# Save against the new path. The engine must open B (not A), splice the
# mirror, write back to B. If it's secretly latching onto the original
# ingest path, this would silently land bytes at A — which no longer
# exists, so we'd notice on the reopen below.
"$KEYHOLE" create-entry "$B" "Bar" --username bar >/dev/null

# Force a fresh read from B (mirror nuke means no shortcut path can hide
# a missing kdbx write — every assertion below is "did it land on disk").
rm -rf "$B.mirror"

[ -f "$B" ] || { echo "FAIL: $B did not exist after second save"; exit 1; }
[ ! -f "$A" ] || { echo "FAIL: $A reappeared — engine wrote to the old path"; exit 1; }

titles="$("$KEYHOLE" list "$B" | awk '/^[0-9a-f]{8}-/ {$1=""; print substr($0,2)}' | sort)"
expected="$(printf 'Bar <bar>\nFoo <foo>\n')"
[ "$titles" = "$expected" ] || {
  echo "FAIL: expected entries Foo+Bar at $B, got:"
  echo "$titles"
  exit 1
}

echo "PASS: save_to_kdbx writes to the path it is given; a moved vault's bytes land at the new location"
