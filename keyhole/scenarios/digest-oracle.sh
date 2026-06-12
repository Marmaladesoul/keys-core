#!/usr/bin/env bash
#
# Scenario: the content digest is a trustworthy convergence oracle —
# stable where state is equal, different where it isn't. The fuzz
# harness leans its whole weight on `digest(A) == digest(B)`, so this
# scenario pins the oracle's three load-bearing properties:
#
#   1. Deterministic across separate processes (same vault, same hex).
#   2. Mirror-independent: a byte-identical copy of the KDBX — which
#      gets its own fresh mirror under the path-keyed scheme — digests
#      identically. The digest reflects vault CONTENT, not mirror
#      incidentals (SQLite rowids, wrap nonces, ingest order).
#   3. Sensitive to real change: an entry edit, a move, and a group
#      creation each change the digest.
#
# Teeth: property 2 would fail if the digest accidentally hashed any
# mirror-local artefact (AES-GCM ciphertexts differ per mirror); 3
# would fail if the digest were under-scoped.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/oracle.kdbx"
CLONE="$TMP/clone.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null
"$KEYHOLE" create-entry "$VAULT" "Anchor" --username anchor >/dev/null
uuid="$("$KEYHOLE" list "$VAULT" | awk '/Anchor/ {print $1; exit}')"

# 1. Deterministic across fresh processes.
d1="$("$KEYHOLE" digest "$VAULT")"
d2="$("$KEYHOLE" digest "$VAULT")"
[ -n "$d1" ] && [ "$d1" = "$d2" ] \
    || { echo "FAIL: digest not deterministic across processes ($d1 vs $d2)"; exit 1; }

# 2. Mirror-independent: byte-identical clone, fresh mirror, same digest.
cp "$VAULT" "$CLONE"
dc="$("$KEYHOLE" digest "$CLONE")"
[ "$d1" = "$dc" ] \
    || { echo "FAIL: byte-identical clone digests differently — mirror state is leaking in"; exit 1; }

# 3a. Field edit changes it.
"$KEYHOLE" update-entry "$VAULT" "$uuid" --username changed >/dev/null
d3="$("$KEYHOLE" digest "$VAULT")"
[ "$d1" != "$d3" ] || { echo "FAIL: field edit did not change the digest"; exit 1; }

# 3b. Group creation changes it.
"$KEYHOLE" create-group "$VAULT" "Subfolder" >/dev/null
d4="$("$KEYHOLE" digest "$VAULT")"
[ "$d3" != "$d4" ] || { echo "FAIL: group creation did not change the digest"; exit 1; }

# 3c. Moving the entry into the new group changes it (location is
# content — a moved entry is a divergence the oracle must see).
gid="$("$KEYHOLE" list-groups "$VAULT" | awk '/Subfolder/ {print $1; exit}')"
[ -n "$gid" ] || { echo "FAIL: could not find created group"; exit 1; }
"$KEYHOLE" move-entry "$VAULT" "$uuid" --to "$gid" >/dev/null
d5="$("$KEYHOLE" digest "$VAULT")"
[ "$d4" != "$d5" ] || { echo "FAIL: entry move did not change the digest"; exit 1; }

echo "PASS: digest is deterministic, mirror-independent, and change-sensitive (field/group/move)"
