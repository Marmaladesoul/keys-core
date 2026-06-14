#!/usr/bin/env bash
#
# 5c (the last sliver): a one-sided custom-icon add must propagate its BYTES
# across peers, not just its reference. When B sets a custom icon on a shared
# entry and A ingests B, A adopts the entry's content-addressed
# `custom_icon_uuid` (the ref rides the normal content merge) — but the icon
# BYTES live in a separate vault-level pool (`meta_custom_icon`), and ingest
# must UNION that pool or A is left with a dangling reference: an entry
# pointing at an icon whose bytes A doesn't have.
#
# The convergence digest is BLIND to this: `vault_content_digest` covers an
# entry's icon *ref* but not the pool bytes, so A and B's digests match the
# instant the ref propagates — even while A's pool is missing the blob. The
# honest check is `custom-icon-bytes` (a direct pool read), across a fresh
# disk read (`rm -rf <vault>.mirror`) so it's the KDBX that's interrogated,
# not warm mirror state.
#
# This mirrors the attachment-pool union (5c attachments, already landed):
# content-addressed bytes a peer references must be unioned into the local
# pool on ingest, grow-only.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

icon_bytes() { "$KEYHOLE" custom-icon-bytes "$1" "$2"; }

"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"

# B adds a custom icon to the shared entry (one-sided). The icon UUID is a
# pure function of the bytes (content-addressed), printed back here.
icon="$("$KEYHOLE" --at 2000000 add-custom-icon "$B" "$uuid" "icon-payload-cross-peer")"
[ -n "$icon" ] || { echo "FAIL(setup): add-custom-icon printed no uuid"; exit 1; }
[ "$(icon_bytes "$B" "$icon")" != "(none)" ] \
    || { echo "FAIL(setup): B's own pool is missing the icon it just added"; exit 1; }
[ "$(icon_bytes "$A" "$icon")" = "(none)" ] \
    || { echo "FAIL(setup): A already has the icon before any sync"; exit 1; }

# A ingests B. The ref propagates (digests converge); the bytes must too.
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null

# The ref propagated — digests agree (this passes even while the pool is
# missing the blob; it's here to prove the digest oracle's blind spot, not
# the icon bytes).
[ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ] \
    || { echo "FAIL: digests diverged — the icon ref did not even propagate"; exit 1; }

# Honest disk read: drop the mirror so the assertion interrogates the KDBX.
rm -rf "$A.mirror"

# THE TEST: A's pool must now hold the icon bytes B referenced. A bare
# (none) here is the dangling-icon-reference gap.
got="$(icon_bytes "$A" "$icon")"
[ "$got" != "(none)" ] \
    || { echo "FAIL: A adopted the icon REF but not its BYTES — dangling custom-icon reference (pool union missing on ingest)"; exit 1; }

# And it's the same blob B has (length is a cheap proxy; bytes are
# content-addressed so equal length on the same uuid means equal bytes).
[ "$got" = "$(icon_bytes "$B" "$icon")" ] \
    || { echo "FAIL: A's unioned icon bytes differ from B's (A=$got B=$(icon_bytes "$B" "$icon"))"; exit 1; }

echo "PASS: one-sided custom-icon add unions its bytes cross-peer (no dangling reference; survives a fresh disk read)"
