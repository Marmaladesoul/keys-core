#!/usr/bin/env bash
#
# RED → GREEN (task #29): `keyhole --uuid-seed S --at T create` must mint
# the root group + recycle-bin UUIDs deterministically from the seed, so a
# fuzz run replays byte-for-byte instead of drawing fresh random ids each
# run. The seeded engine UuidSource (task #27) already covers every id
# minted AFTER create; the create itself was the last gap — root + eager
# bin came from keepass-core's raw `Uuid::new_v4()`, outside the engine,
# so two same-seed creates diverged and a fuzz failure couldn't be replayed.
#
# Fix: a keepass-core `UuidSource` (mirroring the engine's) injected into a
# deterministic create entry point, surfaced through keys-ffi
# `Vault::create_empty_deterministic` and wired to keyhole's `create` verb.
# Root = from_u64_pair(seed, 0), bin = from_u64_pair(seed, 1).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The group lines from a fresh disk read (mirror removed first, so the
# UUIDs are re-ingested from the KDBX, not served from a stale mirror).
groups() {
    rm -rf "$1.mirror"
    "$KEYHOLE" list-groups "$1" \
        | grep -E '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
}

# Same seed + clock → identical root + bin UUIDs across two fresh creates.
"$KEYHOLE" --uuid-seed 7 --at 1000000 create "$TMP/s1.kdbx" >/dev/null
"$KEYHOLE" --uuid-seed 7 --at 1000000 create "$TMP/s2.kdbx" >/dev/null
[ "$(groups "$TMP/s1.kdbx")" = "$(groups "$TMP/s2.kdbx")" ] \
    || { echo "FAIL: same seed produced different vault uuids (create ignored --uuid-seed)"; exit 1; }

# A different seed → different UUIDs (the seed genuinely drives them, not a
# hard-coded constant masquerading as determinism).
"$KEYHOLE" --uuid-seed 99 --at 1000000 create "$TMP/s3.kdbx" >/dev/null
[ "$(groups "$TMP/s1.kdbx")" != "$(groups "$TMP/s3.kdbx")" ] \
    || { echo "FAIL: different seeds produced identical uuids (seed not wired through)"; exit 1; }

# Negative control: WITHOUT a seed, creation stays random — two unseeded
# creates must differ, proving determinism didn't leak into the prod path.
"$KEYHOLE" create "$TMP/r1.kdbx" >/dev/null
"$KEYHOLE" create "$TMP/r2.kdbx" >/dev/null
[ "$(groups "$TMP/r1.kdbx")" != "$(groups "$TMP/r2.kdbx")" ] \
    || { echo "FAIL: unseeded create produced identical uuids (determinism leaked into the random path)"; exit 1; }

echo "PASS: --uuid-seed makes create mint deterministic root+bin uuids; unseeded stays random"
