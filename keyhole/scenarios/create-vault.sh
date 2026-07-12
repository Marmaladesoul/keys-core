#!/usr/bin/env bash
#
# Scenario: VAULT CREATION through the engine-generation entry point.
#
# `keyhole create` drives `keys_ffi::create_vault` — the same call the GUI
# clients drive on their "new vault" flow. Creation writes the KDBX file and
# returns no handle: the new vault is then opened through the SAME Engine
# path as any existing vault (open + ingest), so this scenario is also the
# proof that a just-minted vault round-trips through that path.
#
# Assertions:
#
#   (a) NEW-VAULT POLICY — a fresh vault, read by a FRESH process ingesting
#       from disk (no carried-over mirror), has the recycle bin ENABLED and
#       the bin group ALREADY PRESENT (fixed before the vault ever syncs),
#       exactly two groups (root + bin), and zero entries.
#   (b) REFUSE OVERWRITE — `create` onto an existing path fails and leaves
#       the file intact.
#   (c) DETERMINISTIC IDS — two vaults minted with the same --uuid-seed +
#       --at carry IDENTICAL root + bin uuids (the id space that drives
#       sync replay); a different seed yields different ids.
#   (d) DETERMINISTIC + KEYFILE COMPOSE — a vault minted with --uuid-seed +
#       --at + --keyfile opens only with the keyfile (fail-closed without)
#       AND carries the same pinned uuids as the keyfile-less same-seed
#       mint — the two axes are orthogonal.
#
# Every "what does the vault contain?" is a fresh keyhole process over a
# wiped mirror, so the answer reflects the on-disk KDBX, never carried-over
# mirror state.
#
# Self-contained: keyhole's own create / inspect / list-groups.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PW="keyhole-create-master"
AT=1700000000000
SEED=42

# Fresh-ingest inspect of $1 — wipe the mirror so the output reflects disk.
inspect_fresh() { # <vault>
    rm -rf "$1.mirror"
    KEYHOLE_PASSWORD="$PW" "$KEYHOLE" inspect "$1" 2>/dev/null
}

# Fresh-ingest group listing of $1 (uuid column only, sorted).
group_uuids_fresh() { # <vault> [keyfile]
    rm -rf "$1.mirror"
    if [ -n "${2:-}" ]; then
        KEYHOLE_PASSWORD="$PW" "$KEYHOLE" list-groups "$1" --keyfile "$2" 2>/dev/null
    else
        KEYHOLE_PASSWORD="$PW" "$KEYHOLE" list-groups "$1" 2>/dev/null
    fi | awk 'NF >= 2 && $1 ~ /^[0-9a-f-]{36}$/ { print $1 }' | sort
}

# ── (a) new-vault policy, read fresh from disk ───────────────────────────────
V1="$TMP/v1.kdbx"
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V1" >/dev/null \
    || { echo "FAIL: create failed"; exit 1; }
[ -f "$V1" ] || { echo "FAIL: create reported success but wrote no file"; exit 1; }

OUT="$(inspect_fresh "$V1")" || { echo "FAIL: fresh process could not open the new vault"; exit 1; }
echo "$OUT" | grep -q "recycle bin:  enabled" \
    || { echo "FAIL: new vault does not have the recycle bin enabled"; exit 1; }
echo "$OUT" | grep -q "bin group:    present" \
    || { echo "FAIL: new vault is missing the eager bin group"; exit 1; }
echo "$OUT" | grep -q "entries:      0" \
    || { echo "FAIL: new vault is not empty"; exit 1; }
echo "$OUT" | grep -q "groups:       2" \
    || { echo "FAIL: new vault should hold exactly root + bin"; exit 1; }

# ── (b) refuse overwrite ─────────────────────────────────────────────────────
BEFORE="$(cksum "$V1")"
if KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V1" >/dev/null 2>&1; then
    echo "FAIL: create onto an existing path succeeded — must refuse"; exit 1
fi
[ "$(cksum "$V1")" = "$BEFORE" ] \
    || { echo "FAIL: refused create still modified the existing file"; exit 1; }

# ── (c) deterministic ids ────────────────────────────────────────────────────
V2="$TMP/v2.kdbx"
V3="$TMP/v3.kdbx"
V4="$TMP/v4.kdbx"
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V2" --at "$AT" --uuid-seed "$SEED" >/dev/null \
    || { echo "FAIL: deterministic create failed"; exit 1; }
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V3" --at "$AT" --uuid-seed "$SEED" >/dev/null \
    || { echo "FAIL: second deterministic create failed"; exit 1; }
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V4" --at "$AT" --uuid-seed 43 >/dev/null \
    || { echo "FAIL: different-seed create failed"; exit 1; }

U2="$(group_uuids_fresh "$V2")"
U3="$(group_uuids_fresh "$V3")"
U4="$(group_uuids_fresh "$V4")"
[ -n "$U2" ] || { echo "FAIL: could not list groups of the deterministic vault"; exit 1; }
[ "$U2" = "$U3" ] \
    || { echo "FAIL: same seed + clock minted DIFFERENT root/bin uuids"; exit 1; }
[ "$U2" != "$U4" ] \
    || { echo "FAIL: different seeds minted the SAME root/bin uuids"; exit 1; }

# ── (d) deterministic + keyfile compose ──────────────────────────────────────
V5="$TMP/v5.kdbx"
KF="$TMP/v5.keyfile"
KEYHOLE_PASSWORD="$PW" "$KEYHOLE" create "$V5" --at "$AT" --uuid-seed "$SEED" --keyfile "$KF" >/dev/null \
    || { echo "FAIL: deterministic + keyfile create failed (the axes must compose)"; exit 1; }
rm -rf "$V5.mirror"
if KEYHOLE_PASSWORD="$PW" "$KEYHOLE" inspect "$V5" >/dev/null 2>&1; then
    echo "FAIL: keyfile-keyed deterministic vault opened WITHOUT the keyfile"; exit 1
fi
U5="$(group_uuids_fresh "$V5" "$KF")"
[ -n "$U5" ] || { echo "FAIL: keyfile-keyed deterministic vault did not open WITH the keyfile"; exit 1; }
[ "$U2" = "$U5" ] \
    || { echo "FAIL: adding a keyfile changed the seeded uuid sequence"; exit 1; }

echo "PASS: engine-generation create ships bin-enabled root+bin vaults readable by a fresh process, refuses overwrite, pins ids under --uuid-seed/--at, and composes deterministic with keyfile"
