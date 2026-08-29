#!/usr/bin/env bash
#
# Scenario: a session key rotated out from under a *closed* vault must be
# caught at the vault's next OPEN, and the repair must cost nothing the
# KDBX still holds.
#
# The sidecar seals every protected field under a session key the platform
# supplies out-of-band (on a desktop client, one wrapped by a hardware
# keystore). Rotate that key while the vault is closed and the sidecar is
# left in a state no consumer can see: the SQLCipher mirror still opens,
# the recorded kdbx-state signature still matches disk, so the open-time
# skip-ingest fast path engages — on a sidecar whose every sealed blob has
# become unreadable. The failure then surfaces much later, on a reveal, a
# merge or a save, long after the vault was reported open.
#
# The seam is where this has to be caught. `open_vault_self_healing` now
# probes the sealed blobs against the live session key before it hands the
# engine back, and heals the one case that warrants healing.
#
# Asserts:
#   1. a vault whose session key rotated WHILE IT WAS CLOSED is repaired at
#      its next open — protected reads and saves work again, with no
#      explicit recovery verb driven by the caller;
#   2. an UNSEALED-column delta (title / username / tags — the half that
#      survives a key loss) comes through the repair intact;
#   3. a parked conflict row sealed under the lost key is cleared by the
#      repair, so no badge is left pointing at a payload nothing can open;
#   4. THE FAIL-CLOSED GUARD: a protector that cannot produce a key AT ALL
#      is a transient condition, not evidence of rotation, and must never
#      be answered by discarding the mirror. The open fails closed, the
#      mirror survives byte-for-byte, and it is still usable under the real
#      key. "The keystore was momentarily unavailable" and "the key
#      changed" are different facts; a consumer handed one undifferentiated
#      failure cannot tell them apart, and answering the first with the
#      remedy for the second destroys data with no fault required.
#
# Each assertion asserts across a close+reopen, because every keyhole
# invocation is its own process over a PERSISTENT mirror — which is the
# whole point here: the mirror is what carries the stale seal across the
# rotation, exactly like a real client's local store.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-se-session-key-pw"
export KEYHOLE_PASSWORD="$PW"

# A session key (64 hex / 32 bytes) distinct from the adapter default —
# "the keystore now yields a different key".
ROTATED_KEY="$(printf 'e%.0s' {1..64})"
# 64 chars that are NOT hex: the adapter rejects the override and reports
# KeyUnavailable — a protector that cannot produce a key at all, which is
# what an unreachable keystore looks like from below the seam.
UNAVAILABLE_KEY="$(printf 'z%.0s' {1..64})"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/se-recovery.kdbx"
PEER="$TMP/se-recovery-peer.kdbx"

# Count of entries carrying a parked conflict. `KEYHOLE_FIELD_KEY` is read
# from the environment by the callee, so a caller that wants the rotated
# key exports it around the call rather than prefixing this function (a
# `VAR=x func` prefix leaks into the caller's shell in bash).
badge() { "$KEYHOLE" list-conflicts "$1" 2>/dev/null \
    | grep -Eic '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true; }

# ── seed: an entry with a PROTECTED password plus UNSEALED columns ─────
"$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL(setup): could not create vault"; exit 1; }
"$KEYHOLE" --at 1000000 create-entry "$VAULT" "Bank" \
    --username alice --entry-password "Tr0ub4dor&3" >/dev/null \
    || { echo "FAIL(setup): could not seed entry"; exit 1; }
ENTRY="$("$KEYHOLE" list "$VAULT" 2>/dev/null | grep -i 'Bank' | grep -oE '[0-9a-fA-F-]{36}' | head -1)"
[ -n "$ENTRY" ] || { echo "FAIL(setup): could not resolve the seeded entry uuid"; exit 1; }
"$KEYHOLE" --at 1100000 set-tags "$VAULT" "$ENTRY" "finance,personal" >/dev/null \
    || { echo "FAIL(setup): could not set tags"; exit 1; }

# Park a genuine conflict, so the mirror carries owner rows sealed under
# the same session key the rotation is about to strand.
cp "$VAULT" "$PEER"
"$KEYHOLE" --at 2000000 update-entry "$VAULT" "$ENTRY" --username alice-local >/dev/null
"$KEYHOLE" --at 2000000 update-entry "$PEER" "$ENTRY" --username alice-peer >/dev/null
"$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-peer >/dev/null
[ "$(badge "$VAULT")" = 1 ] \
    || { echo "FAIL(setup): the peer clash did not park a conflict"; exit 1; }

# Everything above is now flushed to the KDBX and mirrored. The vault is
# CLOSED — every keyhole process exits — which is the "locked vault" the
# recovery has to reach.

# ── 4. fail-closed guard, checked FIRST (before anything has healed) ───
#    A protector that cannot produce a key must not cost us the mirror.
MIRROR_DB="$(find "$VAULT.mirror" -maxdepth 1 -name '*.sqlite' -o -maxdepth 1 -name '*.db' 2>/dev/null | head -1)"
if [ -z "$MIRROR_DB" ]; then
    MIRROR_DB="$(find "$VAULT.mirror" -maxdepth 1 -type f 2>/dev/null | head -1)"
fi
[ -n "$MIRROR_DB" ] || { echo "FAIL(setup): could not locate the mirror db under $VAULT.mirror"; exit 1; }
before_size="$(wc -c < "$MIRROR_DB" | tr -d ' ')"

unavail_out="$(KEYHOLE_FIELD_KEY="$UNAVAILABLE_KEY" "$KEYHOLE" list "$VAULT" 2>&1)"
unavail_rc=$?
if [ "$unavail_rc" -eq 0 ]; then
    echo "FAIL: an open under an UNAVAILABLE protector succeeded — a transient must fail closed, not sail past"
    printf '%s\n' "$unavail_out" | sed 's/^/    /'
    exit 1
fi
after_size="$(wc -c < "$MIRROR_DB" | tr -d ' ')"
if [ "$before_size" != "$after_size" ]; then
    echo "FAIL: the mirror was rewritten ($before_size -> $after_size bytes) by an open whose protector was merely UNAVAILABLE"
    exit 1
fi
"$KEYHOLE" list "$VAULT" 2>/dev/null | grep -q 'Bank' \
    || { echo "FAIL: the mirror is no longer usable under the real key after an unavailable-protector open"; exit 1; }
[ "$(badge "$VAULT")" = 1 ] \
    || { echo "FAIL: the parked conflict did not survive an unavailable-protector open"; exit 1; }
echo "note: an unavailable protector failed the open closed and left the mirror intact"

# ── 1. rotated session key on a CLOSED vault is repaired at next open ──
#    `update-entry` mutates then saves; the save projects the whole vault,
#    which must unwrap every protected field. Under a rotated key that can
#    only work if the open repaired the sidecar first.
#
#    NO `--at` from here on, deliberately: a pinned clock selects keyhole's
#    deterministic open, which mints its engine directly and never reaches
#    the self-healing path the GUI clients drive. Everything past this point
#    must run the production-shaped open.
rot_out="$(KEYHOLE_FIELD_KEY="$ROTATED_KEY" "$KEYHOLE" \
    update-entry "$VAULT" "$ENTRY" --username alice-after 2>&1)"
rot_rc=$?
if [ "$rot_rc" -ne 0 ]; then
    echo "FAIL: a protected-field save under a rotated session key failed — the open answered from the stale mirror instead of repairing it"
    printf '%s\n' "$rot_out" | sed 's/^/    /'
    exit 1
fi
printf '%s\n' "$rot_out" | grep -q 'rotated session key' \
    || { echo "FAIL: the open did not report repairing a rotated session key"; printf '%s\n' "$rot_out" | sed 's/^/    /'; exit 1; }
echo "note: the closed vault's rotated session key was caught and repaired at open"

# ── 2. the unsealed-column delta came through the repair intact ────────
#    Proven against a FRESH disk read: nuke the mirror so the answer can
#    only come from the KDBX the repair re-ingested from.
rm -rf "$VAULT.mirror"
listing="$(KEYHOLE_FIELD_KEY="$ROTATED_KEY" "$KEYHOLE" list "$VAULT" 2>/dev/null)"
printf '%s\n' "$listing" | grep -q 'Bank' \
    || { echo "FAIL: the entry title did not survive the repair"; exit 1; }
printf '%s\n' "$listing" | grep -q 'alice-after' \
    || { echo "FAIL: the username written after the repair did not reach the KDBX"; exit 1; }
tags="$(KEYHOLE_FIELD_KEY="$ROTATED_KEY" "$KEYHOLE" tags "$VAULT" "$ENTRY" 2>/dev/null)"
printf '%s\n' "$tags" | grep -q '^finance$' \
    || { echo "FAIL: the 'finance' tag did not survive the repair"; printf '%s\n' "$tags" | sed 's/^/    /'; exit 1; }
printf '%s\n' "$tags" | grep -q '^personal$' \
    || { echo "FAIL: the 'personal' tag did not survive the repair"; printf '%s\n' "$tags" | sed 's/^/    /'; exit 1; }
echo "note: the unsealed-column delta (title, username, tags) survived the repair"

# ── 3. the parked conflict row did not outlive the key that sealed it ──
#    Its payload was sealed under the lost key, so a surviving badge would
#    be an inert control: it renders, and nothing can open what it points
#    at. The repair must clear it rather than leave it haunting the vault.
export KEYHOLE_FIELD_KEY="$ROTATED_KEY"
remaining="$(badge "$VAULT")"
unset KEYHOLE_FIELD_KEY
if [ "$remaining" != 0 ]; then
    echo "FAIL: a conflict row sealed under the lost session key outlived the repair — an inert badge"
    exit 1
fi
echo "note: the parked conflict sealed under the lost key was cleared by the repair"

echo "PASS: a session key rotated under a closed vault is caught at open and repaired; an unavailable protector fails closed and keeps the mirror"
