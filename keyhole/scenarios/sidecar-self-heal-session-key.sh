#!/usr/bin/env bash
#
# Scenario: the explicit `rebuild` verb — the POST-OPEN arm of the sidecar
# self-heal (`keys_ffi::rebuild_vault_local_data`).
#
# The sidecar seals each protected field under a session key the platform
# supplies separately from the SQLCipher mirror key (on a real client, one
# wrapped by a hardware keystore). Rotate that key and the mirror still
# opens; only its sealed blobs stop opening. The remedy is to discard the
# sidecar and re-ingest from the KDBX, which re-seals every protected
# field under the *current* session key — keeping the mirror's DB key,
# unlike `purge`.
#
# PREMISE CHANGE, worth stating because this scenario used to assert the
# opposite: a rotation is now caught at OPEN. `open_vault_self_healing`
# probes the sidecar's sealed blobs against the live session key before it
# hands the engine back, so a vault that was closed across the rotation
# repairs itself and a protected-field save no longer fails. That path is
# covered by `se-session-key-recovery.sh`. What is left for THIS scenario
# is the verb itself: the remedy a client drives when it observes the
# failure mid-session, with the engine already open and the open-time
# probe long since past.
#
# Asserts:
#   1. `rebuild` discards the sidecar and re-ingests, reporting both;
#   2. afterwards a protected-field operation SUCCEEDS under the session
#      key in force, and the entry survived the rebuild;
#   3. `rebuild` is NOT an auth bypass — under a wrong master password it
#      fails closed, because the re-ingest must unlock the KDBX first.
#      A recovery verb that skipped that check would be a way to rebuild
#      a vault's local data without ever proving you can open the vault.
#
# NOTE on data-loss surface (accepted): a rebuild throws away the
# sidecar, so any mutation made but not yet saved to the KDBX is dropped.
# That is intrinsic to "re-ingest from the source of truth". A caller
# should therefore flush what it owes the KDBX *before* driving this, not
# after — the ordering is the caller's to get right, and the drop is
# silent if it doesn't.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-self-heal-session-pw"
export KEYHOLE_PASSWORD="$PW"

# A session key (64 hex / 32 bytes) distinct from the adapter default —
# "the keystore now yields a different key".
ALT_FIELD_KEY="$(printf 'c%.0s' {1..64})"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/session-heal.kdbx"

# Seed: a vault + an entry with a PROTECTED password, sealed under the
# default session key.
"$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL: could not create vault"; exit 1; }
"$KEYHOLE" create-entry "$VAULT" "Secret" \
    --username alice --entry-password "Tr0ub4dor&3" >/dev/null \
    || { echo "FAIL: could not seed entry"; exit 1; }
ENTRY="$("$KEYHOLE" list "$VAULT" 2>/dev/null | grep -i 'Secret' | grep -oE '[0-9a-fA-F-]{36}' | head -1)"
[ -n "$ENTRY" ] || { echo "FAIL: could not resolve the seeded entry uuid"; exit 1; }

# ── 1. rebuild discards the sidecar and re-ingests ────────────────────
rb_out="$(KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" rebuild "$VAULT" 2>&1)" \
    || { echo "FAIL: rebuild verb errored"; printf '%s\n' "$rb_out" | sed 's/^/    /'; exit 1; }
printf '%s\n' "$rb_out" | grep -q '^rebuilt: true$' \
    || { echo "FAIL: rebuild did not report success"; printf '%s\n' "$rb_out" | sed 's/^/    /'; exit 1; }
discarded="$(printf '%s\n' "$rb_out" | sed -n 's/^sidecars-discarded: //p')"
case "$discarded" in
    ''|*[!0-9]*) echo "FAIL: rebuild did not report a numeric sidecars-discarded count"; printf '%s\n' "$rb_out" | sed 's/^/    /'; exit 1 ;;
esac
[ "$discarded" -ge 1 ] \
    || { echo "FAIL: rebuild discarded $discarded sidecar files — expected >= 1"; exit 1; }
echo "note: rebuild discarded $discarded stale sidecar file(s) and re-ingested"

# ── 2. the entry survived and protected-field ops work afterwards ─────
#    `update-entry` mutates then saves; the save projects the whole vault,
#    which must unwrap every protected field.
fixed_out="$(KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" update-entry "$VAULT" "$ENTRY" --username bob 2>&1)" \
    || { echo "FAIL: protected-field save fails after rebuild"; printf '%s\n' "$fixed_out" | sed 's/^/    /'; exit 1; }
KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" list "$VAULT" 2>/dev/null | grep -q 'Secret' \
    || { echo "FAIL: the Secret entry did not survive the rebuild"; exit 1; }
echo "note: the entry survived and protected-field access works under the current session key"

# ── 3. rebuild is not an auth bypass ──────────────────────────────────
wrong_out="$(KEYHOLE_PASSWORD="definitely-not-the-master-password" \
    KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" rebuild "$VAULT" 2>&1)"
wrong_rc=$?
if [ "$wrong_rc" -eq 0 ]; then
    echo "FAIL: rebuild succeeded under a WRONG master password — the recovery verb is an auth bypass"
    printf '%s\n' "$wrong_out" | sed 's/^/    /'
    exit 1
fi
# And the vault is still intact under the real password.
"$KEYHOLE" list "$VAULT" 2>/dev/null | grep -q 'Secret' \
    || { echo "FAIL: the vault is no longer readable after a refused wrong-password rebuild"; exit 1; }
echo "note: rebuild under a wrong master password failed closed and left the vault intact"

echo "PASS: the post-open rebuild discards the sidecar, re-seals from the KDBX, and re-gates on the master password"
