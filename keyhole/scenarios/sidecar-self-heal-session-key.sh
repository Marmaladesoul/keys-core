#!/usr/bin/env bash
#
# Scenario: the field-protection (session-key) arm of the sidecar
# self-heal. The sidecar seals each protected field under a session key
# the platform supplies separately from the SQLCipher mirror key (on a
# real client, an SE-wrapped key). If that session key is rotated out
# from under a populated sidecar, the SQLCipher mirror still OPENS fine —
# but the first read that has to unwrap a protected field fails AES-GCM.
# Unlike the db-key failure mode, this is NOT visible at open; it surfaces
# later, on a projection / save / reveal. The remedy is the same: discard
# the sidecar and re-ingest from the KDBX, which re-seals the protected
# fields under the *current* session key.
#
# keyhole reproduces a rotated session key by reopening with a different
# KEYHOLE_FIELD_KEY than the sidecar was sealed under, and drives the
# remedy through the explicit `rebuild` verb (the headless analogue of a
# client observing its SE-failure signal and rebuilding).
#
# Asserts:
#   1. with the session key rotated, a save (which must unwrap every
#      protected field) FAILS — the stale-session-key symptom;
#   2. `rebuild` discards the sidecar and re-ingests, reporting it;
#   3. afterwards the same protected-field operation SUCCEEDS under the
#      new session key, and the entry survived the rebuild.
#
# NOTE on data-loss surface (accepted): a session-key rebuild throws away
# the sidecar, so any mutation made but not yet saved to the KDBX is
# dropped. That is intrinsic to "re-ingest from the source of truth" and
# acceptable for the mid-session SE-failure case — the session was
# already unusable for protected fields.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-self-heal-session-pw"
export KEYHOLE_PASSWORD="$PW"

# A session key (64 hex / 32 bytes) distinct from the adapter default —
# "the SE now yields a different key".
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

# ── 1. rotated session key -> a save fails to unwrap protected fields ──
#    `update-entry` mutates then saves; the save projects the whole vault,
#    which must unwrap the protected password — sealed under the default
#    session key, now being read under ALT_FIELD_KEY.
broke_out="$(KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" update-entry "$VAULT" "$ENTRY" --username bob 2>&1)"
broke_rc=$?
if [ "$broke_rc" -eq 0 ]; then
    echo "FAIL: a protected-field save succeeded under a rotated session key — the stale key was not detected"
    exit 1
fi
echo "note: rotated session key broke the protected-field save (as expected)"

# ── 2. rebuild discards the sidecar and re-ingests ────────────────────
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

# ── 3. the same protected-field op now SUCCEEDS, and the entry survived
#    Re-seal happened under ALT_FIELD_KEY, so a save that unwraps the
#    protected field now works.
fixed_out="$(KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" update-entry "$VAULT" "$ENTRY" --username bob 2>&1)" \
    || { echo "FAIL: protected-field save still fails after rebuild"; printf '%s\n' "$fixed_out" | sed 's/^/    /'; exit 1; }
KEYHOLE_FIELD_KEY="$ALT_FIELD_KEY" "$KEYHOLE" list "$VAULT" 2>/dev/null | grep -q 'Secret' \
    || { echo "FAIL: the Secret entry did not survive the rebuild"; exit 1; }

echo "PASS: a rotated session key broke protected-field access; rebuild re-sealed from the KDBX and restored it"
