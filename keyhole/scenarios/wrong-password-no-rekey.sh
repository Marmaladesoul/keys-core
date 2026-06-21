#!/usr/bin/env bash
#
# Scenario: "a wrong master password can never re-key (or corrupt) the
# vault" — the data-safety invariant that typing a WRONG password into a
# consumer's unlock flow must never silently re-key a live vault and lock
# the user out of their own data.
#
# The root cause lives at this seam: `Session::open` skips ingest when
# the mirror's recorded (mtime,size) signature matches the kdbx on disk
# (the steady-state perf win — no Argon2). That skip path NEVER reads
# the kdbx, so on its own it can't reject a wrong password — the open
# "succeeds" for any string. This scenario exercises exactly that
# skip-path-accepts-wrong-password gap, then asserts the one thing that
# actually matters for the user's data: a subsequent save must NOT
# re-key the kdbx to that wrong password.
#
# Today the protection is `save_to_kdbx`: it opens the on-disk kdbx with
# the supplied password FIRST (as the crypto-envelope template), so a
# wrong password makes the save FAIL CLOSED rather than re-key. This
# test pins that invariant — if anyone ever changes the save path to
# re-derive the key from the password instead of open-then-reuse, the
# vault would re-key to the wrong password and this scenario goes red.
#
# Self-contained: drives keyhole's own `create` / `create-entry` /
# `inspect`, no keepassxc-cli.
#
# NOTE (altitude): the skip-path open ITSELF accepting a wrong password
# is a gap a consumer is expected to close one rung up (e.g. by verifying
# the typed password against a previously-verified one before trusting
# the skip). keyhole has no consumer-side secret store, so it can't
# exercise that specific remedy — see DESIGN.md → Findings → "Skip-ingest
# unlock does not verify the master password".

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
CORRECT="keyhole-correct-pw"
WRONG="keyhole-wrong-pw-DELIBERATELY-WRONG"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# Honest "does the kdbx open under password $1?" — force a fresh ingest
# from disk by wiping the persistent mirror first (the mirror would
# otherwise answer from carried-over state, not the on-disk key).
opens_with() {
    rm -rf "$VAULT.mirror"
    KEYHOLE_PASSWORD="$1" "$KEYHOLE" inspect "$VAULT" >/dev/null 2>&1
}

# --- seed: a vault created + mutated under the CORRECT password ------
# The create alone doesn't establish a mirror; the first correct-pw
# mutation ingests + saves, recording a signature that matches disk —
# which is precisely the state that arms the skip path next time.
KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL: could not create seed vault"; exit 1; }
KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" create-entry "$VAULT" "Original" --username keep >/dev/null \
    || { echo "FAIL: could not seed entry under the correct password"; exit 1; }

# Sanity: the seed vault opens under the correct password to start with.
opens_with "$CORRECT" || { echo "FAIL: seed vault doesn't open under its own password"; exit 1; }

# --- the gap: open+mutate+save under the WRONG password --------------
# The mirror signature now matches disk, so Session::open takes the skip
# path and accepts $WRONG without verifying it (the skip-path gap under test).
# Then create-entry mutates the mirror and save_to_kdbx($WRONG) runs.
set +e
out="$(KEYHOLE_PASSWORD="$WRONG" "$KEYHOLE" create-entry "$VAULT" "Injected" --username attacker 2>&1)"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    echo "note: open+mutate+save under the WRONG password reported SUCCESS"
else
    echo "note: open+mutate+save under the WRONG password was refused (rc=$rc):"
    echo "$out" | sed 's/^/    /'
fi

# --- the assertion that protects the user's data --------------------
# Regardless of whether the save errored, the on-disk kdbx must be
# UNTOUCHED by the wrong password: still openable under the correct one,
# still rejecting the wrong one.
correct_opens=no; opens_with "$CORRECT" && correct_opens=yes
wrong_opens=no;   opens_with "$WRONG"   && wrong_opens=yes
echo "note: after the wrong-password write — correct opens: $correct_opens, wrong opens: $wrong_opens"

if [ "$correct_opens" != "yes" ]; then
    echo "FAIL: vault no longer opens under the CORRECT password — a wrong unlock attempt destroyed access"
    exit 1
fi
if [ "$wrong_opens" = "yes" ]; then
    echo "FAIL: vault now opens under the WRONG password — it was silently RE-KEYED"
    exit 1
fi

# And the wrong-password write must not have leaked onto disk either.
rm -rf "$VAULT.mirror"
listing="$(KEYHOLE_PASSWORD="$CORRECT" "$KEYHOLE" list "$VAULT" 2>/dev/null)"
if printf '%s\n' "$listing" | grep -q 'Injected'; then
    echo "FAIL: the wrong-password write persisted an 'Injected' entry to disk"
    exit 1
fi

echo "PASS: a wrong-password unlock attempt left the kdbx key intact — save_to_kdbx fails closed, no re-key, no leaked write"
