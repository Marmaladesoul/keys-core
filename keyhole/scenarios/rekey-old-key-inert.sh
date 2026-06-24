#!/usr/bin/env bash
#
# Scenario: "vault re-key rotates the master key so the OLD password is
# inert and the NEW one opens the vault, with contents byte-preserved" —
# the engine half of the revoke / lost-device / share-revoke primitive.
#
# Re-key is the load-bearing data-safety operation behind every "make the
# old key stop working" path, so it gets the harshest honest test keyhole
# can mount: every open is a FRESH process over a wiped mirror, forcing a
# real ingest from disk. The persistent mirror would otherwise answer
# "does it open?" from carried-over state, not the on-disk key — so the
# only truthful "did the KDBX really re-encrypt on disk?" is
# `rm -rf "$VAULT.mirror"` + a fresh keyhole process re-ingesting.
#
# Assertions:
#   1. after re-key, the OLD password no longer opens the vault;
#   2. the NEW password does;
#   3. the content digest is unchanged (entries/groups/fields preserved);
#   4. teeth — a re-key attempt under the WRONG current password fails
#      closed: it does NOT rotate (the on-disk envelope is opened under
#      the current password first), leaving OLD still working and the
#      attempted new password inert.
#
# Self-contained: drives keyhole's own create / create-entry / digest /
# inspect — no keepassxc-cli.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
OLD="keyhole-old-master-pw"
NEW="keyhole-new-master-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# Honest "does the kdbx open under password $1?" — force a fresh ingest
# from disk by wiping the persistent mirror first.
opens_with() {
    rm -rf "$VAULT.mirror"
    KEYHOLE_PASSWORD="$1" "$KEYHOLE" inspect "$VAULT" >/dev/null 2>&1
}

# Content digest of the on-disk vault as unlocked under password $1 —
# a fresh-ingest read so it reflects disk, not carried-over mirror state.
# The digest covers user-visible content (fields, group tree, icons,
# recycle-bin state) and excludes timestamps/history, so it is the right
# "contents preserved across re-key" oracle (the master-key-changed stamp
# re-key writes is a timestamp and does not perturb it).
digest_with() {
    rm -rf "$VAULT.mirror"
    KEYHOLE_PASSWORD="$1" "$KEYHOLE" digest "$VAULT" 2>/dev/null
}

# --- seed: a vault created + populated under the OLD password --------
# The create alone doesn't establish a mirror; the first mutation
# ingests + saves, recording a signature that matches disk.
KEYHOLE_PASSWORD="$OLD" "$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL: could not create seed vault"; exit 1; }
KEYHOLE_PASSWORD="$OLD" "$KEYHOLE" create-group "$VAULT" "Logins" >/dev/null \
    || { echo "FAIL: could not seed group"; exit 1; }
KEYHOLE_PASSWORD="$OLD" "$KEYHOLE" create-entry "$VAULT" "Secret" \
    --username alice --entry-password "Tr0ub4dor&3" >/dev/null \
    || { echo "FAIL: could not seed entry under the old password"; exit 1; }

# Sanity + baseline: the seed vault opens under OLD, not under NEW, and
# we capture its content digest to compare across the re-key.
opens_with "$OLD"  || { echo "FAIL: seed vault doesn't open under its own password"; exit 1; }
opens_with "$NEW"  && { echo "FAIL: seed vault opens under the NEW password before re-key"; exit 1; }
baseline="$(digest_with "$OLD")"
[ -n "$baseline" ] || { echo "FAIL: could not capture baseline digest"; exit 1; }

# --- the operation under test: re-key OLD -> NEW ---------------------
KEYHOLE_PASSWORD="$OLD" KEYHOLE_NEW_PASSWORD="$NEW" "$KEYHOLE" rekey "$VAULT" >/dev/null \
    || { echo "FAIL: rekey verb errored"; exit 1; }

# 1 + 2: the OLD password is now inert; the NEW one opens the vault.
if opens_with "$OLD"; then
    echo "FAIL: OLD password still opens the vault after re-key — old key not inert"
    exit 1
fi
if ! opens_with "$NEW"; then
    echo "FAIL: NEW password does not open the vault after re-key — re-key lost the key"
    exit 1
fi

# 3: contents preserved — same digest, and the entry is still there.
after="$(digest_with "$NEW")"
if [ "$after" != "$baseline" ]; then
    echo "FAIL: content digest changed across re-key (before=$baseline after=$after)"
    exit 1
fi
rm -rf "$VAULT.mirror"
listing="$(KEYHOLE_PASSWORD="$NEW" "$KEYHOLE" list "$VAULT" 2>/dev/null)"
printf '%s\n' "$listing" | grep -q 'Secret' \
    || { echo "FAIL: the 'Secret' entry did not survive the re-key"; exit 1; }

echo "note: re-key rotated OLD->NEW; old key inert, new key opens, digest preserved ($baseline)"

# --- teeth: a WRONG current password must NOT re-key (fail closed) ---
# The engine opens the on-disk envelope under the supplied current
# password FIRST, so a wrong one can never rotate the vault. Attempt a
# re-key with a bogus current password toward an attacker-chosen new one.
WRONG="keyhole-wrong-current-DELIBERATELY-WRONG"
ATTACKER="keyhole-attacker-new-pw"
set +e
out="$(KEYHOLE_PASSWORD="$WRONG" KEYHOLE_NEW_PASSWORD="$ATTACKER" "$KEYHOLE" rekey "$VAULT" 2>&1)"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    echo "FAIL: re-key under the WRONG current password reported SUCCESS — it must fail closed"
    echo "$out" | sed 's/^/    /'
    exit 1
fi

# After the refused attempt the key must be untouched: NEW still opens
# (the legitimate re-key above), the attacker's chosen password does not.
if ! opens_with "$NEW"; then
    echo "FAIL: a refused wrong-current-password re-key broke access under the NEW password"
    exit 1
fi
if opens_with "$ATTACKER"; then
    echo "FAIL: the vault was re-keyed to the attacker's password despite a wrong current password"
    exit 1
fi

echo "PASS: re-key makes the old key inert and the new key open (contents preserved); a wrong current password fails closed without rotating"
