#!/usr/bin/env bash
#
# Scenario: "purge destroys a removed vault's LOCAL-device data" — the
# engine-owned teardown a client drives when a vault is removed from a
# device. It must destroy the on-disk SQLCipher mirror sidecar (the
# encrypted local copy of the vault's full contents) AND the mirror's
# DB key, while leaving the canonical KDBX untouched (removing a vault
# from a device is not the same as deleting the vault).
#
# The engine owns the *sequence* (delete the sidecar files whose layout
# it knows — the DB file + its -wal/-shm/-journal siblings — then call
# the key provider's deleteDbKey); the platform owns the *mechanism*
# (the keystore delete). keyhole has no real keystore, so it drives the
# purge with a recording key provider and the verb itself fails closed
# if deleteDbKey was not invoked — so reaching this far already proves
# the key-deletion half ran.
#
# Assertions:
#   1. before purge the mirror sidecar exists on disk with real content;
#   2. after purge every mirror sidecar file (mirror.sqlite + WAL/SHM)
#      is gone — the encrypted local copy is destroyed;
#   3. the verb reports the db key was deleted (deleteDbKey invoked);
#   4. the source KDBX is NOT touched — it still exists and still opens;
#   5. a fresh process must RE-INGEST from the KDBX (the old mirror did
#      not survive): the sidecar is rebuilt and the entry reappears,
#      proving purge erased the local copy without harming the vault.
#
# Self-contained: drives keyhole's own create / create-entry / digest /
# list / purge — no external tooling.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-purge-master-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"
MIRROR_DIR="$VAULT.mirror"
SIDECAR="$MIRROR_DIR/mirror.sqlite"

# Count the mirror sidecar files currently on disk (mirror.sqlite plus
# any -wal/-shm/-journal siblings).
count_sidecars() {
    # `find` so a glob-with-no-match doesn't expand to a literal.
    find "$MIRROR_DIR" -maxdepth 1 -name 'mirror.sqlite*' 2>/dev/null | wc -l | tr -d ' '
}

# --- seed: a vault with one entry, establishing a populated mirror ----
# `create` alone does not establish a mirror; the first mutation ingests
# + saves, building the SQLCipher sidecar on disk.
"$KEYHOLE" create "$VAULT" >/dev/null \
    || { echo "FAIL: could not create seed vault"; exit 1; }
"$KEYHOLE" create-entry "$VAULT" "Secret" \
    --username alice --entry-password "Tr0ub4dor&3" >/dev/null \
    || { echo "FAIL: could not seed entry"; exit 1; }

# 1. the encrypted local mirror exists on disk before purge.
[ -f "$SIDECAR" ] \
    || { echo "FAIL: mirror sidecar absent before purge — nothing to destroy"; exit 1; }
[ -s "$SIDECAR" ] \
    || { echo "FAIL: mirror sidecar is empty before purge"; exit 1; }
baseline="$("$KEYHOLE" digest "$VAULT" 2>/dev/null)"
[ -n "$baseline" ] || { echo "FAIL: could not capture baseline digest"; exit 1; }

# --- the operation under test: purge the local data ------------------
out="$("$KEYHOLE" purge "$VAULT" 2>&1)" \
    || { echo "FAIL: purge verb errored"; printf '%s\n' "$out" | sed 's/^/    /'; exit 1; }

# 3. the verb reports the db key deletion was driven (the verb already
#    fails closed if deleteDbKey was not invoked; assert the signal too).
printf '%s\n' "$out" | grep -q '^db-key-deleted: true$' \
    || { echo "FAIL: purge did not report the db key was deleted"; printf '%s\n' "$out" | sed 's/^/    /'; exit 1; }

# 2. every mirror sidecar file is gone — the encrypted local copy is
#    destroyed (not merely the main DB file: WAL/SHM siblings too).
if [ -f "$SIDECAR" ]; then
    echo "FAIL: mirror sidecar still present after purge — local data survived"
    exit 1
fi
remaining="$(count_sidecars)"
if [ "$remaining" != "0" ]; then
    echo "FAIL: $remaining mirror sidecar file(s) survived purge (expected 0)"
    find "$MIRROR_DIR" -maxdepth 1 -name 'mirror.sqlite*' | sed 's/^/    /'
    exit 1
fi

# 4. purge is local-only: the canonical KDBX is untouched.
[ -f "$VAULT" ] \
    || { echo "FAIL: purge deleted the source KDBX — it must touch only the local mirror"; exit 1; }

echo "note: purge removed every mirror sidecar and reported the db key deleted; KDBX intact"

# 5. a fresh process must RE-INGEST from the KDBX — proving the old
#    mirror did not survive (the sidecar is rebuilt) and the vault is
#    intact (the entry reappears with the same content digest).
listing="$("$KEYHOLE" list "$VAULT" 2>/dev/null)"
printf '%s\n' "$listing" | grep -q 'Secret' \
    || { echo "FAIL: the 'Secret' entry did not survive in the KDBX (re-ingest empty)"; exit 1; }
[ -f "$SIDECAR" ] \
    || { echo "FAIL: a post-purge open did not rebuild the mirror (no fresh ingest)"; exit 1; }
after="$("$KEYHOLE" digest "$VAULT" 2>/dev/null)"
if [ "$after" != "$baseline" ]; then
    echo "FAIL: content digest changed across purge+re-ingest (before=$baseline after=$after)"
    exit 1
fi

echo "PASS: purge destroyed the local mirror + db key; the canonical vault is untouched and re-ingests cleanly ($baseline)"
