#!/usr/bin/env bash
#
# Scenario: "a KEYFILE-KEYED vault can peer-sync" — the sync half of keyfile
# support, and the fail-closed teeth on the peer-ingest path.
#
# `keyfile-vault.sh` proves a keyfile-keyed vault opens, round-trips and
# re-keys. That is all local: it says nothing about whether such a vault can
# take part in sync. `ingest-peer` is the per-device-key transport verb, and it
# opens a SECOND KDBX (the peer blob off the wire) under its own key factors.
# If that open is password-only, a keyfile-keyed vault cannot peer-sync AT ALL
# — it is not a degraded merge, it is a hard "no". This scenario is the gate on
# that capability.
#
# Replicas of one vault share its key factors (they are the same vault on two
# devices), so the peer blob decrypts under the same password + keyfile as the
# local vault.
#
# Assertions:
#
#   (a) CONVERGENCE — two keyfile-keyed replicas diverge on one entry;
#       `ingest-peer` parks the conflict rather than clobbering; the resolution
#       syncs back and both replicas reach the same content digest. The whole
#       loop `offline-divergence.sh` runs for a password-only vault must hold
#       identically when a keyfile is in the composite.
#
#   (b) FAIL-CLOSED TEETH — peer-ingest with an ABSENT keyfile, and with a
#       WRONG-but-valid keyfile, must both FAIL. Neither may fall back to a
#       password-only open, and neither may leave the mirror mutated: a correct
#       peer-ingest must still work afterwards.
#
# Why (b) runs over a WARM mirror: with a cold mirror, `Session::open` ingests
# the LOCAL vault from disk first, so a missing keyfile would fail there — and
# we would be re-proving `keyfile-vault.sh`'s local gate, not the peer-open
# gate. A warm mirror (signature matches → local ingest skipped) lets execution
# actually REACH the peer open, which is the code path under test. It is also
# the realistic shape: a client with the vault already open receives a blob.
#
# Self-contained: keyhole's own create / create-entry / update-entry /
# ingest-peer / list-conflicts / resolve / digest (+ the keyfile mint).

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-keyfile-sync-master"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VAULT="$TMP/device-a.kdbx"   # replica A (the one receiving the merge)
PEER="$TMP/device-b.kdbx"    # replica B (the blob "off the wire")
KF="$TMP/vault.keyfile"      # the shared keyfile — both replicas are keyed with it
WKF="$TMP/wrong.keyfile"     # an unrelated mint: valid keyfile, wrong vault

# ── seed: one keyfile-keyed vault, one entry, cloned to a second device ──────
"$KEYHOLE" create "$VAULT" --keyfile "$KF" >/dev/null \
    || { echo "FAIL(setup): could not create the keyfile-keyed vault"; exit 1; }
"$KEYHOLE" create-entry "$VAULT" "Shared Login" --username original --keyfile "$KF" >/dev/null \
    || { echo "FAIL(setup): could not seed the entry under pw+keyfile"; exit 1; }
uuid="$("$KEYHOLE" list "$VAULT" --keyfile "$KF" | awk '/Shared Login/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL(setup): could not find the seeded entry"; exit 1; }

# A replica is the same vault on another device: same file, same key factors.
cp "$VAULT" "$PEER"

# A WRONG-but-valid keyfile = an unrelated mint (distinct 32 bytes). Minted via
# a decoy vault, exactly as keyfile-vault.sh does.
KEYHOLE_PASSWORD="decoy" "$KEYHOLE" create "$TMP/decoy.kdbx" --keyfile "$WKF" >/dev/null 2>&1 \
    || { echo "FAIL(setup): could not mint the wrong keyfile"; exit 1; }

# ── (a) convergence: diverge while apart, then sync ──────────────────────────
"$KEYHOLE" update-entry "$VAULT" "$uuid" --username alice --keyfile "$KF" >/dev/null \
    || { echo "FAIL: could not diverge replica A"; exit 1; }
"$KEYHOLE" update-entry "$PEER" "$uuid" --username bob --keyfile "$KF" >/dev/null \
    || { echo "FAIL: could not diverge replica B"; exit 1; }

# The assertion this whole scenario exists for: a keyfile-keyed peer blob is
# INGESTIBLE. Before the keyfile reached this verb, this call could not open
# the peer at all and a keyfile-keyed vault was simply excluded from sync.
"$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-b --keyfile "$KF" >/dev/null \
    || { echo "FAIL: ingest-peer could not open a keyfile-keyed peer — the vault cannot sync"; exit 1; }

# Parked, not clobbered — and visible from a separate process (persistent mirror).
"$KEYHOLE" list-conflicts "$VAULT" --keyfile "$KF" | grep "$uuid" >/dev/null \
    || { echo "FAIL: divergence did not park as a held conflict on a keyfile-keyed vault"; exit 1; }

"$KEYHOLE" resolve "$VAULT" --entry "$uuid" --choose remote --keyfile "$KF" >/dev/null \
    || { echo "FAIL: could not resolve the conflict on a keyfile-keyed vault"; exit 1; }

# Convergence must be ON DISK: nuke the mirror so the read re-ingests from the
# KDBX under pw+keyfile — the only honest "did the resolution save?".
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" --keyfile "$KF" | grep '<bob>' >/dev/null \
    || { echo "FAIL: the resolved username did not persist to the keyfile-keyed KDBX"; exit 1; }

# Sync the resolution back to B: it must adopt (no re-park) and both replicas
# must digest identically.
"$KEYHOLE" ingest-peer "$PEER" "$VAULT" --owner device-a --keyfile "$KF" >/dev/null \
    || { echo "FAIL: replica B could not ingest the resolved keyfile-keyed peer"; exit 1; }
"$KEYHOLE" list-conflicts "$PEER" --keyfile "$KF" | grep '(no held conflicts)' >/dev/null \
    || { echo "FAIL: replica B re-parked a conflict the peer already resolved"; exit 1; }

da="$("$KEYHOLE" digest "$VAULT" --keyfile "$KF")"
db="$("$KEYHOLE" digest "$PEER" --keyfile "$KF")"
[ -n "$da" ] || { echo "FAIL: could not digest replica A under pw+keyfile"; exit 1; }
[ "$da" = "$db" ] \
    || { echo "FAIL: keyfile-keyed replicas did not converge"; echo "  A: $da"; echo "  B: $db"; exit 1; }

echo "note: keyfile-keyed replicas park, resolve and converge (digest $da)"

# ── (b) fail-closed teeth on the peer open ──────────────────────────────────
# Give B an edit A doesn't have, so a successful ingest has real work to do (a
# no-op ingest could "succeed" without the peer open ever mattering — no teeth
# in that). Both replicas converged above, so this one-sided edit ADOPTS on A
# rather than parking; adoption is the observable that proves the peer was
# actually opened and merged.
"$KEYHOLE" update-entry "$PEER" "$uuid" --username carol --keyfile "$KF" >/dev/null \
    || { echo "FAIL(setup): could not advance replica B"; exit 1; }

# Warm A's mirror so Session::open skips the LOCAL ingest (see header): the
# keyfile-less attempts below then genuinely reach the PEER open.
"$KEYHOLE" inspect "$VAULT" --keyfile "$KF" >/dev/null 2>&1 \
    || { echo "FAIL(setup): could not warm replica A's mirror"; exit 1; }

# No keyfile at all: must NOT fall back to a password-only open of the peer.
if "$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-b >/dev/null 2>&1; then
    echo "FAIL: peer-ingest SUCCEEDED with no keyfile — the peer open fell back to password-only"
    exit 1
fi

# Wrong-but-valid keyfile: the keyfile must actually participate in the composite.
if "$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-b --keyfile "$WKF" >/dev/null 2>&1; then
    echo "FAIL: peer-ingest SUCCEEDED with the WRONG keyfile — the keyfile is not in the composite"
    exit 1
fi

# The refused attempts must not have damaged anything: a correct peer-ingest
# still works afterwards, and B's edit lands. Read back over a WIPED mirror so
# the assertion reflects the KDBX on disk, not carried-over mirror state.
"$KEYHOLE" ingest-peer "$VAULT" "$PEER" --owner device-b --keyfile "$KF" >/dev/null \
    || { echo "FAIL: a refused-keyfile peer-ingest broke the correct one afterwards"; exit 1; }
rm -rf "$VAULT.mirror"
"$KEYHOLE" list "$VAULT" --keyfile "$KF" | grep '<carol>' >/dev/null \
    || { echo "FAIL: the post-refusal peer-ingest did not adopt the peer's edit"; exit 1; }

echo "PASS: keyfile-keyed replicas peer-sync to convergence, and peer-ingest fails closed on an absent or wrong keyfile (no password-only fallback)"
