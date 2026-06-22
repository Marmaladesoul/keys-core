#!/usr/bin/env bash
#
# Scenario: "the sync/merge paths can never re-key an existing vault to a
# wrong password — only a fresh create keys from a raw password."
#
# Follow-up to wrong-password-no-rekey.sh. That one proved the local save
# path fails closed; this hunts the *other* candidate re-key vectors —
# the sync/merge ones — where a wrong key arriving over the sync transport
# could in principle re-key or corrupt an existing vault.
#
# Three vectors, one conclusion:
#   1. `ingest-peer` under a wrong password — the per-device-key transport
#      merge. Opens the peer kdbx with the supplied key, so a wrong key
#      fails closed before anything is written.
#   2. `reconcile_with_disk` under a wrong password — the disk-watcher
#      path taken when the on-disk signature no longer matches the mirror
#      (exactly what a sync write to the file triggers). Opens+unlocks the
#      disk kdbx with the key, so a wrong key fails closed.
#   3. `create` on a FRESH path under a "wrong" password — the ONLY path
#      that keys a kdbx from a raw, caller-supplied password (there's no
#      existing file to open-and-fail-against).
#
# The takeaway recorded in DESIGN.md: a wrong password can NEVER re-key an
# *existing* vault at this seam. So any observed re-key of an existing
# vault cannot have come from save/ingest/reconcile — it can only come
# from a fresh-create / vault-materialisation handed an unverified
# (cached) wrong password. That's a consumer-glue vector, above this seam.
#
# Self-contained: keyhole's own verbs, no keepassxc-cli.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
P="keyhole-real-pw"
W="keyhole-wrong-pw-DELIBERATELY-WRONG"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/local.kdbx"      # the user's vault, keyed P
B="$TMP/peer.kdbx"       # a peer replica, keyed P
C="$TMP/fresh.kdbx"      # a brand-new path (no file yet)

# Honest "opens under password $1?" for an arbitrary vault — fresh ingest
# from disk by wiping the mirror first.
opens_with() { # <vault> <password>
    rm -rf "$1.mirror"
    KEYHOLE_PASSWORD="$2" "$KEYHOLE" inspect "$1" >/dev/null 2>&1
}

# --- seed: local vault A (P, armed mirror) + peer replica B (P) ------
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create "$A" >/dev/null \
    || { echo "FAIL: create A"; exit 1; }
# A correct-pw mutation records a signature matching disk — arms the skip
# path (vector 1) and the reconcile path (vector 2).
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create-entry "$A" "Local" --username local >/dev/null \
    || { echo "FAIL: seed A entry"; exit 1; }
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create "$B" >/dev/null \
    || { echo "FAIL: create peer B"; exit 1; }
KEYHOLE_PASSWORD="$P" "$KEYHOLE" create-entry "$B" "Peer" --username peer >/dev/null \
    || { echo "FAIL: seed B entry"; exit 1; }

# --- VECTOR 1: ingest-peer under the WRONG password -----------------
# Don't wipe A's mirror here — we want vector 2 to still find it armed.
set +e
v1="$(KEYHOLE_PASSWORD="$W" "$KEYHOLE" ingest-peer "$A" "$B" 2>&1)"; v1rc=$?
set -e
echo "note: vector 1 (ingest-peer, wrong pw) rc=$v1rc :: $v1"
[ "$v1rc" -ne 0 ] || { echo "FAIL: ingest-peer SUCCEEDED under the wrong password"; exit 1; }

# --- VECTOR 2: reconcile (disk signature mismatch) under WRONG pw ----
# Bump A's mtime to a fixed far-future stamp so the mirror's recorded
# signature no longer matches disk → Session::open takes the reconcile
# path (the one a sync write to the file would trigger), not a fresh
# ingest. Must run before any mirror-wiping assertion.
touch -t 203012312359 "$A"
set +e
v2="$(KEYHOLE_PASSWORD="$W" "$KEYHOLE" inspect "$A" 2>&1)"; v2rc=$?
set -e
echo "note: vector 2 (reconcile, wrong pw) rc=$v2rc :: $v2"
[ "$v2rc" -ne 0 ] || { echo "FAIL: reconcile-path open SUCCEEDED under the wrong password"; exit 1; }

# --- the assertion: neither A nor B was re-keyed --------------------
opens_with "$A" "$P" || { echo "FAIL: local vault no longer opens under the correct password"; exit 1; }
if opens_with "$A" "$W"; then echo "FAIL: local vault was RE-KEYED to the wrong password"; exit 1; fi
opens_with "$B" "$P" || { echo "FAIL: peer vault no longer opens under the correct password"; exit 1; }
if opens_with "$B" "$W"; then echo "FAIL: peer vault was RE-KEYED to the wrong password"; exit 1; fi

# --- VECTOR 3: the ONE path that keys from a raw password -----------
# `create` on a fresh path has no existing file to open-and-fail-against,
# so it keys the new vault to whatever password it's handed. This is the
# only re-key vector — and it's why a vault-materialisation / first-save
# in a consumer MUST use a verified password, never a cached unverified one.
KEYHOLE_PASSWORD="$W" "$KEYHOLE" create "$C" >/dev/null \
    || { echo "FAIL: create fresh C"; exit 1; }
opens_with "$C" "$W" \
    || { echo "FAIL: a freshly-created vault didn't open under the password it was created with"; exit 1; }

echo "PASS: ingest-peer + reconcile fail closed on a wrong password (no re-key of an existing vault);"
echo "      only create-on-a-fresh-path keys from a raw password — the consumer-glue vector to guard."
