#!/usr/bin/env bash
#
# Scenario: a KEYFILE-KEYED vault — the engine half of "keyfile support".
#
# A keyfile is a second key factor mixed into the standard interoperable KDBX
# composite (SHA-256(SHA-256(pw) || keyfile_hash) -> KDF). Its security job is
# to harden the *at-rest / cloud-synced KDBX file* against offline brute force:
# the keyfile lives apart from the .kdbx (a client's keychain; a file for
# keyhole, which has no keychain) and never travels with it. There is NO
# engine-side "this vault needs a keyfile" flag — the crypto IS the enforcement:
# a vault keyed with a keyfile simply cannot be unlocked without it. The concept
# is fully decoupled from sync (keyfiles apply to local and synced vaults alike).
#
# This is keyhole's first keyfile-bearing surface. It exercises:
#   --keyfile <path>      the vault's keyfile (minted at the path on `create`
#                         if absent; an existing file is used as-is)
#   --new-keyfile <path>  the rotation target for `rekey`
# and `generate_keyfile` (the mint primitive) via the create/rekey mint path.
#
# Assertions, run against BOTH KDBX 3.1 and KDBX 4 (the composite is
# format-agnostic, so both must be green):
#
#   (a) KEYFILE-REQUIRED — opening the vault WITHOUT the keyfile fails closed;
#       WITH the correct keyfile it opens normally.
#   (b) ROUND-TRIP — create under pw+keyfile -> close + wipe mirror -> reopen
#       under pw+keyfile -> `rekey` to a NEW keyfile -> wipe mirror -> the OLD
#       keyfile is inert, the NEW pw+keyfile opens, and the content digest is
#       UNCHANGED (the rekey rotated the key, not the contents).
#   (c) FAIL-CLOSED TEETH — correct pw + ABSENT keyfile fails; correct pw +
#       WRONG keyfile fails; both leave the vault still openable under the
#       correct pw+keyfile.
#
# A local-only (no-keyfile) vault is unaffected by all of this — and rejects a
# spurious keyfile (proving the keyfile actually participates in the composite).
#
# Every "does it open?" is a FRESH keyhole process over a wiped mirror, so the
# answer reflects the on-disk key, never carried-over mirror state — the only
# honest test of a crypto-envelope change.
#
# Self-contained: keyhole's own create / create-entry / rekey / inspect /
# digest (+ the keyfile mint). No keepassxc-cli.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$HERE/fixtures/kdbx3-minimal.kdbx"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Honest "does $1 open under password $2 (+ optional keyfile $3)?" — force a
# fresh ingest from disk by wiping the persistent mirror first.
opens_with() { # <vault> <password> [keyfile]
    rm -rf "$1.mirror"
    if [ -n "${3:-}" ]; then
        KEYHOLE_PASSWORD="$2" "$KEYHOLE" inspect "$1" --keyfile "$3" >/dev/null 2>&1
    else
        KEYHOLE_PASSWORD="$2" "$KEYHOLE" inspect "$1" >/dev/null 2>&1
    fi
}

# Content digest of $1 as unlocked under password $2 + keyfile $3 — a
# fresh-ingest read, so it reflects disk, not carried-over mirror state. The
# digest covers user-visible content and excludes timestamps/history, so it is
# the right "contents preserved across re-key" oracle.
digest_with() { # <vault> <password> <keyfile>
    rm -rf "$1.mirror"
    KEYHOLE_PASSWORD="$2" "$KEYHOLE" digest "$1" --keyfile "$3" 2>/dev/null
}

# KDBX major version from the signature block (offset 10, little-endian):
# "0300" = KDBX3, "0400" = KDBX4. od is POSIX (portable across macOS + CI).
kdbx_major() { od -An -tx1 -j10 -N2 "$1" | tr -d ' \n'; }

# Assertions (a) + (b) + (c) against an already-created pw+keyfile vault.
run_suite() { # <vault> <password> <keyfile> <label>
    local V="$1" PW="$2" KF="$3" LABEL="$4"
    local NKF="$V.new.keyfile"
    local WKF="$TMP/wrong-$LABEL.keyfile"
    # A WRONG-but-valid keyfile = an unrelated mint (distinct 32 bytes).
    KEYHOLE_PASSWORD="x" "$KEYHOLE" create "$TMP/decoy-$LABEL.kdbx" --keyfile "$WKF" >/dev/null 2>&1

    # (a) + (c): the correct keyfile opens; absent / wrong fail closed; and the
    # refused attempts leave the correct keyfile working.
    opens_with "$V" "$PW" "$KF" \
        || { echo "FAIL[$LABEL]: pw+keyfile does not open its own vault"; exit 1; }
    if opens_with "$V" "$PW"; then
        echo "FAIL[$LABEL]: vault opened WITHOUT the keyfile — not fail-closed"; exit 1
    fi
    if opens_with "$V" "$PW" "$WKF"; then
        echo "FAIL[$LABEL]: vault opened with the WRONG keyfile"; exit 1
    fi
    opens_with "$V" "$PW" "$KF" \
        || { echo "FAIL[$LABEL]: a refused-keyfile attempt broke access under the correct keyfile"; exit 1; }

    # (b): baseline digest, then rotate to a NEW keyfile and prove the old one
    # is inert, the new one opens, and the content digest is unchanged.
    local d0
    d0="$(digest_with "$V" "$PW" "$KF")"
    [ -n "$d0" ] || { echo "FAIL[$LABEL]: could not capture baseline digest under pw+keyfile"; exit 1; }

    rm -rf "$V.mirror"
    KEYHOLE_PASSWORD="$PW" KEYHOLE_NEW_PASSWORD="$PW" \
        "$KEYHOLE" rekey "$V" --keyfile "$KF" --new-keyfile "$NKF" >/dev/null \
        || { echo "FAIL[$LABEL]: rekey to a new keyfile errored"; exit 1; }

    if opens_with "$V" "$PW" "$KF"; then
        echo "FAIL[$LABEL]: the OLD keyfile still opens after rekey — old key not inert"; exit 1
    fi
    opens_with "$V" "$PW" "$NKF" \
        || { echo "FAIL[$LABEL]: the NEW keyfile does not open after rekey — rekey lost the key"; exit 1; }

    local d1
    d1="$(digest_with "$V" "$PW" "$NKF")"
    [ "$d0" = "$d1" ] \
        || { echo "FAIL[$LABEL]: content digest changed across keyfile rekey (before=$d0 after=$d1)"; exit 1; }

    echo "note[$LABEL]: keyfile-required + round-trip + rekey-rotates-keyfile hold (digest $d0)"
}

# ── KDBX 4 leg ───────────────────────────────────────────────────────────────
# keyhole mints a v4 keyfile vault directly (`create --keyfile` mints the .keyx).
V4="$TMP/v4.kdbx"
KF4="$TMP/v4.keyfile"
PW4="keyhole-v4-master"
KEYHOLE_PASSWORD="$PW4" "$KEYHOLE" create "$V4" --keyfile "$KF4" >/dev/null \
    || { echo "FAIL: could not create the v4 keyfile vault"; exit 1; }
KEYHOLE_PASSWORD="$PW4" "$KEYHOLE" create-entry "$V4" "Secret" \
    --username alice --entry-password "Tr0ub4dor&3" --keyfile "$KF4" >/dev/null \
    || { echo "FAIL: could not seed the v4 entry under pw+keyfile"; exit 1; }
[ "$(kdbx_major "$V4")" = "0400" ] \
    || { echo "FAIL(setup): the minted vault is not KDBX4 (got $(kdbx_major "$V4"))"; exit 1; }
run_suite "$V4" "$PW4" "$KF4" "kdbx4"

# ── KDBX 3.1 leg ─────────────────────────────────────────────────────────────
# keyhole can't author KDBX3, so take the vendored password-only KDBX3 fixture
# and `rekey` it from password-only to password+keyfile (the None -> Some
# transition). The engine performs this WITHOUT upgrading the on-disk format, so
# the result is a genuine KDBX3 vault keyed by a keyfile — proving the composite
# (and the keyfile-required behaviour) is format-agnostic. The fixture password
# is the public one from its sidecar (a test credential, not a secret); single
# quotes keep the emoji/backslash literal, and this stays bash-3.2-safe.
V3="$TMP/v3.kdbx"
KF3="$TMP/v3.keyfile"
FPW='tëst pässwörd 🔑/\'
cp "$FIXTURE" "$V3"
[ "$(kdbx_major "$V3")" = "0300" ] \
    || { echo "FAIL(setup): vendored fixture is not KDBX3 (got $(kdbx_major "$V3"))"; exit 1; }

rm -rf "$V3.mirror"
KEYHOLE_PASSWORD="$FPW" KEYHOLE_NEW_PASSWORD="$FPW" \
    "$KEYHOLE" rekey "$V3" --new-keyfile "$KF3" >/dev/null \
    || { echo "FAIL: could not rekey the KDBX3 fixture to add a keyfile"; exit 1; }
[ "$(kdbx_major "$V3")" = "0300" ] \
    || { echo "FAIL: adding a keyfile UPGRADED KDBX3 -> $(kdbx_major "$V3") — the source format must be preserved"; exit 1; }
run_suite "$V3" "$FPW" "$KF3" "kdbx3"

# ── local-only vault is unaffected ───────────────────────────────────────────
LV="$TMP/local.kdbx"
PWL="keyhole-local-master"
KEYHOLE_PASSWORD="$PWL" "$KEYHOLE" create "$LV" >/dev/null \
    || { echo "FAIL: could not create the local-only vault"; exit 1; }
opens_with "$LV" "$PWL" \
    || { echo "FAIL: local-only (no-keyfile) vault does not open under its own password"; exit 1; }
if opens_with "$LV" "$PWL" "$KF4"; then
    echo "FAIL: local-only vault accepted a keyfile it was never keyed with (keyfile ignored?)"; exit 1
fi

echo "PASS: keyfile-keyed vaults fail closed without the keyfile, round-trip across close+reopen, and rekey rotates the keyfile (KDBX 3.1 + KDBX 4); a local-only vault is unaffected"
