#!/usr/bin/env bash
#
# Adversarial save-fidelity on KDBX 3.1 (the format-breadth pass for
# save-fidelity-adversarial.sh). KDBX3 is the older on-disk format — coarser
# timestamps, binaries in the inner header, a different element set — so it's
# the classic place a projection bug hides, and the place a silent format
# UPGRADE (KDBX3 → 4 on save) would surprise a user who keeps a 3.1 vault for
# another tool's sake.
#
# keyhole can't author KDBX3 (create makes v4), so this opens a vendored KDBX3
# fixture (keepassxc-authored, one entry), builds it rich through the engine —
# every mutation saves, and the engine preserves the source format — then an
# INDEPENDENT reader (keepassxc-cli) confirms (a) the file is STILL KDBX3 and
# (b) every facet survived. Same adversarial discipline as the v4 scenario:
# independent oracle (not our own reader), teeth, fail-loud if the cli is gone.
#
# Fixture password is the public one from the fixture's .json sidecar (a test
# credential, not a secret).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$HERE/fixtures/kdbx3-minimal.kdbx"
# The fixture sidecar password, as a literal (emoji is UTF-8 in this file;
# single quotes keep the trailing backslash literal). Avoids bash 4.2+ `\U`
# escapes — this must run under macOS's bash 3.2 too.
PW='tëst pässwörd 🔑/\'
export KEYHOLE_PASSWORD="$PW"

XC="$(command -v keepassxc-cli 2>/dev/null || true)"
if [ -z "$XC" ] && [ -x "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli" ]; then
    XC="/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"
fi
if [ -z "$XC" ]; then
    echo "FAIL: keepassxc-cli not found — KDBX3 save-fidelity REQUIRES an independent reader;"
    echo "      it must never silently skip. CI: 'apt-get install -y keepassxc'; macOS: KeePassXC.app."
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
V="$TMP/k3.kdbx"
cp "$FIXTURE" "$V"

xc() { printf '%s\n' "$PW" | "$XC" "$@" 2>/dev/null; }
# KDBX major version from the signature block (offset 10, little-endian):
# "0300" = KDBX3, "0400" = KDBX4. od is POSIX (portable across macOS + CI).
kdbx_major() { od -An -tx1 -j10 -N2 "$1" | tr -d ' \n'; }

[ "$(kdbx_major "$V")" = "0300" ] \
    || { echo "FAIL(setup): vendored fixture is not KDBX3 (got $(kdbx_major "$V"))"; exit 1; }

# --- build rich content through the engine (each mutation saves; the engine
#     must preserve the KDBX3 format it opened) ------------------------------
"$KEYHOLE" --at 1000000 create-entry "$V" "Secret" --username alpha --entry-password s3cret >/dev/null
uuid="$("$KEYHOLE" list "$V" | awk '/Secret/ {print $1; exit}')"
"$KEYHOLE" --at 2000000 update-entry "$V" "$uuid" --url "https://example.test" --notes "hello notes" >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$V" "$uuid" --username bravo >/dev/null   # alpha → history
"$KEYHOLE" --at 4000000 set-attachment "$V" "$uuid" "file.bin" --text "PAYLOAD-k3-attach" >/dev/null
"$KEYHOLE" --at 5000000 add-custom-icon "$V" "$uuid" "ICON-IMAGE-K3" >/dev/null
"$KEYHOLE" --at 6000000 set-field "$V" "$uuid" "API-Token" "tok-k3-field" >/dev/null

# --- (1) FORMAT preserved: the engine must not silently upgrade KDBX3 → 4 ---
[ "$(kdbx_major "$V")" = "0300" ] \
    || { echo "FAIL: engine UPGRADED the vault KDBX3 → KDBX4 on save (silent format change — would break the user's 3.1 tooling)"; exit 1; }

# --- (2) CONTENT survived, read back by the independent reader --------------
show="$(xc show -s "$V" "Secret")"
grep -q "UserName: bravo"           <<<"$show" || { echo "FAIL: username lost on KDBX3 save"; exit 1; }
grep -q "Password: s3cret"          <<<"$show" || { echo "FAIL: password lost on KDBX3 save"; exit 1; }
grep -q "URL: https://example.test" <<<"$show" || { echo "FAIL: url lost on KDBX3 save"; exit 1; }
grep -q "Notes: hello notes"        <<<"$show" || { echo "FAIL: notes lost on KDBX3 save"; exit 1; }

[ "$(xc show -a "API-Token" "$V" "Secret")" = "tok-k3-field" ] \
    || { echo "FAIL: custom field lost on KDBX3 save"; exit 1; }

xc attachment-export "$V" "Secret" "file.bin" "$TMP/att.out" >/dev/null
[ "$(cat "$TMP/att.out")" = "PAYLOAD-k3-attach" ] \
    || { echo "FAIL: attachment bytes lost/mangled on KDBX3 save (got: $(cat "$TMP/att.out"))"; exit 1; }

xml="$(xc export --format xml "$V")"
grep -q "<History>" <<<"$xml"        || { echo "FAIL: <History> stripped on KDBX3 save"; exit 1; }
grep -q "alpha"     <<<"$xml"        || { echo "FAIL: history content (pre-edit username) stripped on KDBX3 save"; exit 1; }
grep -q "<CustomIcons>"    <<<"$xml" || { echo "FAIL: custom-icon pool stripped on KDBX3 save"; exit 1; }
grep -q "<CustomIconUUID>" <<<"$xml" || { echo "FAIL: custom-icon reference stripped on KDBX3 save"; exit 1; }

# --- TEETH: prove the independent-reader check isn't vacuous ----------------
cp "$V" "$TMP/sabotaged.kdbx"
xc attachment-rm "$TMP/sabotaged.kdbx" "Secret" "file.bin" >/dev/null
if xc attachment-export "$TMP/sabotaged.kdbx" "Secret" "file.bin" "$TMP/sab.out" >/dev/null 2>&1 \
   && [ "$(cat "$TMP/sab.out" 2>/dev/null)" = "PAYLOAD-k3-attach" ]; then
    echo "FAIL(teeth): the attachment check did not detect a removed attachment — it is vacuous"
    exit 1
fi

echo "PASS: KDBX3 vault round-trips through the engine staying KDBX3, all facets intact under an independent reader (keepassxc-cli $($XC --version 2>/dev/null)); teeth-verified"
