#!/usr/bin/env bash
#
# Adversarial save-fidelity (pre-soak insurance): the engine never saves a
# vault directly — it projects the SQLite mirror back into a vault and
# re-serialises that to KDBX. So a save is only as faithful as the projection,
# and a projection that silently drops a facet loses it on EVERY save (this
# already bit once — keyhole Finding #6, history attachments stripped on save).
#
# The naive check — round-trip through our own writer + reader — can pass
# VACUOUSLY: if our writer drops `<Foo>` and our reader also ignores it, they
# agree while a real client sees the loss. So the oracle here is an
# INDEPENDENT reader (keepassxc-cli): build a deliberately-rich vault via
# keyhole (every mutation saves through the engine projection), then have
# keepassxc — which shares none of our assumptions — read the engine-saved
# file back and assert every facet survived. The convergence digest is useless
# here: it deliberately excludes history / timestamps / unknown-XML, exactly
# the round-trip facets at risk.
#
# Facets covered (bounded first cut): standard entry fields, per-entry history,
# an attachment (name + exact bytes), a custom icon (pool + entry ref). Custom
# fields / unknown-XML / KDBX-3.1 are a later breadth pass.
#
# Needs an independent KDBX reader; SKIPs cleanly where keepassxc-cli is
# absent (e.g. a bare CI runner), so it's a real local gate without breaking
# the suite elsewhere.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

# Independent reader: PATH first, then the macOS app bundle.
XC="$(command -v keepassxc-cli 2>/dev/null || true)"
if [ -z "$XC" ] && [ -x "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli" ]; then
    XC="/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"
fi
if [ -z "$XC" ]; then
    echo "SKIP: keepassxc-cli not found — adversarial save-fidelity needs an independent KDBX reader"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
V="$TMP/rich.kdbx"

# keepassxc-cli with the master password fed on stdin; diagnostics silenced.
xc() { printf '%s\n' "$PW" | "$XC" "$@" 2>/dev/null; }

# --- build a deliberately-rich vault; each keyhole mutation saves it back
#     to disk through the engine projection, so $V IS the engine's output ----
"$KEYHOLE" create "$V" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$V" "Secret" --username alpha --entry-password s3cret >/dev/null
uuid="$("$KEYHOLE" list "$V" | awk '/Secret/ {print $1; exit}')"
# Two edits → history snapshots. The ORIGINAL username "alpha" then lives only
# in <History>; the live entry is "bravo". So "alpha" surviving in the saved
# file proves history content round-tripped, not just an empty <History> tag.
"$KEYHOLE" --at 2000000 update-entry "$V" "$uuid" --url "https://example.test" --notes "hello notes" >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$V" "$uuid" --username bravo >/dev/null
"$KEYHOLE" --at 4000000 set-attachment "$V" "$uuid" "file.bin" --text "PAYLOAD-7f3a-attach" >/dev/null
icon="$("$KEYHOLE" --at 5000000 add-custom-icon "$V" "$uuid" "ICON-IMAGE-BYTES-001")"
# Sanity: the input is sound — keyhole's own mirror holds the icon it added
# (so a later miss is the SAVE projection, not a broken input).
[ "$("$KEYHOLE" custom-icon-bytes "$V" "$icon")" != "(none)" ] \
    || { echo "FAIL(setup): keyhole's own mirror lost the custom icon"; exit 1; }

# --- INDEPENDENT READER asserts every facet survived the engine save -------
show="$(xc show -s "$V" "Secret")"
grep -q "UserName: bravo"            <<<"$show" || { echo "FAIL: username lost/mangled on save"; echo "$show"; exit 1; }
grep -q "Password: s3cret"           <<<"$show" || { echo "FAIL: password lost/mangled on save"; exit 1; }
grep -q "URL: https://example.test"  <<<"$show" || { echo "FAIL: url lost/mangled on save"; exit 1; }
grep -q "Notes: hello notes"         <<<"$show" || { echo "FAIL: notes lost/mangled on save"; exit 1; }

# Attachment: export to a real file (not /dev/stdout, which the cli mixes with
# its success message) and compare exact bytes.
xc attachment-export "$V" "Secret" "file.bin" "$TMP/att.out" >/dev/null
[ "$(cat "$TMP/att.out")" = "PAYLOAD-7f3a-attach" ] \
    || { echo "FAIL: attachment bytes lost/mangled on save (got: $(cat "$TMP/att.out"))"; exit 1; }

xml="$(xc export --format xml "$V")"
grep -q "<History>" <<<"$xml" || { echo "FAIL: <History> stripped on save"; exit 1; }
grep -q "alpha"     <<<"$xml" || { echo "FAIL: history CONTENT (pre-edit username) stripped on save"; exit 1; }
grep -q "<CustomIcons>"    <<<"$xml" || { echo "FAIL: custom-icon pool stripped on save"; exit 1; }
grep -q "<CustomIconUUID>" <<<"$xml" || { echo "FAIL: entry's custom-icon reference stripped on save"; exit 1; }

# --- TEETH: prove the independent-reader checks aren't vacuously green. ------
# Sabotage a copy (keepassxc removes the attachment), re-run the SAME check; it
# must go red. If it stays green the harness can't see a dropped facet at all.
cp "$V" "$TMP/sabotaged.kdbx"
xc attachment-rm "$TMP/sabotaged.kdbx" "Secret" "file.bin" >/dev/null
if xc attachment-export "$TMP/sabotaged.kdbx" "Secret" "file.bin" "$TMP/sab.out" >/dev/null 2>&1 \
   && [ "$(cat "$TMP/sab.out" 2>/dev/null)" = "PAYLOAD-7f3a-attach" ]; then
    echo "FAIL(teeth): the attachment check did not detect a removed attachment — it is vacuous"
    exit 1
fi

echo "PASS: engine-saved vault round-trips fields/history/attachment/custom-icon intact under an independent reader (keepassxc-cli $($XC --version 2>/dev/null)); checks teeth-verified"
