#!/usr/bin/env bash
#
# Saving an entry without changing anything must change nothing: no history
# snapshot, no `modified_at` bump, no write to the vault file. An editor's
# Save hands the engine the entry's WHOLE state (`save_entry`, replace-all),
# so a Save with nothing edited re-states the current state verbatim — every
# protected value re-sealed under a fresh nonce, so the stored bytes differ
# even though the content does not. Archiving a snapshot for it bloats
# history with copies of the live version (and each copy then has to
# propagate to every peer). A save that DOES change something still archives
# exactly one snapshot.
#
# The entry carries tags, a plain custom field and a protected one, so the
# no-op is proven across every facet `save_entry` rewrites — the protected
# field and the password are the ones only a plaintext comparison can see
# through. `patch` repeats the check for `update-entry` (patch semantics)
# with the value the field already holds.
#
# Each check reads back after `rm -rf "$VAULT.mirror"` (the mirror persists
# state across processes like a real client's local store, so only a fresh
# re-ingest from the KDBX is honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
V="$TMP/v.kdbx"

fail() { echo "FAIL($1): $2"; exit 1; }
# Snapshot count after an honest disk read.
hist_count() {
    rm -rf "$V.mirror"
    "$KEYHOLE" history "$V" "$1" | awk '/snapshot\(s\)$/ {print $1; found=1} END {if (!found) print 0}'
}
file_sum() { shasum -a 256 "$V" | awk '{print $1}'; }

"$KEYHOLE" create "$V" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$V" "E" --username u0 --entry-password p0 >/dev/null
uuid="$("$KEYHOLE" list "$V" | awk '/E/ {print $1; exit}')"
"$KEYHOLE" --at 2000000 set-tags "$V" "$uuid" "alpha,beta" >/dev/null
"$KEYHOLE" --at 3000000 set-field "$V" "$uuid" "Plain" "visible" >/dev/null
out="$("$KEYHOLE" --at 4000000 save-entry "$V" "$uuid" --set-protected "PIN=2468")"
case "$out" in *"(changed"*) ;; *) fail setup "adding a protected field should save: $out" ;; esac
base="$(hist_count "$uuid")"
[ "$base" -ge 1 ] || fail setup "expected setup history, got $base"

# ── save: Save with nothing edited ──
before="$(file_sum)"
out="$("$KEYHOLE" --at 5000000 save-entry "$V" "$uuid")"
case "$out" in *"(no change"*) ;; *) fail save "an unchanged save should be a no-op: $out" ;; esac
[ "$(file_sum)" = "$before" ] || fail save "an unchanged save rewrote the vault file"
[ "$(hist_count "$uuid")" = "$base" ] || fail save "history grew $base → $(hist_count "$uuid") on an unchanged save"

# ── patch: update-entry with the value it already has ──
"$KEYHOLE" --at 6000000 update-entry "$V" "$uuid" --username u0 >/dev/null
[ "$(file_sum)" = "$before" ] || fail patch "a same-value patch rewrote the vault file"
[ "$(hist_count "$uuid")" = "$base" ] || fail patch "history grew $base → $(hist_count "$uuid") on a same-value patch"

# ── change: a real edit still archives exactly one snapshot ──
out="$("$KEYHOLE" --at 7000000 save-entry "$V" "$uuid" --username u1)"
case "$out" in *"(changed"*) ;; *) fail change "a real edit should save: $out" ;; esac
[ "$(hist_count "$uuid")" = "$((base + 1))" ] || fail change "history $(hist_count "$uuid"), expected $((base + 1))"
rm -rf "$V.mirror"
grep -q "<u1>" <<<"$("$KEYHOLE" list "$V")" || fail change "the edit didn't reach disk"
[ "$("$KEYHOLE" history "$V" "$uuid" | awk 'NF==2 && $1 ~ /^[0-9]+$/ && $2 !~ /snapshot/' | tail -1 | awk '{print $2}')" = "u0" ] \
    || fail change "the newest snapshot should hold the pre-edit username u0"

echo "PASS noop-save-no-history"
