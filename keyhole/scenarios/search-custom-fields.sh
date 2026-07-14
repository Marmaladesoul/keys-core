#!/usr/bin/env bash
#
# Scenario: `search` under the any-field scope reaches non-protected
# custom (string) fields — the extra attributes a client shows below the
# canonical Title/Username/URL/Notes. An "Any Field" search that could
# only see the canonical columns is a search box that silently can't find
# what the user can plainly see on the entry (e.g. an account number
# parked in a custom field).
#
# What's proven:
#
#   1. A token present ONLY in a custom field's VALUE — in no canonical
#      column, no tag, no other entry — is found by an any-field search.
#      (Regress the query back to canonical-columns-only and this goes
#      red: the value lives nowhere the old clause looked.)
#   2. A token present only in a custom field's NAME is likewise found —
#      the field label is user-visible content, same as a tag name.
#   3. A token present in NO field at all returns nothing — the custom-
#      field clause widened the net, it didn't tear it (a malformed
#      always-true EXISTS would match every entry; this catches that).
#   4. The custom-field match survives a close+reopen from disk (mirror
#      nuked -> fresh ingest — the only honest "did it hit the KDBX?").
#      Custom fields are re-derived from the KDBX on ingest, so a value
#      that matches cold proves the round-trip, not a warm-mirror fluke.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# A value that appears in NO canonical column and NO other entry — its
# only home is the custom field we set below. If a search finds it, the
# search reached the custom field. (Synthetic, obviously-fake token — a
# custom field's classic use is an account number / licence key.)
CUSTOM_VALUE="synthetic-acct-778899"
CUSTOM_NAME="Account ID"
# A token present nowhere in the vault — the negative control.
ABSENT="zzz-no-such-token-zzz"

# --- seed: one entry whose title/username carry none of CUSTOM_VALUE ---
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g "$VAULT" "AWS-console" >/dev/null
# A second, unrelated entry so the negative/positive counts are honest.
printf '%s\n' "$PW" | keepassxc-cli add -g "$VAULT" "Unrelated-login" >/dev/null

uuid="$("$KEYHOLE" list "$VAULT" | awk '/AWS-console/ {print $1; exit}')"
[ -n "$uuid" ] || { echo "FAIL: could not find AWS-console entry"; exit 1; }

# Full-read grep (never grep -q — an early-closed pipe SIGPIPEs keyhole
# and pipefail misreads it; see DESIGN.md).
warm_hits() {                         "$KEYHOLE" search "$VAULT" "$1" --bin exclude | { grep -c -- "  AWS-console" || true; } }
cold_hits() { rm -rf "$VAULT.mirror"; "$KEYHOLE" search "$VAULT" "$1" --bin exclude | { grep -c -- "  AWS-console" || true; } }

# Sanity: before the field exists, the value is genuinely absent.
[ "$(warm_hits "$CUSTOM_VALUE")" = "0" ] || { echo "FAIL: CUSTOM_VALUE matched before the field was set — value leaked from the seed?"; exit 1; }

# --- set a non-protected custom field on the entry --------------------
"$KEYHOLE" set-field "$VAULT" "$uuid" "$CUSTOM_NAME" "$CUSTOM_VALUE" >/dev/null

# 1) value present only in the custom field -> found (warm).
[ "$(warm_hits "$CUSTOM_VALUE")" = "1" ] || { echo "FAIL: any-field search did not reach the custom field VALUE warm: $(warm_hits "$CUSTOM_VALUE"), want 1"; exit 1; }

# 2) field NAME is searchable too (user-visible label).
[ "$(warm_hits "Account")" = "1" ] || { echo "FAIL: any-field search did not reach the custom field NAME warm: $(warm_hits Account), want 1"; exit 1; }

# 3) negative control: a token in no field matches nothing.
[ "$(warm_hits "$ABSENT")" = "0" ] || { echo "FAIL: absent token matched — custom-field clause is over-broad (always-true EXISTS?): $(warm_hits "$ABSENT"), want 0"; exit 1; }

# 4) the match survives a fresh ingest from disk (cold).
[ "$(cold_hits "$CUSTOM_VALUE")" = "1" ] || { echo "FAIL: custom-field VALUE lost across reopen: $(cold_hits "$CUSTOM_VALUE"), want 1"; exit 1; }

echo "PASS: any-field search reaches non-protected custom fields (value + name), stays scoped (absent token misses), and survives a close+reopen"
