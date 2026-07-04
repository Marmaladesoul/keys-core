#!/usr/bin/env bash
#
# Scenario: `service` — the AutoFill-style lookup — excludes recycle-bin
# entries by subtree MEMBERSHIP, never the per-entry `is_recycled` flag.
# This is the lookup a credential-fill UI drives, so a leak here doesn't
# just mis-render a list: it offers up a deleted credential.
#
# What's proven:
#
#   1. A recycled entry drops out of lookup results warm (the live
#      mirror a client reads right after the mutation).
#   2. The exclusion survives a close+reopen from disk (mirror nuked →
#      fresh ingest — the only honest "did it hit the KDBX?").
#   3. An entry BURIED in a group that is then moved under the bin also
#      drops out — the discriminating case, asserted against the WARM
#      live mirror. A group recycle re-parents the group but leaves its
#      descendant entries' `is_recycled` flag at 0 until the next ingest
#      re-derives it from ancestry; a flag-based filter would keep
#      serving the buried entry in exactly the in-session state a client
#      fills from right after the mutation. (Regress the filter to the
#      flag and this step goes red — a cold re-ingested read would NOT
#      catch it, since ingest normalises the flag.)
#   4. With the bin DISABLED there is no live/binned distinction: former
#      bin contents come back into lookup results (matching `search
#      --bin exclude`), rather than being filtered by a stale flag.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# --- seed: three entries for one service, one buried inside a group ---
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --url "https://example.com" "$VAULT" "Alpha-svc"  >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --url "https://example.com" "$VAULT" "Bravo-svc"  >/dev/null
printf '%s\n' "$PW" | keepassxc-cli mkdir "$VAULT" "/Doomed" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --url "https://example.com" "$VAULT" "/Doomed/Buried-svc" >/dev/null

# Warm lookup: the live mirror a client reads in-session (where a group
# move hasn't been re-ingested yet — step 3's teeth live here). Cold
# lookup: nuke the mirror first, forcing a fresh ingest from the KDBX.
hits_warm() {                         "$KEYHOLE" service "$VAULT" "example.com" | { grep -c -- "-svc" || true; } }
hits_cold() { rm -rf "$VAULT.mirror"; "$KEYHOLE" service "$VAULT" "example.com" | { grep -c -- "-svc" || true; } }
# Full-read grep (never grep -q — an early-closed pipe SIGPIPEs keyhole
# and pipefail misreads it; see DESIGN.md).
has_warm() { "$KEYHOLE" service "$VAULT" "example.com" | grep -- "$1" >/dev/null; }

[ "$(hits_cold)" = "3" ] || { echo "FAIL: fresh vault lookup hits $(hits_warm), want 3"; exit 1; }

# --- 1) recycle Bravo: it drops out of the lookup warm ----------------
bravo="$("$KEYHOLE" list "$VAULT" | awk '/Bravo/ {print $1; exit}')"
[ -n "$bravo" ] || { echo "FAIL: could not find Bravo-svc"; exit 1; }
"$KEYHOLE" recycle "$VAULT" "$bravo" >/dev/null

[ "$(hits_warm)" = "2" ] || { echo "FAIL: lookup after recycle: $(hits_warm), want 2"; exit 1; }
! has_warm "Bravo"       || { echo "FAIL: recycled Bravo leaked into lookup results"; exit 1; }

# --- 2) the exclusion survives a fresh ingest from disk ---------------
[ "$(hits_cold)" = "2" ] || { echo "FAIL: exclusion lost across reopen: $(hits_warm), want 2"; exit 1; }

# --- 3) the discriminating case: an entry buried under a recycled group ---
doomed="$("$KEYHOLE" list-groups "$VAULT" | awk '/Doomed/ {print $1; exit}')"
bin="$(   "$KEYHOLE" list-groups "$VAULT" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$doomed" ] || { echo "FAIL: could not find Doomed group"; exit 1; }
[ -n "$bin" ]    || { echo "FAIL: could not find bin group"; exit 1; }

"$KEYHOLE" move-group "$VAULT" "$doomed" --to "$bin" >/dev/null
# WARM: Buried-svc still carries is_recycled = 0 — only its ancestry
# says "binned". Membership must decide.
[ "$(hits_warm)" = "1" ] || { echo "FAIL: buried entry not excluded warm — $(hits_warm), want 1 (flag-filter regression?)"; exit 1; }
! has_warm "Buried"      || { echo "FAIL: buried-under-bin entry leaked into lookup results warm"; exit 1; }
has_warm "Alpha"         || { echo "FAIL: live Alpha-svc missing from lookup results"; exit 1; }

# --- 4) bin disabled: no live/binned distinction ----------------------
"$KEYHOLE" set-bin "$VAULT" off >/dev/null
[ "$(hits_warm)" = "3" ] || { echo "FAIL: bin-off lookup: $(hits_warm), want 3 (everything is live)"; exit 1; }

echo "PASS: service lookup excludes by subtree membership (direct + buried-in-recycled-group, warm), survives reopen, and degrades correctly with the bin disabled"
