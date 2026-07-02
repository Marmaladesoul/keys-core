#!/usr/bin/env bash
#
# Scenario: `entry_count_excluding_recycle_bin` — the engine-owned "live"
# entry count a client shows on a vault tile / an "All Items" collection,
# computed with one query and NO entry hydration.
#
# What's proven:
#
#   1. A directly-recycled entry drops out of the live count, and that
#      survives a close+reopen from disk (mirror nuked → fresh ingest,
#      the only honest "did it hit the KDBX?").
#   2. An entry BURIED in a group that is then recycled (the group moved
#      under the bin) also drops out — the discriminating case, asserted
#      against the WARM live mirror. Recycling a group re-parents it but
#      leaves its descendant entries' `is_recycled` flag at 0 until the
#      next ingest re-derives it from ancestry; a naive
#      `WHERE is_recycled = 0` count therefore over-counts the buried
#      entry in exactly the in-session state the tile reads right after
#      the mutation. The live count excludes it by bin-subtree
#      MEMBERSHIP. (Regress to a flag count and step 2 goes red — the
#      cold/re-ingested count would NOT catch it, since ingest normalises
#      the flag to match membership.)
#   3. With the bin DISABLED there is no live/binned distinction
#      (recycling permanently deletes), so the live count equals the
#      plain total — every surviving entry is live.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

# --- seed: an enabled-bin vault with three root entries --------------
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-password "$VAULT" >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username a "$VAULT" "Alpha"   >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username b "$VAULT" "Bravo"   >/dev/null
printf '%s\n' "$PW" | keepassxc-cli add -g --username c "$VAULT" "Charlie" >/dev/null

# Cold read: force a fresh ingest from the KDBX (persistence — "did it
# hit disk?"). Warm read: leave the mirror, so keyhole opens the live
# engine state a client actually reads in-session (where a group recycle
# hasn't been re-ingested yet). The membership vs is_recycled-flag
# divergence only exists warm — ingest normalises it — so step 2's teeth
# live in the warm read.
live()      { rm -rf "$VAULT.mirror"; "$KEYHOLE" live-count "$VAULT"; }
live_warm() {                         "$KEYHOLE" live-count "$VAULT"; }
total()     { rm -rf "$VAULT.mirror"; "$KEYHOLE" inspect "$VAULT" | awk '/^entries:/ {print $2}'; }

[ "$(live)"  = "3" ] || { echo "FAIL: fresh vault live count $(live), want 3"; exit 1; }
[ "$(total)" = "3" ] || { echo "FAIL: fresh vault total $(total), want 3"; exit 1; }

# --- 1) direct recycle drops out of the live count -------------------
bravo="$("$KEYHOLE" list "$VAULT" | awk '/Bravo/ {print $1; exit}')"
[ -n "$bravo" ] || { echo "FAIL: could not find Bravo"; exit 1; }
"$KEYHOLE" recycle "$VAULT" "$bravo" >/dev/null

n="$(live)"
[ "$n" = "2" ] || { echo "FAIL: after recycle live count $n, want 2"; exit 1; }
# Bravo is still on disk — it's in the bin, not gone.
[ "$(total)" = "3" ] || { echo "FAIL: after recycle total $(total), want 3 (bin holds Bravo)"; exit 1; }

# --- 2) the discriminating case: a buried entry under a recycled group ---
# Create a group at root and an entry inside it (is_recycled = 0), then
# move the whole group under the bin. The entry's flag stays 0; only its
# ancestry says "binned".
"$KEYHOLE" create-group "$VAULT" "Doomed" >/dev/null
doomed="$("$KEYHOLE" list-groups "$VAULT" | awk '/Doomed/ {print $1; exit}')"
bin="$(   "$KEYHOLE" list-groups "$VAULT" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$doomed" ] || { echo "FAIL: could not find Doomed group"; exit 1; }
[ -n "$bin" ]    || { echo "FAIL: could not find bin group"; exit 1; }

"$KEYHOLE" create-entry "$VAULT" "Buried" --group "$doomed" >/dev/null
# Three live now: Alpha, Charlie, and Buried (in the still-live Doomed).
n="$(live_warm)"
[ "$n" = "3" ] || { echo "FAIL: after burying an entry in a live group, live $n, want 3"; exit 1; }

"$KEYHOLE" move-group "$VAULT" "$doomed" --to "$bin" >/dev/null
# Doomed (with Buried) is now under the bin. In the WARM mirror Buried
# still has is_recycled = 0 (a group recycle doesn't cascade the flag),
# so a flag-based count would wrongly report 3. Membership excludes it.
n="$(live_warm)"
[ "$n" = "2" ] || { echo "FAIL: buried-under-bin entry not excluded warm — live $n, want 2 (flag-count regression?)"; exit 1; }
# And it holds across a fresh ingest from disk (persistence).
n="$(live)"
[ "$n" = "2" ] || { echo "FAIL: buried-under-bin exclusion lost across reopen — live $n, want 2"; exit 1; }

# --- 3) disabling the bin makes every surviving entry live -----------
total_now="$(total)"
"$KEYHOLE" set-bin "$VAULT" off >/dev/null
n="$(live)"
[ "$n" = "$total_now" ] || { echo "FAIL: bin-disabled live $n != total $total_now"; exit 1; }

echo "PASS: live count excludes the bin subtree by membership (direct + buried-in-recycled-group), survives reopen, and equals the total once the bin is disabled"
