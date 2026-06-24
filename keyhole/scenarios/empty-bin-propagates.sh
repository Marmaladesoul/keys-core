#!/usr/bin/env bash
#
# Scenario: `empty-bin` permanently purges the recycle bin's contents, and
# the purge PROPAGATES cross-peer. Emptying the bin is the "delete forever"
# action on already-recycled items; if it didn't propagate, a purged secret
# would live on (recoverable) on every other device.
#
# empty-bin is a VERB-ONLY convenience: it composes the existing
# permanent-delete path, which already records a `<DeletedObjects>` tombstone
# per removed entry/group. This scenario proves the composition — the purged
# records are gone on BOTH replicas after a sync and DON'T resurrect — and
# that the bin group itself survives (emptying is not disabling).
#
# Bin contents exercised: entries sitting directly in the bin (recycled
# entries) AND a subgroup parked inside the bin with its own entry (so the
# cascade — entry tombstones + the group tombstone — is covered). A group's
# presence and every entry are in the convergence digest, so a purge that
# fails to propagate diverges the replicas.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

# Inspect field across a mirror-nuked reopen — the honest "did it hit disk?".
field() { rm -rf "$1.mirror"; "$KEYHOLE" inspect "$1" | awk -F': *' -v k="$2" '$1 == k {print $2}'; }
has_entry() { "$KEYHOLE" list "$1" | grep -F "$2" >/dev/null; }
has_group() { "$KEYHOLE" list-groups "$1" | grep -F "$2" >/dev/null; }
converged() { [ "$("$KEYHOLE" digest "$A")" = "$("$KEYHOLE" digest "$B")" ]; }

# --- build A: a keeper, two recycled entries, and a subgroup-in-bin -------
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-entry "$A" "keeper" --username u >/dev/null
"$KEYHOLE" create-entry "$A" "victim-one" --username u >/dev/null
"$KEYHOLE" create-entry "$A" "victim-two" --username u >/dev/null
v1="$("$KEYHOLE" list "$A" | awk '/victim-one/ {print $1; exit}')"
v2="$("$KEYHOLE" list "$A" | awk '/victim-two/ {print $1; exit}')"

# Recycle the two victims → bin is lazily created, both land directly in it.
"$KEYHOLE" recycle "$A" "$v1" >/dev/null
"$KEYHOLE" recycle "$A" "$v2" >/dev/null
bin="$("$KEYHOLE" list-groups "$A" | awk '/\[bin\]/ {print $1; exit}')"
[ -n "$bin" ] || { echo "FAIL(setup): no recycle bin group after recycling"; exit 1; }

# A subgroup parked inside the bin, holding its own entry, so empty-bin must
# cascade (delete the nested entry AND the subgroup), not just the loose ones.
"$KEYHOLE" create-group "$A" "Old Project" >/dev/null
oldproj="$("$KEYHOLE" list-groups "$A" | awk '/Old Project/ {print $1; exit}')"
"$KEYHOLE" create-entry "$A" "nested-secret" --username u --group "$oldproj" >/dev/null
ns="$("$KEYHOLE" list "$A" | awk '/nested-secret/ {print $1; exit}')"
"$KEYHOLE" move-group "$A" "$oldproj" --to "$bin" >/dev/null

# B forks WITH the full pre-purge bin contents.
cp "$A" "$B"

# Teeth: the bin really does hold the victims (2 directly) + the subgroup
# before we purge, so the "gone after" assertions can't pass vacuously.
[ "$(field "$A" 'recycled')" = "2" ] || { echo "FAIL(setup): expected 2 entries directly in the bin"; exit 1; }
has_entry "$A" "$ns" || { echo "FAIL(setup): nested-secret missing from the bin subtree"; exit 1; }
has_group "$A" "Old Project" || { echo "FAIL(setup): Old Project not in the bin"; exit 1; }

# --- A empties the bin ----------------------------------------------------
# A clock tick so the purge tombstones are unambiguously newer than the fork.
sleep 1.1
"$KEYHOLE" empty-bin "$A" >/dev/null

# Local proof (across a fresh disk read): contents gone, bin group survives.
for label in "$v1:victim-one" "$v2:victim-two" "$ns:nested-secret"; do
    rm -rf "$A.mirror"
    if has_entry "$A" "${label%%:*}"; then
        echo "FAIL: ${label#*:} survived empty-bin on A"; exit 1
    fi
done
has_group "$A" "Old Project" && { echo "FAIL: a bin subgroup survived empty-bin on A"; exit 1; } || true
[ "$(field "$A" 'entries')" = "1" ] || { echo "FAIL: expected only 'keeper' to remain on A"; exit 1; }
[ "$(field "$A" 'recycle bin')" = "enabled" ] || { echo "FAIL: empty-bin disabled the bin (it should only empty it)"; exit 1; }
[ "$(field "$A" 'bin group')" = "present" ] || { echo "FAIL: empty-bin removed the bin group itself"; exit 1; }

# --- sync both ways: the purge must reach B and NOT resurrect on A --------
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
rm -rf "$A.mirror" "$B.mirror"   # honest disk read on both

for vault in "$A" "$B"; do
    for label in "$v1:victim-one" "$v2:victim-two" "$ns:nested-secret"; do
        if has_entry "$vault" "${label%%:*}"; then
            echo "FAIL: ${label#*:} present on $(basename "$vault") after sync (purge didn't propagate / resurrected)"; exit 1
        fi
    done
    has_group "$vault" "Old Project" && { echo "FAIL: a purged bin subgroup present on $(basename "$vault") after sync"; exit 1; } || true
    has_entry "$vault" "keeper" || { echo "FAIL: keeper missing on $(basename "$vault") — purge over-reached"; exit 1; }
    [ "$(field "$vault" 'bin group')" = "present" ] || { echo "FAIL: bin group missing on $(basename "$vault") after sync"; exit 1; }
done

converged || { echo "FAIL: replicas diverged after the bin purge — A=$("$KEYHOLE" digest "$A") B=$("$KEYHOLE" digest "$B")"; exit 1; }

echo "PASS: empty-bin purges the bin's contents (loose entries + a subgroup cascade), the purge propagates cross-peer and doesn't resurrect, and the bin group survives — across a fresh disk read"
