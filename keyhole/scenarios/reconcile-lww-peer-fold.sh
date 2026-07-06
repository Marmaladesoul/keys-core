#!/usr/bin/env bash
#
# Scenario: field-level (LCA) disk-reconcile vs. an entry-level last-writer-
# wins peer that FOLDS a concurrent field edit into <History>.
#
# Background. Keys reconciles an external KDBX change with a per-field 3-way
# merge, basing each field on the true common ancestor found by walking both
# sides' <History> (keepass-merge::find_common_ancestor). Most other KeePass
# clients merge at ENTRY granularity: the newer-modified entry wins wholesale
# and the losing record is preserved as the most-recent history rung. That
# entry-level model cannot represent two concurrent edits to DIFFERENT fields
# of one record — it linearises the two siblings, burying one under the other.
#
# Two arms, IDENTICAL except for the remote's <History> lineage:
#
#   Arm A — FAIR peer (the regression guard for what LCA is FOR).
#     A peer forks from the shared base V0 = hoho/aa and edits ONLY the
#     username (-> hoho/aabb). Its history is honest: [V0]. Its file lands on
#     our path. The true LCA is V0, so the per-field merge keeps our title edit
#     AND takes the peer's username edit:
#         title    : local moved hoho->hoho-1, remote == V0  -> keep hoho-1
#         username : remote moved aa->aabb,     local == V0   -> take aabb
#     MUST converge to hoho-1 / aabb, no conflict. This is the promise of LCA:
#     concurrent edits to different fields of one entry both survive.
#
#   Arm B — FOLDING peer (characterisation of an interop LIMIT, not a bug).
#     An entry-level-LWW peer, on save, folds our on-disk hoho-1 write DOWN
#     into <History> beneath its own newer current (hoho/aabb). Its history is
#     now [V0, hoho-1/aa] — it presents our concurrent edit as an ANCESTOR it
#     built past. The latest shared version is therefore hoho-1/aa, and against
#     that base our title "did not move" while the peer's hoho "changed it":
#         title    : local == base hoho-1, remote hoho != base -> take remote
#     so the title silently reverts to hoho. This is byte-and-timestamp
#     IDENTICAL to the peer having deliberately renamed hoho-1 back to hoho, so
#     no correct merge — LCA or otherwise — can tell them apart or recover the
#     edit. The loss is committed by the folding peer before Keys sees the
#     file; the field-level reconcile merely converges to it. See DESIGN.md
#     Findings ("entry-level-LWW peer folds a concurrent edit into history").
#
#     This arm PINS that accepted behaviour: if the reconcile ever stops
#     reverting here (recovers the edit, or parks a conflict), this test fails
#     on purpose — revisit the interop-limit decision consciously.
#
# Timing is an input, not a race: edit stamps are injected with --at, so
# "the peer wrote later" is deterministic. (sleep 1 is only a file-mtime nudge
# so the overwrite trips the mirror's disk-change signature.)
#
# Teeth: Arm A fails if the title comes back hoho (a base/LWW regression) or a
# spurious conflict parks; Arm B fails if the pinned revert changes shape.
# Both asserted across a mirror-nuke cold re-ingest (the only honest disk read).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

title_on() { "$KEYHOLE" list "$1" | awk -v u="$2" '$1==u {print $2}'; }
user_on()  { "$KEYHOLE" list "$1" | awk -v u="$2" '$1==u {print $3}'; }   # yields <name> or empty

# ── Arm A: fair peer (remote history = [V0]) → both edits survive ─────
A="$TMP/a.kdbx"; PA="$TMP/a-peer.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "hoho" --username aa >/dev/null
uuidA="$("$KEYHOLE" list "$A" | awk '$2=="hoho" {print $1; exit}')"
[ -n "$uuidA" ] || { echo "FAIL(a): could not find seeded entry"; exit 1; }
cp "$A" "$PA"                                                             # fork at V0

"$KEYHOLE" --at 5000000 update-entry "$A"  "$uuidA" --title hoho-1  >/dev/null   # local: title, saved
"$KEYHOLE" --at 9000000 update-entry "$PA" "$uuidA" --username aabb >/dev/null   # peer: username only, from V0
sleep 1; cp "$PA" "$A"                                                    # external file lands on our path

"$KEYHOLE" list "$A" >/dev/null 2>"$TMP/a.err"                            # any verb opens+reconciles
grep -q "changed on disk" "$TMP/a.err" \
    || { echo "FAIL(a): disk-reconcile path was not exercised:"; cat "$TMP/a.err"; exit 1; }
"$KEYHOLE" list-conflicts "$A" 2>/dev/null | grep -q "no held conflicts" \
    || { echo "FAIL(a): a clean one-sided-per-field merge parked a conflict:"; "$KEYHOLE" list-conflicts "$A"; exit 1; }

rm -rf "$A.mirror"                                                        # honest from-disk re-ingest
ta="$(title_on "$A" "$uuidA")"; ua="$(user_on "$A" "$uuidA")"
[ "$ta" = "hoho-1" ] \
    || { echo "FAIL(a): LCA merge lost the local title edit (got title=$ta user=$ua; want hoho-1/<aabb>)"; cat "$TMP/a.err"; exit 1; }
[ "$ua" = "<aabb>" ] \
    || { echo "FAIL(a): LCA merge lost the peer username edit (got title=$ta user=$ua; want hoho-1/<aabb>)"; exit 1; }
echo "PASS(a): fair-peer concurrent field edits both survive (hoho-1 / aabb)"

# ── Arm B: folding peer (remote history = [V0, hoho-1/aa]) → pinned revert ─
B="$TMP/b.kdbx"; PB="$TMP/b-peer.kdbx"
"$KEYHOLE" create "$B" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$B" "hoho" --username aa >/dev/null
uuidB="$("$KEYHOLE" list "$B" | awk '$2=="hoho" {print $1; exit}')"
[ -n "$uuidB" ] || { echo "FAIL(b): could not find seeded entry"; exit 1; }
cp "$B" "$PB"                                                             # fork at V0

"$KEYHOLE" --at 5000000 update-entry "$B"  "$uuidB" --title hoho-1 >/dev/null    # local: title, saved
# Peer models an entry-level-LWW merge-on-save: it folds our hoho-1/aa into its
# lineage (same content+stamp as our head), then supersedes it with a newer
# current hoho/aabb — leaving hoho-1/aa as the most-recent history rung.
"$KEYHOLE" --at 5000000 update-entry "$PB" "$uuidB" --title hoho-1 >/dev/null
"$KEYHOLE" --at 9000000 update-entry "$PB" "$uuidB" --title hoho --username aabb >/dev/null
sleep 1; cp "$PB" "$B"                                                    # folded file lands on our path

"$KEYHOLE" list "$B" >/dev/null 2>"$TMP/b.err"
grep -q "changed on disk" "$TMP/b.err" \
    || { echo "FAIL(b): disk-reconcile path was not exercised:"; cat "$TMP/b.err"; exit 1; }
# The fold reads as a deliberate revert, so it auto-merges with NO conflict.
"$KEYHOLE" list-conflicts "$B" 2>/dev/null | grep -q "no held conflicts" \
    || { echo "FAIL(b): the folded lineage unexpectedly parked a conflict — behaviour changed, revisit the interop-limit call:"; "$KEYHOLE" list-conflicts "$B"; exit 1; }

rm -rf "$B.mirror"
tb="$(title_on "$B" "$uuidB")"; ub="$(user_on "$B" "$uuidB")"
[ "$ub" = "<aabb>" ] \
    || { echo "FAIL(b): peer username edit missing (got title=$tb user=$ub)"; exit 1; }
# CHARACTERISATION: the title reverts to hoho because hoho-1 was folded into the
# peer's history as a false ancestor. Not desired, but inherent — see header.
[ "$tb" = "hoho" ] \
    || { echo "FAIL(b): title is '$tb', not the pinned revert 'hoho' — the reconcile no longer converges to the folding peer's state. If this is a deliberate hardening, update this characterisation and DESIGN.md."; exit 1; }
echo "PASS(b): folded concurrent edit converges to the peer's state (title reverts to hoho) — documented interop limit"

echo "PASS: field-level reconcile keeps concurrent edits from a fair peer, and faithfully converges to an entry-level-LWW peer's fold (which it cannot distinguish from a deliberate revert)"
