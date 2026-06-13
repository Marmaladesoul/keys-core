#!/usr/bin/env bash
#
# Scenario: the two-device convergence fuzzer — the thing keyhole was
# built for (DESIGN.md payoff #1). Two replicas of one vault take
# seeded-random concurrent edits (entry create / field edits / hard
# delete / attachment set+remove — the supported 5b+5c cross-peer
# surface; see mutate() for why location ops are excluded), then sync
# each round:
#
#   A ingests B  →  A resolves every parked conflict (random side)
#   B ingests A  →  B must adopt A's resolutions (no re-park)
#   digest(A) == digest(B)  — the convergence oracle, every round.
#
# Reproducibility: bash's $RANDOM is seeded (FUZZ_SEED, default 42),
# but entry UUIDs are freshly random every run, so the index→target
# mapping — and therefore the exact op sequence — varies run to run.
# A failing run is therefore preserved, not replayed: on any failure
# the two vaults AND their mirrors are copied to a kept directory and
# the path printed — the artefacts are the repro. FUZZ_ROUNDS
# (default 6) keeps CI bounded — crank it for soak runs:
#
#   FUZZ_ROUNDS=50 ./fuzz-convergence.sh

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

SEED="${FUZZ_SEED:-42}"
ROUNDS="${FUZZ_ROUNDS:-6}"
RANDOM=$SEED

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

fail() {
    echo "FAIL (seed=$SEED round=$round): $*"
    for side in "$A" "$B"; do
        echo "--- $(basename "$side") entries ---"
        "$KEYHOLE" list "$side" 2>&1
        echo "--- $(basename "$side") groups ---"
        "$KEYHOLE" list-groups "$side" 2>&1
        echo "--- $(basename "$side") state ---"
        "$KEYHOLE" inspect "$side" 2>&1
    done
    # Preserve the evidence: vaults + mirrors. KEYHOLE_PASSWORD above
    # unlocks them for post-mortem (test data, throwaway).
    keep="${TMPDIR:-/tmp}/keyhole-fuzz-failure-$$"
    mkdir -p "$keep" && cp -R "$TMP"/. "$keep"/
    echo "artefacts preserved in: $keep"
    exit 1
}

# --- seed: a small shared world, then split into two devices ---------
# Several SHARED groups give the move ops (5d) somewhere to move TO that
# both replicas already hold; the device-local g-* groups created during
# the run get adopted by the peer (5d group adoption). ROOT is captured
# right after `create` (the only group then) so the move/delete target
# picker can exclude it — root has no parent and deleting it would wipe
# the vault.
# Determinism: seed-time entity ids are pinned via --uuid-seed (distinct
# high values, well clear of the loop's per-op ids below) so the shared
# world replays byte-for-byte across runs. (The root group + default
# recycle bin are minted by Vault::create_empty, OUTSIDE the engine's
# UuidSource, so they stay random — but both devices share them via the
# cp below, and they never participate in the entry conflicts under
# test, so they don't affect convergence/replay of a finding.)
SEED_AT=1799999000000
us=9000000000
"$KEYHOLE" create "$A" >/dev/null
ROOT="$("$KEYHOLE" list-groups "$A" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1; exit}')"
for f in Folder Folder-2 Folder-3; do
    us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-group "$A" "$f" >/dev/null
done
for t in alpha beta gamma; do
    us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-entry "$A" "$t" --username "u-$t" >/dev/null
done
# A dedicated "battleground" entry that BOTH devices edit (same field,
# distinct values) every round, guaranteeing a genuine same-field clash
# parks each round — otherwise the random op mix produces a conflict
# only ~1 round in 10, leaving the park/resolve/parity paths barely
# exercised. Excluded from random_entry so a random delete/move can't
# remove it out from under the contention step.
us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-entry "$A" "Contested" --username u-contested >/dev/null
CONTESTED="$("$KEYHOLE" list "$A" | awk '/Contested/ {print $1; exit}')"
cp "$A" "$B"

# A random group uuid (any of the shared seed groups or root), for moves.
random_group() { # $1=vault → uuid of a random group
    "$KEYHOLE" list-groups "$1" 2>/dev/null | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1}' \
        | awk -v r=$((RANDOM)) 'BEGIN{srand(r)} {a[NR]=$0} END{if (NR) print a[int(rand()*NR)+1]}'
}

# A random NON-root, non-bin group — a safe move/delete target. Root has no
# parent and the bin is structural; list-groups marks the bin "[bin]" and
# root is the first row (the only one create made before the seed folders),
# but rather than rely on position we exclude by the fields list-groups
# prints: skip the row whose name is the bin's and skip root by its known
# uuid (captured at seed time as $ROOT).
random_movable_group() { # $1=vault → uuid of a random non-root, non-bin group
    "$KEYHOLE" list-groups "$1" 2>/dev/null \
        | awk -v root="$ROOT" '$1 ~ /^[0-9a-f-]{36}$/ && $1 != root && $0 !~ /\[bin\]/ {print $1}' \
        | awk -v r=$((RANDOM)) 'BEGIN{srand(r)} {a[NR]=$0} END{if (NR) print a[int(rand()*NR)+1]}'
}

# Pick a random live entry, indexing into a TITLE-sorted list so the
# index→target mapping is stable within a run regardless of the order
# the engine happens to return rows in.
random_entry() { # $1=vault → uuid of a random live entry, "" if none
    # Excludes $CONTESTED — that entry is driven only by the per-round
    # contention step, so random ops must never delete/move/edit it. The
    # exclusion is an awk guard (not `grep -v`): grep exits 1 when it
    # filters every line, which under `set -o pipefail` would kill the
    # whole run the moment the contested entry is the only one left.
    "$KEYHOLE" list "$1" 2>/dev/null \
        | awk -v c="$CONTESTED" 'NF>1 && $1 ~ /^[0-9a-f-]{36}$/ && $1 != c {print $2, $1}' \
        | sort | awk '{print $2}' \
        | awk -v r=$((RANDOM)) 'BEGIN{srand(r)} {a[NR]=$0} END{if (NR) print a[int(rand()*NR)+1]}'
}

n=0  # monotonic counter so generated values never collide
mutate() { # $1=vault $2=device-prefix (unused since attachment names went shared)
    local v="$1" op e g
    : "$2"
    n=$((n + 1))
    # Op mix = the cross-peer surface the multipeer store supports today:
    # entry create, field edits, hard delete (5b tombstones), attachment
    # set/remove (5c), entry MOVE (5d location LWW), and group CREATE
    # (5d peer-only group adoption — a device-local new group the peer
    # adopts on ingest, into which subsequent moves can land). Merged in
    # as each finding/slice landed (#7 conflict-row attachments, #8 LCA
    # disambiguation, 5d location LWW + group adoption). Attachment names
    # are SHARED across devices (both-sided clash parks + resolves in
    # resolve_all). The FULL group-structure surface is now exercised:
    # create (adoption), rename (metadata LWW), move (re-parent LWW +
    # deterministic cycle-break for concurrent mutual moves), delete
    # (tombstone consumption) — moves/deletes target non-root, non-bin
    # groups (random_movable_group) since deleting root would wipe the
    # vault and root has no parent to move. Scope ledger:
    # sync-multipeer-store.md.
    # NB: if/fi rather than `[ -n ] &&` — under `set -e` a final failing
    # && would silently kill the whole run when a pick comes up empty.
    # Every mutation is stamped at $AT (pinned by the loop). A and B
    # share the same $AT within a round, so concurrent edits genuinely
    # race; the loop advances $AT a clean second+ past the prior round's
    # resolution so an edit is never ambiguously in the same floored
    # second as a resolution (the sub-second hazard that silently
    # auto-merges a real clash — caught when this fuzzer first ran a
    # contended edit every round).
    op=$((RANDOM % 11))
    case $op in
        7) "$KEYHOLE" --at "$AT" --uuid-seed "$n" create-group "$v" "g-$n" >/dev/null ;;
        8) g="$(random_group "$v")"
           # Rename a random group (5d group metadata LWW). Every group
           # uuid is shared once adopted, so a rename either propagates
           # one-sided or races + resolves LWW; a just-created g-* not yet
           # on the peer converges next round (adoption + rename both
           # propagate). Renames on the same shared group race.
           if [ -n "$g" ]; then "$KEYHOLE" --at "$AT" rename-group "$v" "$g" "r-$n" >/dev/null 2>&1 || true; fi ;;
        9) g="$(random_movable_group "$v")"; dst="$(random_movable_group "$v")"
           # Re-parent a group under another (5d group move). Concurrent
           # mutual moves resolve via the deterministic cycle-break.
           if [ -n "$g" ] && [ -n "$dst" ]; then "$KEYHOLE" --at "$AT" move-group "$v" "$g" --to "$dst" >/dev/null 2>&1 || true; fi ;;
        10) g="$(random_movable_group "$v")"
           # Delete a group (5d cross-peer group delete via tombstone).
           if [ -n "$g" ]; then "$KEYHOLE" --at "$AT" delete-group "$v" "$g" >/dev/null 2>&1 || true; fi ;;
        0) "$KEYHOLE" --at "$AT" --uuid-seed "$n" create-entry "$v" "fz-$n" --username "fu-$n" >/dev/null ;;
        1) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" update-entry "$v" "$e" --username "edit-$n" >/dev/null; fi ;;
        2) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" update-entry "$v" "$e" --url "https://fz$n.example" --notes "note-$n" >/dev/null; fi ;;
        3) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" delete-entry "$v" "$e" >/dev/null; fi ;;
        4) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" set-attachment "$v" "$e" "att-$((RANDOM % 2))" --text "payload-$n" >/dev/null; fi ;;
        5) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" remove-attachment "$v" "$e" "att-$((RANDOM % 2))" >/dev/null 2>&1 || true; fi ;;
        6) e="$(random_entry "$v")"; g="$(random_group "$v")"
           if [ -n "$e" ] && [ -n "$g" ]; then "$KEYHOLE" --at "$AT" move-entry "$v" "$e" --to "$g" >/dev/null 2>&1 || true; fi ;;
    esac
}

conflicts_on() { # $1=vault — sorted parked-conflict uuid set ('' if none)
    "$KEYHOLE" list-conflicts "$1" \
        | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        | sort | tr '\n' ',' || true
}

resolve_all() { # $1=vault — resolve every held conflict, random side; stamps $AT
    local v="$1" u side
    "$KEYHOLE" list-conflicts "$v" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1}' \
    | while read -r u; do
        if [ $((RANDOM % 2)) -eq 0 ]; then side=local; else side=remote; fi
        # "no held conflict" here is benign: resolving one entry can
        # legitimately settle a sibling listed in the same sweep. The
        # real invariant is the caller's post-loop "no held conflicts"
        # assertion — a resolve that failed while leaving the conflict
        # held still fails the round there.
        "$KEYHOLE" --at "$AT" resolve "$v" --entry "$u" --choose "$side" >/dev/null 2>&1 \
            || echo "note: $u settled between list and resolve" >&2
    done
}

# --- the loop ---------------------------------------------------------
# Pinned monotonic clock (epoch-ms). Each round's edits share one
# instant ($AT) so A and B genuinely race; resolution lands a clean
# second+ later, and the next round jumps a full minute past that — so
# no operation is ever ambiguously in the same floored second as the
# prior round's resolution (KDBX is second-granular). CLOCK_BASE is a
# fixed constant, not wall-clock, so a seed reproduces byte-for-byte.
CLOCK_BASE=1800000000000   # 2027-01-15, comfortably future-proof
for round in $(seq 1 "$ROUNDS"); do
    AT=$((CLOCK_BASE + round * 60000))   # edits this round: +60s per round

    # Concurrent edits while "offline": 1–3 per device, all at $AT.
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$A" a; done
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$B" b; done

    # Guaranteed contention: both devices edit the battleground entry's
    # same field to distinct values, so a genuine clash parks this round
    # (gives the parity + resolve assertions real teeth every round).
    "$KEYHOLE" --at "$AT" update-entry "$A" "$CONTESTED" --username "a-r$round" >/dev/null
    "$KEYHOLE" --at "$AT" update-entry "$B" "$CONTESTED" --username "b-r$round" >/dev/null

    # Sync, symmetric: BOTH devices ingest each other before anyone
    # resolves, so each independently derives its parked-conflict set.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

    # Oracle 1 — conflict-set PARITY: a genuine clash is symmetric, so
    # both replicas must hold the SAME set of parked entries (the digest
    # does NOT cover conflict rows, so a one-sided / ghost badge is
    # invisible to the digest oracle below — this catches it).
    ca="$(conflicts_on "$A")"
    cb="$(conflicts_on "$B")"
    [ "$ca" = "$cb" ] || fail "held-conflict set differs across peers: A=[$ca] B=[$cb]"
    # The battleground guarantees a clash every round, so an EMPTY set
    # here means the clash silently auto-merged instead of parking — a
    # regression in conflict detection, not benign.
    [ -n "$ca" ] || fail "round $round: contended edit did not park (auto-merged a genuine clash?)"

    # Resolve on A, then push the resolution to B; settle A against B's
    # post-adoption state. Both must end clean (no ghost, no re-park).
    # Resolution lands 10s after this round's edits and 50s before the
    # next round's, so it never shares a floored second with either.
    AT=$((CLOCK_BASE + round * 60000 + 10000))
    resolve_all "$A"
    "$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
        || fail "conflicts remain on A after resolve_all"
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    [ -z "$(conflicts_on "$B")" ] || fail "B kept a ghost conflict A already resolved"
    [ -z "$(conflicts_on "$A")" ] || fail "A re-parked after B's adoption"

    # Oracle 2 — content convergence.
    da="$("$KEYHOLE" digest "$A")"
    db="$("$KEYHOLE" digest "$B")"
    [ "$da" = "$db" ] || fail "digest divergence after sync: A=$da B=$db"
done

echo "PASS: $ROUNDS rounds of seeded concurrent edits (seed=$SEED) converged every round"
