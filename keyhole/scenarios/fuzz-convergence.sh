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
"$KEYHOLE" create "$A" >/dev/null
ROOT="$("$KEYHOLE" list-groups "$A" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1; exit}')"
for f in Folder Folder-2 Folder-3; do
    "$KEYHOLE" create-group "$A" "$f" >/dev/null
done
for t in alpha beta gamma; do
    "$KEYHOLE" create-entry "$A" "$t" --username "u-$t" >/dev/null
done
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
    "$KEYHOLE" list "$1" 2>/dev/null | awk 'NF>1 && $1 ~ /^[0-9a-f-]{36}$/ {print $2, $1}' \
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
    op=$((RANDOM % 11))
    case $op in
        7) "$KEYHOLE" create-group "$v" "g-$n" >/dev/null ;;
        8) g="$(random_group "$v")"
           # Rename a random group (5d group metadata LWW). Every group
           # uuid is shared once adopted, so a rename either propagates
           # one-sided or races + resolves LWW; a just-created g-* not yet
           # on the peer converges next round (adoption + rename both
           # propagate). Renames on the same shared group race.
           if [ -n "$g" ]; then "$KEYHOLE" rename-group "$v" "$g" "r-$n" >/dev/null 2>&1 || true; fi ;;
        9) g="$(random_movable_group "$v")"; dst="$(random_movable_group "$v")"
           # Re-parent a group under another (5d group move). Concurrent
           # mutual moves resolve via the deterministic cycle-break.
           if [ -n "$g" ] && [ -n "$dst" ]; then "$KEYHOLE" move-group "$v" "$g" --to "$dst" >/dev/null 2>&1 || true; fi ;;
        10) g="$(random_movable_group "$v")"
           # Delete a group (5d cross-peer group delete via tombstone).
           if [ -n "$g" ]; then "$KEYHOLE" delete-group "$v" "$g" >/dev/null 2>&1 || true; fi ;;
        0) "$KEYHOLE" create-entry "$v" "fz-$n" --username "fu-$n" >/dev/null ;;
        1) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" update-entry "$v" "$e" --username "edit-$n" >/dev/null; fi ;;
        2) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" update-entry "$v" "$e" --url "https://fz$n.example" --notes "note-$n" >/dev/null; fi ;;
        3) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" delete-entry "$v" "$e" >/dev/null; fi ;;
        4) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" set-attachment "$v" "$e" "att-$((RANDOM % 2))" --text "payload-$n" >/dev/null; fi ;;
        5) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" remove-attachment "$v" "$e" "att-$((RANDOM % 2))" >/dev/null 2>&1 || true; fi ;;
        6) e="$(random_entry "$v")"; g="$(random_group "$v")"
           if [ -n "$e" ] && [ -n "$g" ]; then "$KEYHOLE" move-entry "$v" "$e" --to "$g" >/dev/null 2>&1 || true; fi ;;
    esac
}

resolve_all() { # $1=vault — resolve every held conflict, random side
    local v="$1" u side
    "$KEYHOLE" list-conflicts "$v" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1}' \
    | while read -r u; do
        if [ $((RANDOM % 2)) -eq 0 ]; then side=local; else side=remote; fi
        # "no held conflict" here is benign: resolving one entry can
        # legitimately settle a sibling listed in the same sweep. The
        # real invariant is the caller's post-loop "no held conflicts"
        # assertion — a resolve that failed while leaving the conflict
        # held still fails the round there.
        "$KEYHOLE" resolve "$v" --entry "$u" --choose "$side" >/dev/null 2>&1 \
            || echo "note: $u settled between list and resolve" >&2
    done
}

# --- the loop ---------------------------------------------------------
for round in $(seq 1 "$ROUNDS"); do
    # Concurrent edits while "offline": 1–3 per device.
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$A" a; done
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$B" b; done

    # Sync: A pulls B, resolves; B pulls the resolved A.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    resolve_all "$A"
    "$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
        || fail "conflicts remain on A after resolve_all"

    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" list-conflicts "$B" | grep '(no held conflicts)' >/dev/null \
        || fail "B re-parked a conflict A already resolved"

    da="$("$KEYHOLE" digest "$A")"
    db="$("$KEYHOLE" digest "$B")"
    [ "$da" = "$db" ] || fail "digest divergence after sync: A=$da B=$db"
done

echo "PASS: $ROUNDS rounds of seeded concurrent edits (seed=$SEED) converged every round"
