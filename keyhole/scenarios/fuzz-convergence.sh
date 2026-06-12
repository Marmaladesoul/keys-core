#!/usr/bin/env bash
#
# Scenario: the two-device convergence fuzzer — the thing keyhole was
# built for (DESIGN.md payoff #1). Two replicas of one vault take
# seeded-random concurrent edits (entry create / field edits / hard
# delete — exactly the supported 5b cross-peer surface; see mutate()
# for why location ops are excluded), then sync each round:
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
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" create-group "$A" "Folder" >/dev/null
for t in alpha beta gamma; do
    "$KEYHOLE" create-entry "$A" "$t" --username "u-$t" >/dev/null
done
cp "$A" "$B"

# Pick a random live entry, indexing into a TITLE-sorted list so the
# index→target mapping is stable within a run regardless of the order
# the engine happens to return rows in.
random_entry() { # $1=vault → uuid of a random live entry, "" if none
    "$KEYHOLE" list "$1" 2>/dev/null | awk 'NF>1 && $1 ~ /^[0-9a-f-]{36}$/ {print $2, $1}' \
        | sort | awk '{print $2}' \
        | awk -v r=$((RANDOM)) 'BEGIN{srand(r)} {a[NR]=$0} END{if (NR) print a[int(rand()*NR)+1]}'
}

n=0  # monotonic counter so generated values never collide
mutate() { # $1=vault — one random legal edit
    local v="$1" op e
    n=$((n + 1))
    # Op mix = exactly the cross-peer surface the multipeer store
    # supports today: entry create, field edits, hard delete (5b
    # tombstones). LOCATION ops — move / recycle / restore /
    # create-group — are deliberately ABSENT: group + location
    # reconciliation is the known-deferred 5d slice, and the fuzzer's
    # first two runs (seed 42) duly rediscovered that gap. Fold them
    # into the mix when 5d lands; the scope ledger lives in
    # sync-multipeer-store.md.
    # NB: if/fi rather than `[ -n ] &&` — under `set -e` a final failing
    # && would silently kill the whole run when a pick comes up empty.
    op=$((RANDOM % 4))
    case $op in
        0) "$KEYHOLE" create-entry "$v" "fz-$n" --username "fu-$n" >/dev/null ;;
        1) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" update-entry "$v" "$e" --username "edit-$n" >/dev/null; fi ;;
        2) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" update-entry "$v" "$e" --url "https://fz$n.example" --notes "note-$n" >/dev/null; fi ;;
        3) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" delete-entry "$v" "$e" >/dev/null; fi ;;
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
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$A"; done
    for _ in $(seq 1 $((RANDOM % 3 + 1))); do mutate "$B"; done

    # Sync: A pulls B, resolves; B pulls the resolved A.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    resolve_all "$A"
    "$KEYHOLE" list-conflicts "$A" | grep -q '(no held conflicts)' \
        || fail "conflicts remain on A after resolve_all"

    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" list-conflicts "$B" | grep -q '(no held conflicts)' \
        || fail "B re-parked a conflict A already resolved"

    da="$("$KEYHOLE" digest "$A")"
    db="$("$KEYHOLE" digest "$B")"
    [ "$da" = "$db" ] || fail "digest divergence after sync: A=$da B=$db"
done

echo "PASS: $ROUNDS rounds of seeded concurrent edits (seed=$SEED) converged every round"
