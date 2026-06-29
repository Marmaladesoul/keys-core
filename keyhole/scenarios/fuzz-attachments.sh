#!/usr/bin/env bash
#
# Scenario: the attachment-propagation fuzzer — seeded random one-sided
# attachment set/replace/remove across two replicas, digest-asserted
# every round. The attachment-focused twin of fuzz-convergence.sh
# (whose mix now also carries attachment ops alongside field edits);
# this one hammers attachment churn alone at a higher density, which
# is what surfaced Finding #8 (content-hash LCA aliasing) — it
# reproduced ~1-in-7 runs until the matcher learnt generation
# disambiguation, and has been a CI gate since.
#
# Names are device-prefixed: same-name both-sided attachment edits
# stay on the conservative no-auto-pick path until the remaining 5c
# slice (both-sided attachment park/resolve) lands.
#
# Reproducibility: the op stream is a pure function of FUZZ_SEED. Both the
# entry picker and the per-device op count draw from the MAIN-shell seeded
# $RANDOM stream (the picker via a deterministic main-shell counter), never
# inside a `$(...)`/`$(seq …)` subshell — bash reseeds a subshell's $RANDOM
# with run-varying entropy, which would desync the stream from the seed and
# make a failing run unreplayable. See reference_bash_subshell_random.

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
    keep="${TMPDIR:-/tmp}/keyhole-fuzz-att-failure-$$"
    mkdir -p "$keep" && cp -R "$TMP"/. "$keep"/
    echo "artefacts preserved in: $keep"
    exit 1
}

"$KEYHOLE" create "$A" >/dev/null
for t in alpha beta gamma; do
    "$KEYHOLE" create-entry "$A" "$t" --username "u-$t" >/dev/null
done
cp "$A" "$B"

# Deterministic pick index from the main-shell op counter $n and the seed.
# CRUCIAL: this must NOT read $RANDOM, because random_entry runs inside a
# `$(...)` command substitution (`e="$(random_entry …)"`) and bash reseeds a
# subshell's $RANDOM with run-varying entropy — so a $RANDOM-based pick is not
# reproducible across runs, silently desyncing the op stream from the seed
# (the same trap fuzz-convergence.sh was fixed away from; see
# reference_bash_subshell_random + DESIGN.md Findings). $n is a main-shell
# counter, a pure function of the seeded run, so a pick derived from it replays.
pick_idx() { # $1=op counter → a large deterministic non-negative int
    echo $(( ($1 * 48271 + SEED * 2654435761) % 1000000000 ))
}

random_entry() { # $1=vault → uuid of a random entry (title-sorted index)
    "$KEYHOLE" list "$1" 2>/dev/null | awk 'NF>1 && $1 ~ /^[0-9a-f-]{36}$/ {print $2, $1}' \
        | sort | awk '{print $2}' \
        | awk -v idx="$(pick_idx "$n")" '{a[NR]=$0} END{if (NR) print a[(idx % NR)+1]}'
}

n=0
mutate() { # $1=vault $2=device-prefix — one random attachment op
    local v="$1" p="$2" e
    n=$((n + 1))
    e="$(random_entry "$v")"
    [ -n "$e" ] || return 0
    if [ $((RANDOM % 3)) -eq 0 ]; then
        "$KEYHOLE" remove-attachment "$v" "$e" "${p}-att-$((RANDOM % 2))" >/dev/null 2>&1 || true
    else
        "$KEYHOLE" set-attachment "$v" "$e" "${p}-att-$((RANDOM % 2))" --text "payload-$n" >/dev/null
    fi
}

for round in $(seq 1 "$ROUNDS"); do
    # Draw the per-device op count in the MAIN shell first. Reading $RANDOM
    # directly inside `$(seq 1 $((RANDOM % 3 + 1)))` evaluates it in the
    # command-substitution subshell, which bash reseeds with run-varying
    # entropy — so the count (hence the whole op stream) would desync across
    # runs of one seed. A main-shell assignment is a pure function of the
    # seeded stream, so it replays. Same subshell-$RANDOM trap as the picker.
    na=$((RANDOM % 3 + 1)); for _ in $(seq 1 "$na"); do mutate "$A" a; done
    nb=$((RANDOM % 3 + 1)); for _ in $(seq 1 "$nb"); do mutate "$B" b; done

    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
        || fail "attachment-only ops parked a conflict on A"

    da="$("$KEYHOLE" digest "$A")"
    db="$("$KEYHOLE" digest "$B")"
    [ "$da" = "$db" ] || fail "digest divergence after sync: A=$da B=$db"
done

echo "PASS: $ROUNDS rounds of seeded one-sided attachment churn (seed=$SEED) converged every round"
