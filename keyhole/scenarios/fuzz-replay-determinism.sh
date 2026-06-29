#!/usr/bin/env bash
#
# Prove the convergence fuzzer REPLAYS byte-for-byte across two runs of one
# seed. Four non-determinism sources had to be pinned to get here:
#   1. the op stream            — bash $RANDOM seeded from FUZZ_SEED;
#   2. entity ids               — engine UuidSource (--uuid-seed);
#   3. timestamps               — injected clock (--at);
#   4. create-time root/bin ids — Vault::create_empty_deterministic (task #29);
# plus two bash subshell-$RANDOM traps that silently desynced the op stream
# across runs (a subshell's $RANDOM is reseeded with run-varying entropy):
#   - the target pickers read $RANDOM inside $(...) — fixed by pick_idx
#     (deterministic main-shell counter); and
#   - the per-device op COUNT was drawn as `$(seq 1 $((RANDOM % 3 + 1)))`,
#     evaluating $RANDOM in the seq subshell — THE cross-run replay residual,
#     fixed by drawing the count in the main shell first.
# With all six pinned, a whole run (create included) is a pure function of
# its seed. (See keyhole DESIGN.md → Findings and reference_bash_subshell_random.)
#
# Each (seed) is run twice via the fuzzer's FUZZ_KEEP hook — which dumps each
# device's final entries + groups-with-uuids + content digest — and the two
# captures are asserted byte-identical. The groups capture includes the
# create-time root/bin uuids, so this fails the instant create determinism
# regresses, not just engine-side determinism.
#
# SCOPE: a full multi-round, multi-seed replay gate. Sweeps a few seeds at a
# soak round count (the residual compounded over rounds, so >1 round is the
# sensitive case) and proves each replays byte-for-byte. Overridable:
#   FUZZ_SEEDS="42 43 777"   the seeds to sweep
#   FUZZ_ROUNDS=6            rounds per seed (per the two internal runs)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
FUZZER="$HERE/fuzz-convergence.sh"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

# Default sweep: the headline seed plus a few that historically surfaced
# convergence/parity findings (43, 777). Each is replay-checked independently.
SEEDS="${FUZZ_SEEDS:-42 43 777}"
ROUNDS="${FUZZ_ROUNDS:-6}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Captures the fuzzer's stdout+stderr (which carries fail() diagnostics from
# fuzz-convergence.sh, plus the preserved-artefacts path) to a per-run log so
# a failure surfaces the actual assertion rather than silently exiting via
# set -e. Returning non-zero (rather than letting set -e abort here) lets the
# loop print the captured log and move on to the next seed — without that, a
# fuzzer failure on the first seed eats every later seed's signal too.
run() { # $1=seed $2=capture-dir $3=log-path
    if ! FUZZ_SEED="$1" FUZZ_ROUNDS="$ROUNDS" FUZZ_KEEP="$2" \
         bash "$FUZZER" >"$3" 2>&1; then
        echo "FAIL: seed=$1 — underlying fuzzer (fuzz-convergence.sh) failed; output:"
        sed 's/^/    /' "$3"
        return 1
    fi
}

fails=0
for seed in $SEEDS; do
    d1="$TMP/$seed/run1"
    d2="$TMP/$seed/run2"
    if ! run "$seed" "$d1" "$TMP/$seed.run1.log"; then
        fails=$((fails + 1)); continue
    fi
    if ! run "$seed" "$d2" "$TMP/$seed.run2.log"; then
        fails=$((fails + 1)); continue
    fi

    if ! diff -r "$d1" "$d2" >"$TMP/$seed.delta" 2>&1; then
        echo "FAIL: seed=$seed ($ROUNDS rounds) — runs diverged, fuzzer is not byte-reproducible:"
        cat "$TMP/$seed.delta"
        fails=$((fails + 1))
        continue
    fi
    # Guard against a vacuous pass if the FUZZ_KEEP hook broke.
    if [ ! -s "$d1/device-a.kdbx.groups" ]; then
        echo "FAIL: seed=$seed — replay capture is empty (FUZZ_KEEP hook produced nothing)"
        fails=$((fails + 1))
        continue
    fi
    echo "ok: seed=$seed ($ROUNDS rounds) — two runs byte-identical (create incl. root/bin uuids replays)"
done

if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails seed(s) did not replay"
    exit 1
fi
echo "PASS: every seed [$SEEDS] replays byte-for-byte at $ROUNDS rounds"
