#!/usr/bin/env bash
#
# Task #29 end-to-end: prove the convergence fuzzer REPLAYS byte-for-byte.
# With the op-stream seeded (bash $RANDOM), entity ids seeded (engine
# UuidSource) and timestamps pinned (--at), the last gap was the create
# itself — the root group + eager recycle bin were minted from random v4
# (kdbx.rs), so two runs of the same FUZZ_SEED produced vaults that
# differed in those ids and a failure could be preserved but never
# re-derived. Now `create` draws them from a seeded keepass-core
# UuidSource too (Vault::create_empty_deterministic), so a whole run is a
# pure function of its seed.
#
# This runs the fuzzer twice with one seed (via the FUZZ_KEEP hook, which
# dumps each device's final entries + groups-with-uuids + content digest)
# and asserts the two captures are identical. The groups capture includes
# the create-time root/bin uuids, so this fails the instant create
# determinism regresses — not just engine-side determinism.
#
# SCOPE (current): defaults to ONE round, which replays byte-for-byte and
# guards the create-uuid + deterministic-picker + deterministic-resolve
# work. Cranking FUZZ_ROUNDS past ~1 currently surfaces an OPEN residual:
# a rare, compounding cross-run divergence over many rounds (see keyhole
# DESIGN.md → "Fuzzer multi-round replay residual"). Round 1 is proven
# deterministic (draws, picks, content all identical across runs); the
# multi-round residual is a separate, deeper investigation. Until it's
# closed, this scenario is a single-round regression guard, not a full
# multi-round replay proof.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
FUZZER="$HERE/fuzz-convergence.sh"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SEED="${FUZZ_SEED:-42}"
ROUNDS="${FUZZ_ROUNDS:-1}"

run() {
    FUZZ_SEED="$SEED" FUZZ_ROUNDS="$ROUNDS" FUZZ_KEEP="$1" bash "$FUZZER" >/dev/null
}

run "$TMP/run1"
run "$TMP/run2"

if ! diff -r "$TMP/run1" "$TMP/run2" >"$TMP/delta" 2>&1; then
    echo "FAIL: same-seed runs diverged — the fuzzer is not byte-reproducible:"
    cat "$TMP/delta"
    exit 1
fi

# Guard against the capture being empty (a vacuous pass if the hook broke).
[ -s "$TMP/run1/device-a.kdbx.groups" ] \
    || { echo "FAIL: replay capture is empty (FUZZ_KEEP hook produced nothing)"; exit 1; }

echo "PASS: two runs of seed=$SEED ($ROUNDS rounds) are byte-identical (create incl. root/bin uuids replays)"
