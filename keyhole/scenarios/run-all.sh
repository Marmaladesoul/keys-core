#!/usr/bin/env bash
#
# Run every keyhole scenario and report. Non-zero exit if any fail — this
# is the entry point CI gates on. Each scenario is self-cleaning and uses
# its own throwaway vault.
#
# Builds keyhole first: a stale binary lies.

set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

echo "building keyhole…"
( cd "$ROOT" && cargo build ) || { echo "BUILD FAILED"; exit 2; }

pass=0
fail=0
failed_names=()

for s in "$DIR"/*.sh; do
    name="$(basename "$s")"
    [ "$name" = "run-all.sh" ] && continue
    # Both fuzzers are full CI gates: fuzz-convergence since Findings
    # #4 + #5 (timestamp flooring + dissolved-conflict badge clearing),
    # fuzz-attachments since Finding #8 (LCA generation disambiguation)
    # — each soaked green at re-gate time. Interleaving varies
    # run-to-run (fresh uuids), so a red here is a real convergence
    # bug: the failure preserves both vaults + mirrors for post-mortem.
    printf '\n── %s ─────────────────────────\n' "$name"
    if bash "$s"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        failed_names+=("$name")
    fi
done

printf '\n=========================================\n'
printf 'scenarios: %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
    printf 'FAILED: %s\n' "${failed_names[*]}"
    exit 1
fi
echo "ALL GREEN"
