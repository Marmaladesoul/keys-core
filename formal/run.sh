#!/bin/sh
# Runs every ProVerif model of the keys-pairing protocol and checks each
# query's result against pairing/expected.txt.
#
# Exits non-zero unless every query of every run prints exactly the result
# the manifest declares for it: a query expected to be true that isn't, an
# attack witness expected to be false that isn't, a query ProVerif can't
# decide, a missing or extra query, or a ProVerif error all fail the script.
# So does a manifest that is missing, empty, repeats a run, lists a run
# with no expected results, or leaves out a model under either transport
# with the protocol's own binding. The log of every run that fails is printed.
#
# Usage: formal/run.sh            (ProVerif from $PROVERIF, else `proverif` on PATH)
#        JOBS=4 formal/run.sh     (runs in parallel; default is the CPU count)

set -u

PROVERIF="${PROVERIF:-proverif}"
if ! command -v "$PROVERIF" >/dev/null 2>&1; then
    echo "run.sh: ProVerif not found (set PROVERIF or put proverif on PATH)" >&2
    exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
models="$here/pairing"
manifest="$models/expected.txt"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
TRANSPORTS="claimed authenticated"
# Every model must be listed with each of these. Other bindings (the
# weakened `noshare`) are run only where the manifest lists them.
BINDINGS="current"

# The file a run's verdict is written to. Model, transport and binding
# identify a run; the manifest may not list the same three twice.
verdict_file() {
    echo "$out/$1.$2.$3.verdict"
}

# One manifest line: run the model, write "ok" or the reason to its verdict
# file.
run_one() {
    model=$1 transport=$2 binding=$3 options=$4
    shift 4
    expected="$*"
    name="$model.$transport.$binding"
    verdict=$(verdict_file "$model" "$transport" "$binding")

    set --
    case "$options" in
        -) ;;
        precise) set -- -set preciseActions true ;;
        *) echo "unknown option '$options'" > "$verdict"; return ;;
    esac

    # The libraries are named by relative path, so run from the models'
    # directory.
    if ! (cd "$models" && "$PROVERIF" "$@" \
            -lib primitives.pvl \
            -lib "transport-$transport.pvl" \
            -lib "binding-$binding.pvl" \
            -lib protocol.pvl \
            "$model.pv") > "$out/$name.log" 2>&1; then
        echo "ProVerif failed: $(grep -m1 'Error' "$out/$name.log")" > "$verdict"
        return
    fi

    # ProVerif prints one "RESULT ... is true." / "is false." / "cannot be
    # proved." line per query, in file order. Lines starting "RESULT (" are
    # commentary on the line before.
    actual=$(grep '^RESULT' "$out/$name.log" | grep -v '^RESULT (' | sed \
        -e 's/.* is true\.$/true/' \
        -e 's/.* is false\.$/false/' \
        -e 's/.* cannot be proved\.$/unproved/' | tr '\n' ' ' | sed 's/ $//')

    if [ "$actual" = "$expected" ]; then
        echo ok > "$verdict"
    else
        echo "expected [$expected] got [$actual]" > "$verdict"
    fi
}

# xargs re-enters this script once per manifest line.
if [ "${1:-}" = --run-one ]; then
    shift
    out=$KEYS_PAIRING_FORMAL_OUT
    run_one "$@"
    exit 0
fi

fail() {
    echo "run.sh: $*" >&2
    exit 1
}

out=$(mktemp -d "${TMPDIR:-/tmp}/keys-pairing-formal.XXXXXX") || fail "can't make a scratch directory"
trap 'rm -rf "$out"' EXIT

# ─── the manifest must be sound before anything runs ───────────────────────

[ -r "$manifest" ] || fail "can't read $manifest"
runs="$out/runs"
grep -v -e '^#' -e '^[[:space:]]*$' "$manifest" | sed 's/[[:space:]]*$//' > "$runs"
[ -s "$runs" ] || fail "$manifest lists no runs"

while read -r model transport binding options expected; do
    [ -n "${options:-}" ] || fail "manifest line for '$model' is incomplete"
    [ -n "$expected" ] || fail "manifest lists no expected results for $model $transport $binding"
    for result in $expected; do
        case "$result" in
            true|false) ;;
            *) fail "manifest expects '$result' of $model $transport $binding; only true and false can be expected" ;;
        esac
    done
    [ -f "$models/$model.pv" ] || fail "manifest names $model, but there is no pairing/$model.pv"
done < "$runs"

repeated=$(awk '{ print $1, $2, $3 }' "$runs" | sort | uniq -d)
[ -z "$repeated" ] || fail "manifest lists a run more than once: $repeated"

for file in "$models"/*.pv; do
    model=$(basename "$file" .pv)
    for transport in $TRANSPORTS; do
        for binding in $BINDINGS; do
            awk -v m="$model" -v t="$transport" -v b="$binding" \
                '$1 == m && $2 == t && $3 == b { found = 1 } END { exit !found }' "$runs" ||
                fail "pairing/$model.pv has no manifest line for the $transport transport with the $binding binding"
        done
    done
done

# ─── run ────────────────────────────────────────────────────────────────────

KEYS_PAIRING_FORMAL_OUT="$out" PROVERIF="$PROVERIF" \
    xargs -P "$JOBS" -L 1 "$here/run.sh" --run-one < "$runs" ||
    fail "the job pool failed"

failures=0
while read -r model transport binding options expected; do
    verdict=$(cat "$(verdict_file "$model" "$transport" "$binding")" 2>/dev/null ||
        echo "no verdict (the run did not finish)")
    count=$(echo "$expected" | wc -w | tr -d ' ')
    if [ "$verdict" = ok ]; then
        printf 'ok    %-18s %-14s %-8s %2s queries as expected\n' "$model" "$transport" "$binding" "$count"
    else
        printf 'FAIL  %-18s %-14s %-8s %s\n' "$model" "$transport" "$binding" "$verdict"
        failures=$((failures + 1))
        # The scratch directory goes when the script exits, so show the
        # log now: it holds the trace ProVerif found, or its error.
        {
            echo "──── log of $model $transport $binding ────"
            cat "$out/$model.$transport.$binding.log" 2>/dev/null || echo "(no log)"
            echo "──── end of log ────"
        } >&2
    fi
done < "$runs"

if [ "$failures" -gt 0 ]; then
    echo "$failures run(s) did not match pairing/expected.txt" >&2
    exit 1
fi
echo "every query matched pairing/expected.txt"
