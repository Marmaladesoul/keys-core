# Shared helpers for the pairing-*.sh scenarios. Sourced, not run.
#
# The pairing verbs need no vault and no password: `pair-sim` stands up both
# sheets in one process and plays the person; `pair-keygen` prints public
# keys. Nothing touches disk.

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"

# sim <flags...>: run a scripted pairing, output in $OUT.
sim() { OUT="$("$KEYHOLE" pair-sim "$@")"; }

# expect <line>: the last sim's output has this exact line.
expect() {
    grep -qxF -- "$1" <<<"$OUT" || { echo "FAIL: missing line '$1' in:"; echo "$OUT"; exit 1; }
}

# refute <line>: the last sim's output does not have this exact line.
refute() {
    if grep -qxF -- "$1" <<<"$OUT"; then echo "FAIL: unexpected line '$1' in:"; echo "$OUT"; exit 1; fi
}

# count <line>: how many times the last sim printed this exact line.
count() { grep -cxF -- "$1" <<<"$OUT" || true; }

# expect_re <regex>: some line of the last sim's output matches this
# extended regex in full.
expect_re() {
    grep -qxE -- "$1" <<<"$OUT" || { echo "FAIL: no line matching '$1' in:"; echo "$OUT"; exit 1; }
}
