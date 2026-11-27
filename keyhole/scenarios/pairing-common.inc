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

# net <flags...>: run a scripted pairing over the transport, output in $OUT.
net() { OUT="$("$KEYHOLE" pair-net "$@")"; }

# link_line: the link the last net run printed (links are public by design).
link_line() { sed -n 's/^link: //p' <<<"$OUT" | head -1; }

# before <first> <second>: in the last output, the first exact line comes
# before the second.
before() {
    local first second
    first="$(grep -nxF -- "$1" <<<"$OUT" | head -1 | cut -d: -f1)"
    second="$(grep -nxF -- "$2" <<<"$OUT" | head -1 | cut -d: -f1)"
    if [ -z "$first" ] || [ -z "$second" ] || [ "$first" -ge "$second" ]; then
        echo "FAIL: expected '$1' before '$2' in:"; echo "$OUT"; exit 1
    fi
}

# no_code_in_output: nothing in the last output looks like a pairing code.
# Links and ids are hex and can hold six digits in a row by chance, so they
# are set aside first.
no_code_in_output() {
    local rest
    rest="$(sed -E '/^link: /d; s/(id|peer-identity)=[0-9a-f]+//g' <<<"$OUT")"
    if grep -qE '[0-9]{6}' <<<"$rest"; then
        echo "FAIL: a six-digit run in the output:"; echo "$OUT"; exit 1
    fi
}
