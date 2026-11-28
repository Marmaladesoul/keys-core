# Shared helpers for the account-*.sh scenarios. Sourced, not run.
#
# The account verbs need no vault and no password. A directory stands in for
# one device's secure storage: one file per stored form, written by one
# keyhole process and read back by another. Every directory here is a
# throwaway under $WORK, removed on exit.

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# run <verb> <args...>: run an account verb, output in $OUT.
run() { OUT="$("$KEYHOLE" "$@")"; }

# expect <line>: the last run's output has this exact line.
expect() {
    grep -qxF -- "$1" <<<"$OUT" || { echo "FAIL: missing line '$1' in:"; echo "$OUT"; exit 1; }
}

# refute_re <regex>: no line of the last run's output matches this regex.
refute_re() {
    if grep -qE -- "$1" <<<"$OUT"; then echo "FAIL: unexpected '$1' in:"; echo "$OUT"; exit 1; fi
}

# field <prefix>: the last word of the last run's line starting with <prefix>.
field() { awk -v p="$1" 'index($0, p " ") == 1 { print $NF }' <<<"$OUT"; }

# flip <file> <offset>: invert every bit of the byte at <offset>, in place.
flip() {
    local byte
    byte=$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')
    printf "$(printf '\\%03o' $((byte ^ 255)))" \
        | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null
}

# truncate_to <file> <bytes>
truncate_to() {
    local tmp="$1.tmp"
    head -c "$2" "$1" >"$tmp" && mv "$tmp" "$1"
}
