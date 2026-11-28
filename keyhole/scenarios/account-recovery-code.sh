#!/usr/bin/env bash
#
# Scenario: reading a recovery code back, as a person types it.
#
# The code is 28 characters in seven groups of four, from Crockford's base32
# (no I, L, O or U). The last two characters are checks: a single mistyped
# character is caught and its group named, any two are caught, and swapped
# neighbours are caught. Reading forgives what people do: any case, no
# hyphens or spaces instead, O for 0, I or L for 1. Where the account is to
# hand, a well-formed code of another account is told apart; where it isn't
# (a device with nothing yet), only the form is checked.

set -euo pipefail
source "$(dirname "$0")/account-common.inc"

DEV="$WORK/device"
run account-create "$DEV" >/dev/null
CODE="$(cat "$DEV/recovery-code")"
[[ "$CODE" =~ ^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{4}$ ]] \
    || { echo "FAIL: not seven groups of four from the alphabet"; exit 1; }

# typed <text> [--dir]: check <text> as typed; verdict in $OUT.
typed() {
    printf '%s' "$1" >"$WORK/typed"
    shift
    run account-recovery "$WORK/typed" "$@"
}

# The forgiving spellings all read as the code.
typed "$CODE" --dir "$DEV"; expect "recovery-code: valid"
typed "$(tr 'A-Z' 'a-z' <<<"$CODE")" --dir "$DEV"; expect "recovery-code: valid"
typed "${CODE//-/}" --dir "$DEV"; expect "recovery-code: valid"
typed "${CODE//-/ }" --dir "$DEV"; expect "recovery-code: valid"
typed "$(tr '01' 'OI' <<<"$CODE")" --dir "$DEV"; expect "recovery-code: valid"
typed "$(tr '1' 'l' <<<"$CODE")" --dir "$DEV"; expect "recovery-code: valid"
# Form alone, with no account to hand.
typed "$CODE"; expect "recovery-code: valid"

# other <character>: a different character of the alphabet.
other() { [ "$1" = "X" ] && echo "Y" || echo "X"; }
PLAIN="${CODE//-/}"
# A mistyped character in each group, at each position in it, names that group.
for group in 1 2 3 4 5 6 7; do
    for within in 0 1 2 3; do
        at=$(( (group - 1) * 4 + within ))
        wrong="${PLAIN:0:at}$(other "${PLAIN:at:1}")${PLAIN:at+1}"
        typed "$wrong" --dir "$DEV"; expect "recovery-code: typo group=$group"
        typed "$wrong"; expect "recovery-code: typo group=$group"
    done
done

# Two mistyped characters, in the same group or in two, are never accepted.
for pair in "0 1" "0 27" "5 18" "26 27"; do
    read -r a b <<<"$pair"
    wrong="${PLAIN:0:a}$(other "${PLAIN:a:1}")${PLAIN:a+1}"
    wrong="${wrong:0:b}$(other "${wrong:b:1}")${wrong:b+1}"
    typed "$wrong" --dir "$DEV"
    refute_re "recovery-code: valid"
done

# Swapped neighbours are never accepted.
for at in 0 3 4 13 26; do
    [ "${PLAIN:at:1}" = "${PLAIN:at+1:1}" ] && continue
    swapped="${PLAIN:0:at}${PLAIN:at+1:1}${PLAIN:at:1}${PLAIN:at+2}"
    typed "$swapped" --dir "$DEV"
    refute_re "recovery-code: valid"
done

# A character that is never in a code (U) names its group.
typed "${PLAIN:0:9}U${PLAIN:10}" --dir "$DEV"; expect "recovery-code: not-in-alphabet group=3"
# The wrong number of characters.
typed "${PLAIN:0:27}" --dir "$DEV"; expect "recovery-code: wrong-length characters=27"
typed "${PLAIN}0" --dir "$DEV"; expect "recovery-code: wrong-length characters=29"
typed "" --dir "$DEV"; expect "recovery-code: wrong-length characters=0"

# Another account's code: well formed, so its form alone passes, but it isn't
# this account's.
run account-create "$WORK/other" >/dev/null
OTHER="$(cat "$WORK/other/recovery-code")"
typed "$OTHER"; expect "recovery-code: valid"
typed "$OTHER" --dir "$DEV"; expect "recovery-code: not-this-account"

echo "PASS: recovery codes forgive spelling, point at a single typo's group, and catch two typos, swaps and other accounts' codes"
