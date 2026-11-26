#!/usr/bin/env bash
#
# The mirror remembers the peer copy it last merged from each owner, so
# ingesting those exact bytes again is "no change" without a key derivation —
# across processes, since a client re-reads every peer's head at each launch.
#
# The probe: `--peer-password-env` opens the peer copy with a WRONG password.
# An ingest that derives fails; one answered from the remembered head
# succeeds. So "no change under a wrong password" proves no derivation ran.
#
# The record must stay exact:
#   - per owner: the same bytes under another owner still derive;
#   - per content: a peer's next copy derives (and a failed ingest records
#     nothing, so retrying it derives again);
#   - per mirror: a mirror rebuilt from the vault file alone, or wholesale
#     re-ingested from it, merges every peer copy again;
#   - complete merges only: a copy that parked a conflict merges again (its
#     peer value lives only in conflict rows, which a dismissal drops), and
#     resolving a conflict, a replace from the mirror's own projection,
#     keeps the other peers' records.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"
export KEYHOLE_WRONG_PEER_PASSWORD="keyhole-scenario-pw-DELIBERATELY-WRONG"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL($1): $2"; exit 1; }

A="$TMP/a.kdbx"
B="$TMP/b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" E --username v0 >/dev/null
cp "$A" "$B"
"$KEYHOLE" --at 2000000 create-entry "$B" from-b >/dev/null
has() { "$KEYHOLE" list "$A" | awk -v t="$1" '$2==t {found=1} END {exit !found}'; }

ingest() { "$KEYHOLE" ingest-peer "$A" "$B" "$@" 2>&1; }
wrong() { ingest --peer-password-env KEYHOLE_WRONG_PEER_PASSWORD "$@"; }

skips() {
    local label="$1" out
    shift
    out="$(wrong "$@")" || fail "$label" "a remembered copy was derived again (wrong password failed): $out"
    case "$out" in *": no change"*) : ;; *) fail "$label" "a remembered copy wasn't answered no change: $out";; esac
    echo "  ok($label): remembered copy answered without deriving"
}
derives() {
    local label="$1" out
    shift
    if out="$(wrong "$@")"; then
        fail "$label" "a copy that must be merged was skipped: $out"
    fi
    case "$out" in *"wrong key or corrupt data"*) : ;; *) fail "$label" "failed, but not at the key derivation: $out";; esac
    echo "  ok($label): derived (the wrong password failed)"
}

out="$(ingest --owner b)"
case "$out" in *"merged state saved to disk"*) : ;; *) fail "first" "B's change didn't merge: $out";; esac
has from-b || fail "first" "B's entry isn't in A"

skips "next-process" --owner b
skips "again" --owner b
derives "other-owner" --owner c

# B's next copy: new bytes, so it derives — and a failed ingest records nothing.
"$KEYHOLE" --at 3000000 create-entry "$B" from-b-2 >/dev/null
derives "new-copy" --owner b
derives "new-copy-retry" --owner b
ingest --owner b >/dev/null || fail "new-copy" "B's next copy didn't merge under the right password"
has from-b-2 || fail "new-copy" "B's next entry isn't in A"
skips "new-copy-merged" --owner b

# A mirror rebuilt from the vault file alone merges every peer copy again.
rm -rf "$A.mirror"
derives "rebuilt" --owner b
ingest --owner b >/dev/null || fail "rebuilt" "B's copy didn't merge into the rebuilt mirror"
skips "rebuilt-merged" --owner b

# So does a wholesale re-ingest of the vault file into the existing mirror.
"$KEYHOLE" reingest "$A" >/dev/null 2>&1 || fail "reingest" "re-ingest failed"
derives "reingested" --owner b

# A copy that parks a conflict isn't recorded; resolving keeps other records.
C="$TMP/c.kdbx"
D="$TMP/d.kdbx"
F="$TMP/f.kdbx"
"$KEYHOLE" create "$C" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$C" E --username v0 >/dev/null
e="$("$KEYHOLE" list "$C" | awk '$2=="E" {print $1; exit}')"
cp "$C" "$D"
cp "$C" "$F"
"$KEYHOLE" --at 2000000 create-entry "$D" from-d >/dev/null
"$KEYHOLE" ingest-peer "$C" "$D" --owner d >/dev/null
"$KEYHOLE" --at 3000000 update-entry "$C" "$e" --username from-c >/dev/null
"$KEYHOLE" --at 3100000 update-entry "$F" "$e" --username from-f >/dev/null
"$KEYHOLE" ingest-peer "$C" "$F" --owner f >/dev/null
"$KEYHOLE" list-conflicts "$C" | grep -q "$e" || fail "parked" "F's clash didn't park a conflict"
A="$C" B="$F"
derives "parked" --owner f
"$KEYHOLE" resolve "$C" --entry "$e" --choose local >/dev/null
B="$D"
skips "resolved-keeps-others" --owner d

echo "PASS: a peer's last-merged copy is answered without deriving, per owner and per content, until the mirror is rebuilt"
