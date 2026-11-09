#!/usr/bin/env bash
#
# Scenario: THE MIRROR MOVES WHILE A HELD CONFLICT SETTLES. When local
# converges on a held conflict's clashing field, the conflict dissolves and
# the peer's non-clashing changes are landed (conflict-dissolve-adopts-peer-
# changes.sh). The settle projects the vault, merges the peer row into that
# projection, and replaces the mirror with the result. Another connection to
# the mirror can write at any moment, so a write landing between the
# projection and the replace would be wiped by it: no tombstone, no error, and
# the next save writes the loss to the file.
#
# keyhole's `update-entry --sidecar-create` opens a second engine on the same
# mirror and creates an entry through it on a chosen session-key request of
# the update. The update asks for the key four times: for its own edit, for
# the settle's projection (`project_to_vault`), in the settle itself
# (`reconcile_conflict_rows`), and to land the adopted merge. So the third
# request falls after the projection and before the landing.
#
# Assertions:
#   1. NOT LOST → the entry the second engine created survives in the file.
#   2. NOT LANDED → the settle was abandoned rather than landed over the move,
#      so the conflict is still held and the peer's title isn't adopted yet.
#      This is also what proves the write hit the window: a write before the
#      projection would leave nothing to refuse.
#   3. NOT STUCK → the next settle (opening the resolver) adopts the peer's
#      title and clears the conflict, keeping the entry.
#
# Every data assertion reads from a fresh ingest of the file, because
# surviving in the mirror proves nothing about surviving on disk.
#
# Self-contained: keyhole's own verbs; throwaway vaults.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

fail() { echo "FAIL: $*"; exit 1; }

# The listing of a fresh ingest of $A.
file_listing() {
    local probe="$TMP/probe.kdbx"
    cp "$A" "$probe"
    rm -rf "$probe.mirror"
    "$KEYHOLE" list "$probe"
}

# A and B fork; both change the username (the clash) and B also renames the
# entry, which waits in B's parked row.
"$KEYHOLE" create "$A" >/dev/null || fail "create"
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u0 >/dev/null || fail "seed"
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username uA >/dev/null || fail "local edit"
"$KEYHOLE" --at 2100000 update-entry "$B" "$uuid" --title "E-peer" --username uB >/dev/null \
    || fail "peer edit"
"$KEYHOLE" --at 3000000 ingest-peer "$A" "$B" --owner b >/dev/null || fail "ingest-peer"
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null || fail "no conflict held"

# Local converges on the clash, so the conflict dissolves, while a second
# engine on the mirror creates an entry.
out="$("$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username uB \
    --sidecar-create "Saved meanwhile" --sidecar-at-key-request 3 2>&1)" \
    || fail "update-entry: $out"
grep "a second engine on the mirror created entry" >/dev/null <<<"$out" \
    || fail "the second engine never wrote, so this tested nothing: $out"

listing="$(file_listing)"
grep "Saved meanwhile" >/dev/null <<<"$listing" \
    || fail "the entry created through a second engine during the settle was lost: [$listing]"
"$KEYHOLE" list-conflicts "$A" | grep "$uuid" >/dev/null \
    || fail "the settle landed over a mirror that moved after its projection"
grep "E-peer" >/dev/null <<<"$listing" \
    && fail "the abandoned settle adopted the peer's title anyway: [$listing]"

# The next settle, with nothing writing meanwhile, lands it.
"$KEYHOLE" --at 5000000 show-conflict "$A" >/dev/null || fail "show-conflict"
"$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
    || fail "the next settle didn't clear the dissolved conflict"
listing="$(file_listing)"
grep "E-peer" >/dev/null <<<"$listing" \
    || fail "the next settle didn't adopt the peer's title: [$listing]"
grep "Saved meanwhile" >/dev/null <<<"$listing" \
    || fail "the next settle lost the entry the second engine created: [$listing]"

echo "PASS: a settle is abandoned, not landed, if the mirror moved after its projection"
