#!/usr/bin/env bash
#
# History created on one replica AFTER the replicas fork must reach the other
# replica through peer ingest, and both must converge on the same snapshot set
# across a fresh disk read. The cross-peer history merge is LOSSLESS (it unions
# histories, honouring `keys.history_tombstones`): when a peer's newer version
# of an entry is adopted, the peer's snapshots come with it. Adopting only the
# live fields leaves the receiver with no record of the versions it never saw —
# so a previous password is recoverable only on the device that made the edit,
# and the two replicas' histories diverge for good.
#
# history-delete-propagates.sh forks AFTER its history exists, so it never
# exercised history that is born post-fork; this scenario does.
#
# Four shapes, each in its own throwaway pair:
#   a→b   A edits after the fork; B must receive A's snapshots.
#   b→a   the mirror image (the ingest direction is not special).
#   both  shared pre-fork history, then non-conflicting edits on BOTH sides
#         (A the username, B the notes after a username detour), each growing
#         snapshots the other never saw. After the sync settles, both replicas
#         hold the same set, including each side's unique snapshot.
#   att   B adds an attachment after the fork, then replaces it, so B's history
#         holds a version whose bytes A never had. A's pull must fold it in
#         with its bytes and then SETTLE: a second pull is a no-op, not a
#         history rewrite (and a save) on every pull.
#
# NB the convergence digest is NO oracle here — it deliberately EXCLUDES
# history — so we compare snapshot sets directly via the `history` verb, after
# `rm -rf "$VAULT.mirror"` (the mirror persists state across processes like a
# real client's local store, so only a fresh re-ingest from the KDBX is honest).

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
export KEYHOLE_PASSWORD="keyhole-scenario-pw"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The set of usernames across an entry's history snapshots, sorted+joined.
hist_users() { "$KEYHOLE" history "$1" "$2" | awk 'NF==2 && $1 ~ /^[0-9]+$/ && $2 !~ /snapshot/ {print $2}' | sort | tr '\n' ' ' | sed 's/ $//'; }
# The live username of entry $2 in vault $1 (`list` prints `<uuid>  <title>  <username>`).
live_user() { "$KEYHOLE" list "$1" | awk -v u="$2" '$1==u' | sed -n 's/.*<\(.*\)>.*/\1/p'; }
fail() { echo "FAIL($1): $2"; exit 1; }

# One-sided post-fork edits: $1 = label, $2 = the editing vault, $3 = the
# receiving vault. The receiver pulls first, then the editor pulls back.
one_sided() {
    local label="$1" editor="$2" receiver="$3" uuid
    "$KEYHOLE" create "$editor" >/dev/null
    "$KEYHOLE" --at 1000000 create-entry "$editor" "E" --username v0 >/dev/null
    uuid="$("$KEYHOLE" list "$editor" | awk '/E/ {print $1; exit}')"
    cp "$editor" "$receiver"   # the fork: both hold E (v0) with no history
    "$KEYHOLE" --at 2000000 update-entry "$editor" "$uuid" --username v1 >/dev/null
    "$KEYHOLE" --at 3000000 update-entry "$editor" "$uuid" --username v2 >/dev/null
    [ "$(hist_users "$editor" "$uuid")" = "v0 v1" ] || fail "$label,setup" "editor history [$(hist_users "$editor" "$uuid")], expected v0 v1"

    "$KEYHOLE" ingest-peer "$receiver" "$editor" --owner editor >/dev/null
    "$KEYHOLE" ingest-peer "$editor" "$receiver" --owner receiver >/dev/null
    rm -rf "$editor.mirror" "$receiver.mirror"   # honest disk read

    local he hr
    he="$(hist_users "$editor" "$uuid")"; hr="$(hist_users "$receiver" "$uuid")"
    [ "$(live_user "$receiver" "$uuid")" = "v2" ] || fail "$label" "receiver live username [$(live_user "$receiver" "$uuid")], expected v2"
    [ "$(live_user "$editor" "$uuid")" = "v2" ]   || fail "$label" "editor live username [$(live_user "$editor" "$uuid")], expected v2"
    [ "$hr" = "v0 v1" ] || fail "$label" "receiver history [$hr], expected v0 v1 (the editor's post-fork snapshots never arrived)"
    [ "$he" = "v0 v1" ] || fail "$label" "editor history [$he], expected v0 v1"
    echo "  ok($label): both replicas hold {v0, v1}, live v2"
}

one_sided "a→b" "$TMP/ab-a.kdbx" "$TMP/ab-b.kdbx"
one_sided "b→a" "$TMP/ba-b.kdbx" "$TMP/ba-a.kdbx"

# Both sides grow history after a fork that already carries history.
A="$TMP/both-a.kdbx"
B="$TMP/both-b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username v0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
"$KEYHOLE" --at 2000000 update-entry "$A" "$uuid" --username v1 >/dev/null
cp "$A" "$B"   # both: history {v0}, live v1
# A: username v1 → a2 → a3.
"$KEYHOLE" --at 3000000 update-entry "$A" "$uuid" --username a2 >/dev/null
"$KEYHOLE" --at 4000000 update-entry "$A" "$uuid" --username a3 >/dev/null
# B: a username detour (v1 → b2 → v1) then a notes edit. Its live username is
# back at the shared value, so the sync is a field auto-merge (A's username,
# B's notes), not a conflict — but B's history now carries a `b2` A never saw.
"$KEYHOLE" --at 3100000 update-entry "$B" "$uuid" --username b2 >/dev/null
"$KEYHOLE" --at 3200000 update-entry "$B" "$uuid" --username v1 >/dev/null
"$KEYHOLE" --at 3300000 update-entry "$B" "$uuid" --notes from-b >/dev/null
[ "$(hist_users "$A" "$uuid")" = "a2 v0 v1" ]    || fail "both,setup" "A history [$(hist_users "$A" "$uuid")]"
[ "$(hist_users "$B" "$uuid")" = "b2 v0 v1 v1" ] || fail "both,setup" "B history [$(hist_users "$B" "$uuid")]"

# Sync until settled: each pull folds the other's history; the bounce-back
# carries what the first pull added.
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
"$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
rm -rf "$A.mirror" "$B.mirror"   # honest disk read

ha="$(hist_users "$A" "$uuid")"; hb="$(hist_users "$B" "$uuid")"
[ "$(live_user "$A" "$uuid")" = "a3" ] || fail "both" "A live username [$(live_user "$A" "$uuid")], expected a3"
[ "$(live_user "$B" "$uuid")" = "a3" ] || fail "both" "B live username [$(live_user "$B" "$uuid")], expected a3"
[ "$ha" = "$hb" ] || fail "both" "replicas diverge on history — A=[$ha] B=[$hb]"
for want in v0 v1 a2 b2; do
    case " $ha " in *" $want "*) : ;; *) fail "both" "converged history [$ha] is missing '$want'";; esac
done
echo "  ok(both): both replicas hold the same history [$ha], live a3"

# A history version whose attachment bytes only the peer holds.
A="$TMP/att-a.kdbx"
B="$TMP/att-b.kdbx"
"$KEYHOLE" create "$A" >/dev/null
"$KEYHOLE" --at 1000000 create-entry "$A" "E" --username u0 >/dev/null
uuid="$("$KEYHOLE" list "$A" | awk '/E/ {print $1; exit}')"
cp "$A" "$B"
"$KEYHOLE" --at 2000000 set-attachment "$B" "$uuid" a.bin --text first >/dev/null
"$KEYHOLE" --at 3000000 set-attachment "$B" "$uuid" a.bin --text second >/dev/null
hist_count() { "$KEYHOLE" history "$1" "$2" | awk '/snapshot\(s\)/ {print $1}'; }
[ "$(hist_count "$B" "$uuid")" = "2" ] || fail "att,setup" "B history count [$(hist_count "$B" "$uuid")], expected 2"

"$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
second="$("$KEYHOLE" ingest-peer "$A" "$B" --owner device-b 2>&1)"
case "$second" in *"no change"*) : ;; *) fail "att" "A's second pull still changed something (the fold never settles): $second";; esac
rm -rf "$A.mirror"   # honest disk read
[ "$(hist_count "$A" "$uuid")" = "2" ] || fail "att" "A history count [$(hist_count "$A" "$uuid")], expected 2 (B's two versions)"
echo "  ok(att): A folded B's attachment-bearing history and the pull settles"

echo "PASS: history created after a fork propagates through peer ingest in both directions and converges across a fresh disk read"
