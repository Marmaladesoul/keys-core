#!/usr/bin/env bash
#
# Scenario: the two-device convergence fuzzer — the thing keyhole was
# built for (DESIGN.md payoff #1). Two replicas of one vault take
# seeded-random concurrent edits (entry create / field edits / hard
# delete / attachment set+remove — the supported 5b+5c cross-peer
# surface; see mutate() for why location ops are excluded), then sync
# each round:
#
#   A ingests B  →  A resolves every parked conflict (random side)
#   B ingests A  →  B must adopt A's resolutions (no re-park)
#   digest(A) == digest(B)  — the convergence oracle, every round.
#
# Reproducibility: bash's $RANDOM is seeded (FUZZ_SEED, default 42),
# but entry UUIDs are freshly random every run, so the index→target
# mapping — and therefore the exact op sequence — varies run to run.
# A failing run is therefore preserved, not replayed: on any failure
# the two vaults AND their mirrors are copied to a kept directory and
# the path printed — the artefacts are the repro. FUZZ_ROUNDS
# (default 6) keeps CI bounded — crank it for soak runs:
#
#   FUZZ_ROUNDS=50 ./fuzz-convergence.sh

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

SEED="${FUZZ_SEED:-42}"
ROUNDS="${FUZZ_ROUNDS:-6}"
RANDOM=$SEED

# Per-create entity-id seed. MUST vary with FUZZ_SEED so different seeds
# explore different entity-id ORDERINGS — that ordering is what several
# tiebreaks (same-second LWW, group cycle-break, parked-conflict order)
# turn on, so it's a first-class fuzzing dimension, not noise. Folding
# SEED in (a) decorrelates id-order from creation-order (a bare counter
# made "older == smaller" an invariant, so orderings that contradict
# creation order — where real bugs hide — were UNREACHABLE), while
# (b) staying a pure function of (SEED, command index) so a given
# FUZZ_SEED still replays byte-for-byte. The multiplicative mix is
# injective in $1 for a fixed SEED over the command counts we hit (so no
# id collisions) and scatters across the 0..4e9 block (kept clear of the
# 9e9+ seed-time block below).
mix() { echo $(( (($1 * 48271) + (SEED * 2654435761)) % 4000000000 )); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
A="$TMP/device-a.kdbx"
B="$TMP/device-b.kdbx"

fail() {
    echo "FAIL (seed=$SEED round=$round): $*"
    for side in "$A" "$B"; do
        echo "--- $(basename "$side") entries ---"
        "$KEYHOLE" list "$side" 2>&1
        echo "--- $(basename "$side") groups ---"
        "$KEYHOLE" list-groups "$side" 2>&1
        echo "--- $(basename "$side") state ---"
        "$KEYHOLE" inspect "$side" 2>&1
    done
    # Preserve the evidence: vaults + mirrors. KEYHOLE_PASSWORD above
    # unlocks them for post-mortem (test data, throwaway).
    keep="${TMPDIR:-/tmp}/keyhole-fuzz-failure-$$"
    mkdir -p "$keep" && cp -R "$TMP"/. "$keep"/
    echo "artefacts preserved in: $keep"
    exit 1
}

# --- seed: a small shared world, then split into two devices ---------
# Several SHARED groups give the move ops (5d) somewhere to move TO that
# both replicas already hold; the device-local g-* groups created during
# the run get adopted by the peer (5d group adoption). ROOT is captured
# right after `create` (the only group then) so the move/delete target
# picker can exclude it — root has no parent and deleting it would wipe
# the vault.
# Determinism: every seed-time id is pinned via --uuid-seed so the shared
# world replays byte-for-byte across runs. Three disjoint seed bands keep
# the sequences collision-free (ids only clash when both seed-half AND
# counter match): the per-op loop ids use mix() in [0, 4e9); the seed-time
# create-group/create-entry ids use the 9e9+ band (`us` below); and the
# create itself (root group + eager recycle bin, minted in keepass-core
# via Vault::create_empty_deterministic — task #29) uses 8e9, in the gap
# between the two. Both devices share the create ids via the cp below.
SEED_AT=1799999000000
CREATE_SEED=8000000000
us=9000000000
"$KEYHOLE" --at "$SEED_AT" --uuid-seed "$CREATE_SEED" create "$A" >/dev/null
ROOT="$("$KEYHOLE" list-groups "$A" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1; exit}')"
for f in Folder Folder-2 Folder-3; do
    us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-group "$A" "$f" >/dev/null
done
for t in alpha beta gamma; do
    us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-entry "$A" "$t" --username "u-$t" >/dev/null
done
# A dedicated "battleground" entry that BOTH devices edit (same field,
# distinct values) every round, guaranteeing a genuine same-field clash
# parks each round — otherwise the random op mix produces a conflict
# only ~1 round in 10, leaving the park/resolve/parity paths barely
# exercised. Excluded from random_entry so a random delete/move can't
# remove it out from under the contention step.
us=$((us + 1)); "$KEYHOLE" --at "$SEED_AT" --uuid-seed "$us" create-entry "$A" "Contested" --username u-contested >/dev/null
CONTESTED="$("$KEYHOLE" list "$A" | awk '/Contested/ {print $1; exit}')"
cp "$A" "$B"

# Deterministic pick index from the main-shell op counter $n, a per-call
# salt, and the fuzz SEED. CRUCIAL: pickers must NOT read $RANDOM, because
# they run inside $(...) command substitutions and bash reseeds a
# subshell's $RANDOM with run-varying entropy — so $RANDOM-based selection
# is NOT reproducible across runs (the subshell draws differ every run,
# desyncing the whole op stream). $n is a main-shell counter (a pure
# function of the run), so an index derived from it replays byte-for-byte.
# The salt distinguishes two picks within ONE mutate (e.g. op 9 picks two
# distinct movable groups) so they don't collapse to the same target.
pick_idx() { # $1=op counter, $2=salt → a large deterministic non-negative int
    echo $(( ($1 * 48271 + $2 * 40503 + SEED * 2654435761) % 1000000000 ))
}

# A random group uuid (any of the shared seed groups or root), for moves.
# Selects idx % NR into a UUID-sorted list so the index→target mapping is
# stable within AND across runs, regardless of the order the engine returns
# groups in (that order differs between an incrementally-built mirror and
# one re-ingested from the KDBX).
random_group() { # $1=vault [$2=salt] → uuid of a random group
    "$KEYHOLE" list-groups "$1" 2>/dev/null | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1}' \
        | sort \
        | awk -v idx="$(pick_idx "$n" "${2:-0}")" '{a[NR]=$0} END{if (NR) print a[(idx % NR)+1]}'
}

# A random NON-root, non-bin group — a safe move/delete target. Root has no
# parent and the bin is structural; list-groups marks the bin "[bin]" and
# root is excluded by its known uuid (captured at seed time as $ROOT).
random_movable_group() { # $1=vault [$2=salt] → uuid of a random non-root, non-bin group
    "$KEYHOLE" list-groups "$1" 2>/dev/null \
        | awk -v root="$ROOT" '$1 ~ /^[0-9a-f-]{36}$/ && $1 != root && $0 !~ /\[bin\]/ {print $1}' \
        | sort \
        | awk -v idx="$(pick_idx "$n" "${2:-0}")" '{a[NR]=$0} END{if (NR) print a[(idx % NR)+1]}'
}

# Pick a random live entry, idx % NR into a TITLE-sorted list so the mapping
# is stable within and across runs regardless of engine row order.
random_entry() { # $1=vault [$2=salt] → uuid of a random live entry, "" if none
    # Excludes $CONTESTED — that entry is driven only by the per-round
    # contention step, so random ops must never delete/move/edit it. The
    # exclusion is an awk guard (not `grep -v`): grep exits 1 when it
    # filters every line, which under `set -o pipefail` would kill the
    # whole run the moment the contested entry is the only one left.
    "$KEYHOLE" list "$1" 2>/dev/null \
        | awk -v c="$CONTESTED" 'NF>1 && $1 ~ /^[0-9a-f-]{36}$/ && $1 != c {print $2, $1}' \
        | sort | awk '{print $2}' \
        | awk -v idx="$(pick_idx "$n" "${2:-0}")" '{a[NR]=$0} END{if (NR) print a[(idx % NR)+1]}'
}

n=0  # monotonic counter so generated values never collide
mutate() { # $1=vault $2=device-prefix (unused since attachment names went shared)
    local v="$1" op e g
    : "$2"
    n=$((n + 1))
    # Op mix = the cross-peer surface the multipeer store supports today:
    # entry create, field edits, hard delete (5b tombstones), attachment
    # set/remove (5c), tag replace (3-way set merge), history-snapshot delete
    # (the privacy fix part 2 — history-tombstone union/prune on ingest), entry
    # MOVE (5d location LWW), and group CREATE
    # (5d peer-only group adoption — a device-local new group the peer
    # adopts on ingest, into which subsequent moves can land). Merged in
    # as each finding/slice landed (#7 conflict-row attachments, #8 LCA
    # disambiguation, 5d location LWW + group adoption). Attachment names
    # are SHARED across devices (both-sided clash parks + resolves in
    # resolve_all). The FULL group-structure surface is now exercised:
    # create (adoption), rename (metadata LWW), move (re-parent LWW +
    # deterministic cycle-break for concurrent mutual moves), delete
    # (tombstone consumption) — moves/deletes target non-root, non-bin
    # groups (random_movable_group) since deleting root would wipe the
    # vault and root has no parent to move. Scope ledger:
    # sync-multipeer-store.md.
    # NB: if/fi rather than `[ -n ] &&` — under `set -e` a final failing
    # && would silently kill the whole run when a pick comes up empty.
    # Every mutation is stamped at $AT (pinned by the loop). A and B
    # share the same $AT within a round, so concurrent edits genuinely
    # race; the loop advances $AT a clean second+ past the prior round's
    # resolution so an edit is never ambiguously in the same floored
    # second as a resolution (the sub-second hazard that silently
    # auto-merges a real clash — caught when this fuzzer first ran a
    # contended edit every round).
    op=$((RANDOM % 13))
    case $op in
        7) "$KEYHOLE" --at "$AT" --uuid-seed "$(mix "$n")" create-group "$v" "g-$n" >/dev/null ;;
        8) g="$(random_group "$v")"
           # Rename a random group (5d group metadata LWW). Every group
           # uuid is shared once adopted, so a rename either propagates
           # one-sided or races + resolves LWW; a just-created g-* not yet
           # on the peer converges next round (adoption + rename both
           # propagate). Renames on the same shared group race.
           if [ -n "$g" ]; then "$KEYHOLE" --at "$AT" rename-group "$v" "$g" "r-$n" >/dev/null 2>&1 || true; fi ;;
        9) g="$(random_movable_group "$v" 1)"; dst="$(random_movable_group "$v" 2)"
           # Re-parent a group under another (5d group move). Distinct salts
           # (1, 2) so the source and destination picks don't collapse to the
           # same group (a self-move the engine would just reject). Concurrent
           # mutual moves resolve via the deterministic cycle-break.
           if [ -n "$g" ] && [ -n "$dst" ]; then "$KEYHOLE" --at "$AT" move-group "$v" "$g" --to "$dst" >/dev/null 2>&1 || true; fi ;;
        10) g="$(random_movable_group "$v" 1)"
           # Delete a group (5d cross-peer group delete via tombstone).
           if [ -n "$g" ]; then "$KEYHOLE" --at "$AT" delete-group "$v" "$g" >/dev/null 2>&1 || true; fi ;;
        0) "$KEYHOLE" --at "$AT" --uuid-seed "$(mix "$n")" create-entry "$v" "fz-$n" --username "fu-$n" >/dev/null ;;
        1) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" update-entry "$v" "$e" --username "edit-$n" >/dev/null; fi ;;
        2) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" update-entry "$v" "$e" --url "https://fz$n.example" --notes "note-$n" >/dev/null; fi ;;
        3) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" delete-entry "$v" "$e" >/dev/null; fi ;;
        4) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" set-attachment "$v" "$e" "att-$((RANDOM % 2))" --text "payload-$n" >/dev/null; fi ;;
        5) e="$(random_entry "$v")"
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" remove-attachment "$v" "$e" "att-$((RANDOM % 2))" >/dev/null 2>&1 || true; fi ;;
        6) e="$(random_entry "$v")"; g="$(random_group "$v" 1)"
           if [ -n "$e" ] && [ -n "$g" ]; then "$KEYHOLE" --at "$AT" move-entry "$v" "$e" --to "$g" >/dev/null 2>&1 || true; fi ;;
        11) e="$(random_entry "$v")"
           # Replace an entry's tag set (tags reconcile by 3-way SET semantics,
           # not LWW). The set is a deterministic function of $n — replace-all,
           # so it both adds and removes tags as $n varies, exercising the
           # union-of-adds + removal-vs-LCA merge under concurrency. Tags are
           # order-independent and the digest covers them, so a real divergence
           # still fails the oracle. Proven path: tags-cross-peer.sh.
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" set-tags "$v" "$e" "t-$((n % 3)),t-$((n % 5))" >/dev/null; fi ;;
        12) e="$(random_entry "$v")"
           # Delete a history snapshot (the privacy fix, part 2): writes a
           # keys.history_tombstones.v1 record that the peer's ingest unions +
           # prunes against, so the deletion propagates cross-peer even though
           # the live entry stays InSync. Index 0 (oldest) always exists when
           # history is non-empty; an empty-history entry just no-ops (|| true).
           # Deterministic: target via random_entry, fixed index 0, tombstone
           # `at` stamped from the pinned $AT — no $RANDOM, so replay holds.
           # The digest excludes history + tombstones, so this can't perturb
           # the convergence oracle; it exercises the ingest history-reconcile
           # path under churn. Proven path: history-delete-propagates.sh.
           if [ -n "$e" ]; then "$KEYHOLE" --at "$AT" delete-history "$v" "$e" 0 >/dev/null 2>&1 || true; fi ;;
    esac
}

conflicts_on() { # $1=vault — sorted parked-conflict uuid set ('' if none)
    "$KEYHOLE" list-conflicts "$1" \
        | grep -Ei '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        | sort | tr '\n' ',' || true
}

resolve_all() { # $1=vault — resolve every held conflict, random side; stamps $AT
    local v="$1" u side
    # Sort the conflict uuids before the read loop: each iteration draws a
    # $RANDOM to pick local/remote, so an unsorted (engine-order) list would
    # assign sides by incidental order and desync replay across runs.
    "$KEYHOLE" list-conflicts "$v" | awk '$1 ~ /^[0-9a-f-]{36}$/ {print $1}' | sort \
    | while read -r u; do
        # Side is a deterministic function of (uuid, round clock), NOT a
        # $RANDOM draw: it still varies per-entry and per-round (so both
        # resolution directions get exercised), but a $RANDOM draw inside
        # this read loop would consume a stream-position that depends on
        # the conflict COUNT — desyncing replay across runs whenever the
        # parked set size differs by a single entry.
        if [ $(($(printf '%s' "$u-$AT" | cksum | cut -d' ' -f1) % 2)) -eq 0 ]; then
            side=local
        else
            side=remote
        fi
        # "no held conflict" here is benign: resolving one entry can
        # legitimately settle a sibling listed in the same sweep. The
        # real invariant is the caller's post-loop "no held conflicts"
        # assertion — a resolve that failed while leaving the conflict
        # held still fails the round there.
        "$KEYHOLE" --at "$AT" resolve "$v" --entry "$u" --choose "$side" >/dev/null 2>&1 \
            || echo "note: $u settled between list and resolve" >&2
    done
}

# --- the loop ---------------------------------------------------------
# Pinned monotonic clock (epoch-ms). Each round's edits share one
# instant ($AT) so A and B genuinely race; resolution lands a clean
# second+ later, and the next round jumps a full minute past that — so
# no operation is ever ambiguously in the same floored second as the
# prior round's resolution (KDBX is second-granular). CLOCK_BASE is a
# fixed constant, not wall-clock, so a seed reproduces byte-for-byte.
CLOCK_BASE=1800000000000   # 2027-01-15, comfortably future-proof
for round in $(seq 1 "$ROUNDS"); do
    AT=$((CLOCK_BASE + round * 60000))   # edits this round: +60s per round

    # Concurrent edits while "offline": 1–3 per device, all at $AT.
    # CRUCIAL: draw the per-device op count in the MAIN shell first. Reading
    # $RANDOM directly inside `$(seq 1 $((RANDOM % 3 + 1)))` evaluates it in
    # the command-substitution SUBSHELL, which bash reseeds with run-varying
    # entropy — so the count (hence the whole op stream) desynced across two
    # runs of one seed, even at a single round. THIS was the cross-run replay
    # residual: a varying count produced an extra/absent `g-$n` group (op 7)
    # and trailing op-target drift. Same subshell-$RANDOM trap the pickers hit
    # (see reference_bash_subshell_random + DESIGN.md Findings); a main-shell
    # assignment is a pure function of the seeded stream, so it replays.
    na=$((RANDOM % 3 + 1)); for _ in $(seq 1 "$na"); do mutate "$A" a; done
    nb=$((RANDOM % 3 + 1)); for _ in $(seq 1 "$nb"); do mutate "$B" b; done

    # Guaranteed contention: both devices edit the battleground entry's
    # same field to distinct values, so a genuine clash parks this round
    # (gives the parity + resolve assertions real teeth every round).
    "$KEYHOLE" --at "$AT" update-entry "$A" "$CONTESTED" --username "a-r$round" >/dev/null
    "$KEYHOLE" --at "$AT" update-entry "$B" "$CONTESTED" --username "b-r$round" >/dev/null

    # Sync, symmetric: BOTH devices ingest each other before anyone
    # resolves, so each independently derives its parked-conflict set.
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null

    # Oracle 1 — conflict-set PARITY: a genuine clash is symmetric, so
    # both replicas must hold the SAME set of parked entries (the digest
    # does NOT cover conflict rows, so a one-sided / ghost badge is
    # invisible to the digest oracle below — this catches it).
    ca="$(conflicts_on "$A")"
    cb="$(conflicts_on "$B")"
    [ "$ca" = "$cb" ] || fail "held-conflict set differs across peers: A=[$ca] B=[$cb]"
    # The battleground guarantees a clash every round, so an EMPTY set
    # here means the clash silently auto-merged instead of parking — a
    # regression in conflict detection, not benign.
    [ -n "$ca" ] || fail "round $round: contended edit did not park (auto-merged a genuine clash?)"

    # Resolve on A, then push the resolution to B; settle A against B's
    # post-adoption state. Both must end clean (no ghost, no re-park).
    # Resolution lands 10s after this round's edits and 50s before the
    # next round's, so it never shares a floored second with either.
    AT=$((CLOCK_BASE + round * 60000 + 10000))
    resolve_all "$A"
    "$KEYHOLE" list-conflicts "$A" | grep '(no held conflicts)' >/dev/null \
        || fail "conflicts remain on A after resolve_all"
    "$KEYHOLE" ingest-peer "$B" "$A" --owner device-a >/dev/null
    "$KEYHOLE" ingest-peer "$A" "$B" --owner device-b >/dev/null
    [ -z "$(conflicts_on "$B")" ] || fail "B kept a ghost conflict A already resolved"
    [ -z "$(conflicts_on "$A")" ] || fail "A re-parked after B's adoption"

    # Oracle 2 — content convergence.
    da="$("$KEYHOLE" digest "$A")"
    db="$("$KEYHOLE" digest "$B")"
    [ "$da" = "$db" ] || fail "digest divergence after sync: A=$da B=$db"
done

# Replay hook: with FUZZ_KEEP set, dump each device's final logical state
# (entries + groups WITH uuids — including the create-time root/bin — and
# the content digest) to that dir before the trap cleans up. The
# replay-determinism harness runs this twice with one seed and diffs the
# two dirs, proving the whole run (create included) is byte-reproducible.
if [ -n "${FUZZ_KEEP:-}" ]; then
    mkdir -p "$FUZZ_KEEP"
    for side in "$A" "$B"; do
        b="$(basename "$side")"
        # Sort the listings: the engine's row order is legitimately
        # unspecified (a client sorts in its own view layer) and differs
        # between an incrementally-built mirror and a re-ingested one, so we
        # compare canonical CONTENT, not incidental row order. A real
        # divergence (different uuids / counts) still shows; pure reordering
        # doesn't masquerade as one.
        "$KEYHOLE" list "$side" | sort >"$FUZZ_KEEP/$b.entries"
        "$KEYHOLE" list-groups "$side" | sort >"$FUZZ_KEEP/$b.groups"
        "$KEYHOLE" digest "$side" >"$FUZZ_KEEP/$b.digest"
    done
fi

echo "PASS: $ROUNDS rounds of seeded concurrent edits (seed=$SEED) converged every round"
