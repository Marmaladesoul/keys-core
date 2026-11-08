#!/usr/bin/env bash
#
# Scenario: SHOW THE KDF SETTINGS, GET A YES, THEN DERIVE EXACTLY THOSE. A
# KDBX file's outer header names its own KDF parameters and the KDF runs
# before anything else about the file can be checked, so every derive is
# gated on what the header demands:
#
#   - the vault's own file must demand the settings the mirror recorded for
#     it, or — nothing recorded yet, as on a first open — stay within the
#     process's ceiling. Anything else is `KdfApprovalRequired` until the
#     call is repeated with exactly the file's settings approved;
#   - a peer replica must demand the vault's recorded settings, or it is
#     refused (`KdfParametersMismatch`); `adopt-peer-kdf` takes a peer whose
#     settings changed, but only at exactly the settings approved, and the
#     vault then carries them.
#
# Real setting changes come from `set-kdf` (a re-key under the same
# password, as another client would make); hostile ones from `forge-kdf`
# (header rewritten, so no key opens it — what's under test is whether the
# reader derives before finding out).
#
# Assertions:
#   1. FIRST OPEN PAST THE CEILING → a vault whose Argon2 memory is past the
#      memory-constrained ceiling is refused there until approved, then
#      opens; the approval is recorded, so the next open needs none. The
#      mirror-less identity probe is gated the same way. A
#      hostile file (6 GiB × u32::MAX) on a first open under the standard
#      ceiling is refused fast, and approving other settings doesn't let it
#      through.
#   2. CHANGED ON DISK → the vault's file re-keyed to other settings is
#      refused at open, and by a save, with the file untouched, until those
#      exact settings are approved; approving different ones doesn't do.
#      Once approved, the vault records them and opens unprompted.
#   3. PEER RE-KEY ADOPTED → a peer that changed its settings is refused by
#      `ingest-peer`; `adopt-peer-kdf` with its exact settings merges it,
#      the vault's file and recorded settings become the peer's, the merge
#      survives a fresh re-ingest, and the peer's later replicas merge as
#      ordinary ones.
#   4. STALE OR HOSTILE PEER APPROVAL → a peer that changed its settings
#      again after the approval was given is refused, and so is a hostile
#      peer offered under an approval for benign settings — fast, with the
#      vault's file untouched.
#   5. CONTROL → ordinary opens and peer merges at unchanged settings need no
#      approval.
#   6. WEAKER WHATEVER THE TIME → settings that derive in no less time than
#      the vault's recorded Argon2id are still reported weaker (`kdf
#      --against`, the judgement a client shows beside the prompt): AES-KDF
#      (not memory-hard), less memory for more passes, Argon2d, Argon2 1.0.
#      More memory is not.
#   7. ONLY THE KDF IS ADOPTED → a peer copy in a KDBX3 envelope (rewrapped
#      into the vendored fixture's) is adopted under its approved AES-KDF
#      settings: the vault's file takes those settings but stays KDBX4 with
#      its own cipher, and the merge survives a fresh re-ingest.
#
# Self-contained: keyhole's own create / create-entry / list / kdf / set-kdf
# / forge-kdf / ingest-peer / adopt-peer-kdf / envelope / rewrap verbs, plus
# the vendored KDBX3 fixture; throwaway vaults.

set -uo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
HERE="$(cd "$(dirname "$0")" && pwd)"
export KEYHOLE_PASSWORD="keyhole-kdf-approval-pw"
KDBX3_FIXTURE="$HERE/fixtures/kdbx3-minimal.kdbx"
# The fixture's password — a public test credential, mirrored in
# peer-kdf-cost-refused.sh.
export KEYHOLE_TEMPLATE_PASSWORD='tëst pässwörd 🔑/\'
# AES-KDF rounds of the probe whose estimate scales step 6's AES-KDF
# setting to the vault's estimate (about a second's worth on the reference
# device, so its two-decimal estimate is precise to 1%).
AES_PROBE_ROUNDS=15000000
# Headroom on that scaling, so rounding can't land the setting under.
AES_PROBE_MARGIN=1.02

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

NEEDS_APPROVAL="KdfApprovalRequired"
# The mirror-less probes report the same refusal in words.
PROBE_NEEDS_APPROVAL="needs approval before deriving"
PEER_REFUSED="KdfParametersMismatch"
# Seconds a refusal may take. It reads one header; a derive at the forged
# cost runs for hours. The margin absorbs slow runners.
BUDGET_SECS=30
# What a process killed by the watchdog exits with (128 + SIGKILL).
KILLED_RC=137
U32_MAX=4294967295
# Past the memory-constrained ceiling (64 MiB), well within the standard one.
BIG_MEMORY_MIB=128

fail() { echo "FAIL: $*"; exit 1; }

# Run a command, killing it if it outlives the budget; returns its exit
# status (KILLED_RC when the watchdog fired).
bounded() {
    "$@" &
    local pid=$!
    ( sleep "$BUDGET_SECS"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local dog=$!
    wait "$pid"
    local rc=$?
    pkill -P "$dog" 2>/dev/null
    kill "$dog" 2>/dev/null
    wait "$dog" 2>/dev/null
    return "$rc"
}

# The `--approve-kdf` spec of what a file demands, or of what a vault's
# mirror recorded (`spec_of --recorded <vault>`).
spec_of() { "$KEYHOLE" kdf "$@" | cut -f1; }

# Run a keyhole command that must be refused with $1 — fast, and leaving
# the file $2 byte-identical. $3 = label; the rest is the command.
expect_refused() {
    local refusal="$1" file="$2" label="$3"
    shift 3
    cp "$file" "$TMP/before.kdbx"
    bounded "$KEYHOLE" "$@" >"$TMP/out" 2>"$TMP/err"
    local rc=$?
    [ "$rc" -ne "$KILLED_RC" ] || fail "$label: outlived ${BUDGET_SECS}s — the reader derived"
    [ "$rc" -ne 0 ] && grep -q "$refusal" "$TMP/err" \
        || { cat "$TMP/out" "$TMP/err"; fail "$label: not refused with $refusal (rc=$rc)"; }
    cmp -s "$TMP/before.kdbx" "$file" || fail "$label: the refusal rewrote $file"
}

# --- 1: FIRST OPEN PAST THE CEILING -------------------------------------
BIG="$TMP/big.kdbx"
"$KEYHOLE" create "$BIG" >/dev/null || fail "create the big vault"
"$KEYHOLE" create-entry "$BIG" "Big Login" --username big >/dev/null || fail "seed the big vault"
"$KEYHOLE" set-kdf "$BIG" --argon2-memory-mib "$BIG_MEMORY_MIB" >/dev/null || fail "raise its memory"
rm -rf "$BIG.mirror"   # a first open: nothing recorded to compare with
"$KEYHOLE" kdf "$BIG" --kdf-ceiling memory-constrained | grep -q "exceeds_ceiling=true" \
    || fail "the big vault isn't reported past the memory-constrained ceiling"
expect_refused "$NEEDS_APPROVAL" "$BIG" "first open past the constrained ceiling" \
    list "$BIG" --kdf-ceiling memory-constrained
big_spec="$(spec_of "$BIG")"
"$KEYHOLE" list "$BIG" --kdf-ceiling memory-constrained --approve-kdf "$big_spec" >"$TMP/p1.out" \
    || fail "the approved first open failed"
grep -q "Big Login" "$TMP/p1.out" || fail "the approved open didn't ingest the vault"
[ "$(spec_of --recorded "$BIG")" = "$big_spec" ] || fail "the approved settings weren't recorded"
"$KEYHOLE" list "$BIG" --kdf-ceiling memory-constrained >/dev/null \
    || fail "the recorded settings still needed approval"
# The identity probe derives with no mirror, so the ceiling applies to it
# whatever was recorded, until the same settings are approved.
big_root="$("$KEYHOLE" root-uuid "$BIG")" || fail "read the big vault's root uuid"
expect_refused "$PROBE_NEEDS_APPROVAL" "$BIG" "identity probe past the constrained ceiling" \
    verify-identity "$BIG" --expect "$big_root" --kdf-ceiling memory-constrained
"$KEYHOLE" verify-identity "$BIG" --expect "$big_root" --kdf-ceiling memory-constrained \
    --approve-kdf "$big_spec" | grep -qx match || fail "the approved identity probe didn't match"
# The standard ceiling takes the same vault unasked.
rm -rf "$BIG.mirror"
"$KEYHOLE" list "$BIG" >/dev/null || fail "a ${BIG_MEMORY_MIB} MiB vault needed approval under the standard ceiling"

HOSTILE="$TMP/hostile.kdbx"
"$KEYHOLE" forge-kdf "$BIG" "$HOSTILE" --argon2-memory-mib 6144 --argon2-iterations "$U32_MAX" >/dev/null \
    || fail "forge the hostile vault"
expect_refused "$NEEDS_APPROVAL" "$HOSTILE" "hostile first open" list "$HOSTILE"
expect_refused "$NEEDS_APPROVAL" "$HOSTILE" "hostile first open under another approval" \
    list "$HOSTILE" --approve-kdf "$big_spec"

echo "note: a first open past the ceiling is refused until its exact settings are approved"

# --- 2: CHANGED ON DISK --------------------------------------------------
LOCAL="$TMP/local.kdbx"
"$KEYHOLE" create "$LOCAL" >/dev/null || fail "create the vault"
"$KEYHOLE" create-entry "$LOCAL" "Local Login" --username local >/dev/null || fail "seed the vault"
cp "$LOCAL" "$TMP/local-original.kdbx"
"$KEYHOLE" set-kdf "$LOCAL" --argon2-iterations 3 >/dev/null || fail "change the vault's KDF on disk"
changed_spec="$(spec_of "$LOCAL")"
expect_refused "$NEEDS_APPROVAL" "$LOCAL" "open of a file whose KDF changed" list "$LOCAL"
# A save derives the file as its template: held to the recorded settings too.
KEYHOLE_SKIP_OPEN_SYNC=1 expect_refused "$NEEDS_APPROVAL" "$LOCAL" "save over a file whose KDF changed" \
    create-entry "$LOCAL" "Unsaved" --username x
expect_refused "$NEEDS_APPROVAL" "$LOCAL" "open under an approval for other settings" \
    list "$LOCAL" --approve-kdf "$big_spec"
"$KEYHOLE" list "$LOCAL" --approve-kdf "$changed_spec" >"$TMP/p2.out" \
    || fail "the approved open of the changed file failed"
grep -q "Local Login" "$TMP/p2.out" || fail "the approved open lost the vault's entry"
[ "$(spec_of --recorded "$LOCAL")" = "$changed_spec" ] || fail "the changed settings weren't recorded"
"$KEYHOLE" create-entry "$LOCAL" "After Approval" --username after >/dev/null \
    || fail "an ordinary edit after the approval"
"$KEYHOLE" list "$LOCAL" | grep -q "After Approval" || fail "the post-approval edit didn't land"

echo "note: a vault file whose KDF changed on disk is refused, by an open and a save, until approved"

# --- 3: PEER RE-KEY ADOPTED ----------------------------------------------
PEER="$TMP/peer.kdbx"
cp "$LOCAL" "$PEER"
"$KEYHOLE" create-entry "$PEER" "Peer Login" --username peer >/dev/null || fail "seed the replica"
"$KEYHOLE" set-kdf "$PEER" --argon2-memory-mib 96 >/dev/null || fail "change the replica's KDF"
peer_spec="$(spec_of "$PEER")"
[ "$peer_spec" != "$(spec_of --recorded "$LOCAL")" ] || fail "the replica's settings didn't change"
expect_refused "$PEER_REFUSED" "$LOCAL" "ingest of a re-keyed peer" ingest-peer "$LOCAL" "$PEER"
"$KEYHOLE" adopt-peer-kdf "$LOCAL" "$PEER" --approve-kdf "$peer_spec" >"$TMP/p3.out" 2>"$TMP/p3.err" \
    || { cat "$TMP/p3.err"; fail "adopting the re-keyed peer under its approved settings failed"; }
[ "$(spec_of "$LOCAL")" = "$peer_spec" ] || fail "the vault's file didn't take the peer's settings"
[ "$(spec_of --recorded "$LOCAL")" = "$peer_spec" ] || fail "the vault didn't record the peer's settings"
rm -rf "$LOCAL.mirror"
"$KEYHOLE" list "$LOCAL" >"$TMP/p3-list.out" || fail "fresh re-ingest after the adoption"
grep -q "Peer Login" "$TMP/p3-list.out" || fail "the adopted peer's entry didn't persist"
grep -q "Local Login" "$TMP/p3-list.out" || fail "the vault lost its own entry in the adoption"
# The replica's own mirror took the change on its disk too: approve it there.
"$KEYHOLE" create-entry "$PEER" "Peer Later" --username later --approve-kdf "$peer_spec" >/dev/null \
    || fail "edit the replica"
"$KEYHOLE" ingest-peer "$LOCAL" "$PEER" >/dev/null 2>"$TMP/p3b.err" \
    || { cat "$TMP/p3b.err"; fail "the adopted peer's next replica was refused"; }
"$KEYHOLE" list "$LOCAL" | grep -q "Peer Later" || fail "the adopted peer's next replica didn't merge"

echo "note: an approved peer re-key merges and its settings become the vault's"

# --- 4: STALE OR HOSTILE PEER APPROVAL -----------------------------------
# The peer changes its settings again after the user approved the earlier
# ones: that approval no longer covers it.
"$KEYHOLE" set-kdf "$PEER" --argon2-iterations 4 >/dev/null || fail "re-key the replica again"
expect_refused "$PEER_REFUSED" "$LOCAL" "adoption under a stale approval" \
    adopt-peer-kdf "$LOCAL" "$PEER" --approve-kdf "$peer_spec"
"$KEYHOLE" forge-kdf "$PEER" "$TMP/peer-hostile.kdbx" --argon2-memory-mib 6144 --argon2-iterations "$U32_MAX" \
    >/dev/null || fail "forge the hostile replica"
expect_refused "$PEER_REFUSED" "$LOCAL" "hostile peer under a benign approval" \
    adopt-peer-kdf "$LOCAL" "$TMP/peer-hostile.kdbx" --approve-kdf "$(spec_of "$PEER")"
[ "$(spec_of --recorded "$LOCAL")" = "$peer_spec" ] || fail "a refused adoption changed the recorded settings"

echo "note: an approval covers exactly the settings approved; a peer that moved on is refused"

# --- 5: CONTROL ----------------------------------------------------------
CTRL="$TMP/ctrl.kdbx"
"$KEYHOLE" create "$CTRL" >/dev/null || fail "create the control vault"
"$KEYHOLE" create-entry "$CTRL" "Ctrl Login" --username ctrl >/dev/null || fail "seed the control vault"
cp "$CTRL" "$TMP/ctrl-peer.kdbx"
"$KEYHOLE" create-entry "$TMP/ctrl-peer.kdbx" "Ctrl Peer" --username cp >/dev/null || fail "edit the control replica"
"$KEYHOLE" ingest-peer "$CTRL" "$TMP/ctrl-peer.kdbx" >/dev/null 2>"$TMP/p5.err" \
    || { cat "$TMP/p5.err"; fail "an ordinary peer merge needed approval"; }
rm -rf "$CTRL.mirror"
"$KEYHOLE" list "$CTRL" --kdf-ceiling memory-constrained >"$TMP/p5.out" \
    || fail "a default vault's first open needed approval, even memory-constrained"
grep -q "Ctrl Peer" "$TMP/p5.out" || fail "the ordinary merge didn't persist"

# --- 6: WEAKER WHATEVER THE TIME ----------------------------------------
WEAK="$TMP/weak.kdbx"
"$KEYHOLE" create "$WEAK" >/dev/null || fail "create the vault for the weakening checks"
"$KEYHOLE" create-entry "$WEAK" "Weak Login" --username weak >/dev/null || fail "seed it"
mem=67108864; iters=2; lanes=8
"$KEYHOLE" set-kdf "$WEAK" --kdf "argon2id:memory=$mem:iterations=$iters:parallelism=$lanes:version=19" \
    >/dev/null || fail "move it to Argon2id"
rm -rf "$WEAK.mirror"   # record the Argon2id settings on a first open
"$KEYHOLE" list "$WEAK" >/dev/null || fail "open it at Argon2id"
estimated_secs() { tr '\t' '\n' | sed -n 's/^estimated_seconds=//p'; }
current_secs="$("$KEYHOLE" kdf --recorded "$WEAK" | estimated_secs)"
# AES-KDF rounds whose estimate is just past the vault's, scaled from a
# probe's estimate rather than a copy of the engine's reference rates.
cp "$WEAK" "$TMP/probe.kdbx"
"$KEYHOLE" set-kdf "$TMP/probe.kdbx" --kdf "aes-kdf:rounds=$AES_PROBE_ROUNDS" >/dev/null \
    || fail "set the AES-KDF probe"
probe_secs="$("$KEYHOLE" kdf "$TMP/probe.kdbx" | estimated_secs)"
aes_rounds="$(awk -v r="$AES_PROBE_ROUNDS" -v p="$probe_secs" -v c="$current_secs" -v m="$AES_PROBE_MARGIN" \
    'BEGIN { printf "%d", r * c / p * m + 1 }')"

# $1 = spec, $2 = expected `weaker=` value.
expect_weakening() {
    local spec="$1" expected="$2" cand="$TMP/cand.kdbx"
    cp "$WEAK" "$cand"
    "$KEYHOLE" set-kdf "$cand" --kdf "$spec" >/dev/null || fail "set $spec"
    local secs
    secs="$("$KEYHOLE" kdf "$cand" | estimated_secs)"
    awk -v a="$secs" -v b="$current_secs" 'BEGIN { exit !(a >= b) }' \
        || fail "$spec estimates ${secs}s, under the vault's ${current_secs}s — not the case under test"
    local got
    got="$("$KEYHOLE" kdf "$cand" --against "$WEAK")" || fail "judge $spec"
    [ "$got" = "weaker=$expected" ] || fail "$spec: expected weaker=$expected, got $got"
}
expect_weakening "aes-kdf:rounds=$aes_rounds" loses-memory-hardness
expect_weakening "argon2id:memory=$((mem / 8)):iterations=$((iters * 8)):parallelism=$lanes:version=19" less-memory
expect_weakening "argon2d:memory=$mem:iterations=$iters:parallelism=$lanes:version=19" loses-argon2id
expect_weakening "argon2id:memory=$mem:iterations=$iters:parallelism=$lanes:version=16" older-argon2-version
expect_weakening "argon2id:memory=$((mem * 2)):iterations=$iters:parallelism=$lanes:version=19" none

echo "note: a weaker KDF is reported weaker even when it derives no faster"

# --- 7: ONLY THE KDF IS ADOPTED -----------------------------------------
cp "$WEAK" "$TMP/weak-src.kdbx"
"$KEYHOLE" create-entry "$TMP/weak-src.kdbx" "KDBX3 Peer" --username k3 >/dev/null \
    || fail "edit the replica's source"
K3PEER="$TMP/k3-peer.kdbx"
"$KEYHOLE" rewrap "$TMP/weak-src.kdbx" "$KDBX3_FIXTURE" "$K3PEER" >/dev/null \
    || fail "rewrap the replica in the KDBX3 envelope"
"$KEYHOLE" envelope "$K3PEER" | grep -q "^kdbx=3" || fail "the replica isn't KDBX3"
[ "$("$KEYHOLE" kdf "$K3PEER" --against "$WEAK")" = "weaker=loses-memory-hardness" ] \
    || fail "the KDBX3 replica's AES-KDF isn't reported weaker"
envelope_before="$("$KEYHOLE" envelope "$WEAK")"
k3_spec="$(spec_of "$K3PEER")"
expect_refused "$PEER_REFUSED" "$WEAK" "ingest of the KDBX3 replica" ingest-peer "$WEAK" "$K3PEER"
"$KEYHOLE" adopt-peer-kdf "$WEAK" "$K3PEER" --approve-kdf "$k3_spec" >/dev/null 2>"$TMP/p7.err" \
    || { cat "$TMP/p7.err"; fail "adopting the KDBX3 replica's KDF failed"; }
[ "$(spec_of "$WEAK")" = "$k3_spec" ] || fail "the vault's file didn't take the approved KDF"
[ "$(spec_of --recorded "$WEAK")" = "$k3_spec" ] || fail "the vault didn't record the approved KDF"
[ "$("$KEYHOLE" envelope "$WEAK")" = "$envelope_before" ] \
    || fail "the adoption changed the vault's envelope: $("$KEYHOLE" envelope "$WEAK"), was $envelope_before"
rm -rf "$WEAK.mirror"
"$KEYHOLE" list "$WEAK" >"$TMP/p7.out" || fail "fresh re-ingest after the KDBX3 adoption"
grep -q "KDBX3 Peer" "$TMP/p7.out" || fail "the KDBX3 replica's entry didn't persist"
grep -q "Weak Login" "$TMP/p7.out" || fail "the vault lost its own entry in the KDBX3 adoption"

echo "note: an adoption takes the approved KDF settings and nothing else of the peer's envelope"

echo "PASS: a vault file is derived only at its recorded settings, within the ceiling on a first open, or at exactly the settings approved — first opens past the ceiling and on-disk changes wait for approval, an approved peer re-key merges and becomes the vault's settings, a peer that moved on or a hostile one is refused, ordinary opens and merges are unaffected, a weaker KDF is reported weaker whatever its time estimate, and an adoption changes only the vault's KDF settings"
