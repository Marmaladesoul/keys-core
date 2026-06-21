# keyhole — headless test-driver for Keys

> Peek at the brain through the keyhole, without opening the door (the UI).

## What it is

A small Rust CLI that drives the **exact `keys-ffi` surface the GUI apps
drive** — minus the UI. It is the automated-testing client that proves
app-level behaviour one rung below the real Mac/iOS/Windows clients.

It is **not** a general-purpose KDBX client, and must never become one.
It opens *test* vaults, with *test* passwords, and is never shipped. Hold
that line: the moment someone wants it for real vaults it inherits a
security-review and support burden it should not have.

## Why it exists

Three payoffs, roughly in order of value:

1. **Differential / fuzz testing of sync.** Two `keyhole` processes on one
   machine, fed random concurrent edits, asserting they converge. This is
   the thing you *cannot* do through the GUI, and it's exactly where
   CRDT/merge bugs hide. (Replaces the manual 2-Mac soak ritual with
   something scriptable and property-based.)
2. **A baseline the GUI must match.** When the Mac app shipped a
   "delete didn't save" bug, a `keyhole` test would have caught it —
   *provided the save policy lives below the FFI line* (see below). The
   CLI becomes the obvious reference for "what the app should do".
3. **Headless CI.** No GUI test host (KeysTests hangs under `xcodebuild`
   on a GUI host); `keyhole` runs clean in a terminal.

## The seam

```
        Mac app (SwiftUI)   iOS app   Windows app (WinUI)   keyhole
                 \              |            /                 /
                  \             |           /                 /
                   ───────────  keys-ffi  ───────────────────
                   (uniffi facade — THE seam every client drives)
                                  |
                              keys-engine        (universal policy)
                                  |
                       keepass-core / keepass-merge
```

`keyhole` depends on `keys-ffi` directly (it exposes an `rlib` crate-type
alongside its staticlib/cdylib). So when `keyhole` calls
`engine.recycle_entry(...)`, it runs the **identical code** the Swift view
model runs through uniffi. No reimplementation, no second source of truth.

**Rule of thumb:** anything `keyhole` can reach through `keys-ffi` is
universal, shared, and testable here. Anything still living *above* the
FFI line (in Swift/Kotlin view models) is invisible to `keyhole` — and is
a migration candidate.

## Ports / adapters

`Engine::open` injects three platform *ports*; a fourth, the clock, is
injected via `Engine::open_with_clock` (the no-clock `open` defaults to
`SystemClock`):

| Port                  | Mac/iOS adapter            | keyhole adapter (`src/adapters.rs`) |
| --------------------- | -------------------------- | ----------------------------------- |
| `VaultDbKeyProvider`  | Keychain-stored mirror key | fixed 32-byte key                   |
| `VaultFieldProtector` | Secure Enclave session key | fixed 32-byte key                   |
| `VaultFileWatcher`    | NSFilePresenter            | `None` (keyhole drives state)       |
| `Clock` (engine)      | `SystemClock`              | `SystemClock`, or `FixedClock` via `--at` |

keyhole is just *another platform*. Its adapters are deliberately boring
and deterministic — that's a **fuzzing feature** (controllable clock /
file-events / inputs), not a shortcut. They protect only keyhole's
local mirror; they are unrelated to the KDBX master password,
which flows through `ingest_from_kdbx` / `save_to_kdbx`.

### The controllable clock (`--at <epoch-ms>`)

Every engine mutation stamps its timestamps (`modified_at`,
`location_changed_at`, tombstone `deleted_at`, created/accessed) from an
injected `keepass_core::model::Clock`, resolved once per mutation in
`Engine::now_ms` and threaded as an explicit `now: i64` into the
`mutations` layer. (Peer stamps adopted during `ingest_peer` come
verbatim from the peer — the clock is for *local* writes only.)

`keyhole --at <epoch-ms>` opens the engine with a `FixedClock` pinned to
that instant, so the timestamps that drive sync LWW are an **input**,
not a wall-clock race. This is what lets a scenario:

- **pin an exact LWW winner** — give the winning edit a strictly larger
  pinned second (KDBX floors to whole seconds), and it wins both ingest
  directions deterministically (`clock-lww.sh`, `group-rename-lww.sh`,
  `group-move-lww.sh`, `move-lww.sh` — all sleep-free);
- **force a same-second tie** — give both edits the *same* `--at`, and
  the deterministic replica-symmetric tiebreak must still converge
  (`clock-lww.sh`).

Note the lever: `--at` controls per-record LWW stamps. It does **not**
control the KDBX file's mtime (the kdbx-state signature the warm-mirror
skip uses) — scenarios that `sleep` to advance *file* mtime are a
different concern and keep their sleeps. Remaining `sleep`s in the
scenario set are either file-signature waits or not-yet-retrofitted
LWW cases; converting the rest is a mechanical follow-up.

### Deterministic entity ids (`--uuid-seed <n>`)

The third non-determinism source (after the seeded op stream and the
`--at` clock) is entity ids. `Engine::open_with_clock` also injects a
`keys_engine::uuid_source::UuidSource`: production uses `RandomUuids`
(`Uuid::new_v4`); tests/fuzz use `SeededUuids`
(`Uuid::from_u64_pair(seed, counter)`). Surfaced via keys-ffi
`Engine::open_deterministic(clock_ms, uuid_seed)` and `keyhole
--uuid-seed`. The fuzzer passes a DISTINCT per-command seed (the global
op counter `n`; seed-time creates use a high range) so every entity id
is unique AND reproducible across runs — `FUZZ_SEED=777` went from
intermittent to 3/3 consistent.

**Create-time ids are pinned too (task #29).** The root group + default
recycle bin used to be minted by `Vault::create_empty` *outside* the
engine's `UuidSource`, so they stayed random per vault. keepass-core now
has its own `model::UuidSource` (mirroring the engine's) and a
`Kdbx::create_empty_v4_deterministic(clock, uuids)` entry point; keys-ffi
surfaces it as `Vault::create_empty_deterministic(uuid_seed, clock_ms)`,
and `keyhole --uuid-seed --at create` uses it — root = `from_u64_pair(seed,
0)`, eager bin = `from_u64_pair(seed, 1)`. The fuzzer seeds `create` from
an 8e9 band (clear of the per-op `mix()` 0–4e9 band and the 9e9+ seed-time
band), so create replays. Proven by `scenarios/deterministic-vault-uuids.sh`.

**Subshell `$RANDOM` is a replay trap (fixed in two places).** While wiring
the above into the fuzzer, a double-run harness exposed that `$RANDOM` read
*inside* a `$(...)` command substitution is NOT reproducible across runs —
bash reseeds a subshell's `$RANDOM` with run-varying entropy, silently
desyncing the whole op stream. Two instances, both now fixed: (1) the
target-pickers (`random_entry`/`random_group`/…) selected with `awk -v
r=$RANDOM` inside `$(...)` — now select via a deterministic `pick_idx(n,
salt, SEED)` against a UUID-sorted list (`resolve_all` likewise chooses its
side by a cksum of `(uuid, $AT)`); and (2) the per-device op **count** was
drawn as `$(seq 1 $((RANDOM % 3 + 1)))`, evaluating `$RANDOM` in the `seq`
subshell — the cross-run replay residual (task #33), now drawn in the main
shell first. With both fixed the fuzzer replays byte-for-byte:
`scenarios/fuzz-replay-determinism.sh` is a full multi-round, multi-seed gate
(seeds 42/43/777 × 6 rounds) and is **part of `run-all.sh`**; create-uuid
determinism is separately gated by `deterministic-vault-uuids.sh`. General
trap write-up: `reference_bash_subshell_random`.

## The persistent mirror

The SQLCipher mirror lives at **`<vault>.mirror/`**, keyed to the vault
path, and **outlives the process** — exactly like a real client's local
store. That is what lets sync state (held conflicts, owner-tagged peer
rows) parked by one invocation be read and resolved by a later one; an
ephemeral mirror would make the whole conflict harness impossible, and
path-keying means two copies of a vault are two independent "devices"
for free.

Open follows the real unlock flow, driven by the engine's recorded
`(mtime_ms, byte_count)` KDBX-state signature:

- no signature → fresh mirror → `ingest_from_kdbx`;
- signature matches disk → mirror is current → skip ingest (mirror
  state, including held conflicts, carries over);
- signature differs → the KDBX changed underneath → 
  `reconcile_with_disk_park_conflicts` (the disk-watcher path: merge,
  park divergences, never block).

**Scenario-author rule:** a fresh process is no longer automatically a
fresh disk read. The honest "did it save to the KDBX?" assertion is now
`rm -rf "$VAULT.mirror"` first, forcing a re-ingest — a warm mirror
happily carries unsaved state across processes (that's its job). The
mirror cleans up with the scenario's temp dir; keyhole never deletes it
itself.

## The migration workflow (how keyhole grows)

keyhole is fleshed out **one bug or feature at a time**, never up front.
When something lands, classify it:

1. **Pure UI / presentation** (layout, animation, a label) → fix in the
   GUI. keyhole is irrelevant. Done.
2. **Platform mechanism** (file watching, biometrics, background
   scheduling, key storage) → fix at the platform edge. keyhole uses its
   own trivial adapter. No core change.
3. **Universal *policy* currently living in the app** (e.g. "save after a
   mutation", recycle-bin semantics, conflict handling) → **migrate it
   down.** This is the only case that touches keyhole, and the order is:
   1. Write a failing `keyhole` test that reproduces it against `keys-ffi`.
   2. Move the smallest slice of policy down into `keys-engine` / surface
      it on `keys-ffi`.
   3. Make the `keyhole` test green.
   4. Re-point the GUI at the new core call; delete the GUI's copy.
   5. Ship.

keyhole drives the migration and proves it *before* the GUI changes.

**Smell test:** if keyhole ever finds itself reimplementing *policy*
(rather than stubbing a *mechanism*), that's the alarm that some universal
logic leaked too high and wants pushing down. keyhole is thus a continuous
audit of the layering.

## This is incremental, not a big-bang refactor

The FFI seam already exists. Migrating policy is *relocating small
decisions across a boundary that's already there*, one bug at a time — a
strangler-fig, not a rewrite. Until a given area gives you a reason to
touch it, it stays exactly where it is and keeps working. keyhole's
coverage grows monotonically with the migration and never runs ahead of
it. The only cost: a *migrated* bug touches three places (core → keyhole →
GUI) instead of one — short-term effort bought for compounding payoff.

## Where policy should land

- Default target is **`keys-engine` (Rust)** — universal, inherited free
  by all four eventual platforms *and* fuzzed once.
- A **Swift-shared layer** (Mac+iOS only) is a reluctant exception, for
  logic that is *intrinsically* Apple-framework-bound. Let it **emerge**
  from observed Mac/iOS duplication; don't pre-build it, or it becomes the
  cosy place universal logic hides in a form Android/Windows can't use.
  (If one is ever built, it needs its own Swift harness — `keyhole` the
  Rust binary can't reach into it.)

## Status & backlog

- **Done:** crate scaffold; deterministic adapters; `open → ingest →
  read` end-to-end. The **persistent per-vault mirror** (see section
  above) and the **conflict / sync-merge harness**: verbs `ingest-peer`,
  `list-conflicts`, `show-conflict`, `resolve` (all-one-side), plus
  `update-entry` as the divergence-maker — the non-transport half of the
  manual 2-Mac soak, headless. Commands: `create`, `create-entry`,
  `update-entry`, `inspect`, `list`, `recycle` (`--no-save`),
  `ensure-bin`, `ingest-peer`, `list-conflicts`, `show-conflict`,
  `resolve`. `run-all.sh` aggregator, wired into keys-core's CI as a
  step after the workspace tests. Scenarios green:
  [recycle-persists.sh](scenarios/recycle-persists.sh),
  [recycle-self-contained.sh](scenarios/recycle-self-contained.sh),
  [default-recycle-bin.sh](scenarios/default-recycle-bin.sh),
  [ensure-bin-on-add.sh](scenarios/ensure-bin-on-add.sh),
  [offline-divergence.sh](scenarios/offline-divergence.sh). First real
  keyhole-first fix shipped (recycle data-loss — see Findings;
  keys-core#137). Being the first *Rust* consumer of the conflict FFI
  also forced `KdbxStateSignatureFfi` / `ParkConflictsResultFfi` /
  `ParkedConflictsSummaryFfi` onto keys-ffi's `pub use` surface (uniffi
  exported them to Swift, but no Rust re-export existed) — the
  consumer-drives-the-shape loop working as designed.
- **Done (2026-06-12, the fuzz-harness push):** the **content-digest
  convergence oracle** — `keepass_merge::vault_content_digest` (group
  tree + per-entry location/content-hash/icon + bin meta; history,
  timestamps, tombstones excluded) surfaced as
  `Engine::content_digest` → keys-ffi → the `digest` verb, pinned by
  `scenarios/digest-oracle.sh` (deterministic, mirror-independent,
  change-sensitive). New verbs: `create-group`, `list-groups`,
  `move-entry`, `restore`, `delete-entry`. The restore data-loss bug
  this surfaced is Finding #3 (fixed, incl. the
  `<PreviousParentGroup>` round-trip gap). And the **two-process
  convergence fuzzer** `scenarios/fuzz-convergence.sh` — seeded random
  concurrent create/edit/delete + park/resolve/sync, digest-asserted
  every round; op mix deliberately scoped to the supported 5b surface
  (location ops join when 5d lands). On its first day it correctly
  rediscovered the deferred 5d gap twice and then found Finding #4
  (open) — the manual-soak-replacement loop working end to end.
- **Done (2026-06-12, the convergence-fix push):** Finding #4 fixed
  (timestamp flooring — sync decisions are pure functions of synced
  bytes) and Finding #5 found-and-fixed by its validation soak
  (dissolved held conflicts now clear their badge at resolver-open);
  30/30 fuzz soak green; **`fuzz-convergence.sh` is now a CI gate** in
  `run-all.sh`.
- **Done (2026-06-12, resolver-surface push):** per-field `resolve`
  (`--choose local --field Notes=remote`, typo'd field names rejected),
  pinned by [per-field-resolve.sh](scenarios/per-field-resolve.sh)
  (mixed outcome survives reopen + converges across replicas), and
  [delete-vs-edit.sh](scenarios/delete-vs-edit.sh) pinning the 5b rules
  at disk precision: post-delete edit wins and resurrects (tombstone
  scrubbed); same-second tie → delete wins on both sides identically.
- **Done (2026-06-12, attachment foundation):** `set-attachment` pushed
  down through keys-engine (`set_attachment` mutation: content-
  addressed pool insert + link upsert + history snapshot) and keys-ffi
  — no attachment-*add* surface existed below the GUI at all.
  keyhole verbs `set-attachment` / `cat-attachment`;
  [attachment-roundtrip.sh](scenarios/attachment-roundtrip.sh) pins the
  single-replica storage contract (round-trip, replace-by-name,
  digest visibility).
- **Done (2026-06-12, 5c one-sided attachment propagation):**
  `keepass_merge::classify` is attachment-aware — LCA-backed one-sided
  attachment changes feed the verdict and ride
  `Classification::AutoMerged` as explicit `AttachmentChange`
  Take/Drop instructions (bytes included: a merged entry can't
  reference two binary pools), completing the abandoned "slice B3"
  wiring. keys-engine applies them in the `ingest_peer` AutoMerged arm
  (content-addressed upsert / link delete). Verbs `remove-attachment`
  added; [attachment-cross-peer.sh](scenarios/attachment-cross-peer.sh)
  pins add/replace/remove propagation + digest convergence +
  persistence; the fuzz op mix gains device-scoped attachment
  set/remove. Both-sided same-name attachment divergence stays on the
  conservative no-auto-pick path (no silent pick, no park) until
  conflict rows store attachments — the remaining 5c slice, along
  with blob-pool GC.
- **[FIXED] projection silently stripped history attachments — found
  while landing 5c (keyhole finding #6).** The mirror's history
  snapshots store attachments content-addressed (`sha256_hex`), but
  `projection::snapshot_to_entry` never consumed them: every Keys
  save emitted history records with NO attachments. Two consequences:
  (a) round-trip data loss — history attachments other clients wrote
  were stripped on save; (b) **every attachment replace/remove failed
  to propagate cross-peer**, because LCA discovery content-hashes
  history snapshots, and a peer's pre-edit snapshot (attachment
  stripped) could never match our attachment-bearing current. Fix:
  projection resolves snapshot shas through the shared binary pool
  (dedup'd with live attachments); unresolvable refs (pre-widening
  rows, GC'd blobs) skip, matching `history_attachment_bytes`'s
  posture.
- **[FIXED] resolving a parked conflict DROPPED attachments added since
  the fork — found by the widened fuzz mix (keyhole finding #7).**
  Sequence: A sets an attachment on entry X; B (or A) also field-edits
  X both-sided so X parks; A resolves choosing remote. The conflict
  context's "remote" was reconstructed from `conflict_*` rows, which
  carried NO attachments — so the apply replaced X wholesale and A's own
  attachment links were wiped (bytes survived unreferenced in the pool,
  and in the pre-resolve history snapshot, but the live entry lost
  them; the peer that already adopted the attachment kept it →
  replicas diverged). **Fix:** conflict rows store the peer's attachment
  state — migration 0009 adds `conflict_entry_attachment` (names linked
  by sha into the shared content-addressed `attachment_blob` pool;
  bytes upserted at park time), `reconstruct_peer_entry` returns the
  attachments alongside the entry, and `held_conflict_payload` binds
  them into the synthetic "theirs" vault's binary pool — so the
  local-vs-theirs merge sees the peer's true attachment set and
  `apply_merge`'s existing attachment machinery does the rest (a
  genuine divergence now surfaces as a resolver delta instead of a
  silent wipe). The pre-push security review caught a second door to
  the same loss: `clear_vault_tables` (any full re-ingest, e.g.
  resolving a *different* entry) wiped `attachment_blob` wholesale and
  rebuilt it from the vault — a parked peer attachment with DIVERGENT
  bytes exists only in the pool, so its row dangled and "theirs" went
  attachment-less again; the wipe now preserves blobs referenced by
  `conflict_entry_attachment`. NOTE for blob-pool GC (5c remainder):
  `conflict_entry_attachment` is a reference root. Pinned by
  [resolve-keeps-attachments.sh](scenarios/resolve-keeps-attachments.sh)
  (both resolution sides, across reopen + cross-replica convergence)
  and keys-engine `parked_resolution_preserves_attachments` +
  `held_divergent_attachment_survives_resolving_another_entry`.
- **[FIXED] LCA generation-aliasing silently diverged replicas under
  attachment churn — found by `fuzz-attachments.sh` on its first soak
  (keyhole finding #8).** `find_common_ancestor` matched by content
  hash alone, walking local candidates newest-mtime-first; when an
  edit returns an entry to a content-state identical to an OLDER
  shared snapshot (removing an attachment ⇒ back to the pre-add state;
  restoring any old field value), the matcher aliased to that ancient
  generation — the dominant live shape being same-second bursts, where
  the stable mtime sort left history OLDEST-first inside the tie.
  Against the wrong ancestor a one-sided change reads as both-sided
  (swallowed by classify's no-park attachment posture → silent
  divergence: `branch=in-sync` while the replicas disagreed) or a
  stale peer copy reads as a fresh one-sided add (silent revert).
  **Fix (keepass-merge): min-rank pair selection** — the ancestor is
  the content-matching pair maximising `min(local generation rank,
  remote generation rank)` (oldest snapshot = 0, current = highest):
  the version sitting latest in BOTH lineages, which is what "fork
  point" means. Two candidate fixes were empirically eliminated first,
  worth remembering: a *(floored mtime, hash) compound match gate*
  made the fuzzer WORSE (7/30 vs 19/30 baseline) because **the same
  logical generation does not carry the same mtime on both replicas**
  — classify's auto-merge builds the advanced entry from a clone of
  the LOCAL side, so adopted changes keep the adopter's mtime
  (observed live via `KEYS_DEBUG_LCA=1`: identical hashes one second
  apart); and *generation-ordered walking alone* can't help when the
  aliasing candidate IS the local current (always walked first).
  Soak: 30/30 seeds green (was ~1-in-7 red). The env-gated
  `KEYS_DEBUG_LCA=1` candidate dump in `find_common_ancestor` stays,
  kin to `KEYS_DEBUG_ADOPTION` (uuid + ranks + floored mtimes + 4-byte
  hash prefixes + attachment counts only — no names, no values).
  Pinned by keepass-merge `lca_same_second_tie_prefers_newest_generation`
  + `lca_replace_back_to_old_value_does_not_alias` and keyhole
  [attachment-remove-no-resurrect.sh](scenarios/attachment-remove-no-resurrect.sh)
  (the deterministic cross-second remove case — NB it passed even
  pre-fix thanks to attachment tombstones; the fuzzer remains the
  authoritative gate). `fuzz-attachments.sh` is re-gated into
  `run-all.sh`, and `fuzz-convergence.sh`'s mix now carries attachment
  ops (the 5b+5c surface, device-prefixed names until both-sided
  park/resolve lands).
- **Done (2026-06-13):** `set-bin <vault> on|off [--delete-bin-contents]`
  — the behaviour behind Keys-Mac's Vault Info recycle-bin toggle
  (agreed design from the KeysCore #136 review: respect the per-vault
  setting; bin off = permanent delete).
  [set-bin-toggle.sh](scenarios/set-bin-toggle.sh) pins: disable keeps
  the old group as an ordinary group and makes recycling a permanent
  tombstoned delete; enable auto-creates/designates a bin (no group
  picker); disable + delete removes the bin and contents. The GUI
  toggle is now "call the proven path".
- **Done (2026-06-13, Finding #7 fix):** conflict rows store the
  peer's attachment state (migration 0009) and the resolver's rebuilt
  "theirs" carries it — resolving a parked conflict no longer drops
  attachments added since the fork. See Findings.
- **Done (2026-06-13, Finding #8 fix):** `find_common_ancestor` is
  generation-aware (min-rank pair selection, keepass-merge); both
  fuzzers are CI gates and the main fuzz mix carries attachment ops.
  See Findings. The same CI run also surfaced a latent
  scenario-harness race: keyhole prints a summary line after its
  greppable output, so a reader that closes the pipe early
  (`grep -q`, `head -1`, `awk '…; exit'`) makes keyhole's next
  `println!` hit EPIPE — and because Rust sets `SIGPIPE` to `SIG_IGN`,
  that surfaces as a panic, which `pipefail` then turns into a
  false-FAIL. Patched twice: first the `grep -q` sites went full-read
  (`grep X >/dev/null`), then — when an `awk '…; exit'` capture flaked
  `move-propagates.sh` on #152's CI — the durable fix landed in keyhole
  itself: `restore_default_sigpipe` resets `SIGPIPE` to `SIG_DFL` at
  the top of `main`, so keyhole dies quietly like a normal unix tool on
  a closed stdout instead of panicking. That kills the whole class
  regardless of how a scenario reads keyhole's output.
- **Done (2026-06-13, both-sided attachment park/resolve — the 5c
  conflict slice):** `keepass_merge::classify` treats both-sided
  same-name attachment divergence (and the no-LCA conservative
  posture) as a genuine Conflict — it parks with
  `attachment_deltas` surfaced instead of silently coexisting
  un-badged forever. No keys-engine change needed: Finding #7's
  plumbing (conflict rows store attachments; rebuilt "theirs"
  carries them; per-attachment resolve) carries the whole flow.
  Pinned by
  [attachment-both-sided-park.sh](scenarios/attachment-both-sided-park.sh)
  (park → hold-open keeps local → resolver delta → choose-remote
  adopts peer bytes → propagates without re-park → digest converges →
  persists); `fuzz-convergence.sh`'s attachment names went SHARED
  (both-sided clashes park + resolve in the round loop) — 30/30 soak.
- **Done (2026-06-13, blob-pool GC):** the mirror's `attachment_blob`
  pool is swept at save time (`mutations::gc_attachment_blobs` from
  `save::save` — the mirror twin of keepass-core's `gc_binaries_pool`
  for the file). Roots that survive: live links, history-snapshot
  shas, and `conflict_entry_attachment` (the Finding-#7 obligation —
  a parked conflict's divergent peer bytes exist only in the pool).
  Observability: `Engine::attachment_blob_stats` → keys-ffi
  `AttachmentBlobStats` → `inspect`'s "blob pool" line. Pinned by
  [blob-pool-gc.sh](scenarios/blob-pool-gc.sh) (red pre-GC: deleting
  an entry left its blobs forever) and keys-engine
  `gc_attachment_blobs_reaps_only_unrooted`.
- **Done (2026-06-13, 5d entry-location LWW):** a one-sided entry move
  now propagates, and a both-sided move resolves last-writer-wins by
  floored `<LocationChanged>`. Migration 0010 stores
  `location_changed_at` in the mirror (it was dropped on every save
  and invisible to sync — a pure move is content-identical so classify
  verdicts `InSync`); `move_entry`/recycle/restore stamp it; a
  dedicated `reconcile_entry_location` pass in `ingest_peer` (run after
  the content verdict, orthogonal to it) relocates the local entry
  when the peer's floored stamp is strictly newer, adopting the peer's
  **whole location triple verbatim** — destination, `location_changed`,
  AND `<PreviousParentGroup>`. That last one matters: the digest
  covers `PreviousParentGroup` (keepass-core #223), so computing our
  own prev on adoption diverged the digests even when the group
  agreed — the Finding-#8 "adopt, don't re-derive" lesson, extended to
  every location facet. Loop-safe (verbatim stamp ⇒ peer sees nothing
  newer next pull). Pinned by
  [move-propagates.sh](scenarios/move-propagates.sh) (one-sided) +
  [move-lww.sh](scenarios/move-lww.sh) (both-sided, converges on the
  side that didn't make the winning move); `fuzz-convergence.sh` gains
  a move op among pre-seeded shared groups.
- **Done (2026-06-13, 5d peer-only group adoption):** `ingest_peer`
  now adopts groups the peer holds that the local mirror lacks —
  walked top-down (parent before child) in `adopt_peer_groups`, so an
  entry moved or added into a freshly-created peer group lands there
  instead of falling back to root (and `reconcile_entry_location` no
  longer no-ops for want of the destination). Adopted as ordinary
  groups (`is_recycle_bin = 0`) — bin/`<Meta>` reconciliation is its
  own slice and a second minted bin would break the single-bin
  invariant. Pinned by [group-adopt.sh](scenarios/group-adopt.sh) +
  keys-engine `two_engine_adopts_peer_only_group`;
  `fuzz-convergence.sh` gains a `create-group` op (peer-only groups
  adopted under churn) — 30/30 soak.
- **Done (2026-06-13, 5d group metadata LWW):** `adopt_peer_groups`
  grew into `reconcile_peer_groups` — an *existing* group's name /
  notes / icon now reconcile by LWW on the group's `modified_at`
  (bumped by every `update_group`), with a same-second tiebreak over
  `(floored modified_at, name, notes, icon, custom_icon)` and the
  peer's `modified_at` adopted verbatim. Includes the ROOT group: its
  name is in the digest, so a root rename must propagate too — the
  fuzzer caught it diverging when reconciliation only walked root's
  children (`reconcile_peer_groups` now reconciles `peer.root`'s own
  metadata before descending). New keyhole verb `rename-group`; pinned
  by [group-rename-lww.sh](scenarios/group-rename-lww.sh) (one-sided +
  both-sided LWW) + keys-engine
  `two_engine_group_rename_reconciles_and_converges`;
  `fuzz-convergence.sh` gains a `rename-group` op — 30/30 soak.
- **Done (2026-06-13, 5d group move / re-parent LWW + cycle-break):** a
  group re-parent reconciles by LWW on a DEDICATED group
  `location_changed` (migration 0011, the group twin of 0010 for
  entries) — separate from metadata's `modified_at` so a concurrent
  rename and move don't clobber each other. `reconcile_peer_groups` is
  two-pass (adopt all peer-only groups, then reconcile metadata +
  parent). The move-LWW winner per group is symmetric, so a concurrent
  *mutual* move (A→under B while B→under A) yields the SAME cyclic
  edge set on both replicas; `break_group_cycles` then resolves it
  identically (re-root each cycle's smallest-uuid member). Applying the
  winning edge is unconditional (transient in-tx cycles are fine —
  SQLite has no FK cycle check on `parent_uuid`, projection reads only
  committed state); the earlier skip-on-cycle guard was REMOVED because
  it diverged (the skip's order-dependence left the replicas in
  different acyclic trees). New keyhole verb `move-group`; pinned by
  [group-move-lww.sh](scenarios/group-move-lww.sh),
  [group-move-cycle.sh](scenarios/group-move-cycle.sh), and keys-engine
  `two_engine_group_move_reconciles_and_converges`.
- **Done (2026-06-13, 5d cross-peer group delete — option 2, content
  saves the group):** `ingest_peer` consumes peer group tombstones via
  `materialize_group_tombstones`, run after the entry passes + tombstone
  union: liveness is **derived from the merged tree**, not transient
  ingest-time emptiness — a tombstoned group with no live descendant is
  deleted (children-first, FK-safe), one that still holds content is
  **resurrected** (kept, tombstone scrubbed so no live group carries its
  own tombstone). the maintainer's call: **content saves a deleted group** — if
  one device deletes a group while another fills it, the group survives
  with the content; a group empty everywhere stays deleted. Non-sticky
  (a resurrected group becomes ordinary; a later emptying does NOT
  re-delete — sticky would need a Keys-private marker, deferred). This
  REPLACED an earlier empty-only/edit-wins consume that diverged ~5–13%
  (keep/delete decided from per-pass transient emptiness, which differs
  across sync directions). New keyhole verb `delete-group`; pinned by
  [group-delete.sh](scenarios/group-delete.sh) (empty + cascade) +
  [group-delete-keeps-content.sh](scenarios/group-delete-keeps-content.sh)
  + keys-engine `two_engine_group_delete_content_saves_group`.
  **`fuzz-convergence.sh` now drives the entire CRUD + group-structure
  surface** (create/rename/move/delete groups, all entry CRUD,
  attachments, conflicts) — 60/60 soak. 5d's core reconciliation is
  complete.
- **Done (2026-06-14, 5c custom-icon pool union):** `ingest_peer` now unions
  the peer's `meta_custom_icon` pool (grow-only, content-addressed) so an
  adopted icon ref isn't left dangling — the last 5c sliver. New verbs
  `add-custom-icon` / `custom-icon-bytes`; proven by
  `custom-icon-cross-peer.sh` + engine `two_engine_custom_icon_pool_unions`.
  See Findings.
- **Done (2026-06-15, vault-meta convergence):** `ingest_peer` now LWW-
  reconciles the scalar `Meta` facets (recycle-bin config, db name/desc,
  history caps) via the shared `keepass_merge::merge_meta_scalars` — a
  recycle-bin toggle was a proven permanent digest split. keepass-core #229 +
  KeysCore #167; proven by `meta-recycle-bin-converges.sh` + engine
  `two_engine_recycle_bin_meta_converges`. See Findings.
- **Done (2026-06-15, adversarial save-fidelity gate + format/field breadth):**
  the engine projects the mirror → vault → KDBX on every save, so a lossy
  projection silently drops data (Finding #6 class). A self-round-trip can pass
  vacuously, so the gate verifies the engine-saved file with an INDEPENDENT
  reader (`keepassxc-cli`) that shares none of our assumptions; checks are
  teeth-verified (a sabotaged copy goes red) and **fail loudly** if the cli is
  absent (a skipped gate is no gate — CI installs it). `keyhole set-field`
  added so a custom field is authorable. Two scenarios:
  `save-fidelity-adversarial.sh` (KDBX4: fields/history/attachment/custom-icon/
  custom-field) and `save-fidelity-kdbx3.sh` (opens a vendored KDBX3 fixture,
  builds it rich, asserts the engine keeps it KDBX3 — no silent v3→v4 upgrade —
  with every facet intact). Both came back clean. Remaining breadth: unknown-XML
  and a full round-trip fidelity fuzzer.
- **Done (2026-06-16, tags coverage):** a keys-ffi-seam audit found tags were
  the last sync-relevant facet keyhole couldn't author (`create-entry`/
  `update-entry` hardcode an empty tag set) — the same coverage hole class as
  custom-fields and recycle-bin/meta. New verbs `set-tags` / `tags`; tags
  converge by 3-way SET semantics (union of adds, removal-vs-LCA wins), proven
  by `tags-cross-peer.sh` and now fuzzed (op 11 in `fuzz-convergence.sh`,
  200/200 soak + replay-deterministic). Tags already converged — this closed
  the test gap, not a bug.
- **Done (2026-06-17, part 2 of the history-deletion fix):** an `ingest_peer`
  pass unions + prunes history tombstones for shared entries even when classify
  says InSync (see Findings → "History-snapshot deletion didn't propagate"),
  via the new `keepass_merge::reconcile_history_tombstones`. That flipped
  `history-delete-propagates.sh` from forcing-function to a `run-all.sh` gate;
  `fuzz-convergence.sh`'s mix gained a deterministic `delete-history` op.
- **Next (the headline):** the rest of the history-surgery cluster
  (`restore_entry_from_history`, `clear_entry_custom_icon`,
  `save_entry`-atomic-snapshot — `attach_file` dropped as redundant with the
  covered `set-attachment`). Then: previous-parent merge rules; `empty-bin`
  verb; vault-level `<Meta><CustomData>` peer-path convergence; the
  save-fidelity breadth pass (unknown-XML + fidelity fuzzer).
- **Repo home (2026-06-11):** keyhole lives *inside the keys-core
  workspace* (`keyhole/`), not as its own repo. It evolves in lockstep
  with `keys-ffi` (the #138 export PR existed purely because of the old
  repo boundary), so same-repo means seam + first-consumer change
  atomically and CI gates them together — and the standalone repo's
  cross-repo private checkout (and its `SIBLINGS_TOKEN` PAT) is gone.
- **Possible follow-up (unverified):** `keys-engine::restore_entry` clears
  `is_recycled` but doesn't appear to move the entry out of the bin group
  — worth a look when `restore` is wired.

## Findings (surfaced by keyhole)

- **[CHARACTERISED — seam is data-safe; gap guarded one rung up] Skip-ingest
  unlock does not verify the master password — but `save_to_kdbx` fails closed,
  so a wrong password cannot re-key the vault.** Investigating a Keys-Mac
  data-loss report (a WRONG password typed into the unlock modal appeared to
  silently re-key a live vault, locking the user out), keyhole reproduced the
  *mechanism* at this seam: `Session::open` skips ingest when the mirror's
  recorded `(mtime,size)` signature matches the kdbx on disk (the steady-state
  perf win — no Argon2), and that skip path never reads the kdbx, so the open
  **succeeds for ANY password** without verifying it.
  `scenarios/wrong-password-no-rekey.sh` arms that skip path (create + a
  correct-password mutation → signature matches disk), then opens+mutates+saves
  under a deliberately-wrong password. **The decisive result:** the open is
  accepted (skip, no verify) and the mutation lands in the mirror, but the
  trailing `save_to_kdbx(wrong)` **fails closed** —
  `Internal("open kdbx: decryption failed (wrong key or corrupt data)")` —
  because it must `open_unlocked(path, wrong)` the on-disk file FIRST (as the
  crypto-envelope template) and a wrong password is rejected there. So the
  on-disk kdbx is left untouched: it still opens under the correct password,
  rejects the wrong one, and the wrong-password write never reaches disk.
  - **What this means.** `save_to_kdbx` **cannot re-key an existing kdbx to a
    different password** — it is open-then-reuse, not derive-from-password. So
    the `aaaa` re-key observed in the Keys-Mac app did **not** come from the
    save path on the existing vault. The actual re-key vector is therefore
    elsewhere — most likely a *fresh-create / first-save* on a sync peer with no
    existing file to open (the report was against a `sync-test` vault), or the
    `reconcile_with_disk*` path (which builds a `CompositeKey` from the password
    directly). The same corrupted-cached-password state also explains the
    "PR-2 iroh-sync wrong-key / decryption-failed merge failure": once the app
    caches the wrong password, the next signature-mismatch open takes the
    reconcile path and fails to open the disk kdbx.
  - **Re-key-vector hunt — RESOLVED: there is no re-key of an existing vault,
    anywhere.** `scenarios/sync-wrong-password-no-rekey.sh` drives the three
    remaining candidates under a wrong password — `ingest-peer` (per-device-key
    transport merge), `reconcile_with_disk_park_conflicts` (the disk-watcher
    path a sync write to the file triggers), and `create` on a fresh path — and
    pins that the first two **fail closed** (`unlock disk kdbx: decryption
    failed`) leaving both replicas openable only under the correct password,
    while only `create` on a *non-existent* path keys a vault from a raw,
    caller-supplied password. The structural reason: every disk-touching FFI op
    (`save_to_kdbx`, `ingest_from_kdbx`, `reconcile_*`, `ingest_peer_*`)
    `open_unlocked`s the existing file FIRST, so a wrong key is rejected before
    any write; `save_to_kdbx` is open-then-reuse and so cannot even *create* a
    file (its `Kdbx::open` of a missing path is an IO error). A Keys-Mac code
    trace confirms the app honours this: the only `Vault::create_empty` call is
    the user-driven WelcomeView create (password typed + confirmed there), and
    the "rebuild missing vault" path (`MissingVaultRecovery.runRebuild`) routes
    through `save_to_kdbx`, so it too fails closed rather than minting a
    wrong-keyed file. **Conclusion:** the `sync-test` vault was almost certainly
    NOT cryptographically re-keyed — the on-disk kdbx is still keyed with its
    original password. The actual damage is the **Keychain overwrite** (the app
    caches the wrong typed password), which locks the app out (every open now
    tries the wrong password) and breaks sync reconcile with "wrong key" — both
    symptoms of a poisoned cache, not a destroyed vault. That makes Guard 1+2
    (never cache an unverified password — Keys-Mac `DatabaseDocument` /
    `DatabaseManager`) the load-bearing fix; the re-key fear the report opened
    with does not have a code path behind it.
  - **Altitude.** The skip-path open accepting a wrong password is real but
    *not* fixable at this seam without a verify primitive: there is no cheap
    header-auth check (KDBX4 header HMAC needs the Argon2-derived composite key,
    so any real verify pays the KDF the skip exists to avoid). Keys-Mac patches
    it one rung up — `DatabaseDocument` constant-time-compares the typed
    password against the cached **Keychain** password before trusting the skip,
    falling through to a full ingest on mismatch (zero Argon2 on the happy
    path). keyhole has no Keychain, so it can't exercise that specific remedy —
    hence this finding is characterised, not "fixed", here. If we ever want the
    seam itself to reject a wrong password on the skip path (so every client —
    Mac, AutoFill, a future Windows app — inherits it), that's a `keys-ffi`
    `verify_password` / header-auth primitive, and this scenario is where it'd
    be gated.
  - **Also pinned:** `scenarios/wrong-password-ingest-rejected.sh` — the slow
    path (fresh ingest) DOES reject a wrong password, and its error string
    carries a marker Keys-Mac's `VaultUnlockError.isWrongPassword(_:)` classifier
    matches (so the UI shows "Incorrect Password"). That scenario is the canary
    for keepass-core rewording its wrong-key message out from under the Swift
    classifier — keep the marker list in sync with
    `DatabaseManager.swift` → `enum VaultUnlockError.wrongPasswordMarkers`.

- **[FIXED] History-snapshot deletion didn't propagate cross-peer — a privacy
  gap.** Deleting one history snapshot (the "scrub this old version" action —
  e.g. removing a leaked password from an entry's history) did NOT propagate:
  after a sync the two replicas diverged on history depth forever (A=2
  snapshots, B=3), so the deleted secret lived on every other device. Surfaced
  by the `history` / `delete-history` verbs +
  `scenarios/history-delete-propagates.sh`. **Why:** the cross-peer history
  merge is *lossless* (it unions histories), so a bare local `DELETE` can't
  survive — only a `keys.history_tombstones.v1` record (which the merge prunes
  against) makes a deletion stick. Two sub-causes, both now fixed:
  - **(1, part 1)** `delete_history_at` wrote no tombstone. **Fixed**: the
    engine wrapper writes one via `keepass_merge::add_history_tombstone` (keyed
    by the record's content-hash + mtime) before dropping the row.
  - **(2, part 2)** even with the tombstone in A's custom_data, A's live entry
    equalled B's, so `ingest_peer` classified the entry **InSync and skipped it
    entirely** — the tombstone never reached B (diagnosed: B received 0
    tombstones, kept all 3 snapshots). **Fixed**: a per-shared-entry pass in
    `ingest_peer` (after `reconcile_entry_location`, orthogonal to the content
    verdict — the same "runs for every shared entry" shape) reconciles history
    tombstones via the new `keepass_merge::reconcile_history_tombstones`: it
    unions both sides' OR-sets, prunes the local entry's matching history
    records, and persists by rewriting that entry's `entry_history` rows + the
    tombstone custom_data item (a new per-entry history-rewrite helper — ingest
    only ever did a full clear+reinsert before). It reuses the canonical
    `union_history_tombstones` the disk-reconcile path uses, so the two ingest
    paths can't drift on the CRDT. Loop-safe: idempotent once both sides agree,
    and it only touches history snapshots (never a live record). The new
    `IngestPeerOutcome.history_pruned` bucket drives the save decision.
  The convergence digest is no oracle here (it deliberately excludes history),
  which is why this stayed invisible — `history-delete-propagates.sh` compares
  the snapshot sets directly across a fresh disk read and is now a full
  `run-all.sh` gate. Engine-pinned by `two_engine_history_delete_propagates`;
  `fuzz-convergence.sh`'s mix gained a deterministic `delete-history` op.
  - **Pre-commit review catch — the post-pass must reconcile the side the
    verdict arm actually persisted.** The reconcile bases on a clone of the
    pre-ingest local entry, which is right for InSync / auto-merge / held
    conflicts (the mirror still holds local's history) but WRONG for the
    conflict adopt-peer arm: there `advance_local_entry` rebuilds the entry
    from the peer's resolved copy, so basing on stale local history clobbered
    the just-adopted peer snapshots (silent cross-peer history loss + permanent
    depth divergence; privacy still held — the scrub stuck either way). Fixed by
    selecting the base per arm: the peer entry + its pool when we adopted the
    peer's value, else local. Reaching that arm needs a re-edit-after-park (a
    bare resolve snapshots the loser into history, making the next pull an
    AutoMerge, not an adopt) — pinned by
    [history-delete-conflict-adopt.sh](scenarios/history-delete-conflict-adopt.sh)
    (teeth-verified: red when the post-pass bases on local). A history-only
    propagation also now surfaces in `MergeStats.history_pruned` instead of
    reading as an all-zero `Applied`.

- **[FIXED] `ingest_peer` ignored vault Meta → a recycle-bin toggle diverged
  replicas permanently (digest-visible).** The owner-rows peer-sync path
  reconciled entries, groups, resolution records and (since the icon finding
  below) the custom-icon pool, but never the scalar `Meta` facets. So toggling
  the recycle bin on one peer left the other untouched, and since the
  convergence digest covers `recycle_bin_enabled` + the bin pointer, the two
  replicas' digests split and never re-converged — a "stuck out of sync" a
  2-Mac soak would otherwise chase for an afternoon (the fuzzer never toggles
  the bin, so it was a blind spot). Two sub-causes: (1) `set_recycle_bin` never
  stamped `recycle_bin_changed`, so there was no LWW arbiter; (2) `ingest_peer`
  had no meta reconcile at all. **Fix:** stamp `recycle_bin_changed` on every
  toggle, and add `ingest::reconcile_peer_meta` — LWW the scalar facets via
  the shared `keepass_merge::merge_meta_scalars` (one rule-set for the
  peer-sync and disk-reconcile paths), persisting via a new scalar-only
  `meta::write_meta_scalars` (the full `write_meta` plain-inserts the
  custom-data/icon list tables and would duplicate resolution rows mid-ingest —
  a regression the fuzzer caught). Proven by
  `scenarios/meta-recycle-bin-converges.sh` (one-sided adopt + LWW, across a
  fresh disk read) + engine `two_engine_recycle_bin_meta_converges`. Needs
  keepass-core (the `merge_meta_scalars` export) to land first. The other
  scalar facets (db name/description, history caps) ride the same reconcile.

- **[FIXED] custom-icon pool not unioned on `ingest_peer` → dangling icon
  reference (digest-blind).** The last 5c sliver. When a peer adds a custom
  icon to a shared entry, the entry's content-addressed `custom_icon_uuid`
  rides the normal content merge and propagates — but the icon BYTES live in
  a separate vault-level pool (`meta_custom_icon`), and `ingest_peer` never
  unioned it. So the adopting replica was left with a reference to an icon
  whose bytes it didn't have. The convergence digest covers the icon *ref*
  but not the pool bytes, so both replicas' digests matched the instant the
  ref propagated — the oracle was blind to the dangling blob (the same class
  of gap the attachment-pool union closed for 5c attachments). Surfaced by a
  new keyhole scenario reading the pool directly across a fresh disk read.
  **Fix:** `ingest::union_peer_custom_icons` — a grow-only `INSERT OR IGNORE`
  of the peer's `meta.custom_icons` into the local pool at the ingest tail
  (alongside `union_peer_tombstones`); keyed by the content-addressed uuid, so
  a present uuid carries identical bytes and only genuinely-new icons land. New
  keyhole verbs `add-custom-icon` / `custom-icon-bytes`; proven by
  `scenarios/custom-icon-cross-peer.sh` (RED before the fix) + engine
  `two_engine_custom_icon_pool_unions` (teeth-checked: both go red with the
  union removed).

- **[FIXED] Fuzzer pickers read `$RANDOM` inside `$(...)` — not
  replayable.** Surfaced by the new double-run replay harness
  (`fuzz-replay-determinism.sh`) during task #29. The target pickers
  (`random_entry` / `random_group` / `random_movable_group`) selected with
  `awk -v r=$((RANDOM))` *inside* a `$(...)` command substitution. bash
  reseeds a **subshell's** `$RANDOM` with run-varying entropy (verified:
  main-shell draws identical across runs, subshell draws differ), so
  `$(...)`-based selection was never reproducible — it silently desynced
  the whole op stream, which is why a hand-reproducible bug could go
  unhit across a 60×40 soak. **Fix:** pickers select via a deterministic
  `pick_idx(n, salt, SEED)` (main-shell op counter, never subshell
  `$RANDOM`) against a UUID-sorted list, with a per-call salt so two picks
  in one mutate (op 9's source+dest) don't collapse; `resolve_all` chooses
  its side by a cksum of `(uuid, $AT)`. This removed a whole class of desync
  but did NOT by itself make the fuzzer replayable — one more instance of
  the *same* trap survived (the per-device op count, also a `$(…)` subshell
  draw); see the cross-run replay residual finding below, now [FIXED]. (It's
  the class of bug task #28's "audit HashMap order" was meant to catch but
  didn't — the headline source was in bash, not the engine.)

- **[FIXED] Fuzzer cross-run replay residual (task #33) — the per-device op
  count was drawn in a `$(seq …)` subshell.** After create-uuid pinning
  (task #29) + the subshell-`$RANDOM` *picker* fix above, two same-seed runs
  STILL diverged intermittently — flaky even at one round (2 fails + 1 pass
  over three back-to-back `fuzz-replay-determinism.sh` runs; symptom: an extra
  `g-$n` group, i.e. an op-7 `create-group` that fired in one run but not the
  other, plus trailing op-target drift). **Mechanism:** the same
  subshell-`$RANDOM` trap as the pickers, one rung up. Each round drew the
  number of "offline" edits per device as `for _ in $(seq 1 $((RANDOM %
  3 + 1)))` — and `$((RANDOM % 3 + 1))` is evaluated *inside* the `$(seq …)`
  command-substitution subshell, which bash reseeds with run-varying entropy.
  So the **count** of mutations per device per round varied run-to-run (an
  extra op → an extra `g-$n` group → cascading op-target drift), and the draw
  didn't even advance the deterministic main-shell stream. Reproduced
  byte-for-byte: a 5-process `bash -c` harness showed the subshell draw
  yielding `x`/`xx`/`xxx` across runs while a main-shell assignment yielded a
  constant. **Fix:** draw the count in the **main shell** first
  (`na=$((RANDOM % 3 + 1)); for _ in $(seq 1 "$na"); …`), a pure function of
  the seeded stream. Within each run both peers always converged (the
  convergence oracle was 30/30 green throughout), so this was purely a
  reproducibility gap, never a convergence bug. **Now solid:**
  `fuzz-replay-determinism.sh` was promoted to a full multi-round, multi-seed
  gate (seeds 42/43/777 × 6 rounds, byte-for-byte) and **re-included in
  `run-all.sh`**; soaked 18/18 across seeds {42,43,777,115,179,7} × rounds
  {1,6,20} and 12/12 at one round, with convergence still 240/240 green over
  the new op stream. The general trap is in `reference_bash_subshell_random`.

- **[FIXED] Finding #10 — a dissolved conflict left a ghost badge
  (`parked_conflict_uuids` reported a conflict `held_conflict_payload`
  considered gone).** Surfaced by the hardened fuzzer (parity oracle;
  intermittent — seeds 777, 115, 179 across sweeps). **Mechanism:**
  `held_conflict_payload` (`reconcile.rs:402`) self-heals — when a
  parked entry's stored peer value no longer conflicts with local it
  `drop_conflict_rows` and skips. So a conflict row that *dissolved*
  (local converged to the stored peer value with no ingest arm clearing
  it) lingered until a resolver-open ran that lazy heal, while the cheap
  badge query (`SELECT DISTINCT entry_uuid FROM conflict_entry`) counted
  it immediately → a phantom badge / dead resolver entry. **Isolated
  deterministically by hand** (the fuzzer catch is non-replayable — see
  below): park a clash, then *locally edit* the entry to match the
  parked peer value (no resolve, no re-ingest) → badge stays, resolver
  says gone (`scenarios/conflict-stale-badge-on-local-edit.sh`; read the
  badge with `list-conflicts` ONLY — `show-conflict` triggers the heal
  and erases the evidence).
  - **First fix attempt was wrong** (caught by the pre-land review): a
    blanket `drop_conflict_rows` in `bump_modified` is owner-AGNOSTIC, so
    a local edit toward peer B also wiped peer C's still-unresolved row
    (multi-peer over-clear; guard: `conflict-multipeer-no-overclear.sh`).
  - **Fix (shipped — dissolve-reconciliation):**
    `reconcile::reconcile_conflict_rows(engine, entry)` restores the
    invariant "a `conflict_entry(owner,E)` row exists iff E is present
    locally AND still genuinely diverges from that owner's stored value":
    E gone → drop all of E's rows (covers Finding #11); else per owner,
    re-run the same merge-check the resolver uses and drop only the
    *dissolved* owners (owner-scoped `drop_conflict_rows_for_owner`),
    leaving still-divergent peers parked. Called at three sites:
    post-edit (every content-mutation `Engine` wrapper), post-delete
    (`delete_entry`/`recycle_entry`), and post-ingest
    (`reconcile_all_conflict_rows` sweep at the tail of `Engine::ingest_peer`,
    catching a sync that dissolves a *different* owner's conflict). The
    badge stays a trivial `SELECT` — reconciliation is on the write side
    and is a cheap "any rows?" no-op for non-conflicted entries; only an
    entry actually in conflict pays the projection + per-owner merge.
  - **e2e-pinned (task #31, the post-ingest site):**
    `scenarios/conflict-postingest-sweep-different-owner.sh` drives the
    different-owner case end-to-end through keyhole — hub parks vs p1/p2/p3,
    then adopts p1's propagated resolution (hub → p1's value), which the
    owner-scoped ingest arm only clears for p1; the sweep must additionally
    dissolve p2 (which held the same value) while keeping the genuinely
    divergent p3. A fourth peer keeps the entry badged throughout, so the
    owner-agnostic badge is blind to whether p2 was swept — the assertion
    needs the new `conflict-owners <vault> <entry>` verb (a pure `SELECT`,
    so reading it doesn't trigger the lazy heal and the eager drop is what's
    proven). Surfaced `keys-engine::Engine::conflict_owners` →
    `keys-ffi::Engine::conflict_owners` (the per-owner companion to
    `entries_with_parked_conflict`). Teeth verified: with the sweep removed
    the scenario goes red (`owners=[p2, p3]`, same badge).
  - **NB the fuzzer catch was never replayable** (the root group +
    recycle-bin uuids are minted in `Vault::create_empty`, *outside* the
    engine's seeded `UuidSource`, so they stay random per run; seeds
    777/115/179 each failed once and passed ≥13× on isolated rerun). The
    fix is validated by the deterministic hand-repros + full suite +
    fuzz soak, not by re-catching it in the fuzzer. Truly replayable
    fuzzing still needs the `Vault::create_empty` ids pinned (keepass-core
    follow-up) — the last non-determinism source.

- **[FIXED] Finding #11 — `delete_entry`/`recycle_entry` orphaned
  `conflict_entry` rows → ghost badge for a deleted entry** (pre-existing;
  surfaced by the Finding #10 review). No FK cascade onto `conflict_entry`,
  so removing an entry left its parked rows behind. Fixed for free by the
  #10 dissolve-reconciliation: "entry gone locally → drop all its rows."
  Proven by `scenarios/conflict-delete-clears-badge.sh`.

- **[FIXED] Finding #12 — attachment classify asymmetry → cross-peer
  conflict-set divergence** (pre-existing; surfaced by the parity oracle
  during the #10/#11 soak, fuzz seed 43, intermittent). An attachment
  divergence (`att-1` RemoteOnly) classified as a CONFLICT from peer A's
  side but was NOT parked on peer B, so the two peers' conflict sets
  differed — one badged it, the other didn't (Bug-D class). It was a
  *genuine live* conflict (`show-conflict` returned a payload), not a
  dissolved ghost, so it sat **outside** the #10/#11 reconcile fix (which
  correctly leaves live conflicts parked). Root cause was in
  `keepass_merge::find_common_ancestor` (the LCA selection that feeds
  `classify`): the pair-selection tiebreak was
  `(min(local,remote) rank, local_mtime, local_rank)` — its `local_*`
  tail flipped under argument swap, so two same-second shared generations
  on opposite sides resolved to different ancestors depending on which
  peer ran `classify` first, and the attachment facet then classified
  asymmetrically. Same family as Finding #8's LCA work, on attachments.
  **Fix** (keepass-core PR #227, keepass-merge): made the key symmetric —
  `(min rank, max rank, matched content hash)`, every component
  order-independent (the pair only scores when the two sides' content
  hashes are equal). mtime dropped from selection entirely (it was only
  ever the now-removed tiebreak); the floored-mtime `KEYS_DEBUG_LCA` dump
  computes it on the fly. Guarded by `lca_is_symmetric_under_argument_swap`
  (asserts the matched content hash, the real selection key, is identical
  under swap) plus the convergence fuzzer. Verified: 480 fuzz rounds
  (12 seeds × 40), including the original seed 43, converge; keepass-merge's
  203 tests pass.

- **[FIXED] Finding #9 — `resolved_at` was stamped from the system
  clock, not the injected engine clock, so under a pinned clock every
  later conflict on a resolved entry was silently suppressed.**
  Surfaced by the hardened convergence fuzzer (`fuzz-convergence.sh`,
  `FUZZ_SEED=99`) once it was made to (a) sync symmetrically — both
  peers ingest before anyone resolves — and (b) pin every stamp via
  `--at`. Symptom: a genuine attachment clash on a previously-resolved
  entry failed to park (silent divergence — each side kept its own
  bytes, no badge), or parked but the resolution never propagated
  (ghost badge on the peer). The single-shot
  `attachment-both-sided-park.sh` passes, so the trigger was the
  *prior resolution*, not attachment handling.
  - **Root cause (via `KEYS_DEBUG_ADOPTION=1`):** `branch=local-holds`
    fired because `local_res` was real-now (`2026-…`) while the pinned
    edits were at the `--at` instant. `apply_conflict_resolution`
    (`conflict_resolution.rs`) stamped the `keys.conflict_resolutions.v1`
    record's `resolved_at` with `chrono::Utc::now()`. The
    resolved-since gate in `ingest_peer` (`edited_after(peer_mtime,
    local_resolved_at)`) then saw every pinned-time edit as *older*
    than the resolution, so `local_resolution_holds` stayed true and
    suppressed the new conflict. A clock-threading miss from the
    controllable-clock slice — the mutation path was threaded, the
    resolution path wasn't.
  - **Fix:** route `resolved_at` through the engine clock —
    `let now = engine.now()` (new `Engine::now() -> DateTime<Utc>`,
    `= self.clock.now()`) instead of `chrono::Utc::now()`.
    **Production (`SystemClock`) is byte-for-byte unchanged**
    (`engine.now()` == `Utc::now()`); only clock-injected test/fuzz
    engines are affected. Proven by
    `scenarios/conflict-resolved-facet-isolation.sh` (the deterministic
    red → green) and the hardened fuzzer (seeds 1 + 99 went red →
    green). Headless analogue of soak Bug D at multi-round scale.

- **[FIXED] DATA LOSS: recycle silently permanent-deleted on any vault
  without a bin group — keys-engine diverged from keepass-core.** Fix
  landed: `keys-engine::recycle_entry` now lazy-creates the bin when the
  flag is enabled (`create_recycle_bin_group`, mirrors keepass-core's
  `find_or_create_recycle_bin`); new Keys vaults default the bin to
  *enabled* (`keys-ffi Vault::create_empty`). Proven by
  `scenarios/recycle-persists.sh` + `scenarios/default-recycle-bin.sh`
  and keys-engine `recycle_entry_enabled_without_bin_lazy_creates…` /
  `…_disabled_without_bin_hard_deletes…`. The Mac/iOS apps inherit it on
  their next FFI rebuild — no Swift change needed. Original diagnosis
  below for the record:
  - `keepass-core::Kdbx::recycle_entry` (the canonical KDBX model,
    `KeepassCore/.../kdbx.rs:1805`) hard-deletes **only when
    `!enabled && uuid.is_none()`**; otherwise it lazy-creates the bin
    (`find_or_create_recycle_bin`, `kdbx.rs:1927`) and soft-recycles.
  - `keys-engine::recycle_entry` (the SQLite mirror the GUI drives,
    `KeysCore/.../mutations.rs:932`) hard-deletes whenever no
    `is_recycle_bin = 1` group exists, **ignores the `enabled` flag, and
    never lazy-creates.** So it contradicts the model layer's deliberate
    semantics.
  - keys-engine only marks a group `is_recycle_bin = 1` from an ingested
    KDBX that already has one. A fresh Keys/keepassxc vault has none →
    **the first "Move to Trash" is a permanent, tombstoned delete** with
    no recoverable copy. Not an edge case: every new vault until a bin
    exists.
  - The Mac app ([`DatabaseManager.moveToRecycleBin`]) calls `recycleEntry`
    directly under a "trash" label, trusting core — so the UI promises
    recoverability it doesn't get.
  - **Fix (preferred):** port keepass-core's logic into keys-engine
    `recycle_entry` — when no bin group exists and the bin is enabled,
    lazy-create the "Recycle Bin" group (icon 43, auto-type/search off,
    mark `is_recycle_bin = 1`, stamp meta) then soft-recycle; hard-delete
    only when genuinely disabled. Fixes every client at once; save-to-kdbx
    must serialise the new group + `RecycleBinUUID` (verify on impl).
  - **Open product decision:** should new *Keys* vaults default the bin to
    *enabled*? If they default disabled, even the fix leaves fresh-vault
    deletes permanent while the UI says "trash" — so either default-enable
    at creation or branch the UI on the flag.

- **[FIXED] restore left the entry IN the bin group.**
  `keys-engine::restore_entry` cleared `is_recycled` but never touched
  `group_uuid`, so a "restored" entry still sat in the Trash for every
  group-scoped view and every other KDBX client. Found by
  `scenarios/restore-leaves-bin.sh` going red on its first run (the
  suspicion was recorded in the backlog when the recycle verbs landed).
  Root cause one layer deeper: the engine's mirror had **no
  `previous_parent_uuid` column at all** — KDBX 4.1's
  `<PreviousParentGroup>` was silently dropped on ingest and stripped
  from every save (a round-trip fidelity bug affecting other clients'
  data, not just restore). Fix: migration 0008 adds the column;
  ingest/projection round-trip it; `recycle_entry` / `move_entry`
  record the source group; `restore_entry` returns the entry to its
  recorded previous parent (root when absent/deleted, matching
  KeePassXC). Proven across reopen incl. the subfolder round-trip.

- **[FIXED] convergence divergence under rapid re-edit around a
  resolution — found by `scenarios/fuzz-convergence.sh`.** Two replicas
  under seeded concurrent entry create/edit/delete + park/resolve/sync
  rounds intermittently ended a round with different content digests,
  or with one side re-parking a conflict whose resolution record it
  should have adopted. **Fix (30/30 soak runs green; fuzzer now a CI
  gate in `run-all.sh`):** every KDBX serialisation of a timestamp is
  second-precision (our encoder writes ISO-8601 `SecondsFormat::Secs`
  for 3.1 *and* 4.x; KDBX4's native base64 form is i64 seconds — so
  the quantisation is version-independent), and the millisecond
  precision existed only in the SQLite mirror. The projection now
  floors times to seconds (`projection::ms_to_dt`) so a projected
  vault equals what a save → load round-trip produces, and
  `resolution_times` floors `resolved_at` to match — making every
  merge/adoption decision a **pure function of disk-serialised
  (synced) bytes** that both peers compute identically. Same-second
  ties resolve deterministically (resolution wins; edit-vs-delete
  ties keep the documented delete-wins rule). Original evidence
  (env `KEYS_DEBUG_ADOPTION=1` instruments
  `keys-engine/src/ingest.rs`):
  - The same edit reads as `…T14:16:23.677Z` from the local mirror
    (millisecond precision) but `…T14:16:23Z` from the peer's KDBX
    (XML times floor to seconds). Every `edited_after` guard in the
    adoption logic mixes the two precisions, so supersession decisions
    wobble by up to a second — same-second races the manual 2-Mac soak
    can never produce, but real sync absolutely can.
  - The "fresh local edit re-opens a resolved conflict" rule (design
    §5.3, correct in isolation) interleaves with that wobble across
    rounds until the replicas silently disagree (digest mismatch with
    no held conflict on either side — the worst outcome class).
  - Repro: `FUZZ_ROUNDS=8 scenarios/fuzz-convergence.sh` fails roughly
    1 run in 2–10; on failure both vaults + mirrors are preserved
    under `$TMPDIR/keyhole-fuzz-failure-*` (replay caveat: mirrors are
    post-failure state — instrument live instead).
  - Likely fix direction: floor mirror-side mtimes to seconds (or
    carry sub-second into the comparison consistently) wherever they
    are compared against KDBX-derived times, and make adoption match
    on the resolved *values* (content hash) rather than time alone.
  - Related (LOW, adversarial-review catch, deferred with 5d):
    cross-peer adoption (`advance_local_entry`) takes the peer's
    `previous_parent_uuid` wholesale while location reconciliation is
    otherwise deferred — fold proper previous-parent merge rules into
    the 5d work.

- **[FIXED] ghost conflict badge: a dissolved held conflict never
  cleared — found by the fuzz soak that validated the Finding #4 fix.**
  When a held conflict's values converged out-of-band (local edited to
  match the peer, or a peer's resolution record synced in),
  `held_conflict_payload` correctly returned `None` ("no conflict
  remains") but left the `conflict_*` owner rows — so
  `entries_with_parked_conflict` re-reported the entry on every read,
  forever: a resolver that opens to nothing and a badge that never
  clears (in the GUI, plausibly kin to the soak's dead-resolver
  sightings). Fix: resolver-open now drops the stale rows for any
  candidate whose rebuilt merge yields no conflict and walks on to the
  next genuinely-held entry, so `None` means "nothing left to
  resolve". Pinned by keys-engine
  `dissolved_held_conflict_clears_badge_at_resolver_open`.

## Usage

```sh
export KEYHOLE_PASSWORD=…          # read from env, never argv/history
keyhole inspect path/to/test.kdbx
keyhole list    path/to/test.kdbx --group <uuid>

# --at pins the engine clock (epoch-ms) for deterministic LWW stamps:
keyhole --at 5000000 rename-group path/to/test.kdbx <uuid> "New Name"
```
