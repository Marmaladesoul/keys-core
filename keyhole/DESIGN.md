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

`Engine::open` injects three platform *ports*:

| Port                  | Mac/iOS adapter            | keyhole adapter (`src/adapters.rs`) |
| --------------------- | -------------------------- | ----------------------------------- |
| `VaultDbKeyProvider`  | Keychain-stored mirror key | fixed 32-byte key                   |
| `VaultFieldProtector` | Secure Enclave session key | fixed 32-byte key                   |
| `VaultFileWatcher`    | NSFilePresenter            | `None` (keyhole drives state)       |

keyhole is just *another platform*. Its adapters are deliberately boring
and deterministic — that's a **fuzzing feature** (controllable clock /
file-events / inputs), not a shortcut. They protect only keyhole's
local mirror; they are unrelated to the KDBX master password,
which flows through `ingest_from_kdbx` / `save_to_kdbx`.

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
- **Done (2026-06-13, 5d group move / re-parent LWW):** a group
  re-parent now reconciles by LWW on a DEDICATED group
  `location_changed` (migration 0011, the group twin of 0010 for
  entries) — separate from metadata's `modified_at` so a concurrent
  rename and move don't clobber each other. `reconcile_peer_groups`
  became two-pass (adopt all peer-only groups, then reconcile
  metadata + parent) so a winning parent always resolves locally.
  `reconcile_group_location` adopts the peer's parent + stamp verbatim
  when it wins `(floored location_changed, parent uuid)`, with a
  **cycle guard** that skips any re-parent which would put a group
  inside its own subtree — the tree can never go cyclic. New keyhole
  verb `move-group`; pinned by
  [group-move-lww.sh](scenarios/group-move-lww.sh) (one-sided +
  acyclic both-sided LWW) + keys-engine
  `two_engine_group_move_reconciles_and_converges`. **Not yet in the
  fuzzer:** the rare concurrent *mutual* move (A→under B while B→under
  A) leaves the two replicas disagreeing on that one edge (the guard
  skips both sides) until a deterministic cycle-breaking pass lands —
  that pass + fuzzer group-move are the final-final 5d item.
- **Next:** icon pool union (the last 5c sliver); then the last 5d
  pieces — consuming group tombstones (recorded since 5b, never
  consumed) for cross-peer group deletion, plus deterministic
  cycle-breaking for mutual group moves (then group move/delete join
  the fuzzer); the deferred previous-parent merge rules. `empty-bin`
  verb; value-hash-based adoption matching (timestamp-free) as
  hardening when resolution records grow fields.
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
```
