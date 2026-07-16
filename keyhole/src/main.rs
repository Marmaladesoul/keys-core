//! keyhole — a headless test-driver for Keys.
//!
//! It is NOT a general-purpose KDBX client. It exists to drive the
//! exact `keys-ffi` surface the GUI apps drive, so automated tests can
//! prove app-level behaviour one rung below the real client. See
//! DESIGN.md for the architecture and the migration workflow.
//!
//! The `SQLCipher` mirror is *persistent*, keyed to the vault path
//! (`<vault>.mirror/`), exactly like a real client's local store. That
//! is what lets conflict state parked by one keyhole invocation be
//! read and resolved by a later one — the multi-invocation honesty the
//! sync scenarios depend on. Open follows the real unlock flow: fresh
//! mirror → ingest; warm mirror + unchanged KDBX (by `(mtime, size)`
//! signature) → skip ingest; warm mirror + changed KDBX → park-conflicts
//! reconcile, the disk-watcher path.
//!
//! Verbs: vault/entry CRUD (`create`, `create-entry`, `update-entry`,
//! `recycle`, `ensure-bin`), inspection (`inspect`, `list`), and the
//! sync-conflict loop (`ingest-peer`, `list-conflicts`, `show-conflict`,
//! `resolve`). Diagnostics go to stderr; verb results go to stdout so
//! scenario scripts can parse them.

mod adapters;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keys_ffi::{
    AttachmentChoiceFfi, AttachmentChoiceKindFfi, ConflictPayloadFfi, ConflictSideFfi,
    DeleteEditChoiceEntryFfi, DeleteEditChoiceFfi, Engine, EngineEntryUpdate,
    EntryAttachmentChoiceFfi, EntryFieldChoiceFfi, EntryIconChoiceFfi, FieldChoiceFfi, IconRef,
    NewEntryFields, Page, ParkConflictsResultFfi, RecycleBinFilter, ResolutionFfi, SearchScope,
    SyncWithDiskFfi, VaultIdentityVerdict, create_vault as ffi_create_vault,
    create_vault_deterministic as ffi_create_vault_deterministic, open_vault_self_healing,
    purge_vault_local_data, rebuild_vault_local_data, verify_vault_identity,
};

use adapters::{FixedDbKey, FixedProtector, RecordingDbKey};

#[derive(Parser)]
#[command(
    name = "keyhole",
    about = "Headless test-driver for Keys — drives keys-ffi minus the UI",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Environment variable holding the KDBX master password. Kept off
    /// argv (and shell history) on purpose.
    #[arg(long, default_value = "KEYHOLE_PASSWORD", global = true)]
    password_env: String,

    /// Path to the vault's keyfile — the raw keyfile *file content* (32-byte
    /// binary, 64-char hex, or an XML `.keyx`). Supplied alongside the
    /// password to open / save / rekey a keyfile-keyed vault. On `create`, a
    /// fresh `.keyx` is minted at this path if it does not yet exist. Unlike
    /// the password this rides argv on purpose — a keyfile is a path/file, not
    /// a secret string (its secrecy comes from where it is stored).
    #[arg(long, global = true)]
    keyfile: Option<PathBuf>,

    /// Pin the engine clock to this instant (epoch-milliseconds) for the
    /// duration of the command. Every mutation then stamps exactly this
    /// time on `modified_at` / `location_changed_at` / tombstones —
    /// making the timestamps that drive sync LWW deterministic, so
    /// scenarios can force a same-second tie or pin an exact winner
    /// without `sleep`ing between processes. Omit for the system clock
    /// (production behaviour).
    #[arg(long = "at", global = true)]
    clock_ms: Option<i64>,

    /// Make entity ids deterministic: new entries / groups draw from a
    /// seeded UUID source rooted at this value instead of random v4. The
    /// last piece (with `--at`) that makes a run byte-reproducible, so a
    /// fuzz failure replays instead of merely preserving artefacts. Use
    /// a DISTINCT seed per device — two devices sharing a seed would
    /// mint the same id for different entities. Requires `--at`. Honoured
    /// by `create` too: the root group (`from_u64_pair(seed, 0)`) and the
    /// eager recycle bin (`from_u64_pair(seed, 1)`) are drawn from a
    /// keepass-core seeded source, so the whole vault — create included —
    /// is replayable.
    #[arg(long = "uuid-seed", global = true)]
    uuid_seed: Option<u64>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a fresh, empty test vault. Drives the same
    /// `keys_ffi::create_vault` the GUI apps use — so new-vault policy
    /// (e.g. recycle bin enabled by default) is exercised here too.
    Create {
        /// Path to the .kdbx vault to create (must not already exist).
        vault: PathBuf,
    },
    /// Create an entry (then persist to the KDBX). Lets scenarios seed a
    /// vault end-to-end through keyhole itself — no external tooling.
    CreateEntry {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title.
        title: String,
        /// Entry username.
        #[arg(long, default_value = "")]
        username: String,
        /// Entry password (test data — distinct from the vault master password).
        #[arg(long, default_value = "")]
        entry_password: String,
        /// Parent group UUID. Defaults to the vault root.
        #[arg(long)]
        group: Option<String>,
    },
    /// Update fields on an existing entry (patch semantics — only the
    /// flags you pass change), then persist. The divergence-maker for
    /// conflict scenarios: edit the same entry differently in a vault
    /// and a copy of it, then `ingest-peer` one into the other.
    UpdateEntry {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to update (see `list`).
        uuid: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        username: Option<String>,
        /// New entry password (test data).
        #[arg(long)]
        entry_password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Ensure the recycle bin group exists (create it if the bin is enabled
    /// but absent), then persist. Mirrors the hook the GUI should call when a
    /// vault is first added, so an enabled-but-binless vault never lingers.
    EnsureBin {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Enable or disable the vault's recycle bin, then persist — the
    /// behaviour behind the Vault Info toggle. Enabling auto-creates a
    /// bin group when none exists (no group picker). Disabling keeps
    /// the old bin group as an ordinary group by default; afterwards,
    /// recycling is a PERMANENT tombstoned delete (engine policy).
    SetBin {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// `on` or `off`.
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// With `off`: permanently delete the old bin group and all
        /// its contents (tombstoned, propagates to peers).
        #[arg(long)]
        delete_bin_contents: bool,
    },
    /// Permanently purge the recycle bin's contents — hard-delete every
    /// entry and subgroup sitting in the bin (each tombstoned, so the
    /// purge propagates to peers), keeping the bin group itself, then
    /// persist. Composes the existing permanent-delete path; no new sync
    /// policy. A no-op on a vault with no bin group.
    EmptyBin {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Destroy a vault's LOCAL-device data: the persistent `SQLCipher`
    /// mirror sidecar (the on-disk encrypted local copy) plus its
    /// `SQLCipher` DB key. The teardown a client drives when a vault is
    /// *removed* from the device. The source KDBX file is NOT touched —
    /// purge is local-only (removing a vault from a device is not the
    /// same as deleting the vault). Drives the engine-owned
    /// `purge_vault_local_data`, which deletes the sidecar files it owns
    /// the layout of (DB + `-wal`/`-shm`/`-journal`) and calls the key
    /// provider's `deleteDbKey`.
    Purge {
        /// Path to the .kdbx vault whose local mirror to destroy.
        vault: PathBuf,
    },
    /// Discard a vault's stale local mirror sidecar and rebuild it from
    /// the canonical KDBX, KEEPING the mirror's DB key. The recovery a
    /// client drives when the sidecar's cached *session* key has been
    /// rotated out and protected reads fail (the post-open arm of the
    /// self-heal; the open-time arm runs automatically inside every
    /// open). Drives the engine-owned `rebuild_vault_local_data`. Unlike
    /// `purge`, the DB key is preserved — the rebuilt sidecar is sealed
    /// under it.
    Rebuild {
        /// Path to the .kdbx vault whose local mirror to rebuild.
        vault: PathBuf,
    },
    /// Open a vault and print its high-level state (counts, recycle
    /// bin, group tree size). The cheapest end-to-end smoke test.
    Inspect {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Print the count of entries outside the recycle bin (the "live"
    /// count a client shows on a vault tile / "All Items"), one integer
    /// on stdout. The engine-owned `entry_count_excluding_recycle_bin`.
    LiveCount {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// List entry summaries, optionally scoped to a group UUID.
    List {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Only list entries directly inside this group UUID.
        #[arg(long)]
        group: Option<String>,
    },
    /// Full-text search over entry fields (title / username / url /
    /// notes / tags; tokens AND, fields OR), with an EXPLICIT
    /// recycle-bin filter — the seam contract: bin inclusion is the
    /// caller's choice (a "Deleted items" view searches *inside* the
    /// bin), never an implicit policy. Membership is by bin-subtree
    /// ancestry, so an entry buried in a just-recycled group filters
    /// correctly even before a re-ingest re-derives its `is_recycled`
    /// flag.
    Search {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Query string.
        query: String,
        /// Recycle-bin filter: `exclude` (live entries only), `only`
        /// (inside the bin only), or `include` (no filtering).
        #[arg(long, default_value = "exclude", value_parser = ["exclude", "only", "include"])]
        bin: String,
    },
    /// AutoFill-style service lookup (`search_by_service` on the seam):
    /// match entries against a service identifier — a bare host, a full
    /// URL, or anything in between — via the engine's tiered host
    /// matching. Recycle-bin entries are excluded by subtree
    /// membership, same as `search --bin exclude`; with the bin
    /// disabled every entry is live.
    Service {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Service identifier — bare host (`example.com`) or full URL.
        identifier: String,
    },
    /// Recycle (soft-delete) an entry, then persist to the KDBX.
    ///
    /// The save is the whole point: a recycle that isn't written back
    /// to disk is the exact "delete didn't save" bug class this verb
    /// exists to pin down. `--no-save` deliberately skips the persist
    /// so a regression test can prove it has teeth.
    Recycle {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to recycle (see `list`).
        uuid: String,
        /// Mutate the in-memory mirror but do NOT write back to disk.
        #[arg(long)]
        no_save: bool,
    },
    /// Print the engine-owned persistence watermark: `mutation_seq`,
    /// `persisted_seq`, and `dirty` (= the KDBX still owes a write).
    /// The truth lives in the persistent mirror, so a mutation left
    /// unsaved by an earlier invocation (or a crash) reads back dirty
    /// here — the crash-recovery signal a save orchestrator flushes on.
    PersistenceState {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Write the mirror back to the KDBX iff the engine says a write
    /// is owed (`dirty`), else do nothing. Prints `flushed` or `clean`
    /// — machine-greppable. This is the save-orchestrator primitive:
    /// clients call this on lifecycle edges instead of deciding
    /// per-call-site whether a save is due.
    Flush {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Ingest a peer's KDBX into this vault's mirror under a device
    /// owner id — the per-device-key sync transport path. Divergences
    /// park as held conflicts in the persistent mirror (never a modal);
    /// the merged result is saved back to the vault. The peer file must
    /// decrypt under the same factors as this vault — the master password
    /// plus the global `--keyfile` when the vault is keyfile-keyed.
    IngestPeer {
        /// Path to the .kdbx vault receiving the merge.
        vault: PathBuf,
        /// Path to the peer's .kdbx (e.g. a diverged copy).
        peer_kdbx: PathBuf,
        /// Owner id the peer's rows land under (its device id in real sync).
        #[arg(long, default_value = "keyhole-peer")]
        owner: String,
    },
    /// List UUIDs of entries currently held in an unresolved sync
    /// conflict — the headless twin of the GUI's conflict badge. Read
    /// from the persistent mirror, so it sees conflicts parked by
    /// earlier invocations.
    ListConflicts {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Show the rich conflict payload for a held entry: both sides'
    /// title/username plus per-field/attachment/icon deltas. Field
    /// *values* beyond title/username are never printed.
    ShowConflict {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Scope to one held entry UUID. Defaults to the first held entry.
        #[arg(long)]
        entry: Option<String>,
    },
    /// Print the distinct peer owner ids that still hold a parked conflict
    /// row for one entry — one per line, sorted, machine-greppable. The
    /// per-owner companion to `list-conflicts` (which only says *whether* an
    /// entry is badged): this says *which peers* it still diverges from, so a
    /// test can prove the post-ingest dissolve sweep dropped exactly the
    /// converged owner's row while leaving a still-divergent peer parked.
    /// Reads the persistent mirror (owner rows survive across processes).
    ConflictOwners {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry whose conflict owners to list.
        entry: String,
    },
    /// Add a custom-icon blob to the vault's pool and link it to `entry`,
    /// then persist. `data` is the raw icon bytes (any bytes — the pool
    /// stores blobs verbatim, content-addressed; no PNG validation). Prints
    /// the icon's content-addressed UUID, which is a pure function of the
    /// bytes (so two devices that add the same icon mint the same UUID — see
    /// `add_custom_icon_dedup`). Drives the 5c custom-icon-pool surface.
    AddCustomIcon {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to link the icon to.
        entry: String,
        /// Raw icon bytes (their UTF-8 encoding) — deterministic per string.
        data: String,
    },
    /// Print whether a custom-icon UUID's bytes are present in the vault's
    /// pool: `present <len>` or `(none)`. The honest "did the icon's BYTES
    /// arrive?" check (the convergence digest covers an entry's icon *ref*
    /// but not the pool bytes, so a dangling ref it can't see). Reads the
    /// persistent mirror.
    CustomIconBytes {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Content-addressed UUID of the custom icon (see `add-custom-icon`).
        icon: String,
    },
    /// Set a non-protected custom (string) field on an entry, then persist —
    /// the `entry_custom_field` surface that clients show as extra
    /// attributes. Lets scenarios cover custom-field save-fidelity and
    /// cross-peer convergence (a facet `create-entry` can't author).
    SetField {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to set the field on.
        entry: String,
        /// Custom field name (the attribute key).
        name: String,
        /// Custom field value.
        value: String,
    },
    /// Replace an entry's tag set, then persist. Tags reconcile cross-peer by
    /// 3-way SET semantics (union of adds, removals relative to the LCA win) —
    /// distinct from per-field LWW — so this lets scenarios + the fuzzer
    /// exercise tag convergence (a facet `create-entry`/`update-entry` can't
    /// author; they hardcode an empty tag set).
    SetTags {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to set tags on.
        entry: String,
        /// Comma-separated tag set (replace-all); empty string clears tags.
        tags: String,
    },
    /// Print an entry's tags, one per line, sorted — the read side for tag
    /// convergence assertions. `(no tags)` when the set is empty.
    Tags {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry whose tags to print.
        entry: String,
    },
    /// Print an entry's history snapshots — one line per snapshot
    /// (`<index>  <username>`), newest-index last, then a count. The read
    /// oracle for history convergence: the content digest deliberately
    /// EXCLUDES history (replicas can legitimately differ in depth), so a
    /// history scenario must compare the snapshots directly, not the digest.
    History {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry whose history to print.
        entry: String,
    },
    /// Delete one history snapshot by index, then persist — the user
    /// "remove this old version" action (e.g. scrubbing a leaked password
    /// from history). For the deletion to PROPAGATE cross-peer it must write
    /// a history tombstone, or the lossless history merge resurrects it from
    /// the peer; this verb drives exactly that path.
    DeleteHistory {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry.
        entry: String,
        /// Zero-based history index to delete (see `history`).
        index: u32,
    },
    /// Set the vault-wide history retention cap (`<HistoryMaxItems>`), then
    /// persist. A negative value means unlimited (the upstream convention). When a
    /// subsequent edit pushes an entry's history past this cap the oldest
    /// snapshots are trimmed — and on the Engine path that trim must leave a
    /// `quota_trim` history tombstone, or a peer still holding the trimmed
    /// snapshot resurrects it on the next sync; this verb arms exactly that
    /// path for a scenario.
    SetHistoryMax {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Max number of history snapshots to retain per entry
        /// (`<HistoryMaxItems>`); negative = unlimited.
        items: i32,
    },
    /// Print the hex SHA-256 digest of the vault's user-visible
    /// content (fields, locations, icons, group tree, recycle-bin
    /// state). Equal digests ⇔ converged replicas — the convergence
    /// oracle the fuzz harness asserts with. Compare only digests from
    /// the same build; never persist them.
    Digest {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Create a group, then persist.
    CreateGroup {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Group name.
        name: String,
        /// Parent group UUID. Defaults to the vault root.
        #[arg(long)]
        parent: Option<String>,
    },
    /// Rename a group (its `name` metadata), then persist. The
    /// divergence-maker for 5d group metadata LWW.
    RenameGroup {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the group to rename (see `list-groups`).
        uuid: String,
        /// New group name.
        name: String,
    },
    /// Delete a group (cascading its entries + subgroups, recording
    /// `<DeletedObjects>` tombstones), then persist. The divergence-maker
    /// for 5d cross-peer group deletion.
    DeleteGroup {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the group to delete (see `list-groups`).
        uuid: String,
    },
    /// Re-parent a group under another group, then persist. The
    /// divergence-maker for 5d group move (re-parent LWW).
    MoveGroup {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the group to move (see `list-groups`).
        uuid: String,
        /// Destination parent group UUID.
        #[arg(long)]
        to: String,
    },
    /// List every group: UUID, name, and direct entry count, one per
    /// line (the group-side twin of `list`).
    ListGroups {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Print every group UUID in the subtree rooted at `uuid` (root
    /// included), one per line, then a count. Ancestry-derived, so it
    /// reflects a warm group recycle before the `is_recycled` flag does.
    GroupsInSubtree {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the subtree root group (see `list-groups`).
        uuid: String,
    },
    /// Print every entry UUID anywhere in the subtree rooted at `uuid`
    /// (root group included), one per line, then a count.
    EntriesInSubtree {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the subtree root group (see `list-groups`).
        uuid: String,
    },
    /// Move an entry to another group, then persist.
    MoveEntry {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to move (see `list`).
        uuid: String,
        /// Destination group UUID (see `list-groups`).
        #[arg(long)]
        to: String,
    },
    /// Restore a recycled entry out of the bin, then persist.
    Restore {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to restore (see `list`).
        uuid: String,
    },
    /// Permanently delete an entry (recording a tombstone so the
    /// removal propagates to peers instead of zombie-resurrecting),
    /// then persist.
    DeleteEntry {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry to delete (see `list`).
        uuid: String,
    },
    /// Add or replace an attachment on an entry (content-addressed
    /// blob pool + per-entry link), then persist.
    SetAttachment {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry (see `list`).
        uuid: String,
        /// Attachment name (replaces an existing attachment of the
        /// same name).
        name: String,
        /// Attachment content as a literal string (test data).
        #[arg(long)]
        text: String,
    },
    /// Print an attachment's bytes to stdout (raw — pipe or compare;
    /// test data only, like everything keyhole touches).
    CatAttachment {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry (see `list`).
        uuid: String,
        /// Attachment name.
        name: String,
    },
    /// Remove an attachment by name (the pool blob stays — GC is a
    /// separate concern), then persist.
    RemoveAttachment {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the entry (see `list`).
        uuid: String,
        /// Attachment name.
        name: String,
    },
    /// Resolve a held conflict by choosing one side for every delta
    /// (fields, attachments, icon, delete-vs-edit), then persist.
    Resolve {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// UUID of the held entry to resolve (see `list-conflicts`).
        #[arg(long)]
        entry: String,
        /// Default side for every delta: this vault (`local`) or the
        /// ingested peer (`remote`).
        #[arg(long, value_parser = ["local", "remote"])]
        choose: String,
        /// Per-field override: `--field UserName=remote` (repeatable).
        /// Fields not named fall back to `--choose`. Keys are the
        /// KDBX field names shown by `show-conflict`.
        #[arg(long = "field", value_name = "KEY=SIDE")]
        field: Vec<String>,
    },
    /// Re-key the vault: rotate its master key material and re-encrypt
    /// the KDBX so the OLD password no longer opens it and the NEW one
    /// does, contents preserved. The engine half of the
    /// revoke / lost-device / share-revoke primitive.
    ///
    /// Reads the CURRENT master password from `$KEYHOLE_PASSWORD` (like
    /// every verb) and the NEW one from `$KEYHOLE_NEW_PASSWORD` — both
    /// kept off argv. The on-disk envelope is opened under the current
    /// password FIRST, so a wrong current password fails closed: it can
    /// never rotate the vault to the wrong key.
    Rekey {
        /// Path to the .kdbx vault to re-key.
        vault: PathBuf,
        /// Environment variable holding the NEW master password. Kept
        /// off argv (and shell history) on purpose, like the current
        /// password.
        #[arg(long, default_value = "KEYHOLE_NEW_PASSWORD")]
        new_password_env: String,

        /// Path to the NEW keyfile to rotate to (the rotation target). Minted
        /// as a fresh `.keyx` if the path does not yet exist. Omit to rotate
        /// to a password-only vault — removing any keyfile requirement, the
        /// deliberate authenticated downgrade (you must still open under the
        /// CURRENT `--keyfile` to do it).
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
    },
    /// Print the vault's stable identity — its root-group UUID (the
    /// parentless node of the group tree), read from the engine over the
    /// mirror. The root-group UUID is minted once at create and preserved
    /// across every save / re-key / sync, so it is what answers "are these
    /// two files the same vault?".
    ///
    /// This is the EXPECTED side of an identity check: a client recovering a
    /// vault whose KDBX went missing reads this from the vault's own engine /
    /// `SQLite` sidecar (no master password needed), then compares it against a
    /// user-picked file's identity via `verify-identity`.
    RootUuid {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },
    /// Verify a user-picked KDBX file against an expected vault identity —
    /// the headless twin of a client's "Locate…" recovery guard that must
    /// refuse to re-anchor a vault to the WRONG file.
    ///
    /// Decrypts `picked` with `$KEYHOLE_PASSWORD` (+ the global `--keyfile`)
    /// and compares its root-group UUID to `--expect` (see `root-uuid`),
    /// printing the verdict to stdout and setting the exit code so a consumer
    /// can key a relink decision off EITHER:
    ///
    /// - `match`          → exit 0   — the same vault; proceed.
    /// - `mismatch`       → exit 1   — decrypts but a DIFFERENT vault; reject.
    /// - `undecryptable`  → exit 1   — won't open under the supplied
    ///   credential. AMBIGUOUS (wrong file, corrupt, or the genuine vault
    ///   re-keyed since this credential was cached), NOT a "different vault"
    ///   verdict — a real consumer re-derives / re-prompts before rejecting.
    ///
    /// Only `match` exits 0. A missing / non-KDBX file errors (exit 1, message
    /// on stderr). This is a pure read: no mirror is created or touched.
    VerifyIdentity {
        /// Path to the user-picked .kdbx whose identity to check.
        picked: PathBuf,
        /// The expected root-group UUID (e.g. from `root-uuid`).
        #[arg(long)]
        expect: String,
    },
}

// Flat verb dispatch: one match arm per CLI verb, growing linearly
// with the verb list. Splitting it would add indirection, not clarity.
/// Restore the default `SIGPIPE` disposition (`SIG_DFL`) on unix.
///
/// Rust sets `SIGPIPE` to `SIG_IGN` at startup, so writing to a closed
/// stdout (a reader that exits early — `head -1`, `grep -q`,
/// `awk '...; exit'`) surfaces as an `EPIPE` io error that `println!`
/// then panics on ("failed printing to stdout: Broken pipe"). keyhole's
/// machine-greppable output is consumed by exactly those early-exit
/// readers in the scenario scripts, so a default unix tool's behaviour —
/// die quietly on `SIGPIPE` — is what we want. Without this the panic
/// fails the pipeline under `set -o pipefail` and flakes CI on a race
/// that has nothing to do with the behaviour under test (the EPIPE class
/// the scenario-side grep hardening only partly addressed).
#[cfg(unix)]
#[allow(unsafe_code)] // single libc::signal call; justified below
fn restore_default_sigpipe() {
    // SAFETY: `signal(2)` with `SIG_DFL` is async-signal-safe and we call
    // it once at the very top of `main`, before any threads spawn or any
    // output is written.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(unix)]
    restore_default_sigpipe();

    let cli = Cli::parse();
    let password = read_password(&cli.password_env)?;
    let clock_ms = cli.clock_ms;
    let uuid_seed = cli.uuid_seed;
    // `--keyfile` is global. `create` mints one at the path if absent (handled
    // in its own arm); every other (Session-opening) verb loads the bytes here
    // — tolerant of an as-yet-unminted path so the same flag works for both.
    let keyfile_path = cli.keyfile.clone();
    let keyfile: Option<Vec<u8>> = match keyfile_path.as_deref() {
        Some(p) if p.exists() => {
            Some(std::fs::read(p).with_context(|| format!("read keyfile {}", p.display()))?)
        }
        _ => None,
    };

    match cli.command {
        Command::Create { vault } => {
            create_vault(
                &vault,
                &password,
                clock_ms,
                uuid_seed,
                keyfile_path.as_deref(),
            )
            .await?;
        }
        Command::CreateEntry {
            vault,
            title,
            username,
            entry_password,
            group,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.create_entry(title, username, entry_password, group)?;
            session.finish().await?;
        }
        Command::UpdateEntry {
            vault,
            uuid,
            title,
            username,
            entry_password,
            url,
            notes,
        } => {
            anyhow::ensure!(
                title.is_some()
                    || username.is_some()
                    || entry_password.is_some()
                    || url.is_some()
                    || notes.is_some(),
                "nothing to update — pass at least one of --title/--username/--entry-password/--url/--notes"
            );
            let update = EngineEntryUpdate {
                title,
                username,
                url,
                notes,
                password: entry_password,
                icon: None,
                expires_at: None,
            };
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.update_entry(&uuid, update)?;
            session.finish().await?;
        }
        Command::EnsureBin { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.ensure_bin()?;
            session.finish().await?;
        }
        Command::SetBin {
            vault,
            state,
            delete_bin_contents,
        } => {
            anyhow::ensure!(
                !(state == "on" && delete_bin_contents),
                "--delete-bin-contents only applies with `off`"
            );
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_bin(state == "on", delete_bin_contents)?;
            session.finish().await?;
        }
        Command::EmptyBin { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.empty_bin()?;
            session.finish().await?;
        }
        Command::Purge { vault } => {
            // Teardown, not a Session op: purge is path-based (no engine
            // opened), so it deliberately skips Session's ingest/reconcile
            // dance — we're erasing the mirror, not reading it.
            purge_vault(&vault)?;
        }
        Command::Rebuild { vault } => {
            // Recovery, not a Session op: rebuild is path-based (it drives
            // the engine-owned discard + re-ingest), re-gating on the
            // password via the KDBX unlock, so it skips Session's own
            // ingest/reconcile dance.
            rebuild_vault(&vault, &password, keyfile.clone()).await?;
        }
        Command::Inspect { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.inspect()?;
            session.finish().await?;
        }
        Command::LiveCount { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.live_count()?;
            session.finish().await?;
        }
        Command::List { vault, group } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list(group)?;
            session.finish().await?;
        }
        Command::Search { vault, query, bin } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.search(&query, &bin)?;
            session.finish().await?;
        }
        Command::Service { vault, identifier } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.service(&identifier)?;
            session.finish().await?;
        }
        Command::Recycle {
            vault,
            uuid,
            no_save,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.recycle(&uuid, !no_save)?;
            if !no_save {
                session.finish().await?;
            }
        }
        Command::PersistenceState { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.persistence_state()?;
        }
        Command::Flush { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.flush().await?;
        }
        Command::IngestPeer {
            vault,
            peer_kdbx,
            owner,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.ingest_peer(owner, &peer_kdbx).await?;
            session.finish().await?;
        }
        Command::ListConflicts { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list_conflicts()?;
            session.finish().await?;
        }
        Command::ShowConflict { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.show_conflict(entry).await?;
            session.finish().await?;
        }
        Command::ConflictOwners { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.conflict_owners(entry)?;
            session.finish().await?;
        }
        Command::AddCustomIcon { vault, entry, data } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.add_custom_icon(entry, data)?;
            session.finish().await?;
        }
        Command::CustomIconBytes { vault, icon } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.custom_icon_bytes(icon)?;
            session.finish().await?;
        }
        Command::SetField {
            vault,
            entry,
            name,
            value,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_field(entry, &name, value)?;
            session.finish().await?;
        }
        Command::SetTags { vault, entry, tags } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_tags(entry, &tags)?;
            session.finish().await?;
        }
        Command::Tags { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.tags(entry)?;
            session.finish().await?;
        }
        Command::History { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.history(entry)?;
            session.finish().await?;
        }
        Command::DeleteHistory {
            vault,
            entry,
            index,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_history(entry, index)?;
            session.finish().await?;
        }
        Command::SetHistoryMax { vault, items } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_history_max(items)?;
            session.finish().await?;
        }
        Command::Digest { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.digest()?;
            session.finish().await?;
        }
        Command::CreateGroup {
            vault,
            name,
            parent,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.create_group(name, parent)?;
            session.finish().await?;
        }
        Command::RenameGroup { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.rename_group(&uuid, &name)?;
            session.finish().await?;
        }
        Command::MoveGroup { vault, uuid, to } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.move_group(&uuid, &to)?;
            session.finish().await?;
        }
        Command::DeleteGroup { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_group(&uuid)?;
            session.finish().await?;
        }
        Command::ListGroups { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list_groups()?;
            session.finish().await?;
        }
        Command::GroupsInSubtree { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.groups_in_subtree(&uuid)?;
            session.finish().await?;
        }
        Command::EntriesInSubtree { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.entries_in_subtree(&uuid)?;
            session.finish().await?;
        }
        Command::MoveEntry { vault, uuid, to } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.move_entry(&uuid, &to)?;
            session.finish().await?;
        }
        Command::Restore { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.restore(&uuid)?;
            session.finish().await?;
        }
        Command::DeleteEntry { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_entry(&uuid)?;
            session.finish().await?;
        }
        Command::SetAttachment {
            vault,
            uuid,
            name,
            text,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_attachment(&uuid, &name, text.into_bytes())?;
            session.finish().await?;
        }
        Command::CatAttachment { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.cat_attachment(uuid, name)?;
            session.finish().await?;
        }
        Command::RemoveAttachment { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.remove_attachment(&uuid, &name)?;
            session.finish().await?;
        }
        Command::Resolve {
            vault,
            entry,
            choose,
            field,
        } => {
            let side = parse_side(&choose)?;
            let overrides = field
                .iter()
                .map(|spec| {
                    let (key, side_str) = spec
                        .split_once('=')
                        .ok_or_else(|| anyhow::anyhow!("--field wants KEY=SIDE, got {spec:?}"))?;
                    Ok((key.to_owned(), parse_side(side_str)?))
                })
                .collect::<Result<Vec<(String, ConflictSideFfi)>>>()?;
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.resolve(entry, side, &overrides).await?;
            session.finish().await?;
        }
        Command::Rekey {
            vault,
            new_password_env,
            new_keyfile,
        } => {
            // The new master password is sensitive, so it rides an env
            // var (like the current one) rather than argv.
            let new_password = read_password(&new_password_env)?;
            // The rotation-target keyfile, if any — minted at its path if it
            // doesn't exist yet (keyhole stands in for a client minting one).
            // Omitted → rotate to a password-only vault (drop the keyfile).
            let new_keyfile = match new_keyfile.as_deref() {
                Some(p) => Some(ensure_keyfile(p)?),
                None => None,
            };
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.rekey(new_password, new_keyfile).await?;
            session.finish().await?;
        }
        Command::RootUuid { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            println!("{}", session.root_uuid()?);
            session.finish().await?;
        }
        Command::VerifyIdentity { picked, expect } => {
            verify_identity(&picked, &expect, &password, keyfile.clone())?;
        }
    }
    Ok(())
}

/// An opened vault: the engine over the vault's *persistent* mirror
/// (`<vault>.mirror/`). The mirror outlives the process — that is what
/// carries held-conflict state between invocations. keyhole only ever
/// drives throwaway test vaults, so the mirror is cleaned up by the
/// scenario's temp-dir teardown, not by us.
struct Session {
    engine: Arc<Engine>,
    /// Kept so mutating verbs can `save_to_kdbx` back to the source.
    vault_path: PathBuf,
    password: String,
    /// The vault's keyfile bytes, if it is keyfile-keyed. Threaded into every
    /// open / save / rekey so a keyfile-keyed vault stays openable and is never
    /// silently re-saved as password-only. `None` for a plain password vault.
    keyfile: Option<Vec<u8>>,
}

impl Session {
    /// Open the engine over the vault's persistent mirror, then bring
    /// the mirror current the way a real client does on unlock:
    ///
    /// - no recorded signature → fresh mirror → `ingest_from_kdbx`;
    /// - signature matches the on-disk `(mtime_ms, size)` → mirror is
    ///   current → skip ingest (held conflicts and all other mirror
    ///   state carry over untouched);
    /// - signature differs → the KDBX changed under us →
    ///   `reconcile_with_disk_park_conflicts` (the disk-watcher path:
    ///   merges, parks divergences, never blocks).
    async fn open(
        vault: &Path,
        password: &str,
        clock_ms: Option<i64>,
        uuid_seed: Option<u64>,
        keyfile: Option<Vec<u8>>,
    ) -> Result<Self> {
        anyhow::ensure!(vault.exists(), "vault not found: {}", vault.display());

        let mirror_dir = mirror_dir_for(vault);
        std::fs::create_dir_all(&mirror_dir)
            .with_context(|| format!("create mirror dir {}", mirror_dir.display()))?;
        let mirror_db = mirror_db_for(vault);

        // `--at` pins the engine clock and `--uuid-seed` pins entity ids,
        // so the LWW stamps and ids a mutation writes are deterministic;
        // without them we use the system clock + random v4 (production
        // behaviour). The mirror path / key / protector wiring is
        // identical across all three. `--uuid-seed` needs a pinned clock
        // to be meaningfully reproducible, so it requires `--at`.
        let db_path = mirror_db.to_string_lossy().into_owned();
        let engine = match (clock_ms, uuid_seed) {
            (Some(ms), Some(seed)) => Engine::open_deterministic(
                db_path,
                Arc::new(FixedDbKey),
                Arc::new(FixedProtector),
                None,
                ms,
                seed,
            )
            .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?,
            (Some(ms), None) => Engine::open_with_fixed_clock(
                db_path,
                Arc::new(FixedDbKey),
                Arc::new(FixedProtector),
                None,
                ms,
            )
            .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?,
            (None, Some(_)) => {
                anyhow::bail!("--uuid-seed requires --at (a pinned clock) to be reproducible");
            }
            // Production-shaped open (system clock, random ids): drive the
            // self-healing path the GUI clients drive. A sidecar whose
            // cached key no longer decrypts it (a wiped / rotated mirror
            // key) is discarded and rebuilt from the KDBX rather than
            // blocking the unlock. Only this path can meet a real keystore;
            // the deterministic clock/uuid paths above always mint a fresh
            // mirror under the fixed key, so they never hit the heal.
            (None, None) => {
                let outcome = open_vault_self_healing(
                    db_path,
                    vault.to_string_lossy().into_owned(),
                    password.to_owned(),
                    keyfile.clone(),
                    Arc::new(FixedDbKey),
                    Arc::new(FixedProtector),
                    None, // no file watcher — keyhole drives state explicitly
                )
                .await
                .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?;
                if outcome.rebuilt {
                    // Diagnostics on stderr; scenarios grep this marker.
                    eprintln!("note: self-heal: rebuilt mirror from kdbx (stale sidecar key)");
                }
                outcome.engine
            }
        };

        let session = Self {
            engine,
            vault_path: vault.to_path_buf(),
            password: password.to_owned(),
            keyfile,
        };

        // The whole "bring the mirror current" gate — fresh-ingest /
        // signature-skip / reconcile / write-back — lives below the
        // seam now: one verb, no save decision left up here. keyhole
        // only narrates the outcome (stderr; scenarios parse stdout).
        let outcome = session
            .engine
            .sync_with_disk(
                vault.to_string_lossy().into_owned(),
                password.to_owned(),
                session.keyfile.clone(),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("sync_with_disk: {e:?}"))?;
        match &outcome {
            SyncWithDiskFfi::FreshIngest | SyncWithDiskFfi::UpToDate => {}
            SyncWithDiskFfi::NoChange | SyncWithDiskFfi::Applied { .. } => {
                eprintln!("note: KDBX changed on disk — reconciled");
                eprint_sync_outcome(&outcome);
                if let SyncWithDiskFfi::Applied {
                    wrote_back: true, ..
                } = outcome
                {
                    eprintln!("note: reconcile wrote back merged state");
                }
            }
        }

        Ok(session)
    }

    /// Print the engine-owned persistence watermark. Stdout is the
    /// scenario contract: one line, `mutation_seq=<n> persisted_seq=<m>
    /// dirty=<bool>`.
    fn persistence_state(&self) -> Result<()> {
        let st = self
            .engine
            .persistence_state()
            .map_err(|e| anyhow::anyhow!("persistence_state: {e:?}"))?;
        println!(
            "mutation_seq={} persisted_seq={} dirty={}",
            st.mutation_seq, st.persisted_seq, st.is_dirty
        );
        Ok(())
    }

    /// Save iff the engine says a write is owed — the orchestrator
    /// primitive. Prints `flushed` or `clean` on stdout.
    async fn flush(&self) -> Result<()> {
        if self.owes_write()? {
            self.save().await?;
            println!("flushed");
        } else {
            println!("clean");
        }
        Ok(())
    }

    /// Session teardown: write the mirror back iff the engine says a
    /// write is owed ([`keys_ffi::Engine::persistence_state`]). The
    /// single save-placement choke point — verbs only mutate; every
    /// session-opening dispatch arm closes with this, read verbs
    /// included (leftover dirt from a crashed predecessor flushes on
    /// the next session). Safe on read arms because the engine settles
    /// the watermark itself when a reconcile's digest-equal adoption
    /// proves the file already current — a flush after that is a
    /// no-op, not byte churn. Exemptions: `persistence-state` (the
    /// observer must not collapse what it reads) and
    /// `recycle --no-save` (the negative-control lever). Quiet on
    /// stdout (that belongs to the verbs); the loud twin is `flush`.
    async fn finish(&self) -> Result<()> {
        if self.owes_write()? {
            self.save().await?;
        }
        Ok(())
    }

    /// Does the engine say the KDBX is owed a write? The one dirty
    /// check, shared by [`Session::finish`], the `flush` verb, and the
    /// verbs whose engine call can be a structural no-op (their stdout
    /// must not claim a save the teardown won't perform).
    fn owes_write(&self) -> Result<bool> {
        Ok(self
            .engine
            .persistence_state()
            .map_err(|e| anyhow::anyhow!("persistence_state: {e:?}"))?
            .is_dirty)
    }

    /// Write the mirror back to the source KDBX — the raw persist used
    /// by [`Session::finish`], the `flush` verb, and the reconcile
    /// write-back in [`Session::open`].
    async fn save(&self) -> Result<()> {
        self.engine
            .save_to_kdbx_with_keyfile(
                self.vault_path.to_string_lossy().into_owned(),
                self.password.clone(),
                self.keyfile.clone(),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("save_to_kdbx: {e:?}"))
    }

    /// Rotate the vault's master key to `new_password` and re-encrypt
    /// the KDBX on disk. Opens under the session's CURRENT password
    /// first (the engine's fail-closed guard), then rotates: afterwards
    /// the OLD password no longer opens the file and the NEW one does,
    /// contents preserved. The honest "did it really rotate on disk?"
    /// proof lives in the scenario, across a `rm -rf <vault>.mirror`
    /// reopen — a fresh ingest from disk is the only test that can't be
    /// answered by carried-over mirror state.
    async fn rekey(&self, new_password: String, new_keyfile: Option<Vec<u8>>) -> Result<()> {
        self.engine
            .rekey_to_kdbx_with_keyfile(
                self.vault_path.to_string_lossy().into_owned(),
                self.password.clone(),
                self.keyfile.clone(),
                new_password,
                new_keyfile,
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("rekey_to_kdbx: {e:?}"))?;
        println!("re-keyed {} and saved to disk", self.vault_path.display());
        Ok(())
    }

    fn inspect(&self) -> Result<()> {
        let state = self
            .engine
            .state()
            .map_err(|e| anyhow::anyhow!("state: {e:?}"))?;
        let total = self
            .engine
            .entry_count(None)
            .map_err(|e| anyhow::anyhow!("entry_count: {e:?}"))?;
        let live = self
            .engine
            .entry_count_excluding_recycle_bin()
            .map_err(|e| anyhow::anyhow!("entry_count_excluding_recycle_bin: {e:?}"))?;
        let groups = self
            .engine
            .group_tree()
            .map_err(|e| anyhow::anyhow!("group_tree: {e:?}"))?;
        let bin = self
            .engine
            .recycle_bin_enabled()
            .map_err(|e| anyhow::anyhow!("recycle_bin_enabled: {e:?}"))?;
        let bin_present = self
            .engine
            .recycle_bin_uuid()
            .map_err(|e| anyhow::anyhow!("recycle_bin_uuid: {e:?}"))?
            .is_some();
        let recycled = self.recycled_count()?;
        let pool = self
            .engine
            .attachment_blob_stats()
            .map_err(|e| anyhow::anyhow!("attachment_blob_stats: {e:?}"))?;

        println!("state:        {state:?}");
        println!("entries:      {total}");
        println!("live entries: {live}");
        println!("groups:       {}", groups.len());
        println!("recycle bin:  {}", if bin { "enabled" } else { "disabled" });
        println!(
            "bin group:    {}",
            if bin_present { "present" } else { "absent" }
        );
        println!("recycled:     {recycled}");
        println!(
            "blob pool:    {} blob(s), {} byte(s)",
            pool.count, pool.bytes
        );
        Ok(())
    }

    /// Print the live (recycle-bin-excluded) entry count as a bare
    /// integer — the greppable assertion surface for the tile / "All
    /// Items" count a client shows.
    fn live_count(&self) -> Result<()> {
        let live = self
            .engine
            .entry_count_excluding_recycle_bin()
            .map_err(|e| anyhow::anyhow!("entry_count_excluding_recycle_bin: {e:?}"))?;
        println!("{live}");
        Ok(())
    }

    /// Number of entries currently sitting in the recycle bin group
    /// (0 if no bin exists yet). The assertion surface for "did the
    /// recycle actually persist?".
    fn recycled_count(&self) -> Result<u64> {
        let bin = self
            .engine
            .recycle_bin_uuid()
            .map_err(|e| anyhow::anyhow!("recycle_bin_uuid: {e:?}"))?;
        match bin {
            Some(uuid) => self
                .engine
                .entry_count(Some(uuid))
                .map_err(|e| anyhow::anyhow!("entry_count: {e:?}")),
            None => Ok(0),
        }
    }

    /// UUID of the vault's root group (the parentless node).
    fn root_uuid(&self) -> Result<String> {
        self.engine
            .group_tree()
            .map_err(|e| anyhow::anyhow!("group_tree: {e:?}"))?
            .into_iter()
            .find(|g| g.parent_uuid.is_none())
            .map(|g| g.uuid)
            .ok_or_else(|| anyhow::anyhow!("vault has no root group"))
    }

    /// Create an entry under `group` (root if `None`) and persist it.
    fn create_entry(
        &self,
        title: String,
        username: String,
        entry_password: String,
        group: Option<String>,
    ) -> Result<()> {
        let group_uuid = match group {
            Some(g) => g,
            None => self.root_uuid()?,
        };
        let uuid = self
            .engine
            .create_entry(
                group_uuid,
                NewEntryFields {
                    title,
                    username,
                    url: String::new(),
                    notes: String::new(),
                    password: entry_password,
                    icon: IconRef::Builtin { index: 0 },
                    custom_fields: Vec::new(),
                    tags: Vec::new(),
                },
            )
            .map_err(|e| anyhow::anyhow!("create_entry: {e:?}"))?;
        println!("created entry {uuid}");
        Ok(())
    }

    /// Patch an entry and persist.
    fn update_entry(&self, uuid: &str, update: EngineEntryUpdate) -> Result<()> {
        self.engine
            .update_entry(uuid.to_owned(), update)
            .map_err(|e| anyhow::anyhow!("update_entry: {e:?}"))?;
        println!("updated {uuid} and saved to disk");
        Ok(())
    }

    /// Ensure the recycle bin group exists. `ensure_recycle_bin` is a
    /// structural no-op when the bin already exists — the watermark
    /// tells the two cases apart, so stdout never claims a save that
    /// the teardown won't perform.
    fn ensure_bin(&self) -> Result<()> {
        let bin = self
            .engine
            .ensure_recycle_bin()
            .map_err(|e| anyhow::anyhow!("ensure_recycle_bin: {e:?}"))?;
        match &bin {
            Some(uuid) if self.owes_write()? => {
                println!("recycle bin ensured: {uuid} (saved)");
            }
            Some(uuid) => {
                println!("recycle bin ensured: {uuid} (already present — nothing to save)");
            }
            None => println!("recycle bin disabled — nothing to ensure"),
        }
        Ok(())
    }

    /// Toggle the recycle bin and persist. Enable = designate + lazily
    /// create the group (the same `ensure_recycle_bin` the unlock hook
    /// uses); disable = clear the designation, optionally hard-deleting
    /// the old bin group + contents first (tombstoned). The old group
    /// otherwise survives as an ordinary group.
    fn set_bin(&self, enable: bool, delete_contents: bool) -> Result<()> {
        if enable {
            self.engine
                .set_recycle_bin(true, None)
                .map_err(|e| anyhow::anyhow!("set_recycle_bin: {e:?}"))?;
            let bin = self
                .engine
                .ensure_recycle_bin()
                .map_err(|e| anyhow::anyhow!("ensure_recycle_bin: {e:?}"))?;
            match bin {
                Some(uuid) => println!("recycle bin enabled (group {uuid}) and saved"),
                None => anyhow::bail!("enable left no bin group — engine contract violated"),
            }
        } else {
            let old = self
                .engine
                .recycle_bin_uuid()
                .map_err(|e| anyhow::anyhow!("recycle_bin_uuid: {e:?}"))?;
            if delete_contents {
                if let Some(bin) = &old {
                    self.engine
                        .delete_group(bin.clone())
                        .map_err(|e| anyhow::anyhow!("delete_group(bin): {e:?}"))?;
                }
            }
            self.engine
                .set_recycle_bin(false, None)
                .map_err(|e| anyhow::anyhow!("set_recycle_bin: {e:?}"))?;
            match (&old, delete_contents) {
                (Some(b), true) => {
                    println!("recycle bin disabled; old bin {b} deleted with contents; saved");
                }
                (Some(b), false) => {
                    println!("recycle bin disabled; old bin {b} kept as ordinary group; saved");
                }
                (None, _) => println!("recycle bin disabled (no bin group existed); saved"),
            }
        }
        Ok(())
    }

    /// Permanently purge the recycle bin's contents (each removal
    /// tombstoned so it propagates to peers) and persist. Keeps the bin
    /// group itself — emptying is not disabling. The proof that the purge
    /// hit disk and propagated lives in the scenario, across a mirror-nuked
    /// reopen and a cross-peer sync.
    fn empty_bin(&self) -> Result<()> {
        let before = self.recycled_count()?;
        self.engine
            .empty_recycle_bin()
            .map_err(|e| anyhow::anyhow!("empty_recycle_bin: {e:?}"))?;
        // `empty_recycle_bin` is a structural no-op on an absent or
        // already-empty bin — only claim a save the teardown will do.
        if self.owes_write()? {
            println!(
                "emptied recycle bin ({before} entr{} were directly in it) and saved to disk",
                if before == 1 { "y" } else { "ies" }
            );
        } else {
            println!("recycle bin already empty — nothing to save");
        }
        Ok(())
    }

    /// Recycle an entry. The write-back happens at session teardown
    /// (`finish`, skipped under `--no-save`); `will_persist` only picks
    /// the honest message. The reopen-from-disk check that proves
    /// persistence lives in the scenario script, not here — a fresh
    /// process is the only honest test of "did it hit the disk".
    fn recycle(&self, uuid: &str, will_persist: bool) -> Result<()> {
        self.engine
            .recycle_entry(uuid.to_owned())
            .map_err(|e| anyhow::anyhow!("recycle_entry: {e:?}"))?;

        if will_persist {
            println!("recycled {uuid} and saved to disk");
        } else {
            println!("recycled {uuid} in mirror only — NOT saved (--no-save)");
        }
        Ok(())
    }

    /// Full-text search with an explicit recycle-bin filter. Output
    /// matches `list`: one `uuid  title  <username>` line per hit,
    /// machine-greppable.
    fn search(&self, query: &str, bin: &str) -> Result<()> {
        let bin = match bin {
            "exclude" => RecycleBinFilter::ExcludeRecycled,
            "only" => RecycleBinFilter::RecycledOnly,
            "include" => RecycleBinFilter::IncludeRecycled,
            other => anyhow::bail!("unknown --bin filter: {other}"),
        };
        let page = Page {
            offset: 0,
            limit: u64::MAX,
        };
        let hits = self
            .engine
            .search(query.to_owned(), SearchScope::AnyField, bin, page)
            .map_err(|e| anyhow::anyhow!("search: {e:?}"))?;

        print_summaries(&hits, "(no matches)", "match", "matches");
        Ok(())
    }

    /// AutoFill-style service lookup (`search_by_service` on the
    /// seam). Output matches `list`: one `uuid  title  <username>`
    /// line per hit, machine-greppable.
    fn service(&self, identifier: &str) -> Result<()> {
        let hits = self
            .engine
            .search_by_service(identifier.to_owned(), u64::MAX)
            .map_err(|e| anyhow::anyhow!("search_by_service: {e:?}"))?;

        print_summaries(&hits, "(no matches)", "match", "matches");
        Ok(())
    }

    fn list(&self, group: Option<String>) -> Result<()> {
        let page = Page {
            offset: 0,
            limit: u64::MAX,
        };
        let entries = self
            .engine
            .list_entries(group, page)
            .map_err(|e| anyhow::anyhow!("list_entries: {e:?}"))?;

        print_summaries(&entries, "(no entries)", "entry", "entries");
        Ok(())
    }

    /// Merge a peer's KDBX into the mirror under `owner`, park any
    /// divergences as held conflicts, persist the merged result.
    async fn ingest_peer(&self, owner: String, peer: &Path) -> Result<()> {
        anyhow::ensure!(peer.exists(), "peer vault not found: {}", peer.display());
        let result = self
            .engine
            .ingest_peer_kdbx(
                owner.clone(),
                peer.to_string_lossy().into_owned(),
                self.password.clone(),
                self.keyfile.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("ingest_peer_kdbx: {e:?}"))?;
        print_park_result(&format!("ingested peer '{owner}'"), &result);
        // A peer whose content is identical (or that only parked held
        // conflicts — conflict rows are mirror-local) advances nothing:
        // the watermark stays settled, the teardown writes nothing, and
        // the KDBX keeps its mtime — the loop-safety win over the old
        // unconditional rewrite. Only claim the save when it will happen.
        if self.owes_write()? {
            println!("merged state saved to disk");
        } else {
            println!("no local advance — nothing to save");
        }
        Ok(())
    }

    /// Print the UUIDs of entries held in unresolved conflicts — one
    /// per line, machine-greppable.
    fn list_conflicts(&self) -> Result<()> {
        let held = self
            .engine
            .entries_with_parked_conflict()
            .map_err(|e| anyhow::anyhow!("entries_with_parked_conflict: {e:?}"))?;
        if held.is_empty() {
            println!("(no held conflicts)");
            return Ok(());
        }
        for u in &held {
            println!("{u}");
        }
        println!("\n{} held conflict(s)", held.len());
        Ok(())
    }

    /// Print the distinct peer owner ids holding a parked conflict row for
    /// `entry` — one per line, sorted, greppable. Empty set prints a single
    /// `(no parked conflict)` marker (matching `list_conflicts`' style) so a
    /// scenario can assert "this entry diverges from exactly these peers".
    fn conflict_owners(&self, entry: String) -> Result<()> {
        let owners = self
            .engine
            .conflict_owners(entry)
            .map_err(|e| anyhow::anyhow!("conflict_owners: {e:?}"))?;
        if owners.is_empty() {
            println!("(no parked conflict)");
            return Ok(());
        }
        for o in &owners {
            println!("{o}");
        }
        Ok(())
    }

    /// Set a non-protected custom (string) field on `entry`, then persist.
    fn set_field(&self, entry: String, name: &str, value: String) -> Result<()> {
        self.engine
            .set_non_protected_custom_field(entry, name.to_owned(), value)
            .map_err(|e| anyhow::anyhow!("set_non_protected_custom_field: {e:?}"))?;
        println!("set field {name:?} and saved to disk");
        Ok(())
    }

    /// Replace `entry`'s tag set (comma-separated; empty string clears), then
    /// persist. Whitespace around each tag is trimmed; empty items dropped.
    fn set_tags(&self, entry: String, tags: &str) -> Result<()> {
        let parsed: Vec<String> = tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        self.engine
            .set_tags(entry, parsed)
            .map_err(|e| anyhow::anyhow!("set_tags: {e:?}"))?;
        println!("set tags and saved to disk");
        Ok(())
    }

    /// Print `entry`'s tags one per line, sorted (`(no tags)` if empty) — the
    /// read side for tag-convergence assertions. A pure read.
    fn tags(&self, entry: String) -> Result<()> {
        let full = self
            .engine
            .entry(entry)
            .map_err(|e| anyhow::anyhow!("entry: {e:?}"))?
            .ok_or_else(|| anyhow::anyhow!("entry not found"))?;
        let mut tags = full.tags;
        tags.sort();
        if tags.is_empty() {
            println!("(no tags)");
            return Ok(());
        }
        for t in &tags {
            println!("{t}");
        }
        Ok(())
    }

    /// Print `entry`'s history snapshots — `<index>  <username>` per line in
    /// index order, then a count. The history-convergence read oracle (the
    /// digest excludes history). A pure read.
    fn history(&self, entry: String) -> Result<()> {
        let hist = self
            .engine
            .history(entry)
            .map_err(|e| anyhow::anyhow!("history: {e:?}"))?;
        if hist.is_empty() {
            println!("(no history)");
            return Ok(());
        }
        for h in &hist {
            println!("{}  {}", h.history_index, h.username);
        }
        println!("\n{} snapshot(s)", hist.len());
        Ok(())
    }

    /// Delete history snapshot `index` from `entry`, then persist.
    fn delete_history(&self, entry: String, index: u32) -> Result<()> {
        self.engine
            .delete_history_at(entry, index)
            .map_err(|e| anyhow::anyhow!("delete_history_at: {e:?}"))?;
        println!("deleted history snapshot {index} and saved to disk");
        Ok(())
    }

    /// Set the vault-wide `<HistoryMaxItems>` cap, then persist. Subsequent
    /// edits trim each entry's history to this cap (oldest first); the Engine
    /// path must tombstone what it trims so a peer can't resurrect it.
    fn set_history_max(&self, items: i32) -> Result<()> {
        self.engine
            .set_history_max_items(items)
            .map_err(|e| anyhow::anyhow!("set_history_max_items: {e:?}"))?;
        println!("set history_max_items = {items} and saved to disk");
        Ok(())
    }

    /// Add `data`'s bytes as a custom icon, link it to `entry`, persist, and
    /// print the content-addressed icon UUID. The link itself doesn't bump
    /// `modified_at` (favicon semantics), so this is a one-sided cosmetic
    /// change for the cross-peer pool-union scenario.
    fn add_custom_icon(&self, entry: String, data: String) -> Result<()> {
        let uuid = self
            .engine
            .add_custom_icon(data.into_bytes())
            .map_err(|e| anyhow::anyhow!("add_custom_icon: {e:?}"))?;
        self.engine
            .link_entry_custom_icon(entry, uuid.clone())
            .map_err(|e| anyhow::anyhow!("link_entry_custom_icon: {e:?}"))?;
        println!("{uuid}");
        Ok(())
    }

    /// Print `present <len>` if the custom icon's bytes are in the pool, else
    /// `(none)` — the honest "did the icon BYTES arrive?" check (a pure read,
    /// like the digest, so it never perturbs state).
    fn custom_icon_bytes(&self, icon: String) -> Result<()> {
        match self
            .engine
            .custom_icon_bytes(icon)
            .map_err(|e| anyhow::anyhow!("custom_icon_bytes: {e:?}"))?
        {
            Some(bytes) => println!("present {}", bytes.len()),
            None => println!("(none)"),
        }
        Ok(())
    }

    /// Print the rich payload for a held conflict (first held entry if
    /// `entry` is `None`).
    async fn show_conflict(&self, entry: Option<String>) -> Result<()> {
        let payload = self
            .engine
            .held_conflict_payload(
                self.vault_path.to_string_lossy().into_owned(),
                self.password.clone(),
                entry,
            )
            .await
            .map_err(|e| anyhow::anyhow!("held_conflict_payload: {e:?}"))?;
        match payload {
            None => println!("(no held conflict)"),
            Some(p) => print_conflict_payload(&p),
        }
        Ok(())
    }

    /// Create a group under `parent` (root if `None`) and persist.
    fn create_group(&self, name: String, parent: Option<String>) -> Result<()> {
        let parent_uuid = match parent {
            Some(p) => p,
            None => self.root_uuid()?,
        };
        let uuid = self
            .engine
            .create_group(
                parent_uuid,
                keys_ffi::NewGroupFields {
                    name,
                    notes: String::new(),
                    icon: IconRef::Builtin { index: 48 },
                },
            )
            .map_err(|e| anyhow::anyhow!("create_group: {e:?}"))?;
        println!("created group {uuid}");
        Ok(())
    }

    /// Rename a group (its `name`), then persist.
    fn rename_group(&self, uuid: &str, name: &str) -> Result<()> {
        self.engine
            .update_group(
                uuid.to_owned(),
                keys_ffi::EngineGroupUpdate {
                    name: Some(name.to_owned()),
                    notes: None,
                    icon: None,
                    expires_at: None,
                },
            )
            .map_err(|e| anyhow::anyhow!("update_group: {e:?}"))?;
        println!("renamed group {uuid} to {name:?} and saved to disk");
        Ok(())
    }

    /// Re-parent a group under `to`, then persist.
    fn move_group(&self, uuid: &str, to: &str) -> Result<()> {
        self.engine
            .move_group(uuid.to_owned(), to.to_owned())
            .map_err(|e| anyhow::anyhow!("move_group: {e:?}"))?;
        println!("moved group {uuid} under {to} and saved to disk");
        Ok(())
    }

    /// Delete a group (cascading), then persist.
    fn delete_group(&self, uuid: &str) -> Result<()> {
        self.engine
            .delete_group(uuid.to_owned())
            .map_err(|e| anyhow::anyhow!("delete_group: {e:?}"))?;
        println!("deleted group {uuid} and saved to disk");
        Ok(())
    }

    /// Print every group: uuid, name, direct entry count.
    fn list_groups(&self) -> Result<()> {
        let groups = self
            .engine
            .group_tree()
            .map_err(|e| anyhow::anyhow!("group_tree: {e:?}"))?;
        for g in &groups {
            let bin = if g.is_recycle_bin { "  [bin]" } else { "" };
            println!(
                "{}  {}  ({} entries){bin}",
                g.uuid, g.name, g.entry_count_direct
            );
        }
        println!("\n{} group(s)", groups.len());
        Ok(())
    }

    /// Print every group UUID in `root`'s subtree (root included), then
    /// a count. Drives the engine's ancestry-derived subtree primitive.
    fn groups_in_subtree(&self, root: &str) -> Result<()> {
        let uuids = self
            .engine
            .group_uuids_in_subtree(root.to_owned())
            .map_err(|e| anyhow::anyhow!("group_uuids_in_subtree: {e:?}"))?;
        for u in &uuids {
            println!("{u}");
        }
        println!("\n{} group(s) in subtree", uuids.len());
        Ok(())
    }

    /// Print every entry UUID anywhere in `root`'s subtree (root
    /// included), then a count.
    fn entries_in_subtree(&self, root: &str) -> Result<()> {
        let uuids = self
            .engine
            .entry_uuids_in_subtree(root.to_owned())
            .map_err(|e| anyhow::anyhow!("entry_uuids_in_subtree: {e:?}"))?;
        for u in &uuids {
            println!("{u}");
        }
        println!("\n{} entry(ies) in subtree", uuids.len());
        Ok(())
    }

    /// Move an entry to `group_uuid` and persist.
    fn move_entry(&self, uuid: &str, group_uuid: &str) -> Result<()> {
        self.engine
            .move_entry(uuid.to_owned(), group_uuid.to_owned())
            .map_err(|e| anyhow::anyhow!("move_entry: {e:?}"))?;
        println!("moved {uuid} to {group_uuid} and saved to disk");
        Ok(())
    }

    /// Restore a recycled entry and persist.
    fn restore(&self, uuid: &str) -> Result<()> {
        self.engine
            .restore_entry(uuid.to_owned())
            .map_err(|e| anyhow::anyhow!("restore_entry: {e:?}"))?;
        println!("restored {uuid} and saved to disk");
        Ok(())
    }

    /// Permanently delete an entry (tombstoned) and persist.
    fn delete_entry(&self, uuid: &str) -> Result<()> {
        self.engine
            .delete_entry(uuid.to_owned())
            .map_err(|e| anyhow::anyhow!("delete_entry: {e:?}"))?;
        println!("deleted {uuid} permanently (tombstoned) and saved to disk");
        Ok(())
    }

    /// Add or replace an attachment and persist.
    fn set_attachment(&self, uuid: &str, name: &str, bytes: Vec<u8>) -> Result<()> {
        self.engine
            .set_attachment(uuid.to_owned(), name.to_owned(), bytes)
            .map_err(|e| anyhow::anyhow!("set_attachment: {e:?}"))?;
        println!("set attachment {name:?} on {uuid} and saved to disk");
        Ok(())
    }

    /// Remove an attachment by name and persist.
    fn remove_attachment(&self, uuid: &str, name: &str) -> Result<()> {
        self.engine
            .remove_attachment(uuid.to_owned(), name.to_owned())
            .map_err(|e| anyhow::anyhow!("remove_attachment: {e:?}"))?;
        println!("removed attachment {name:?} from {uuid} and saved to disk");
        Ok(())
    }

    /// Write an attachment's raw bytes to stdout. A closed pipe (e.g.
    /// `keyhole cat-attachment … | head`) is a normal way for a reader
    /// to stop early, not an error.
    fn cat_attachment(&self, uuid: String, name: String) -> Result<()> {
        use std::io::Write as _;
        let bytes = self
            .engine
            .attachment_bytes(uuid, name)
            .map_err(|e| anyhow::anyhow!("attachment_bytes: {e:?}"))?;
        match std::io::stdout().write_all(&bytes) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => Ok(other?),
        }
    }

    /// Print the content digest — the convergence oracle. One hex line
    /// on stdout so scenarios can capture and compare directly.
    fn digest(&self) -> Result<()> {
        let d = self
            .engine
            .content_digest()
            .map_err(|e| anyhow::anyhow!("content_digest: {e:?}"))?;
        println!("{d}");
        Ok(())
    }

    /// Resolve one held entry's conflict — every delta to `side`,
    /// except fields named in `overrides` — then persist the converged
    /// state.
    async fn resolve(
        &self,
        entry: String,
        side: ConflictSideFfi,
        overrides: &[(String, ConflictSideFfi)],
    ) -> Result<()> {
        let payload = self
            .engine
            .held_conflict_payload(
                self.vault_path.to_string_lossy().into_owned(),
                self.password.clone(),
                Some(entry.clone()),
            )
            .await
            .map_err(|e| anyhow::anyhow!("held_conflict_payload: {e:?}"))?
            .ok_or_else(|| anyhow::anyhow!("no held conflict for entry {entry}"))?;

        // Reject typo'd overrides up front: every named field must be
        // an actual delta key, or the user is resolving a phantom.
        for (key, _) in overrides {
            let known = payload
                .entry_conflicts
                .iter()
                .any(|c| c.field_deltas.iter().any(|d| &d.key == key));
            anyhow::ensure!(
                known,
                "--field {key}: no such field delta in this conflict (see show-conflict)"
            );
        }

        let resolution = resolution_choosing(&payload, side, overrides);
        self.engine
            .apply_conflict_resolution(payload.id, resolution)
            .await
            .map_err(|e| anyhow::anyhow!("apply_conflict_resolution: {e:?}"))?;
        println!("resolved {entry} choosing {side:?} and saved to disk");
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.engine.close();
    }
}

/// The vault's persistent mirror directory: `<vault-path>.mirror`.
/// Path-keyed so two copies of a vault (a "device" and its "peer") get
/// independent mirrors — two peers for free in conflict scenarios.
fn mirror_dir_for(vault: &Path) -> PathBuf {
    let mut os = vault.as_os_str().to_owned();
    os.push(".mirror");
    PathBuf::from(os)
}

/// The vault's persistent mirror DB file: `<vault>.mirror/mirror.sqlite`.
/// The one place the mirror filename is spelled, shared by `Session::open`
/// (which opens it) and `purge_vault` (which destroys it).
fn mirror_db_for(vault: &Path) -> PathBuf {
    mirror_dir_for(vault).join("mirror.sqlite")
}

/// Render a park-reconcile outcome. `label` names the operation; the
/// parked-conflict UUIDs print one per line for scenario grep.
/// Print entry summaries the way `list` and `search` present them: one
/// `uuid  title  <username>` line per row (machine-greppable), then a
/// `\nN <noun>` count footer; `empty` alone when there are no rows.
fn print_summaries(
    rows: &[keys_ffi::EngineEntrySummary],
    empty: &str,
    singular: &str,
    plural: &str,
) {
    if rows.is_empty() {
        println!("{empty}");
        return;
    }
    for e in rows {
        let user = if e.username.is_empty() {
            String::new()
        } else {
            format!("  <{}>", e.username)
        };
        println!("{}  {}{user}", e.uuid, e.title);
    }
    let noun = if rows.len() == 1 { singular } else { plural };
    println!("\n{} {noun}", rows.len());
}

fn print_park_result(label: &str, r: &ParkConflictsResultFfi) {
    match r {
        ParkConflictsResultFfi::NoChange => println!("{label}: no change"),
        ParkConflictsResultFfi::Applied {
            applied,
            parked,
            needs_write_back,
        } => {
            println!(
                "{label}: entries +{} ~{} -{} moved {}; groups +{} ~{} -{} moved {}; history pruned {}",
                applied.entries_added,
                applied.entries_updated,
                applied.entries_deleted,
                applied.entries_moved,
                applied.groups_added,
                applied.groups_updated,
                applied.groups_deleted,
                applied.groups_moved,
                applied.history_pruned,
            );
            println!(
                "write-back: {}",
                if *needs_write_back {
                    "needed"
                } else {
                    "not needed"
                }
            );
            for u in &parked.entries_with_parked_conflict {
                println!("parked conflict: {u}");
            }
            for u in &parked.entries_restored_from_deletion {
                println!("restored from deletion: {u}");
            }
            for n in &parked.attachments_kept_both {
                println!("attachment kept both: {n}");
            }
        }
    }
}

/// Stderr twin of [`print_park_result`] for open-time reconciles, so
/// verb stdout stays parseable.
fn eprint_sync_outcome(o: &SyncWithDiskFfi) {
    match o {
        SyncWithDiskFfi::FreshIngest | SyncWithDiskFfi::UpToDate => {}
        SyncWithDiskFfi::NoChange => eprintln!("note: reconcile found no change"),
        SyncWithDiskFfi::Applied {
            applied,
            parked,
            wrote_back,
        } => {
            eprintln!(
                "note: reconcile applied entries +{} ~{} -{}; parked {} conflict(s); write-back {}",
                applied.entries_added,
                applied.entries_updated,
                applied.entries_deleted,
                parked.entries_with_parked_conflict.len(),
                if *wrote_back { "needed" } else { "not needed" },
            );
        }
    }
}

/// Print a conflict payload: both sides' title/username plus delta
/// keys/kinds. Field *values* other than title/username are never
/// printed — a `Password` delta shows as its key only.
fn print_conflict_payload(p: &ConflictPayloadFfi) {
    println!("conflict id: {}", p.id);
    for c in &p.entry_conflicts {
        println!("entry {}", c.entry_uuid);
        println!(
            "  local:  title={:?} username={:?}",
            c.local.title, c.local.username
        );
        println!(
            "  remote: title={:?} username={:?}",
            c.remote.title, c.remote.username
        );
        for d in &c.field_deltas {
            println!("  field {}: {:?}", d.key, d.kind);
        }
        for a in &c.attachment_deltas {
            println!("  attachment {}: {:?}", a.name, a.kind);
        }
        if c.icon_delta.is_some() {
            println!("  icon differs");
        }
    }
    for d in &p.delete_edit_conflicts {
        println!("delete-vs-edit {}", d.entry_uuid);
    }
}

/// Parse a `local` / `remote` CLI token.
fn parse_side(s: &str) -> Result<ConflictSideFfi> {
    match s {
        "local" => Ok(ConflictSideFfi::Local),
        "remote" => Ok(ConflictSideFfi::Remote),
        other => anyhow::bail!("side must be local or remote, got {other}"),
    }
}

/// Build a [`ResolutionFfi`] that takes `side` for every delta in the
/// payload — each field (unless named in `overrides`), each attachment
/// (KeepLocal/KeepRemote), the icon, and delete-vs-edit (local → keep
/// edit, remote → accept delete).
fn resolution_choosing(
    p: &ConflictPayloadFfi,
    side: ConflictSideFfi,
    overrides: &[(String, ConflictSideFfi)],
) -> ResolutionFfi {
    // keyhole only ever constructs Local/Remote (see the --choose
    // parse); the wildcard arms satisfy the upstream #[non_exhaustive]
    // and should stay unreachable until keyhole maps a new variant.
    let attachment_kind = match side {
        ConflictSideFfi::Local => AttachmentChoiceKindFfi::KeepLocal,
        ConflictSideFfi::Remote => AttachmentChoiceKindFfi::KeepRemote,
        _ => unreachable!("ConflictSideFfi variant keyhole doesn't map"),
    };
    let delete_edit_choice = match side {
        ConflictSideFfi::Local => DeleteEditChoiceFfi::KeepLocal,
        ConflictSideFfi::Remote => DeleteEditChoiceFfi::AcceptRemoteDelete,
        _ => unreachable!("ConflictSideFfi variant keyhole doesn't map"),
    };

    let mut field_choices = Vec::new();
    let mut attachment_choices = Vec::new();
    let mut icon_choices = Vec::new();
    for c in &p.entry_conflicts {
        if !c.field_deltas.is_empty() {
            field_choices.push(EntryFieldChoiceFfi::new(
                c.entry_uuid.clone(),
                c.field_deltas
                    .iter()
                    .map(|d| {
                        let chosen = overrides
                            .iter()
                            .find(|(k, _)| *k == d.key)
                            .map_or(side, |(_, s)| *s);
                        FieldChoiceFfi::new(d.key.clone(), chosen)
                    })
                    .collect(),
            ));
        }
        if !c.attachment_deltas.is_empty() {
            attachment_choices.push(EntryAttachmentChoiceFfi::new(
                c.entry_uuid.clone(),
                c.attachment_deltas
                    .iter()
                    .map(|a| AttachmentChoiceFfi::new(a.name.clone(), attachment_kind.clone()))
                    .collect(),
            ));
        }
        if c.icon_delta.is_some() {
            icon_choices.push(EntryIconChoiceFfi::new(c.entry_uuid.clone(), side));
        }
    }
    let delete_edit = p
        .delete_edit_conflicts
        .iter()
        .map(|d| DeleteEditChoiceEntryFfi::new(d.entry_uuid.clone(), delete_edit_choice))
        .collect();

    ResolutionFfi::new(field_choices, attachment_choices, icon_choices, delete_edit)
}

/// Create a fresh empty vault via the same FFI entry point the GUI uses
/// (`keys_ffi::create_vault`; no `Vault` handle — the new file opens
/// through the same `Engine` path as any existing vault).
///
/// With `--uuid-seed` + `--at` the root group + recycle-bin ids and
/// creation timestamps are pinned (via `create_vault_deterministic`)
/// so a fuzz run replays byte-for-byte; without them the production path
/// mints random ids under the system clock. `--uuid-seed` requires `--at`,
/// matching the engine-open contract. `--keyfile` composes with both.
async fn create_vault(
    vault: &Path,
    password: &str,
    clock_ms: Option<i64>,
    uuid_seed: Option<u64>,
    keyfile: Option<&Path>,
) -> Result<()> {
    anyhow::ensure!(
        !vault.exists(),
        "refusing to overwrite existing file: {}",
        vault.display()
    );
    // Mint the keyfile at its path if it doesn't exist yet (keyhole stands in
    // for a client that mints + stores one); an existing file is used as-is,
    // which also lets a scenario point `create` at a foreign client's keyfile.
    let keyfile_bytes = match keyfile {
        Some(p) => Some(ensure_keyfile(p)?),
        None => None,
    };
    let path = vault.to_string_lossy().into_owned();
    match (clock_ms, uuid_seed) {
        (Some(ms), Some(seed)) => {
            ffi_create_vault_deterministic(
                path,
                password.to_owned(),
                keyfile_bytes,
                "keyhole".to_owned(),
                Some(Arc::new(FixedProtector)),
                None,
                seed,
                ms,
            )
            .await
            .map_err(|e| anyhow::anyhow!("create_vault_deterministic: {e:?}"))?;
        }
        (None, Some(_)) => anyhow::bail!("--uuid-seed requires --at on create"),
        (_, None) => {
            ffi_create_vault(
                path,
                password.to_owned(),
                keyfile_bytes,
                "keyhole".to_owned(),
                Some(Arc::new(FixedProtector)),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("create_vault: {e:?}"))?;
        }
    }
    println!("created {}", vault.display());
    Ok(())
}

/// Destroy a vault's LOCAL-device data: its persistent `SQLCipher`
/// mirror sidecar and the mirror's DB key. The teardown a client drives
/// when a vault is *removed* from the device.
///
/// The source KDBX is deliberately NOT touched — purge is local-only
/// (removing a vault from a device is not the same as deleting it), so
/// after a purge the canonical vault still opens and a reopen re-ingests
/// it from scratch into a fresh mirror.
///
/// Drives the same path-based `keys_ffi::purge_vault_local_data` the GUI
/// clients drive — no engine is opened (keyhole runs one verb per
/// process, so nothing holds the mirror open). keyhole has no real
/// keystore to inspect, so it passes a [`RecordingDbKey`] and asserts
/// its `delete_db_key` fired — proving the engine drove BOTH halves
/// (sidecar-file deletion AND key deletion), not just the files. The
/// honest "is the local copy really gone?" proof — the sidecar file
/// vanished, a fresh process must re-ingest — lives in the scenario.
fn purge_vault(vault: &Path) -> Result<()> {
    anyhow::ensure!(vault.exists(), "vault not found: {}", vault.display());
    let mirror_db = mirror_db_for(vault);

    let provider = Arc::new(RecordingDbKey::new());
    let deleted = provider.deletion_flag();

    let sidecars_removed =
        purge_vault_local_data(mirror_db.to_string_lossy().into_owned(), provider)
            .map_err(|e| anyhow::anyhow!("purge: {e:?}"))?;

    // keyhole's keystore stand-in: the purge must have called
    // delete_db_key, or the key-deletion half of teardown is missing.
    let key_deleted = deleted.load(Ordering::SeqCst);
    anyhow::ensure!(
        key_deleted,
        "purge did not invoke delete_db_key — the key-deletion half of teardown is missing"
    );
    // keyhole always seeds a real mirror before purging, so a zero count
    // means db_path resolved to nothing on disk — a regression here, not
    // a benign already-purged re-run.
    anyhow::ensure!(
        sidecars_removed > 0,
        "purge removed no sidecar files — db_path resolved to nothing on disk (mis-targeted purge)"
    );

    println!("db-key-deleted: {key_deleted}");
    println!("sidecars-removed: {sidecars_removed}");
    println!("purged local data for {}", vault.display());
    Ok(())
}

/// Discard a vault's stale local mirror sidecar and rebuild it from the
/// canonical KDBX, KEEPING the mirror's DB key (the post-open arm of the
/// self-heal — the SE/session-key case). Drives the engine-owned
/// `rebuild_vault_local_data`, which discards the sidecar files, re-opens
/// a fresh mirror under the *same* key, and re-ingests from the KDBX under
/// the master password (so a wrong password fails closed here, just as at
/// a normal open).
///
/// The open-time arm (a wiped/rotated *DB* key) needs no verb — it runs
/// automatically inside every `Session::open`. This verb exists for the
/// post-open arm a real client triggers off its SE-failure signal, which
/// is not observable at open.
async fn rebuild_vault(vault: &Path, password: &str, keyfile: Option<Vec<u8>>) -> Result<()> {
    anyhow::ensure!(vault.exists(), "vault not found: {}", vault.display());
    let mirror_db = mirror_db_for(vault);

    let sidecars_discarded = rebuild_vault_local_data(
        mirror_db.to_string_lossy().into_owned(),
        vault.to_string_lossy().into_owned(),
        password.to_owned(),
        keyfile,
        Arc::new(FixedDbKey),
        Arc::new(FixedProtector),
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("rebuild: {e:?}"))?;

    println!("rebuilt: true");
    println!("sidecars-discarded: {sidecars_discarded}");
    println!("rebuilt local mirror for {} from kdbx", vault.display());
    Ok(())
}

/// Read a keyfile's bytes, minting a fresh `.keyx` at `path` if it
/// does not yet exist. keyhole has no keychain, so it stands in for a client by
/// minting the keyfile to a file (via [`keys_ffi::generate_keyfile`]) and
/// reading it back. An existing file is used verbatim — which lets a scenario
/// point keyhole at a foreign client's keyfile to prove interop.
fn ensure_keyfile(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        std::fs::read(path).with_context(|| format!("read keyfile {}", path.display()))
    } else {
        let bytes =
            keys_ffi::generate_keyfile().map_err(|e| anyhow::anyhow!("generate_keyfile: {e:?}"))?;
        std::fs::write(path, &bytes)
            .with_context(|| format!("write keyfile {}", path.display()))?;
        Ok(bytes)
    }
}

/// Verify a picked KDBX file against an `expected` root-group UUID — the
/// recovery-flow guard, headless. Calls the `keys-ffi` `verify_vault_identity`
/// seam (a pure read — no mirror) and surfaces its three-way verdict on stdout
/// + the exit code:
///
/// - `match`         → prints `match`, exits 0 (the same vault; proceed);
/// - `mismatch`      → prints `mismatch`, exits non-zero (a DIFFERENT vault);
/// - `undecryptable` → prints `undecryptable`, exits non-zero — ambiguous
///   (wrong file, corrupt, or a genuine vault re-keyed since this credential
///   was cached), which a real consumer resolves by re-deriving, not by
///   declaring a different vault.
///
/// Only `match` exits 0, so a consumer keying off the exit code can never read
/// a reject as success. A missing / non-KDBX file errors (exit non-zero).
fn verify_identity(
    picked: &Path,
    expected: &str,
    password: &str,
    keyfile: Option<Vec<u8>>,
) -> Result<()> {
    anyhow::ensure!(
        picked.exists(),
        "picked file not found: {}",
        picked.display()
    );
    let verdict = verify_vault_identity(
        picked.to_string_lossy().into_owned(),
        password.to_owned(),
        keyfile,
        expected.to_owned(),
    )
    .map_err(|e| anyhow::anyhow!("verify: {e}"))?;
    match verdict {
        VaultIdentityVerdict::Match => {
            println!("match");
            Ok(())
        }
        VaultIdentityVerdict::Mismatch => {
            println!("mismatch");
            anyhow::bail!("picked file is a different vault (root-group UUID mismatch)");
        }
        VaultIdentityVerdict::Undecryptable => {
            println!("undecryptable");
            anyhow::bail!(
                "picked file did not decrypt under the supplied credential — wrong file, \
                 corrupt, or a genuine vault re-keyed since this credential was cached"
            );
        }
    }
}

fn read_password(var: &str) -> Result<String> {
    std::env::var(var).map_err(|_| {
        anyhow::anyhow!(
            "master password not set: export {var}=… (keyhole reads it from the \
             environment so it never lands in argv or shell history)"
        )
    })
}
