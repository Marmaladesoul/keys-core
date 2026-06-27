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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keys_ffi::{
    AttachmentChoiceFfi, AttachmentChoiceKindFfi, ConflictPayloadFfi, ConflictSideFfi,
    DeleteEditChoiceEntryFfi, DeleteEditChoiceFfi, Engine, EngineEntryUpdate,
    EntryAttachmentChoiceFfi, EntryFieldChoiceFfi, EntryIconChoiceFfi, FieldChoiceFfi, IconRef,
    NewEntryFields, Page, ParkConflictsResultFfi, ResolutionFfi, Vault, VaultIdentityVerdict,
    verify_vault_identity,
};

use adapters::{FixedDbKey, FixedProtector};

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
    /// Create a fresh, empty test vault. Drives the same `Vault::create_empty`
    /// the GUI apps use — so new-vault policy (e.g. recycle bin enabled by
    /// default) is exercised here too.
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
    /// Open a vault and print its high-level state (counts, recycle
    /// bin, group tree size). The cheapest end-to-end smoke test.
    Inspect {
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
    /// Ingest a peer's KDBX into this vault's mirror under a device
    /// owner id — the per-device-key sync transport path. Divergences
    /// park as held conflicts in the persistent mirror (never a modal);
    /// the merged result is saved back to the vault. The peer file must
    /// decrypt under the same master password.
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
            )?;
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
            session
                .create_entry(title, username, entry_password, group)
                .await?;
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
            session.update_entry(uuid, update).await?;
        }
        Command::EnsureBin { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.ensure_bin().await?;
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
            session.set_bin(state == "on", delete_bin_contents).await?;
        }
        Command::EmptyBin { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.empty_bin().await?;
        }
        Command::Inspect { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.inspect()?;
        }
        Command::List { vault, group } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list(group)?;
        }
        Command::Recycle {
            vault,
            uuid,
            no_save,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.recycle(uuid, !no_save).await?;
        }
        Command::IngestPeer {
            vault,
            peer_kdbx,
            owner,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.ingest_peer(owner, &peer_kdbx).await?;
        }
        Command::ListConflicts { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list_conflicts()?;
        }
        Command::ShowConflict { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.show_conflict(entry).await?;
        }
        Command::ConflictOwners { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.conflict_owners(entry)?;
        }
        Command::AddCustomIcon { vault, entry, data } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.add_custom_icon(entry, data).await?;
        }
        Command::CustomIconBytes { vault, icon } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.custom_icon_bytes(icon)?;
        }
        Command::SetField {
            vault,
            entry,
            name,
            value,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_field(entry, name, value).await?;
        }
        Command::SetTags { vault, entry, tags } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_tags(entry, tags).await?;
        }
        Command::Tags { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.tags(entry)?;
        }
        Command::History { vault, entry } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.history(entry)?;
        }
        Command::DeleteHistory {
            vault,
            entry,
            index,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_history(entry, index).await?;
        }
        Command::SetHistoryMax { vault, items } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.set_history_max(items).await?;
        }
        Command::Digest { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.digest()?;
        }
        Command::CreateGroup {
            vault,
            name,
            parent,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.create_group(name, parent).await?;
        }
        Command::RenameGroup { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.rename_group(uuid, name).await?;
        }
        Command::MoveGroup { vault, uuid, to } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.move_group(uuid, to).await?;
        }
        Command::DeleteGroup { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_group(uuid).await?;
        }
        Command::ListGroups { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.list_groups()?;
        }
        Command::MoveEntry { vault, uuid, to } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.move_entry(uuid, to).await?;
        }
        Command::Restore { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.restore(uuid).await?;
        }
        Command::DeleteEntry { vault, uuid } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.delete_entry(uuid).await?;
        }
        Command::SetAttachment {
            vault,
            uuid,
            name,
            text,
        } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session
                .set_attachment(uuid, name, text.into_bytes())
                .await?;
        }
        Command::CatAttachment { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.cat_attachment(uuid, name)?;
        }
        Command::RemoveAttachment { vault, uuid, name } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            session.remove_attachment(uuid, name).await?;
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
        }
        Command::RootUuid { vault } => {
            let session =
                Session::open(&vault, &password, clock_ms, uuid_seed, keyfile.clone()).await?;
            println!("{}", session.root_uuid()?);
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
        let mirror_db = mirror_dir.join("mirror.sqlite");

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
            ),
            (Some(ms), None) => Engine::open_with_fixed_clock(
                db_path,
                Arc::new(FixedDbKey),
                Arc::new(FixedProtector),
                None,
                ms,
            ),
            (None, Some(_)) => {
                anyhow::bail!("--uuid-seed requires --at (a pinned clock) to be reproducible");
            }
            (None, None) => Engine::open(
                db_path,
                Arc::new(FixedDbKey),
                Arc::new(FixedProtector),
                None, // no file watcher — keyhole drives state explicitly
            ),
        }
        .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?;

        let session = Self {
            engine,
            vault_path: vault.to_path_buf(),
            password: password.to_owned(),
            keyfile,
        };

        let recorded = session
            .engine
            .kdbx_state_signature()
            .map_err(|e| anyhow::anyhow!("kdbx_state_signature: {e:?}"))?;
        match recorded {
            None => {
                session
                    .engine
                    .ingest_from_kdbx_with_keyfile(
                        vault.to_string_lossy().into_owned(),
                        password.to_owned(),
                        session.keyfile.clone(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("ingest_from_kdbx: {e:?}"))?;
            }
            Some(sig) => {
                let (mtime_ms, byte_count) = disk_signature(vault)?;
                if sig.mtime_ms != mtime_ms || sig.byte_count != byte_count {
                    let result = session
                        .engine
                        .reconcile_with_disk_park_conflicts_with_keyfile(
                            vault.to_string_lossy().into_owned(),
                            password.to_owned(),
                            session.keyfile.clone(),
                        )
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("reconcile_with_disk_park_conflicts: {e:?}")
                        })?;
                    // Diagnostics on stderr: scenarios parse stdout.
                    eprintln!("note: KDBX changed on disk — reconciled");
                    eprint_park_result(&result);
                }
            }
        }

        Ok(session)
    }

    /// Write the mirror back to the source KDBX — the shared persist
    /// tail of every mutating verb.
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
    async fn create_entry(
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
        self.save().await?;
        println!("created entry {uuid}");
        Ok(())
    }

    /// Patch an entry and persist.
    async fn update_entry(&self, uuid: String, update: EngineEntryUpdate) -> Result<()> {
        self.engine
            .update_entry(uuid.clone(), update)
            .map_err(|e| anyhow::anyhow!("update_entry: {e:?}"))?;
        self.save().await?;
        println!("updated {uuid} and saved to disk");
        Ok(())
    }

    /// Ensure the recycle bin group exists, then persist if one was created.
    async fn ensure_bin(&self) -> Result<()> {
        let bin = self
            .engine
            .ensure_recycle_bin()
            .map_err(|e| anyhow::anyhow!("ensure_recycle_bin: {e:?}"))?;
        match &bin {
            Some(uuid) => {
                self.save().await?;
                println!("recycle bin ensured: {uuid} (saved)");
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
    async fn set_bin(&self, enable: bool, delete_contents: bool) -> Result<()> {
        if enable {
            self.engine
                .set_recycle_bin(true, None)
                .map_err(|e| anyhow::anyhow!("set_recycle_bin: {e:?}"))?;
            let bin = self
                .engine
                .ensure_recycle_bin()
                .map_err(|e| anyhow::anyhow!("ensure_recycle_bin: {e:?}"))?;
            self.save().await?;
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
            self.save().await?;
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
    async fn empty_bin(&self) -> Result<()> {
        let before = self.recycled_count()?;
        self.engine
            .empty_recycle_bin()
            .map_err(|e| anyhow::anyhow!("empty_recycle_bin: {e:?}"))?;
        self.save().await?;
        println!(
            "emptied recycle bin ({before} entr{} were directly in it) and saved to disk",
            if before == 1 { "y" } else { "ies" }
        );
        Ok(())
    }

    /// Recycle an entry, then (unless `save` is false) write the result
    /// back to the source KDBX. The reopen-from-disk check that proves
    /// persistence lives in the scenario script, not here — a fresh
    /// process is the only honest test of "did it hit the disk".
    async fn recycle(&self, uuid: String, save: bool) -> Result<()> {
        self.engine
            .recycle_entry(uuid.clone())
            .map_err(|e| anyhow::anyhow!("recycle_entry: {e:?}"))?;

        if save {
            self.save().await?;
            println!("recycled {uuid} and saved to disk");
        } else {
            println!("recycled {uuid} in mirror only — NOT saved (--no-save)");
        }
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

        if entries.is_empty() {
            println!("(no entries)");
            return Ok(());
        }
        for e in &entries {
            let user = if e.username.is_empty() {
                String::new()
            } else {
                format!("  <{}>", e.username)
            };
            println!("{}  {}{user}", e.uuid, e.title);
        }
        println!(
            "\n{} entr{}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        );
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
            )
            .await
            .map_err(|e| anyhow::anyhow!("ingest_peer_kdbx: {e:?}"))?;
        print_park_result(&format!("ingested peer '{owner}'"), &result);
        self.save().await?;
        println!("merged state saved to disk");
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
    async fn set_field(&self, entry: String, name: String, value: String) -> Result<()> {
        self.engine
            .set_non_protected_custom_field(entry, name.clone(), value)
            .map_err(|e| anyhow::anyhow!("set_non_protected_custom_field: {e:?}"))?;
        self.save().await?;
        println!("set field {name:?} and saved to disk");
        Ok(())
    }

    /// Replace `entry`'s tag set (comma-separated; empty string clears), then
    /// persist. Whitespace around each tag is trimmed; empty items dropped.
    async fn set_tags(&self, entry: String, tags: String) -> Result<()> {
        let parsed: Vec<String> = tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        self.engine
            .set_tags(entry, parsed)
            .map_err(|e| anyhow::anyhow!("set_tags: {e:?}"))?;
        self.save().await?;
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
    async fn delete_history(&self, entry: String, index: u32) -> Result<()> {
        self.engine
            .delete_history_at(entry, index)
            .map_err(|e| anyhow::anyhow!("delete_history_at: {e:?}"))?;
        self.save().await?;
        println!("deleted history snapshot {index} and saved to disk");
        Ok(())
    }

    /// Set the vault-wide `<HistoryMaxItems>` cap, then persist. Subsequent
    /// edits trim each entry's history to this cap (oldest first); the Engine
    /// path must tombstone what it trims so a peer can't resurrect it.
    async fn set_history_max(&self, items: i32) -> Result<()> {
        self.engine
            .set_history_max_items(items)
            .map_err(|e| anyhow::anyhow!("set_history_max_items: {e:?}"))?;
        self.save().await?;
        println!("set history_max_items = {items} and saved to disk");
        Ok(())
    }

    /// Add `data`'s bytes as a custom icon, link it to `entry`, persist, and
    /// print the content-addressed icon UUID. The link itself doesn't bump
    /// `modified_at` (favicon semantics), so this is a one-sided cosmetic
    /// change for the cross-peer pool-union scenario.
    async fn add_custom_icon(&self, entry: String, data: String) -> Result<()> {
        let uuid = self
            .engine
            .add_custom_icon(data.into_bytes())
            .map_err(|e| anyhow::anyhow!("add_custom_icon: {e:?}"))?;
        self.engine
            .link_entry_custom_icon(entry, uuid.clone())
            .map_err(|e| anyhow::anyhow!("link_entry_custom_icon: {e:?}"))?;
        self.save().await?;
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
    async fn create_group(&self, name: String, parent: Option<String>) -> Result<()> {
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
        self.save().await?;
        println!("created group {uuid}");
        Ok(())
    }

    /// Rename a group (its `name`), then persist.
    async fn rename_group(&self, uuid: String, name: String) -> Result<()> {
        self.engine
            .update_group(
                uuid.clone(),
                keys_ffi::EngineGroupUpdate {
                    name: Some(name.clone()),
                    notes: None,
                    icon: None,
                    expires_at: None,
                },
            )
            .map_err(|e| anyhow::anyhow!("update_group: {e:?}"))?;
        self.save().await?;
        println!("renamed group {uuid} to {name:?} and saved to disk");
        Ok(())
    }

    /// Re-parent a group under `to`, then persist.
    async fn move_group(&self, uuid: String, to: String) -> Result<()> {
        self.engine
            .move_group(uuid.clone(), to.clone())
            .map_err(|e| anyhow::anyhow!("move_group: {e:?}"))?;
        self.save().await?;
        println!("moved group {uuid} under {to} and saved to disk");
        Ok(())
    }

    /// Delete a group (cascading), then persist.
    async fn delete_group(&self, uuid: String) -> Result<()> {
        self.engine
            .delete_group(uuid.clone())
            .map_err(|e| anyhow::anyhow!("delete_group: {e:?}"))?;
        self.save().await?;
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

    /// Move an entry to `group_uuid` and persist.
    async fn move_entry(&self, uuid: String, group_uuid: String) -> Result<()> {
        self.engine
            .move_entry(uuid.clone(), group_uuid.clone())
            .map_err(|e| anyhow::anyhow!("move_entry: {e:?}"))?;
        self.save().await?;
        println!("moved {uuid} to {group_uuid} and saved to disk");
        Ok(())
    }

    /// Restore a recycled entry and persist.
    async fn restore(&self, uuid: String) -> Result<()> {
        self.engine
            .restore_entry(uuid.clone())
            .map_err(|e| anyhow::anyhow!("restore_entry: {e:?}"))?;
        self.save().await?;
        println!("restored {uuid} and saved to disk");
        Ok(())
    }

    /// Permanently delete an entry (tombstoned) and persist.
    async fn delete_entry(&self, uuid: String) -> Result<()> {
        self.engine
            .delete_entry(uuid.clone())
            .map_err(|e| anyhow::anyhow!("delete_entry: {e:?}"))?;
        self.save().await?;
        println!("deleted {uuid} permanently (tombstoned) and saved to disk");
        Ok(())
    }

    /// Add or replace an attachment and persist.
    async fn set_attachment(&self, uuid: String, name: String, bytes: Vec<u8>) -> Result<()> {
        self.engine
            .set_attachment(uuid.clone(), name.clone(), bytes)
            .map_err(|e| anyhow::anyhow!("set_attachment: {e:?}"))?;
        self.save().await?;
        println!("set attachment {name:?} on {uuid} and saved to disk");
        Ok(())
    }

    /// Remove an attachment by name and persist.
    async fn remove_attachment(&self, uuid: String, name: String) -> Result<()> {
        self.engine
            .remove_attachment(uuid.clone(), name.clone())
            .map_err(|e| anyhow::anyhow!("remove_attachment: {e:?}"))?;
        self.save().await?;
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
        self.save().await?;
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

/// `(mtime_ms, byte_count)` of the on-disk KDBX, computed with the
/// exact formula `keys_engine::KdbxStateSignature::from_path` uses
/// (truncating-millisecond i64, pre-1970 clamped negative) so the
/// comparison against the recorded signature can never drift.
fn disk_signature(vault: &Path) -> Result<(i64, u64)> {
    let meta = std::fs::metadata(vault).with_context(|| format!("stat {}", vault.display()))?;
    let mtime = meta.modified().context("kdbx mtime unavailable")?;
    let mtime_ms = match mtime.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    };
    Ok((mtime_ms, meta.len()))
}

/// Render a park-reconcile outcome. `label` names the operation; the
/// parked-conflict UUIDs print one per line for scenario grep.
fn print_park_result(label: &str, r: &ParkConflictsResultFfi) {
    match r {
        ParkConflictsResultFfi::NoChange => println!("{label}: no change"),
        ParkConflictsResultFfi::Applied { applied, parked } => {
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
fn eprint_park_result(r: &ParkConflictsResultFfi) {
    match r {
        ParkConflictsResultFfi::NoChange => eprintln!("note: reconcile found no change"),
        ParkConflictsResultFfi::Applied { applied, parked } => {
            eprintln!(
                "note: reconcile applied entries +{} ~{} -{}; parked {} conflict(s)",
                applied.entries_added,
                applied.entries_updated,
                applied.entries_deleted,
                parked.entries_with_parked_conflict.len(),
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

/// Create a fresh empty vault via the same FFI entry point the GUI uses.
///
/// With `--uuid-seed` + `--at` the root group + recycle-bin ids and
/// creation timestamps are pinned (via `Vault::create_empty_deterministic`)
/// so a fuzz run replays byte-for-byte; without them the production path
/// mints random ids under the system clock. `--uuid-seed` requires `--at`,
/// matching the engine-open contract.
fn create_vault(
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
    match (clock_ms, uuid_seed, keyfile_bytes) {
        (Some(ms), Some(seed), None) => {
            Vault::create_empty_deterministic(
                path,
                password.to_owned(),
                "keyhole".to_owned(),
                Some(Arc::new(FixedProtector)),
                None,
                seed,
                ms,
            )
            .map_err(|e| anyhow::anyhow!("create_empty_deterministic: {e:?}"))?;
        }
        (Some(_), Some(_), Some(_)) => {
            // No scenario needs deterministic + keyfile and the FFI has no
            // deterministic keyfile constructor; reject explicitly.
            anyhow::bail!(
                "--keyfile with deterministic create (--at + --uuid-seed) is not supported"
            );
        }
        (None, Some(_), _) => anyhow::bail!("--uuid-seed requires --at on create"),
        (_, None, Some(kf)) => {
            Vault::create_empty_with_keyfile(
                path,
                password.to_owned(),
                kf,
                "keyhole".to_owned(),
                Some(Arc::new(FixedProtector)),
                None,
            )
            .map_err(|e| anyhow::anyhow!("create_empty_with_keyfile: {e:?}"))?;
        }
        (_, None, None) => {
            Vault::create_empty(
                path,
                password.to_owned(),
                "keyhole".to_owned(),
                Some(Arc::new(FixedProtector)),
                None,
            )
            .map_err(|e| anyhow::anyhow!("create_empty: {e:?}"))?;
        }
    }
    println!("created {}", vault.display());
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
