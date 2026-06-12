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
    NewEntryFields, Page, ParkConflictsResultFfi, ResolutionFfi, Vault,
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
}

// Flat verb dispatch: one match arm per CLI verb, growing linearly
// with the verb list. Splitting it would add indirection, not clarity.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let password = read_password(&cli.password_env)?;

    match cli.command {
        Command::Create { vault } => {
            create_vault(&vault, &password)?;
        }
        Command::CreateEntry {
            vault,
            title,
            username,
            entry_password,
            group,
        } => {
            let session = Session::open(&vault, &password).await?;
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
            let session = Session::open(&vault, &password).await?;
            session.update_entry(uuid, update).await?;
        }
        Command::EnsureBin { vault } => {
            let session = Session::open(&vault, &password).await?;
            session.ensure_bin().await?;
        }
        Command::Inspect { vault } => {
            let session = Session::open(&vault, &password).await?;
            session.inspect()?;
        }
        Command::List { vault, group } => {
            let session = Session::open(&vault, &password).await?;
            session.list(group)?;
        }
        Command::Recycle {
            vault,
            uuid,
            no_save,
        } => {
            let session = Session::open(&vault, &password).await?;
            session.recycle(uuid, !no_save).await?;
        }
        Command::IngestPeer {
            vault,
            peer_kdbx,
            owner,
        } => {
            let session = Session::open(&vault, &password).await?;
            session.ingest_peer(owner, &peer_kdbx).await?;
        }
        Command::ListConflicts { vault } => {
            let session = Session::open(&vault, &password).await?;
            session.list_conflicts()?;
        }
        Command::ShowConflict { vault, entry } => {
            let session = Session::open(&vault, &password).await?;
            session.show_conflict(entry).await?;
        }
        Command::Digest { vault } => {
            let session = Session::open(&vault, &password).await?;
            session.digest()?;
        }
        Command::CreateGroup {
            vault,
            name,
            parent,
        } => {
            let session = Session::open(&vault, &password).await?;
            session.create_group(name, parent).await?;
        }
        Command::ListGroups { vault } => {
            let session = Session::open(&vault, &password).await?;
            session.list_groups()?;
        }
        Command::MoveEntry { vault, uuid, to } => {
            let session = Session::open(&vault, &password).await?;
            session.move_entry(uuid, to).await?;
        }
        Command::Restore { vault, uuid } => {
            let session = Session::open(&vault, &password).await?;
            session.restore(uuid).await?;
        }
        Command::DeleteEntry { vault, uuid } => {
            let session = Session::open(&vault, &password).await?;
            session.delete_entry(uuid).await?;
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
            let session = Session::open(&vault, &password).await?;
            session.resolve(entry, side, &overrides).await?;
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
    async fn open(vault: &Path, password: &str) -> Result<Self> {
        anyhow::ensure!(vault.exists(), "vault not found: {}", vault.display());

        let mirror_dir = mirror_dir_for(vault);
        std::fs::create_dir_all(&mirror_dir)
            .with_context(|| format!("create mirror dir {}", mirror_dir.display()))?;
        let mirror_db = mirror_dir.join("mirror.sqlite");

        let engine = Engine::open(
            mirror_db.to_string_lossy().into_owned(),
            Arc::new(FixedDbKey),
            Arc::new(FixedProtector),
            None, // no file watcher — keyhole drives state explicitly
        )
        .map_err(|e| anyhow::anyhow!("engine open: {e:?}"))?;

        let session = Self {
            engine,
            vault_path: vault.to_path_buf(),
            password: password.to_owned(),
        };

        let recorded = session
            .engine
            .kdbx_state_signature()
            .map_err(|e| anyhow::anyhow!("kdbx_state_signature: {e:?}"))?;
        match recorded {
            None => {
                session
                    .engine
                    .ingest_from_kdbx(vault.to_string_lossy().into_owned(), password.to_owned())
                    .await
                    .map_err(|e| anyhow::anyhow!("ingest_from_kdbx: {e:?}"))?;
            }
            Some(sig) => {
                let (mtime_ms, byte_count) = disk_signature(vault)?;
                if sig.mtime_ms != mtime_ms || sig.byte_count != byte_count {
                    let result = session
                        .engine
                        .reconcile_with_disk_park_conflicts(
                            vault.to_string_lossy().into_owned(),
                            password.to_owned(),
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
            .save_to_kdbx(
                self.vault_path.to_string_lossy().into_owned(),
                self.password.clone(),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("save_to_kdbx: {e:?}"))
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

        println!("state:        {state:?}");
        println!("entries:      {total}");
        println!("groups:       {}", groups.len());
        println!("recycle bin:  {}", if bin { "enabled" } else { "disabled" });
        println!(
            "bin group:    {}",
            if bin_present { "present" } else { "absent" }
        );
        println!("recycled:     {recycled}");
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
                "{label}: entries +{} ~{} -{} moved {}; groups +{} ~{} -{} moved {}",
                applied.entries_added,
                applied.entries_updated,
                applied.entries_deleted,
                applied.entries_moved,
                applied.groups_added,
                applied.groups_updated,
                applied.groups_deleted,
                applied.groups_moved,
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
fn create_vault(vault: &Path, password: &str) -> Result<()> {
    anyhow::ensure!(
        !vault.exists(),
        "refusing to overwrite existing file: {}",
        vault.display()
    );
    Vault::create_empty(
        vault.to_string_lossy().into_owned(),
        password.to_owned(),
        "keyhole".to_owned(),
        Some(Arc::new(FixedProtector)),
        None,
    )
    .map_err(|e| anyhow::anyhow!("create_empty: {e:?}"))?;
    println!("created {}", vault.display());
    Ok(())
}

fn read_password(var: &str) -> Result<String> {
    std::env::var(var).map_err(|_| {
        anyhow::anyhow!(
            "master password not set: export {var}=… (keyhole reads it from the \
             environment so it never lands in argv or shell history)"
        )
    })
}
