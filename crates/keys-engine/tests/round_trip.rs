//! Round-trip property tests — Phase 2 exit gate (task 2.7).
//!
//! Drives the whole pipeline `kdbx → ingest → SQLite → serialise →
//! kdbx → reopen` against a corpus of synthetic fixtures (and one
//! pre-existing KDBX3 fixture loaded from keepass-core) and asserts
//! the reopened vault is equivalent to the source under a **tolerant**
//! equality helper that accommodates the lossy bits of KDBX
//! serialisation (timestamp truncation to whole seconds, the v1
//! schema's deliberately-narrow projection of `Meta`).
//!
//! Synthetic-only by design: this harness builds vaults in memory via
//! `keepass_core::Kdbx::create_empty_v4_with_protector` plus a smattering
//! of editor calls. That keeps the corpus reproducible, makes shape
//! variation a deliberate test parameter, and means no real-vault
//! contents (real personal vaults) ever land near a public test file.
//! Real-vault round-trip stays a manual sanity check on the maintainer's box.
//!
//! ## What the equality helper checks
//!
//! See `vault_round_trip_eq` below for the source of truth. Summary:
//!
//! * **Strict**: group hierarchy + UUIDs + names; entry counts + UUIDs;
//!   plaintext field values (title, username, url, notes); revealed
//!   protected fields (password + protected custom fields); tag set
//!   (order-insensitive); attachment names + SHA-256 of bytes; history
//!   shape + per-snapshot plaintext; `recycle_bin_uuid`,
//!   `recycle_bin_enabled`.
//! * **Tolerant**: timestamps are compared at second-precision because
//!   KDBX serialisation drops sub-second components (per task 2.5
//!   findings).
//! * **Out of scope** (preserved from the source-side kdbx, not from
//!   the `SQLite` mirror): every other `Meta` field — `database_name`,
//!   `generator`, `custom_icons`, `custom_data`, `unknown_xml`, etc. —
//!   plus `deleted_objects`. The serialise path's `splice_preserving_meta`
//!   carries them across verbatim, so a round-trip preserves them; the
//!   equality helper doesn't re-check them because the projection has no
//!   notion of them and a strict cross-check would just test
//!   `kdbx.vault().meta` against itself.
//! * Both protected and non-protected custom fields round-trip via
//!   `entry_protected` and `entry_custom_field` (migration 0002)
//!   respectively. The helper compares both flavours.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{
    CustomFieldValue, Entry, EntryId, Group, HistoryPolicy, NewEntry, NewGroup, Vault,
};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, KeyProvider, KeyProviderError};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use secrecy::SecretString;
use sha2::{Digest, Sha256};

// ─────────────────────── test infrastructure ───────────────────────

#[derive(Debug)]
struct FixedKey([u8; 32]);
impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(self.0))
    }
}

#[derive(Debug, Clone)]
struct FixedProtector([u8; 32]);
impl FieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(self.0))
    }
}

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];
const COMPOSITE_PW: &[u8] = b"round-trip-test";

fn protector() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector(SESSION_KEY_BYTES))
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(COMPOSITE_PW)
}

fn fresh_kdbx_v4(name: &str) -> Kdbx<Unlocked> {
    Kdbx::create_empty_v4_with_protector(&composite(), name, Some(protector())).expect("create")
}

// ─────────────────────── synthetic fixtures ───────────────────────

/// Smallest non-empty vault: root + one entry with title + password.
fn make_minimal_vault() -> Kdbx<Unlocked> {
    let mut kdbx = fresh_kdbx_v4("minimal");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(
        root,
        NewEntry::new("Only Entry").password(SecretString::from("only-password")),
    )
    .expect("add minimal entry");
    kdbx
}

/// Rich KDBX4 vault hitting every Phase-2 feature that the harness can
/// observe — nested groups, recycle bin (+ one recycled entry), tags,
/// shared and per-entry attachments, history, protected custom fields,
/// URLs that exercise `url_host` extraction.
fn make_rich_vault() -> Kdbx<Unlocked> {
    let mut kdbx = fresh_kdbx_v4("rich");
    let root = kdbx.vault().root.id;

    // Three nested groups; one of them is going to become the recycle bin.
    let work = kdbx.add_group(root, NewGroup::new("Work")).expect("Work");
    let personal = kdbx
        .add_group(root, NewGroup::new("Personal"))
        .expect("Personal");
    let archive = kdbx
        .add_group(work, NewGroup::new("Archive"))
        .expect("Archive");

    // Ten entries with assorted fields.
    let urls = [
        "https://login.example.com/path?q=1",
        "https://mail.contoso.example/",
        "https://example.org/account",
        "",
        "https://Login.Example.COM/Another",
        "ftp://files.example.net/",
        "https://bank.example/login",
        "https://forum.example",
        "",
        "https://travel.example/booking",
    ];
    let groups = [
        work, personal, archive, work, personal, root, root, work, personal, archive,
    ];

    let mut ids: Vec<EntryId> = Vec::new();
    for i in 0..10 {
        let title = format!("acme-{i}");
        let id = kdbx
            .add_entry(
                groups[i],
                NewEntry::new(title.clone())
                    .username(format!("user{i}@example.com"))
                    .password(SecretString::from(format!("p4ssw0rd-{i}!")))
                    .url(urls[i])
                    .notes(format!("Some notes for entry {i}\nMultiline."))
                    .tags(vec![
                        "rich".into(),
                        format!("bucket-{}", i % 3),
                        // Deliberate dup-with-trim to exercise dedup.
                        "rich".into(),
                    ]),
            )
            .expect("add rich entry");
        ids.push(id);
    }

    // Attach files. Two entries share the same blob so dedup is exercised.
    let shared_bytes = b"shared-attachment-bytes-0123456789".to_vec();
    let unique_bytes = b"unique-payload-for-one-entry".to_vec();
    kdbx.edit_entry(ids[0], HistoryPolicy::Snapshot, |e| {
        e.attach("shared.bin", shared_bytes.clone(), false);
        e.attach("unique.txt", unique_bytes.clone(), false);
        e.set_custom_field(
            "Recovery",
            CustomFieldValue::Protected(SecretString::from("rec-0")),
        );
        e.set_custom_field(
            "ApiToken",
            CustomFieldValue::Protected(SecretString::from("tok-0")),
        );
        // Non-protected custom field — exercises migration 0002's
        // `entry_custom_field` table end-to-end.
        e.set_custom_field(
            "Website",
            CustomFieldValue::Plain("https://example.com/recovery".to_string()),
        );
    })
    .expect("edit ids[0]");

    kdbx.edit_entry(ids[1], HistoryPolicy::Snapshot, |e| {
        e.attach("shared.bin", shared_bytes.clone(), false);
        e.set_custom_field(
            "Recovery",
            CustomFieldValue::Protected(SecretString::from("rec-1")),
        );
    })
    .expect("edit ids[1]");

    // History snapshots — exercise the two-snapshot path on entry 2.
    kdbx.edit_entry(ids[2], HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("rev-1"));
        e.set_notes("rev-1 notes");
    })
    .expect("first revision");
    kdbx.edit_entry(ids[2], HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("rev-2"));
        e.set_title("acme-2-renamed");
    })
    .expect("second revision");

    // Pre-enable the recycle bin in meta so `recycle_entry` actually
    // soft-deletes (rather than hard-deleting because the freshly-
    // created vault has `recycle_bin_enabled = false` + no bin uuid).
    // `Kdbx::recycle_entry` lazily creates the bin group when both
    // flags say "go", so we just flip `recycle_bin_enabled = true`
    // and let the model code do the rest.
    let mut vault = kdbx.vault().clone();
    vault.meta.recycle_bin_enabled = true;
    kdbx.replace_vault(vault);

    let _bin = kdbx
        .recycle_entry(ids[9])
        .expect("recycle entry")
        .expect("recycle bin created (enabled=true)");

    let _ = archive; // archive group is exercised by the walk; suppress unused

    kdbx
}

/// Large vault — `n` entries with random-ish content. Used for the
/// `#[ignore]`-d perf-flavoured round-trip.
fn make_large_vault(n: usize) -> Kdbx<Unlocked> {
    let mut kdbx = fresh_kdbx_v4("large");
    let root = kdbx.vault().root.id;
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);

    // A handful of groups under root so entries are distributed.
    let mut groups = vec![root];
    for i in 0..8 {
        let g = kdbx
            .add_group(root, NewGroup::new(format!("group-{i}")))
            .expect("add group");
        groups.push(g);
    }

    for i in 0..n {
        let g_idx: usize = rng.gen_range(0..groups.len());
        let pw_len: usize = rng.gen_range(8..24);
        let mut pw = String::with_capacity(pw_len);
        for _ in 0..pw_len {
            // Printable ASCII, avoiding control chars.
            let c: u8 = rng.gen_range(33..127);
            pw.push(c as char);
        }
        kdbx.add_entry(
            groups[g_idx],
            NewEntry::new(format!("entry-{i}"))
                .username(format!("u{i}"))
                .password(SecretString::from(pw))
                .url(format!("https://host-{}.example/", i % 200)),
        )
        .expect("add large entry");
    }
    kdbx
}

// ─────────────────────── round-trip driver ───────────────────────

/// The Phase 2 exit-gate property: ingest, save, reopen, compare.
fn assert_kdbx_round_trips(kdbx: Kdbx<Unlocked>, label: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("round_trip.kdbx");

    // 1. Snapshot source vault for comparison (plaintext-protected).
    let source_vault = kdbx
        .vault_with_unwrapped_protected()
        .expect("source vault unwrap");

    // 2. Open the engine.
    let mut engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector()).expect("engine open");

    // 3. Ingest.
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    // 4. Save back to KDBX. `save_to_kdbx` needs `&mut kdbx`; the
    //    splice path on save mutates the in-memory vault, so we have
    //    to give it ownership of mutability. We can still re-read the
    //    pre-save vault via the snapshot captured in step 1.
    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx)
        .expect("save_to_kdbx");

    drop(engine);
    drop(kdbx);

    // 5. Reopen from disk.
    let reopened = reopen_kdbx(&kdbx_path);
    let reopened_vault = reopened
        .vault_with_unwrapped_protected()
        .expect("reopened vault unwrap");

    // 6. Compare.
    if let Err(diff) = vault_round_trip_eq(&source_vault, &reopened_vault) {
        panic!("round-trip diverged [{label}]: {diff}");
    }
}

fn reopen_kdbx(path: &Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open from disk")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(protector()))
        .expect("unlock")
}

// ─────────────────────── tolerant equality ───────────────────────

/// Compare two vaults that have just round-tripped through `SQLite` +
/// KDBX. Returns `Err(reason)` on divergence with a message that
/// points at the divergent field.
fn vault_round_trip_eq(source: &Vault, reloaded: &Vault) -> Result<(), String> {
    // Meta — only the recycle-bin pair is projected. Everything else
    // round-trips through `splice_preserving_meta` from the live kdbx
    // handle, so a cross-check here would essentially compare
    // `source.meta` to `reloaded.meta` for fields that are carried
    // verbatim. That'd add no real coverage; we restrict to the two
    // fields the projection actually owns.
    if source.meta.recycle_bin_uuid != reloaded.meta.recycle_bin_uuid {
        return Err(format!(
            "meta.recycle_bin_uuid: {:?} vs {:?}",
            source.meta.recycle_bin_uuid, reloaded.meta.recycle_bin_uuid,
        ));
    }
    // `recycle_bin_enabled` is now strict — ingest persists it
    // explicitly in `setting` under key `meta.recycle_bin_enabled`,
    // and projection reads it back. This covers the "enabled=true,
    // uuid=None" intermediate state KeePassXC emits.
    if source.meta.recycle_bin_enabled != reloaded.meta.recycle_bin_enabled {
        return Err(format!(
            "meta.recycle_bin_enabled: {} vs {}",
            source.meta.recycle_bin_enabled, reloaded.meta.recycle_bin_enabled,
        ));
    }

    // Build attachment SHA lookups against each side's binary pool so
    // attachment comparison can be "name + sha256" without depending on
    // ref_id stability (ref_ids are reassigned by the projection).
    let src_sha = build_binary_sha_pool(source);
    let dst_sha = build_binary_sha_pool(reloaded);

    compare_groups(&source.root, &reloaded.root, &src_sha, &dst_sha, "root")?;

    Ok(())
}

fn compare_groups(
    a: &Group,
    b: &Group,
    src_sha: &[[u8; 32]],
    dst_sha: &[[u8; 32]],
    path: &str,
) -> Result<(), String> {
    if a.id != b.id {
        return Err(format!("group {path} uuid: {:?} vs {:?}", a.id, b.id));
    }
    if a.name != b.name {
        return Err(format!(
            "group {path} ({}) name: {:?} vs {:?}",
            a.id.0, a.name, b.name
        ));
    }
    compare_times(
        &format!("group {path} ({})", a.id.0),
        a.times.creation_time,
        b.times.creation_time,
        "creation_time",
    )?;
    compare_times(
        &format!("group {path} ({})", a.id.0),
        a.times.last_modification_time,
        b.times.last_modification_time,
        "last_modification_time",
    )?;

    // Entries — compare as ordered children. Ingest preserves walk
    // order; projection rebuilds it from the rows. Order matches.
    if a.entries.len() != b.entries.len() {
        return Err(format!(
            "group {path} ({}) entry count: {} vs {}",
            a.id.0,
            a.entries.len(),
            b.entries.len()
        ));
    }
    for (ea, eb) in a.entries.iter().zip(b.entries.iter()) {
        compare_entries(ea, eb, src_sha, dst_sha)?;
    }

    // Subgroups — compare by UUID-matched pairs (order may differ
    // because projection walks children in HashMap insertion order
    // for the `children_of` map, while ingest walks them in vector
    // order).
    if a.groups.len() != b.groups.len() {
        return Err(format!(
            "group {path} ({}) subgroup count: {} vs {}",
            a.id.0,
            a.groups.len(),
            b.groups.len()
        ));
    }
    for sub_a in &a.groups {
        let sub_b = b
            .groups
            .iter()
            .find(|g| g.id == sub_a.id)
            .ok_or_else(|| format!("subgroup {} missing in reloaded vault", sub_a.id.0))?;
        compare_groups(
            sub_a,
            sub_b,
            src_sha,
            dst_sha,
            &format!("{path}/{}", sub_a.name),
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn compare_entries(
    a: &Entry,
    b: &Entry,
    src_sha: &[[u8; 32]],
    dst_sha: &[[u8; 32]],
) -> Result<(), String> {
    let id = a.id.0;
    if a.id != b.id {
        return Err(format!("entry uuid: {:?} vs {:?}", a.id, b.id));
    }
    compare_str(id, "title", &a.title, &b.title)?;
    compare_str(id, "username", &a.username, &b.username)?;
    compare_str(id, "url", &a.url, &b.url)?;
    compare_str(id, "notes", &a.notes, &b.notes)?;
    compare_str(id, "password", &a.password, &b.password)?;

    // Tags: order-insensitive set comparison. Ingest dedups + projection
    // sorts; the source may carry duplicates or any order.
    let tags_a: HashSet<String> = a
        .tags
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let tags_b: HashSet<String> = b.tags.iter().cloned().collect();
    if tags_a != tags_b {
        return Err(format!(
            "entry {id} tags differ: source={tags_a:?} reloaded={tags_b:?}"
        ));
    }

    // Custom fields — both protected and non-protected (migration 0002).
    // Compared by name; value compared as Secret-wrapper equality on the
    // CustomField struct.
    if a.custom_fields.len() != b.custom_fields.len() {
        return Err(format!(
            "entry {id} custom-field count: {} vs {}",
            a.custom_fields.len(),
            b.custom_fields.len()
        ));
    }
    for cf_a in &a.custom_fields {
        let cf_b = b
            .custom_fields
            .iter()
            .find(|c| c.key == cf_a.key)
            .ok_or_else(|| format!("entry {id} custom field {:?} missing", cf_a.key))?;
        if cf_a.protected != cf_b.protected {
            return Err(format!(
                "entry {id} custom field {:?} protected flag: {} vs {}",
                cf_a.key, cf_a.protected, cf_b.protected
            ));
        }
        if cf_a.value != cf_b.value {
            return Err(format!(
                "entry {id} custom field {:?} value: {:?} vs {:?}",
                cf_a.key, cf_a.value, cf_b.value
            ));
        }
    }

    // Attachments: compare by (name, blob SHA-256). ref_ids are
    // reassigned by projection so they're not stable.
    if a.attachments.len() != b.attachments.len() {
        return Err(format!(
            "entry {id} attachment count: {} vs {}",
            a.attachments.len(),
            b.attachments.len()
        ));
    }
    for att_a in &a.attachments {
        let want_sha = src_sha.get(att_a.ref_id as usize).ok_or_else(|| {
            format!(
                "entry {id} attachment {:?}: dangling ref_id (source)",
                att_a.name
            )
        })?;
        let att_b = b
            .attachments
            .iter()
            .find(|att| att.name == att_a.name)
            .ok_or_else(|| format!("entry {id} attachment {:?} missing", att_a.name))?;
        let got_sha = dst_sha.get(att_b.ref_id as usize).ok_or_else(|| {
            format!(
                "entry {id} attachment {:?}: dangling ref_id (reloaded)",
                att_b.name
            )
        })?;
        if want_sha != got_sha {
            return Err(format!(
                "entry {id} attachment {:?} bytes differ (sha256 mismatch)",
                att_a.name
            ));
        }
    }

    // Timestamps — tolerant compare (second precision).
    compare_times(
        &format!("entry {id}"),
        a.times.creation_time,
        b.times.creation_time,
        "creation_time",
    )?;
    compare_times(
        &format!("entry {id}"),
        a.times.last_modification_time,
        b.times.last_modification_time,
        "last_modification_time",
    )?;
    compare_times(
        &format!("entry {id}"),
        a.times.last_access_time,
        b.times.last_access_time,
        "last_access_time",
    )?;

    // History snapshots — compare shape + the plaintext shape recorded
    // inside the JSON column.
    if a.history.len() != b.history.len() {
        return Err(format!(
            "entry {id} history length: {} vs {}",
            a.history.len(),
            b.history.len()
        ));
    }
    for (i, (ha, hb)) in a.history.iter().zip(b.history.iter()).enumerate() {
        compare_str(id, &format!("history[{i}].title"), &ha.title, &hb.title)?;
        compare_str(
            id,
            &format!("history[{i}].username"),
            &ha.username,
            &hb.username,
        )?;
        compare_str(id, &format!("history[{i}].url"), &ha.url, &hb.url)?;
        compare_str(id, &format!("history[{i}].notes"), &ha.notes, &hb.notes)?;
        compare_str(
            id,
            &format!("history[{i}].password"),
            &ha.password,
            &hb.password,
        )?;
    }

    Ok(())
}

fn compare_str(id: uuid::Uuid, field: &str, a: &str, b: &str) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("entry {id} {field}: {a:?} vs {b:?}"))
    }
}

/// Truncate to whole seconds, compare. KDBX serialisation drops
/// sub-second precision (`<Times>` elements carry an ISO-8601 string
/// without milliseconds), so anything finer is irrecoverable on round
/// trip. Per task 2.5 findings.
///
/// Also: the v1 `SQLite` schema declares every timestamp column NOT NULL,
/// so a source-side `None` round-trips as `Some(epoch)`. We treat those
/// two as equivalent (both ≡ "no information"); the alternative is a
/// schema change to nullable timestamp columns, which is a Phase 4
/// design decision, not a 2.7 test-harness concern.
fn compare_times(
    ctx: &str,
    a: Option<chrono::DateTime<chrono::Utc>>,
    b: Option<chrono::DateTime<chrono::Utc>>,
    field: &str,
) -> Result<(), String> {
    let to_secs = |dt: Option<chrono::DateTime<chrono::Utc>>| dt.map_or(0, |d| d.timestamp());
    if to_secs(a) == to_secs(b) {
        Ok(())
    } else {
        Err(format!(
            "{ctx} {field}: {a:?} vs {b:?} (second-precision mismatch)"
        ))
    }
}

/// Build a `ref_id → SHA-256` lookup for a vault's binary pool.
fn build_binary_sha_pool(vault: &Vault) -> Vec<[u8; 32]> {
    vault
        .binaries
        .iter()
        .map(|b| {
            let mut h = Sha256::new();
            h.update(&b.data);
            let out = h.finalize();
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&out);
            sha
        })
        .collect()
}

// ─────────────────────── tests ───────────────────────

#[test]
fn round_trip_minimal() {
    assert_kdbx_round_trips(make_minimal_vault(), "minimal");
}

#[test]
fn round_trip_rich() {
    assert_kdbx_round_trips(make_rich_vault(), "rich");
}

#[test]
fn round_trip_with_unicode_content() {
    let mut kdbx = fresh_kdbx_v4("unicode");
    let root = kdbx.vault().root.id;
    kdbx.add_entry(
        root,
        NewEntry::new("🦀 Krabby")
            .username("аліса")
            .password(SecretString::from("p4ss🔑w0rd"))
            .url("https://例え.example/")
            .notes("Notes 中文 with emoji 😀 and combining á"),
    )
    .expect("add unicode entry");
    let group = kdbx
        .add_group(root, NewGroup::new("Группа"))
        .expect("group");
    kdbx.add_entry(
        group,
        NewEntry::new("Tāmaki Makaurau")
            .username("kia ora")
            .password(SecretString::from("Pō mārie 🌙"))
            .tags(vec!["te-reo".into(), "māori".into()]),
    )
    .expect("entry under unicode group");
    assert_kdbx_round_trips(kdbx, "unicode");
}

#[test]
fn round_trip_with_empty_strings() {
    let mut kdbx = fresh_kdbx_v4("empty-strings");
    let root = kdbx.vault().root.id;
    // Bare-bones: only title; everything else empty.
    kdbx.add_entry(root, NewEntry::new("just-title"))
        .expect("add empty-fields entry");
    // Title-and-password only.
    kdbx.add_entry(
        root,
        NewEntry::new("title+pw").password(SecretString::from("pw")),
    )
    .expect("add title+pw entry");
    // No password, has username/url.
    kdbx.add_entry(
        root,
        NewEntry::new("no-pw")
            .username("alice")
            .url("https://example.com/"),
    )
    .expect("add no-pw entry");
    assert_kdbx_round_trips(kdbx, "empty-strings");
}

#[test]
fn round_trip_keepass_core_fixture() {
    // Optional: round-trip a real KDBX3 fixture if the keepass-core
    // checkout is co-located with this repo. The repo layout (Keys/
    // → KeysCore + KeepassCore as sibling directories) is assumed; if
    // the relative path doesn't resolve we skip gracefully so this
    // test doesn't fail in unfamiliar checkouts.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../KeepassCore/tests/fixtures/keepassxc/kdbx3-basic.kdbx");
    if !fixture.exists() {
        eprintln!(
            "skipping round_trip_keepass_core_fixture: {} not found",
            fixture.display()
        );
        return;
    }

    let composite = CompositeKey::from_password(b"test-basic-002");
    let kdbx = Kdbx::open(&fixture)
        .expect("open fixture")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite, Some(protector()))
        .expect("unlock fixture");

    // Round-trip using the fixture's own composite password — we
    // need a separate harness here because the harness uses
    // COMPOSITE_PW for re-open. Inline the body with the fixture's
    // password.
    let dir = tempfile::tempdir().expect("tempdir");
    let engine_path = dir.path().join("engine.sqlite");
    let kdbx_path = dir.path().join("round_trip.kdbx");

    let source_vault = kdbx
        .vault_with_unwrapped_protected()
        .expect("source vault unwrap");

    let mut engine =
        Engine::open(&engine_path, &FixedKey(DB_KEY_BYTES), protector()).expect("engine open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");

    let mut kdbx = kdbx;
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx)
        .expect("save_to_kdbx");
    drop(engine);
    drop(kdbx);

    let reopened = Kdbx::open(&kdbx_path)
        .expect("reopen")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite, Some(protector()))
        .expect("unlock");
    let reopened_vault = reopened
        .vault_with_unwrapped_protected()
        .expect("reopened unwrap");

    if let Err(diff) = vault_round_trip_eq(&source_vault, &reopened_vault) {
        panic!("round-trip diverged [keepass-core kdbx3-basic]: {diff}");
    }
}

/// Performance smoke test — `#[ignore]`-d so `cargo test` doesn't
/// pay the cost on every run. Invoke with
/// `cargo test --release -- --ignored round_trip_large_vault`.
#[test]
#[ignore = "slow; run with `cargo test --release -- --ignored`"]
fn round_trip_large_vault() {
    let n = 877;
    let started = std::time::Instant::now();
    let kdbx = make_large_vault(n);
    eprintln!("built vault ({n} entries) in {:?}", started.elapsed());

    let t = std::time::Instant::now();
    assert_kdbx_round_trips(kdbx, "large");
    eprintln!("round-tripped {n} entries in {:?}", t.elapsed());
}
