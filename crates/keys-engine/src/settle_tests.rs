//! A held conflict's settle, and a resolution of it, while another engine
//! writes the same mirror on its own connection.
//!
//! The settle projects the vault, decides from the owners' conflict rows,
//! then lands an adopted merge. These tests put the other engine's write in
//! that window: a field protector that runs an action on a chosen session
//! key request, the one point a test sees inside an engine call. The engine
//! asks for the key at fixed points, so the timing is exact.

use std::sync::{Arc, Mutex};

use crate::{
    ConflictResolution, ConflictSide, DbKey, Engine, EntryUpdate, KeyProvider, KeyProviderError,
};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{EntryId, HistoryPolicy, NewEntry, Vault};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use secrecy::SecretString;
use uuid::Uuid;

const SESSION_KEY_BYTES: [u8; 32] = [0x9c; 32];
const DB_KEY_BYTES: [u8; 32] = [0x42; 32];
const PASSWORD: &[u8] = b"pw";

/// Session-key requests an `update_entry` of an entry with parked rows
/// makes before its settle lands: the edit's own, the settle's projection,
/// and the settle's own. The landing's is the next one.
const UPDATE_REQUESTS_BEFORE_LANDING: usize = 3;
/// Session-key requests resolver-open makes before its settle lands: the
/// projection's and its own. The landing's is the next one.
const RESOLVER_OPEN_REQUESTS_BEFORE_LANDING: usize = 2;
/// Session-key requests between an abandoned settle's landing and its
/// retry's: the re-projection the abandoned settle takes.
const REQUESTS_BEFORE_RETRY_LANDING: usize = 1;

#[derive(Debug)]
struct FixedKey;

impl KeyProvider for FixedKey {
    fn acquire_db_key(&self) -> Result<DbKey, KeyProviderError> {
        Ok(DbKey::from_bytes(DB_KEY_BYTES))
    }
}

#[derive(Debug)]
struct FixedProtector;

impl FieldProtector for FixedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes(SESSION_KEY_BYTES))
    }
}

type Action = Box<dyn FnOnce() + Send>;

/// [`FixedProtector`] that runs an armed action on a chosen request.
#[derive(Default)]
struct HookedProtector {
    /// The action and how many requests to let pass before running it.
    armed: Mutex<Option<(usize, Action)>>,
}

impl std::fmt::Debug for HookedProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HookedProtector")
    }
}

impl HookedProtector {
    /// Run `action` on the request after the next `skip` requests. There is
    /// one slot: arming over a pending action would drop it unrun, and the
    /// test would pass without testing what it was for.
    fn arm(&self, skip: usize, action: impl FnOnce() + Send + 'static) {
        let mut armed = self.armed.lock().unwrap();
        assert!(armed.is_none(), "an action is already armed and hasn't run");
        *armed = Some((skip, Box::new(action)));
    }

    fn fired(&self) -> bool {
        self.armed.lock().unwrap().is_none()
    }
}

impl FieldProtector for HookedProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        let due = {
            let mut armed = self.armed.lock().unwrap();
            match armed.as_mut() {
                Some((0, _)) => armed.take().map(|(_, action)| action),
                Some((skip, _)) => {
                    *skip -= 1;
                    None
                }
                None => None,
            }
        };
        // Unlocked first: the action opens an engine of its own.
        if let Some(action) = due {
            action();
        }
        Ok(SessionKey::from_bytes(SESSION_KEY_BYTES))
    }
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(PASSWORD)
}

fn plain() -> Arc<dyn FieldProtector> {
    Arc::new(FixedProtector)
}

fn reopen_kdbx(path: &std::path::Path) -> Kdbx<Unlocked> {
    Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock_with_protector(&composite(), Some(plain()))
        .expect("unlock kdbx")
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    kdbx_path: std::path::PathBuf,
    engine: Engine,
    hook: Arc<HookedProtector>,
    seed: Uuid,
    other: Uuid,
}

/// An engine over a saved vault holding `seed` (username `alice`) and an
/// unrelated `other`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("keys.db");
    let kdbx_path = dir.path().join("vault.kdbx");
    let mut kdbx =
        Kdbx::create_empty_v4_with_protector(&composite(), "test", Some(plain())).expect("create");
    let root = kdbx.vault().root.id;
    let seed = kdbx
        .add_entry(
            root,
            NewEntry::new("seed")
                .username("alice")
                .password(SecretString::new("pw0".into())),
        )
        .expect("seed")
        .0;
    let other = kdbx
        .add_entry(root, NewEntry::new("other"))
        .expect("other")
        .0;
    let hook = Arc::new(HookedProtector::default());
    let mut engine = Engine::open(&db_path, &FixedKey, hook.clone(), None).expect("open");
    engine.ingest_from_kdbx(&kdbx).expect("ingest");
    engine
        .save_to_kdbx(&kdbx_path, &mut kdbx, None)
        .expect("save");
    engine
        .ingest_from_kdbx(&reopen_kdbx(&kdbx_path))
        .expect("re-ingest");
    Fixture {
        _dir: dir,
        db_path,
        kdbx_path,
        engine,
        hook,
        seed,
        other,
    }
}

/// A peer's replica of the saved vault, with `seed` retitled and given
/// another username.
fn peer(f: &Fixture, title: &str, username: &str) -> Vault {
    let mut kdbx = reopen_kdbx(&f.kdbx_path);
    let (title, username) = (title.to_owned(), username.to_owned());
    kdbx.edit_entry(EntryId(f.seed), HistoryPolicy::Snapshot, |e| {
        e.set_title(title);
        e.set_username(username);
    })
    .expect("peer edit");
    kdbx.vault_with_unwrapped_protected().expect("unwrap")
}

/// A second engine on the fixture's mirror, as another process sharing it
/// would open one.
fn sidecar(db_path: &std::path::Path) -> Engine {
    Engine::open(db_path, &FixedKey, plain(), None).expect("open a second engine")
}

/// An action editing `other`'s notes through a second engine on the mirror:
/// a vault write, so it moves `mutation_seq` (if `notes` differ from what
/// `other` already has: a no-op edit writes nothing).
fn edit_other(db_path: std::path::PathBuf, other: Uuid, notes: &'static str) -> impl FnOnce() {
    move || {
        sidecar(&db_path)
            .update_entry(
                other,
                EntryUpdate {
                    notes: Some(notes.into()),
                    ..Default::default()
                },
            )
            .expect("write through the second engine");
    }
}

/// An action moving the mirror (see [`edit_other`]) at the landing it is
/// armed for, and again at the landing of the settle's one retry.
fn move_twice(f: &Fixture) -> impl FnOnce() + Send + 'static {
    let (hook, db_path, other) = (f.hook.clone(), f.db_path.clone(), f.other);
    move || {
        edit_other(db_path.clone(), other, "moved at the landing")();
        hook.arm(
            REQUESTS_BEFORE_RETRY_LANDING,
            edit_other(db_path, other, "moved at the retry's landing"),
        );
    }
}

/// A converged local with owner a's row dissolved but still parked: a's
/// adoption of its title was abandoned because the mirror moved.
fn dissolved_but_parked() -> Fixture {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    f.engine
        .ingest_peer("a", &peer(&f, "seed-a", "u-a"))
        .expect("ingest a");
    f.hook.arm(
        UPDATE_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile"),
    );
    set_username(&mut f, "u-a");
    assert!(f.hook.fired(), "the second engine never wrote");
    assert_eq!(
        f.engine.conflict_owners(f.seed).unwrap(),
        vec!["a".to_owned()]
    );
    f
}

fn set_username(f: &mut Fixture, username: &str) {
    f.engine
        .update_entry(
            f.seed,
            EntryUpdate {
                username: Some(username.into()),
                ..Default::default()
            },
        )
        .expect("local edit");
}

fn seed_title(f: &Fixture) -> String {
    f.engine
        .entry(f.seed)
        .expect("entry")
        .expect("present")
        .title
}

/// A settle consumes the conflict row it merged, as it read it. Another
/// engine re-parking the peer's newer version of that row in the window
/// moves no `mutation_seq` (only vault tables do), so the landing goes
/// ahead; the newer row must survive it, since the landed merge never saw
/// it.
#[test]
fn a_settle_keeps_a_row_re_parked_while_it_lands() {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    let first = peer(&f, "seed-peer", "u-peer");
    f.engine.ingest_peer("peer", &first).expect("ingest peer");
    assert_eq!(
        f.engine.entries_with_parked_conflict().unwrap(),
        vec![f.seed]
    );

    // Local converges on the peer's username, so the row dissolves and its
    // title is adopted; as the adoption lands, the peer's next version
    // (another username: a fresh clash) is parked through a second engine.
    let newer = peer(&f, "seed-peer-2", "u-peer-2");
    let db_path = f.db_path.clone();
    f.hook.arm(UPDATE_REQUESTS_BEFORE_LANDING, move || {
        sidecar(&db_path)
            .ingest_peer("peer", &newer)
            .expect("park the newer version");
    });
    set_username(&mut f, "u-peer");
    assert!(f.hook.fired(), "the second engine never wrote");

    assert_eq!(
        seed_title(&f),
        "seed-peer",
        "the adoption didn't land, so the row guard went untested"
    );
    assert_eq!(
        f.engine.entries_with_parked_conflict().unwrap(),
        vec![f.seed],
        "the newer row was dropped with the one the settle consumed"
    );
    assert!(
        f.engine
            .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
            .expect("held payload")
            .is_some(),
        "the newer row's clash is still there to resolve"
    );
}

/// When a settle is abandoned because the mirror moved, its dissolved row
/// stays parked, and its owner can sort ahead of one that still clashes.
/// Resolver-open must surface the clashing owner, not give up on the entry
/// at the first owner it finds clean.
#[test]
fn resolver_open_surfaces_a_live_owner_behind_a_dissolved_one() {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    f.engine
        .ingest_peer("a", &peer(&f, "seed-a", "u-a"))
        .expect("ingest a");
    f.engine
        .ingest_peer("b", &peer(&f, "seed", "u-b"))
        .expect("ingest b");

    // Local converges on a's username, dissolving a's row; a write through
    // a second engine during each settle leaves it parked.
    f.hook.arm(
        UPDATE_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile 1"),
    );
    set_username(&mut f, "u-a");
    assert!(f.hook.fired(), "the second engine never wrote");

    f.hook
        .arm(RESOLVER_OPEN_REQUESTS_BEFORE_LANDING, move_twice(&f));
    let payload = f
        .engine
        .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
        .expect("held payload");
    assert!(f.hook.fired(), "the second engine never wrote");
    assert_eq!(
        seed_title(&f),
        "seed",
        "a's adoption landed, so no dissolved row was left parked ahead of b"
    );
    let payload = payload.expect("b still clashes with local, so the resolver shows it");

    // Resolving b's clash consumes b's row only. a's row still carries a
    // title local lacks, so dropping it with b's would lose that change.
    let mut resolution = ConflictResolution::default();
    for conflict in &payload.entry_conflicts {
        resolution.entry_field_choices.insert(
            conflict.entry_id,
            conflict
                .field_deltas
                .iter()
                .map(|d| (d.key.clone(), ConflictSide::Local))
                .collect(),
        );
    }
    f.engine
        .apply_conflict_resolution(payload.id, &resolution)
        .expect("resolve b");
    assert_eq!(
        f.engine.conflict_owners(f.seed).expect("owners"),
        vec!["a".to_owned()],
        "resolving b's clash dropped a's unmerged row"
    );

    // With nothing writing meanwhile, the next settle lands a's change.
    assert!(
        f.engine
            .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
            .expect("held payload")
            .is_none()
    );
    assert_eq!(seed_title(&f), "seed-a", "a's title was never adopted");
    assert_eq!(
        f.engine.conflict_owners(f.seed).expect("owners"),
        Vec::<String>::new()
    );
}

/// A settle decides on one projection which rows to drop as dissolved and
/// which to land. A peer's newer version of a row it judged dissolved,
/// re-parked while it lands, was never judged: it must survive.
#[test]
fn a_settle_keeps_a_re_parked_row_it_judged_dissolved() {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    // Converging on "u-shared" dissolves both rows: a's carries nothing
    // else, so it is dropped; b's carries a title, so it is landed.
    f.engine
        .ingest_peer("a", &peer(&f, "seed", "u-shared"))
        .expect("ingest a");
    f.engine
        .ingest_peer("b", &peer(&f, "seed-b", "u-shared"))
        .expect("ingest b");

    // a's next version (a fresh clash) is parked through a second engine
    // as the landing starts. Parked directly: a peer ingest there would
    // also settle b itself, moving the mirror under this settle.
    let newer = peer(&f, "seed", "u-a-2");
    let (db_path, seed) = (f.db_path.clone(), f.seed);
    f.hook.arm(UPDATE_REQUESTS_BEFORE_LANDING, move || {
        let sidecar = sidecar(&db_path);
        let entry = crate::util::tree::find_entry(&newer.root, EntryId(seed))
            .expect("peer entry")
            .clone();
        crate::conflict_rows::drop_conflict_rows_for_owner(sidecar.conn(), "a", seed)
            .expect("unpark a");
        crate::conflict_rows::write_peer_entry(
            sidecar.conn(),
            "a",
            &entry,
            &SessionKey::from_bytes(SESSION_KEY_BYTES),
            &[],
        )
        .expect("re-park a");
    });
    set_username(&mut f, "u-shared");
    assert!(f.hook.fired(), "the second engine never wrote");

    assert_eq!(
        seed_title(&f),
        "seed-b",
        "b's change didn't land, so the drop as read went untested"
    );
    assert_eq!(
        f.engine.conflict_owners(f.seed).expect("owners"),
        vec!["a".to_owned()],
        "a's newer row was dropped as the dissolved one it replaced"
    );
}

/// A settle whose landing finds the mirror moved applies none of its
/// decision: the rows it judged dissolved against the stale projection are
/// not dropped either.
#[test]
fn a_settle_drops_nothing_once_the_mirror_moves() {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    f.engine
        .ingest_peer("a", &peer(&f, "seed", "u-shared"))
        .expect("ingest a");
    f.engine
        .ingest_peer("b", &peer(&f, "seed-b", "u-shared"))
        .expect("ingest b");

    f.hook.arm(
        UPDATE_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile"),
    );
    set_username(&mut f, "u-shared");
    assert!(f.hook.fired(), "the second engine never wrote");

    assert_eq!(
        seed_title(&f),
        "seed",
        "b's change landed over a moved mirror"
    );
    assert_eq!(
        f.engine.conflict_owners(f.seed).expect("owners"),
        vec!["a".to_owned(), "b".to_owned()],
        "a row judged on a stale projection was dropped"
    );
}

/// Resolver open retries a settle the mirror's moving abandoned, so `None`
/// still means nothing is left: the dissolved row is settled, not left
/// parked behind a resolver that has nothing to show.
#[test]
fn resolver_open_retries_a_settle_the_mirror_moved() {
    let mut f = dissolved_but_parked();
    f.hook.arm(
        RESOLVER_OPEN_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile again"),
    );
    let payload = f
        .engine
        .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
        .expect("held payload");
    assert!(f.hook.fired(), "the second engine never wrote");
    assert!(payload.is_none(), "nothing clashes");
    assert_eq!(seed_title(&f), "seed-a", "the retry didn't land a's change");
    assert!(
        f.engine.entries_with_parked_conflict().unwrap().is_empty(),
        "resolver open reported nothing to resolve over a row still parked"
    );
}

/// If the mirror moves again during the retry, resolver open fails, to be
/// opened again, rather than report nothing to resolve over a parked row.
#[test]
fn resolver_open_fails_rather_than_report_nothing_over_a_parked_row() {
    let mut f = dissolved_but_parked();
    f.hook
        .arm(RESOLVER_OPEN_REQUESTS_BEFORE_LANDING, move_twice(&f));
    let opened = f
        .engine
        .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed));
    assert!(f.hook.fired(), "the second engine never wrote twice");
    assert!(
        matches!(opened, Err(crate::EngineError::ResolutionMismatch { .. })),
        "{opened:?}"
    );
    assert_eq!(
        f.engine.conflict_owners(f.seed).unwrap(),
        vec!["a".to_owned()]
    );

    // Opened again with nothing writing meanwhile, it settles the row.
    assert!(
        f.engine
            .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
            .expect("held payload")
            .is_none()
    );
    assert_eq!(seed_title(&f), "seed-a");
    assert_eq!(
        f.engine.entries_with_parked_conflict().unwrap(),
        Vec::<uuid::Uuid>::new()
    );
}

/// Owners that park the same peer value (peers that synced each other)
/// present one clash: a resolution answers it for all of them. An owner
/// parking a different value has a clash of its own, which stays.
#[test]
fn a_resolution_answers_every_owner_parking_the_same_value() {
    let mut f = fixture();
    set_username(&mut f, "u-local");
    let shared = peer(&f, "seed", "u-peer");
    for owner in ["b", "c"] {
        f.engine.ingest_peer(owner, &shared).expect("ingest");
    }
    f.engine
        .ingest_peer("d", &peer(&f, "seed", "u-other"))
        .expect("ingest d");

    let payload = f
        .engine
        .held_conflict_payload(&f.kdbx_path, &composite(), Some(f.seed))
        .expect("held payload")
        .expect("a clash to resolve");
    let mut resolution = ConflictResolution::default();
    for conflict in &payload.entry_conflicts {
        resolution.entry_field_choices.insert(
            conflict.entry_id,
            conflict
                .field_deltas
                .iter()
                .map(|d| (d.key.clone(), ConflictSide::Local))
                .collect(),
        );
    }
    f.engine
        .apply_conflict_resolution(payload.id, &resolution)
        .expect("resolve");
    assert_eq!(
        f.engine.conflict_owners(f.seed).expect("owners"),
        vec!["d".to_owned()],
        "the choice answered b and c alike, and nothing else"
    );
}
