//! A held conflict's settle while another engine writes the same mirror on
//! its own connection.
//!
//! The settle projects the vault, decides from the owners' conflict rows,
//! then lands an adopted merge. These tests put the other engine's write in
//! that window: a field protector that runs an action on a chosen session
//! key request, the one point a test sees inside an engine call. The engine
//! asks for the key at fixed points, so the timing is exact.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{EntryId, HistoryPolicy, NewEntry, Vault};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use keys_engine::{DbKey, Engine, EntryUpdate, KeyProvider, KeyProviderError};
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
    /// Run `action` on the request after the next `skip` requests.
    fn arm(&self, skip: usize, action: impl FnOnce() + Send + 'static) {
        *self.armed.lock().unwrap() = Some((skip, Box::new(action)));
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
    let edit_other = |db_path: std::path::PathBuf, other: Uuid, notes: &'static str| {
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
    };
    f.hook.arm(
        UPDATE_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile 1"),
    );
    set_username(&mut f, "u-a");
    assert!(f.hook.fired(), "the second engine never wrote");

    f.hook.arm(
        RESOLVER_OPEN_REQUESTS_BEFORE_LANDING,
        edit_other(f.db_path.clone(), f.other, "meanwhile 2"),
    );
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
    assert!(
        payload.is_some(),
        "b still clashes with local, so the resolver has something to show"
    );
}
