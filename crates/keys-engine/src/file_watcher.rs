#![allow(clippy::doc_markdown)]
// ↑ Doc comments here name a lot of platform-specific terms (FSEvents,
//   NSFilePresenter, KeePass, GDrive, KeeWeb, WebDAV …) that aren't
//   Rust items and don't benefit from backticks. Suppress doc_markdown
//   for this module rather than littering the prose with backticks.

//! Pluggable file-watcher trait — Phase 4 task 4.5.
//!
//! Detects external writes to the KDBX file (e.g. another KeePass-compatible
//! client editing the same vault, an autofill extension committing a write,
//! an iCloud / Dropbox / GDrive sync drop-in) and fires events so the engine
//! can reconcile against the on-disk KDBX via
//! [`Engine::reconcile_with_disk_park_conflicts`](crate::Engine::reconcile_with_disk_park_conflicts).
//!
//! ## Why pluggable?
//!
//! Per the 2026-05-16 decisions log:
//!
//! - macOS frontends (Keys-Mac) want to honour `NSFilePresenter` /
//!   `NSFileCoordinator` semantics so iCloud sync, Spotlight indexing, and
//!   other coordinated-write clients play nice with the vault file. The
//!   `notify` crate uses FSEvents under the hood and bypasses that
//!   coordination. So Keys-Mac will plug in its own
//!   `NSFilePresenter`-backed [`FileWatcher`] impl.
//! - Future cloud-provider integrations (Dropbox direct-API, GDrive,
//!   WebDAV) will deliver "changed" events out of band of any filesystem
//!   watcher. The event taxonomy ([`FileWatcherEvent`]) is shaped to
//!   accommodate those without an engine-side refactor.
//! - Everyone else gets a sensible default backed by the cross-platform
//!   `notify` crate ([`NotifyFileWatcher`]).
//!
//! ## Self-write filtering
//!
//! Per [`Engine::save_to_kdbx`](crate::Engine::save_to_kdbx), the engine
//! records the `(mtime, size)` of its own KDBX writes via
//! [`SelfWriteSignature`](crate::SelfWriteSignature). The watcher trait
//! itself fires events unconditionally — the engine's internal observer
//! does the signature check (via
//! [`Engine::consume_self_write_signature`](crate::Engine::consume_self_write_signature))
//! and suppresses reconcile when the event matches our own most recent
//! write. This keeps the trait simple: implementers only have to report
//! what they observed, they don't have to know anything about engine state.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Watches the underlying vault storage (file system, cloud provider, …)
/// for changes the engine didn't cause itself. Fires events to a registered
/// observer so the engine can reconcile.
pub trait FileWatcher: Send + Sync + std::fmt::Debug {
    /// Register an observer for file change events. Replaces any prior
    /// observer. `None` clears the observer.
    fn set_observer(&self, observer: Option<Arc<dyn FileWatcherObserver>>);
}

/// Callback target for [`FileWatcher`]. Frontends rarely implement this
/// directly — the engine installs its own internal observer when given a
/// `FileWatcher` via [`Engine::open`](crate::Engine::open).
pub trait FileWatcherObserver: Send + Sync + std::fmt::Debug {
    /// Called by a [`FileWatcher`] on every external storage event.
    ///
    /// Must be cheap and non-blocking — implementations typically dispatch
    /// to another thread / actor. Called from whatever thread the
    /// underlying watcher runs on; no ordering guarantees across events.
    fn on_event(&self, event: FileWatcherEvent);
}

/// File-watcher event taxonomy.
///
/// Designed to accommodate both local-file semantics (FSEvents,
/// `NSFilePresenter`, inotify, the `notify` crate) and future cloud-provider
/// semantics (Dropbox change feed, GDrive changes API, WebDAV polling).
/// `#[non_exhaustive]` so we can add variants (e.g. `BulkChange`,
/// `RenamedTo { new_path }`) without breaking matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FileWatcherEvent {
    /// The watched storage's content has changed (was modified externally).
    /// Trigger to re-read and reconcile.
    ///
    /// `mtime` / `size`, when present, are the watcher's view of the
    /// file's state at the moment of the event. The engine compares
    /// these against its
    /// [`SelfWriteSignature`](crate::SelfWriteSignature) to suppress
    /// self-write echoes. Cloud-provider watchers without filesystem
    /// semantics may set them to `None`; the engine then conservatively
    /// triggers reconcile (no self-write can have happened on a
    /// cloud-managed file from our process).
    ContentChanged {
        /// Filesystem mtime at the moment of the event, if observable.
        mtime: Option<std::time::SystemTime>,
        /// Filesystem byte length at the moment of the event, if observable.
        size: Option<u64>,
    },

    /// The storage is no longer reachable. For local files: file was
    /// deleted, moved, or permissions revoked. For cloud: network down,
    /// auth expired. Causes the engine to transition to
    /// [`VaultState::Disconnected`](crate::VaultState::Disconnected).
    Unavailable {
        /// Human-readable diagnostic, surfaced via
        /// [`DisconnectReason::FileUnreadable`](crate::DisconnectReason::FileUnreadable).
        reason: String,
    },

    /// The storage is reachable again after a prior `Unavailable`. Causes
    /// the engine to transition back to
    /// [`VaultState::Active`](crate::VaultState::Active).
    Available,

    /// A "conflict marker" was detected — e.g. Dropbox created a
    /// "Conflicted Copy" sibling file; GDrive surfaced a sync conflict in
    /// its changes feed. The engine and frontend should surface this to
    /// the user — these conflicts can't be auto-resolved because the
    /// conflicting writer wasn't using our 3-way merge. Not produced by
    /// [`NotifyFileWatcher`]; reserved for future cloud-provider impls.
    ConflictMarker {
        /// Description of the conflict (provider-specific text).
        description: String,
    },
}

/// Errors specific to setting up or running a [`FileWatcher`].
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FileWatcherError {
    /// The underlying `notify` watcher failed to initialise or register
    /// the path. Carries the notify-crate diagnostic.
    #[error("file watcher init failed: {0}")]
    NotifyInit(String),

    /// I/O error while preparing the watch (e.g. resolving the parent
    /// directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ────────────────────────────────────────────────────────────────────────
// NotifyFileWatcher — default `notify`-crate-backed implementation.
// ────────────────────────────────────────────────────────────────────────

/// Default [`FileWatcher`] impl backed by the `notify` crate.
///
/// Uses platform-native APIs under the hood (FSEvents on macOS, inotify on
/// Linux, `ReadDirectoryChangesW` on Windows) via
/// [`notify::recommended_watcher`]. Watches the parent directory of the
/// target file (watching the file directly misses delete/rename events on
/// some platforms) and filters events down to those touching the specific
/// path we care about.
///
/// **Does NOT integrate with macOS `NSFileCoordinator` semantics.**
/// Frontends that need that behaviour (Keys-Mac will) should provide their
/// own [`FileWatcher`] impl backed by `NSFilePresenter`.
///
/// ## Threading
///
/// `notify::recommended_watcher` runs its own internal thread that calls
/// our event-handler closure. We don't spawn an additional drain thread —
/// the closure dispatches straight to the registered observer. Observers
/// are expected to be cheap (push to a channel, set a flag); blocking
/// work belongs on the observer side.
///
/// ## Drop
///
/// Dropping a `NotifyFileWatcher` drops the inner
/// [`notify::RecommendedWatcher`], which stops its background thread.
/// Observer access shuts down with it.
pub struct NotifyFileWatcher {
    /// The target file we report events for. Events on siblings in the
    /// watched parent directory are filtered out.
    target_path: PathBuf,
    /// Currently-registered observer. Swapped via [`Self::set_observer`].
    observer: Arc<Mutex<Option<Arc<dyn FileWatcherObserver>>>>,
    /// The `notify` watcher. Kept alive for the lifetime of this struct;
    /// dropping it terminates the underlying platform watcher thread.
    _watcher: notify::RecommendedWatcher,
    /// Sentinel thread handle used by the drop-terminates-watcher-thread
    /// integration test. The thread itself does no real work; it polls
    /// a `Weak` reference to our observer mutex and exits when the
    /// watcher is dropped. Kept always-on (not `cfg(test)`) so the
    /// integration test in `tests/file_watcher.rs` can join it without
    /// needing dev-only feature flags.
    sentinel: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for NotifyFileWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyFileWatcher")
            .field("target_path", &self.target_path)
            .finish_non_exhaustive()
    }
}

impl NotifyFileWatcher {
    /// Start watching `path`. The parent directory must exist; the file
    /// itself does not have to (the watcher will fire `Available` if it
    /// appears later).
    ///
    /// # Errors
    ///
    /// - [`FileWatcherError::Io`] if `path` has no parent directory.
    /// - [`FileWatcherError::NotifyInit`] if the `notify` watcher refuses
    ///   to start or to register the parent directory.
    ///
    /// # Panics
    ///
    /// Panics only on a poisoned internal `Mutex` — i.e. if another
    /// thread already panicked while holding the observer lock. In
    /// normal use this cannot happen, so the public API stays
    /// panic-free.
    pub fn new(path: PathBuf) -> Result<Self, FileWatcherError> {
        use notify::{EventKind, RecursiveMode, Watcher};

        let parent = path
            .parent()
            .ok_or_else(|| {
                FileWatcherError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "watched path has no parent directory",
                ))
            })?
            .to_path_buf();

        // Canonicalise the parent (resolve symlinks) so the watched
        // directory matches the paths FSEvents/inotify deliver. On
        // macOS tempdir paths under `/var/folders/...` are symlinks
        // to `/private/var/folders/...`; FSEvents reports the
        // canonical form. Without this we'd filter out every event.
        // The target path is canonicalised by joining the canonical
        // parent with the original filename.
        let canonical_parent = std::fs::canonicalize(&parent).unwrap_or(parent.clone());
        let file_name = path.file_name().ok_or_else(|| {
            FileWatcherError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "watched path has no file name",
            ))
        })?;
        let canonical_target = canonical_parent.join(file_name);

        let observer: Arc<Mutex<Option<Arc<dyn FileWatcherObserver>>>> = Arc::new(Mutex::new(None));
        let observer_for_handler = Arc::clone(&observer);
        let target_for_handler = canonical_target.clone();

        // Track whether we last saw the file as available, so we only emit
        // `Available` on a true transition rather than on every Create.
        let was_available = Arc::new(Mutex::new(path.exists()));

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else {
                return;
            };
            // Filter to events touching our specific file path. `notify`
            // delivers events for everything under the watched directory.
            if !event.paths.iter().any(|p| p == &target_for_handler) {
                return;
            }

            let stat_now = || -> (Option<std::time::SystemTime>, Option<u64>) {
                match std::fs::metadata(&target_for_handler) {
                    Ok(m) => (m.modified().ok(), Some(m.len())),
                    Err(_) => (None, None),
                }
            };

            let outgoing = match event.kind {
                EventKind::Modify(_) | EventKind::Any | EventKind::Other => {
                    let (mtime, size) = stat_now();
                    Some(FileWatcherEvent::ContentChanged { mtime, size })
                }
                EventKind::Create(_) => {
                    let mut flag = was_available.lock().unwrap();
                    if *flag {
                        // We were already available; treat as a content
                        // change (some platforms emit Create for atomic
                        // replace via rename-over).
                        let (mtime, size) = stat_now();
                        Some(FileWatcherEvent::ContentChanged { mtime, size })
                    } else {
                        *flag = true;
                        Some(FileWatcherEvent::Available)
                    }
                }
                EventKind::Remove(_) => {
                    let mut flag = was_available.lock().unwrap();
                    *flag = false;
                    Some(FileWatcherEvent::Unavailable {
                        reason: format!("file removed: {}", target_for_handler.display()),
                    })
                }
                EventKind::Access(_) => None,
            };

            if let Some(ev) = outgoing {
                let guard = observer_for_handler.lock().unwrap();
                if let Some(obs) = guard.as_ref() {
                    obs.on_event(ev);
                }
            }
        })
        .map_err(|e| FileWatcherError::NotifyInit(e.to_string()))?;

        watcher
            .watch(&canonical_parent, RecursiveMode::NonRecursive)
            .map_err(|e| FileWatcherError::NotifyInit(e.to_string()))?;

        let sentinel = {
            // A sentinel thread that exits when the weak reference to the
            // observer Mutex can no longer be upgraded — i.e. when this
            // `NotifyFileWatcher` is dropped. Used purely so the
            // drop-terminates test has something to join on.
            let weak = Arc::downgrade(&observer);
            let handle = std::thread::spawn(move || {
                while weak.upgrade().is_some() {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            });
            Mutex::new(Some(handle))
        };

        Ok(Self {
            target_path: path,
            observer,
            _watcher: watcher,
            sentinel,
        })
    }

    /// Test-only accessor: take the sentinel thread handle so an
    /// integration test can join on it to assert that this watcher has
    /// been dropped. Returns `None` after the first call.
    ///
    /// Hidden from public docs; not intended for production callers.
    #[doc(hidden)]
    #[must_use]
    pub fn take_sentinel_for_test(&self) -> Option<JoinHandle<()>> {
        self.sentinel.lock().unwrap().take()
    }
}

impl FileWatcher for NotifyFileWatcher {
    fn set_observer(&self, observer: Option<Arc<dyn FileWatcherObserver>>) {
        *self.observer.lock().unwrap() = observer;
    }
}
