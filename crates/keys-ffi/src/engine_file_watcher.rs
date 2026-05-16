//! [`VaultFileWatcher`] — foreign-implementable file watcher trait.
//!
//! Bridges to [`keys_engine::FileWatcher`]. Frontends that want
//! `NSFilePresenter`-coordinated watching (Keys-Mac) or cloud-provider
//! change feeds implement this and the engine uses it directly. The
//! `NotifyFileWatcher` default backed by the `notify` crate is also
//! constructable from the FFI side as a convenience.

use std::sync::{Arc, Mutex};

use keys_engine::{
    FileWatcher as EngFileWatcher, FileWatcherEvent as EngFileWatcherEvent,
    FileWatcherObserver as EngFileWatcherObserver,
};

/// Foreign-implemented file watcher. Mirrors
/// [`keys_engine::FileWatcher`].
#[uniffi::export(with_foreign)]
pub trait VaultFileWatcher: Send + Sync {
    /// Install (or clear, with `None`) the observer the watcher should
    /// deliver events to.
    fn set_observer(&self, observer: Option<Arc<dyn VaultFileWatcherObserver>>);
}

/// Foreign-implemented sink for [`FileWatcherEvent`].
#[uniffi::export(with_foreign)]
pub trait VaultFileWatcherObserver: Send + Sync {
    fn on_event(&self, event: FileWatcherEvent);
}

/// Wire-friendly mirror of [`keys_engine::FileWatcherEvent`].
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FileWatcherEvent {
    /// Content changed externally. `mtime_unix_ms` and `size_bytes` are
    /// `None` when the watcher can't observe them (cloud providers).
    ContentChanged {
        mtime_unix_ms: Option<i64>,
        size_bytes: Option<u64>,
    },
    Unavailable {
        reason: String,
    },
    Available,
    ConflictMarker {
        description: String,
    },
}

impl From<EngFileWatcherEvent> for FileWatcherEvent {
    fn from(e: EngFileWatcherEvent) -> Self {
        match e {
            EngFileWatcherEvent::ContentChanged { mtime, size } => Self::ContentChanged {
                mtime_unix_ms: mtime.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .and_then(|d| i64::try_from(d.as_millis()).ok())
                }),
                size_bytes: size,
            },
            EngFileWatcherEvent::Unavailable { reason } => Self::Unavailable { reason },
            EngFileWatcherEvent::Available => Self::Available,
            EngFileWatcherEvent::ConflictMarker { description } => {
                Self::ConflictMarker { description }
            }
            // `#[non_exhaustive]` upstream — future variants collapse
            // to `Available` (the most conservative interpretation).
            other => {
                let _ = other;
                Self::Available
            }
        }
    }
}

impl From<FileWatcherEvent> for EngFileWatcherEvent {
    fn from(e: FileWatcherEvent) -> Self {
        match e {
            FileWatcherEvent::ContentChanged {
                mtime_unix_ms,
                size_bytes,
            } => Self::ContentChanged {
                mtime: mtime_unix_ms.and_then(|ms| {
                    let secs = u64::try_from(ms.checked_div(1000)?).ok()?;
                    let nanos = u32::try_from(ms.rem_euclid(1000) * 1_000_000).ok()?;
                    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
                }),
                size: size_bytes,
            },
            FileWatcherEvent::Unavailable { reason } => Self::Unavailable { reason },
            FileWatcherEvent::Available => Self::Available,
            FileWatcherEvent::ConflictMarker { description } => {
                Self::ConflictMarker { description }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Bridges
// ────────────────────────────────────────────────────────────────────────

/// Wraps a foreign-implemented [`VaultFileWatcher`] so the engine sees
/// the upstream [`keys_engine::FileWatcher`] trait.
pub(crate) struct BridgeFileWatcher {
    inner: Arc<dyn VaultFileWatcher>,
    /// Holds the currently-installed engine-side observer so the
    /// bridge can wrap/unwrap it when [`Self::set_observer`] is called.
    current: Mutex<Option<Arc<BridgeObserverFromEngine>>>,
}

impl std::fmt::Debug for BridgeFileWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeFileWatcher(<foreign>)")
    }
}

impl BridgeFileWatcher {
    pub(crate) fn new(inner: Arc<dyn VaultFileWatcher>) -> Self {
        Self {
            inner,
            current: Mutex::new(None),
        }
    }
}

impl EngFileWatcher for BridgeFileWatcher {
    fn set_observer(&self, observer: Option<Arc<dyn EngFileWatcherObserver>>) {
        if let Some(eng_obs) = observer {
            let wrapper = Arc::new(BridgeObserverFromEngine { inner: eng_obs });
            *self.current.lock().unwrap() = Some(Arc::clone(&wrapper));
            self.inner
                .set_observer(Some(wrapper as Arc<dyn VaultFileWatcherObserver>));
        } else {
            *self.current.lock().unwrap() = None;
            self.inner.set_observer(None);
        }
    }
}

/// Adapter that wears the foreign-side [`VaultFileWatcherObserver`] trait
/// but forwards every event to the engine-side
/// [`keys_engine::FileWatcherObserver`] the engine installed.
#[derive(Debug)]
struct BridgeObserverFromEngine {
    inner: Arc<dyn EngFileWatcherObserver>,
}

impl VaultFileWatcherObserver for BridgeObserverFromEngine {
    fn on_event(&self, event: FileWatcherEvent) {
        self.inner.on_event(event.into());
    }
}

/// Build the engine-side `Arc<dyn FileWatcher>` from an optional foreign
/// watcher.
pub(crate) fn bridge(
    watcher: Option<Arc<dyn VaultFileWatcher>>,
) -> Option<Arc<dyn EngFileWatcher>> {
    watcher.map(|w| Arc::new(BridgeFileWatcher::new(w)) as Arc<dyn EngFileWatcher>)
}
