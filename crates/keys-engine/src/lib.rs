pub mod conflict_resolution;
pub mod engine;
pub mod error;
pub mod events;
pub mod file_watcher;
pub mod fingerprint;
pub mod ingest;
pub mod key_provider;
pub mod meta;
pub mod migrations;
pub mod model;
pub mod mutations;
pub mod portable;
pub mod predicate;
pub mod predicate_builtin;
pub mod predicate_sql;
pub mod projection;
pub mod reads;
pub mod reconcile;
pub mod reveal;
pub mod save;
pub mod smart_folder;
pub mod strength;
pub mod totp;

pub use engine::{DisconnectReason, Engine, ReconcileTrigger, VaultState};
pub use error::{EngineError, IngestError, ProjectionError, RevealError};
pub use events::{
    ChangeEvent, ConflictPayload, DataChangeObserver, EntryDeletionInfo, EntryMove,
    EntryParentGroups, GroupDeletionInfo, GroupMove,
};
pub use file_watcher::{
    FileWatcher, FileWatcherError, FileWatcherEvent, FileWatcherObserver, NotifyFileWatcher,
};
pub use fingerprint::fingerprint;
pub use key_provider::{DbKey, KeyProvider, KeyProviderError};
pub use meta::DatabaseMetadata;
pub use migrations::MigrationError;
pub use model::{
    AttachmentRef, CustomFieldRef, EntryFull, EntrySummary, EntryUpdate, GroupNode, GroupUpdate,
    HistoricEntry, IconRef, NewCustomField, NewEntryFields, NewGroupFields, Pagination,
    SmartFolder, StrengthBucket,
};
pub use portable::{PortableAttachment, PortableEntry};
pub use predicate::Predicate;
pub use predicate_builtin::{
    BUILTIN_SMART_FOLDERS, BuiltinFolderIcon, BuiltinSmartFolder, BuiltinSmartFolderKind,
    EXPIRING_SOON_WINDOW, RECENTLY_MODIFIED_WINDOW, expired, expiring_soon, recently_modified,
    recycle_bin_contents, weak_password,
};
pub use predicate_sql::{CompileError, CompiledPredicate, compile as compile_predicate};
pub use reconcile::{MergeResult, MergeStats};
// Re-export the keepass-merge resolution surface as the engine's
// canonical "conflict resolution" carrier. Phase 4 task 4.7 mirrors
// `keepass-merge`'s shape verbatim — wrapping it would be a layer of
// noise without adding any meaning.
pub use keepass_merge::{
    AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution as ConflictResolution,
};
pub use save::SelfWriteSignature;
pub use strength::{Strength, strength};
