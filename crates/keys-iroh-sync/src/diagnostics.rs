//! Opt-in diagnostic log of the transport's own tracing events.
//!
//! iroh, iroh-docs and this crate report connection, discovery and
//! sync-round progress through `tracing`. Without an installed
//! subscriber those events are discarded, so a stall between two peers
//! leaves nothing behind but the caller's own "round failed" line.
//! [`enable_diagnostic_log`] installs a process-wide subscriber that
//! appends them to a file the caller names.
//!
//! What may reach the file is fixed here, not chosen by the caller:
//! [`DIAGNOSTIC_LOG_FILTER`] caps every target at `debug`. iroh-docs'
//! `trace`-level actor events format whole actions, and an
//! import-namespace action carries the namespace secret, so `trace`
//! must never be enabled. At `debug` the events carry node ids,
//! namespace ids, content hashes, socket addresses and relay URLs —
//! peer metadata, not vault content or key material.
//!
//! The file is kept owner-only (0600 on unix), including one left
//! behind by an earlier run. Its size is bounded: once it passes
//! [`DIAGNOSTIC_LOG_ROTATE_BYTES`], the next write first renames it to
//! `<path>` + [`ROTATED_LOG_SUFFIX`] (replacing any older one) and starts
//! a fresh file, so at most two files of about that size exist.

use crate::error::{Result, SyncError};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;

/// Per-target levels written to the diagnostic log. `debug` is the
/// ceiling for every target; see the module docs for why `trace` is
/// excluded. Targets match by prefix, so the `iroh` directive also
/// covers every `iroh_*` crate not named after it; those are named so
/// the set that reaches the file is exactly what's written here.
pub const DIAGNOSTIC_LOG_FILTER: &str = "warn,keys_iroh_sync=debug,iroh=debug,iroh_dns=debug,iroh_docs=debug,iroh_gossip=info,iroh_relay=info,iroh_blobs=info,iroh_base=info,iroh_io=info,iroh_metrics=info,iroh_tickets=info,iroh_util=info";

/// Size past which the log is moved aside before the next write.
pub const DIAGNOSTIC_LOG_ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// Appended to the log's path to name the one rotated-out generation.
pub const ROTATED_LOG_SUFFIX: &str = ".1";

/// Install a process-wide `tracing` subscriber that appends the
/// transport's events to the file at `path`.
///
/// Call it once, before [`crate::IrohNode::bind`], so the bind's own
/// events are captured. A second call in the same process fails without
/// touching the file: the global subscriber can only be set once.
#[uniffi::export]
pub fn enable_diagnostic_log(path: String) -> Result<()> {
    if tracing::dispatcher::has_been_set() {
        return Err(SyncError::Generic(
            "diagnostic log already enabled for this process".to_owned(),
        ));
    }
    let writer = RotatingFile::open(PathBuf::from(path))?;
    let filter: Targets = DIAGNOSTIC_LOG_FILTER
        .parse()
        .map_err(|e| SyncError::Generic(format!("diagnostic log filter: {e}")))?;
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_writer(Mutex::new(writer))
            .with_ansi(false),
    );
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| SyncError::Generic(format!("diagnostic log already enabled: {e}")))?;
    tracing::info!(filter = DIAGNOSTIC_LOG_FILTER, "diagnostic log enabled");
    Ok(())
}

/// An append-only owner-only file that moves itself aside once it
/// passes [`DIAGNOSTIC_LOG_ROTATE_BYTES`]. Unbuffered, so a killed
/// process loses nothing it logged.
struct RotatingFile {
    path: PathBuf,
    file: File,
    len: u64,
}

impl RotatingFile {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        let file = open_owner_only(&path)?;
        let len = file.metadata()?.len();
        Ok(Self { path, file, len })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let mut rotated = self.path.as_os_str().to_owned();
        rotated.push(ROTATED_LOG_SUFFIX);
        std::fs::rename(&self.path, rotated)?;
        self.file = open_owner_only(&self.path)?;
        self.len = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.len > DIAGNOSTIC_LOG_ROTATE_BYTES {
            self.rotate()?;
        }
        let written = self.file.write(buf)?;
        self.len += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn open_owner_only(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_parses_and_never_reaches_trace() {
        let filter: Targets = DIAGNOSTIC_LOG_FILTER.parse().expect("filter parses");
        for target in [
            "keys_iroh_sync",
            "iroh",
            "iroh::magicsock",
            "iroh_dns",
            "iroh_docs::actor",
            "iroh_gossip",
            "iroh_relay",
            "iroh_blobs",
            "noq_proto",
            "some_other_crate",
        ] {
            assert!(
                !filter.would_enable(target, &tracing::Level::TRACE),
                "{target} must not log at trace"
            );
        }
        assert!(filter.would_enable("iroh_docs::engine::live", &tracing::Level::DEBUG));
        assert!(filter.would_enable("iroh_dns", &tracing::Level::DEBUG));
        // Prefix siblings of `iroh` get only what the filter names for them.
        assert!(!filter.would_enable("iroh_metrics", &tracing::Level::DEBUG));
        assert!(!filter.would_enable("iroh_tickets", &tracing::Level::DEBUG));
        assert!(!filter.would_enable("some_other_crate", &tracing::Level::INFO));
    }

    #[test]
    fn rotates_once_past_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.log");
        let rotated = dir.path().join(format!("sync.log{ROTATED_LOG_SUFFIX}"));

        let mut writer = RotatingFile::open(path.clone()).unwrap();
        writer.write_all(b"small").unwrap();
        assert!(!rotated.exists());

        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(DIAGNOSTIC_LOG_ROTATE_BYTES + 1)
            .unwrap();
        let mut writer = RotatingFile::open(path.clone()).unwrap();
        writer.write_all(b"fresh").unwrap();
        assert_eq!(
            std::fs::metadata(&rotated).unwrap().len(),
            DIAGNOSTIC_LOG_ROTATE_BYTES + 1
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_is_made_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.log");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        RotatingFile::open(path.clone()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
