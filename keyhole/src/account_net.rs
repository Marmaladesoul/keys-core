//! What the `account-*` verbs that run real nodes share: a device with its
//! keys and a node on the loopback interface, waiting for entries to sync,
//! and naming authors and devices in output.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use keys_ffi::keys_iroh_sync::{Identity, IrohNode, NodeConfig, bind_local_node_for_testing};
use keys_ffi::{DeviceSyncKeys, PairingAccountKeys, PairingDeviceKeys, next_statement_sequence};

use crate::pairing::hex;

/// How long a reader waits for a write to sync across. Everything is on the
/// loopback interface, so this is only reached when something is wrong.
pub(crate) const SYNC_WAIT: Duration = Duration::from_secs(30);
/// How often a reader looks again while waiting for a write.
pub(crate) const SYNC_POLL: Duration = Duration::from_millis(100);

/// A loopback node's files, removed when the run ends.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(name: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("keyhole-account-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create scratch dir {}", path.display()))?;
        Ok(Self(path))
    }

    pub(crate) fn dir(&self, leaf: &str) -> String {
        self.0.join(leaf).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One device: its keys and a node on the loopback interface.
pub(crate) struct Device {
    pub(crate) name: &'static str,
    pub(crate) node: Arc<IrohNode>,
    pub(crate) keys: Arc<PairingDeviceKeys>,
    pub(crate) sync_keys: Arc<DeviceSyncKeys>,
    pub(crate) author: Vec<u8>,
    _scratch: Scratch,
}

impl Device {
    pub(crate) async fn start(name: &'static str) -> Result<Self> {
        let scratch = Scratch::new(name)?;
        let node = bind_local_node_for_testing(NodeConfig {
            identity: Identity::generate(),
            blob_dir: scratch.dir("blobs"),
            doc_dir: scratch.dir("docs"),
            relay_urls: Vec::new(),
        })
        .await?;
        let author = unhex(&node.author_id().await?)?;
        let device = PairingDeviceKeys::generate()?;
        // As a client does: the signing key read back from its stored form.
        let sync_keys = DeviceSyncKeys::from_stored(device.sync_stored_form())?;
        Ok(Self {
            name,
            node,
            keys: device,
            sync_keys,
            author,
            _scratch: scratch,
        })
    }

    /// This device's enrolment in `account`, with its node's real ids.
    pub(crate) fn enrol(&self, account: &PairingAccountKeys) -> Result<Vec<u8>> {
        Ok(account.enrol_device(
            self.keys.public_keys(),
            self.node.pairing_endpoint_id(),
            self.author.clone(),
        )?)
    }

    /// Waits until this node holds `author`'s entry at `key` with `hash`.
    pub(crate) async fn wait_for_entry(
        &self,
        doc: &str,
        author: &[u8],
        key: &[u8],
        hash: &str,
    ) -> Result<()> {
        let author = hex(author);
        let deadline = tokio::time::Instant::now() + SYNC_WAIT;
        loop {
            let entries = self.node.list_entries(doc.to_owned()).await?;
            if entries
                .iter()
                .any(|e| e.author == author && e.key == key && e.hash_hex == hash)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("{}: an entry never synced across", self.name);
            }
            tokio::time::sleep(SYNC_POLL).await;
        }
    }
}

pub(crate) fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("a slice's length fits in u64")
}

/// Who each author and device id belongs to, for output.
pub(crate) struct Names(Vec<(&'static str, Vec<u8>, Vec<u8>)>);

impl Names {
    pub(crate) fn of(devices: &[&Device]) -> Self {
        Self(
            devices
                .iter()
                .map(|d| (d.name, d.author.clone(), d.keys.public_keys().signing))
                .collect(),
        )
    }

    pub(crate) fn author(&self, author: &[u8]) -> &'static str {
        self.0
            .iter()
            .find(|(_, a, _)| a == author)
            .map_or("unknown", |(name, _, _)| name)
    }

    pub(crate) fn device(&self, device_id: &[u8]) -> &'static str {
        self.0
            .iter()
            .find(|(_, _, d)| d == device_id)
            .map_or("unknown", |(name, _, _)| name)
    }
}

/// A statement sequence from this machine's clock, as a client takes one.
pub(crate) fn sequence(previous: Option<u64>) -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the clock is before the Unix epoch")?;
    let now = u64::try_from(now.as_micros()).context("the clock is out of range")?;
    next_statement_sequence(previous, now).context("this place's sequences are used up")
}

pub(crate) fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("not hex: {text}");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("hex"))
        .collect()
}
