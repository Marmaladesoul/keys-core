//! The pairing transport: how two pairing sheets reach each other.
//!
//! Pairing runs on the node's own endpoint, on its own ALPN
//! ([`PAIRING_ALPN`]), so the endpoint ids a pairing binds are the ones the
//! QUIC handshake authenticated. This module carries bytes and decides who
//! may connect when. It runs no key exchange and holds no secret: the
//! exchange lives in `keys-pairing`, behind the sheets, and everything here
//! is untrusted input to it.
//!
//! **A connection starts with one greeting** from whoever dialled, on a
//! stream of its own, answered with one byte (`keys_pairing::greeting`):
//!
//! - a **knock** naming an invite id, answered from the node's invite book
//!   whether or not a sheet is open, after which the connection ends. Until
//!   the client has opened the book ([`IrohNode::pairing_open_invite_book`])
//!   a knock gets no answer at all, so a knock that arrives while a device
//!   is still starting up is tried again instead of being told, wrongly and
//!   for good, that its invite isn't outstanding;
//! - a **call** ("I will type a code") or an **approach** ("I am showing
//!   one"), accepted only while this node has a [`PairingListener`] open
//!   for the opposite role and the same kind of pairing, and free.
//!
//! So a node with no listener open accepts no call and no approach, and
//! tells a knock only what its invite book says. Opening a listener is what
//! "the sheet is open" means to the transport; closing it closes every link
//! it accepted.
//!
//! **An accepted call or approach is a [`PairingLink`].** On it, each run of
//! the exchange travels on a stream of its own, opened by the side that
//! types, starting with its Hello. A stream is ordered and reliable, and a
//! new run's stream replaces the last one, so a message from an earlier run
//! can't arrive in a later one. The verified session's frames follow on the
//! run's stream. A link closes itself, and gives up its place, when its
//! connection ends.
//!
//! **What a client must do.**
//! - Hand each message to the sheet with the endpoint id its link reports,
//!   send what the sheet answers on the stream the message came from, and
//!   stop when the sheet says the run is over.
//! - When a run's stream fails, tell the sheet. On the displaying side use
//!   the sheet's `abandon_run_of` with that stream's peer: a displaying
//!   sheet can hold several links, and a stream that fails on one of them
//!   must not end a run in flight with another.
//! - After the last message of a run or a session, call
//!   [`PairingRunStream::finish`] before closing anything. Closing a stream,
//!   a link or a listener discards what hasn't been delivered yet.
//! - When a link reports it has closed, take what is left on its run's
//!   stream before closing the link: closing also discards what was
//!   received and not yet taken.
//! - Close listeners and links explicitly when the sheet closes. Dropping
//!   them closes them too, but a runtime that collects garbage drops late.
//!
//! **Limits.** A greeting must arrive within [`GREETING_TIMEOUT`], and every
//! write is given a bounded time for the other side to take it, so a peer
//! that stops reading can't hold a place open. At most
//! [`MAX_INBOUND_CONNECTIONS`] pairing connections are served at once. A
//! message is at most [`MAX_EXCHANGE_MESSAGE_BYTES`] until the client says
//! the pairing has verified ([`PairingRunStream::allow_session_frames`]),
//! then at most [`MAX_SESSION_FRAME_BYTES`]. Those caps bound what this
//! module buffers. They don't bound what the QUIC layer underneath will
//! buffer for a connection's peer on streams nobody reads: that is set by
//! the endpoint's flow-control windows, which this module doesn't change.

// uniffi exports take owned arguments.
#![allow(clippy::needless_pass_by_value)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, TransportAddr};
use keys_pairing::greeting::MAX_GREETING_BYTES;
use keys_pairing::{
    Greeting, InviteBook, InviteId, InviteRecord, KnockAnswer, KnockOutcome, MeetingAnswer,
    PairingAddress, PairingKind, PairingLink as ParsedLink, advert,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};

use crate::node::IrohNode;

/// The ALPN pairing connections use. The trailing number is the transport's
/// version; the exchange inside has its own.
pub const PAIRING_ALPN: &[u8] = b"keys/pairing/1";

/// How long a connection has to say its greeting, how long a dialler waits
/// for the answer, and how long the first message of a run may take to
/// follow its stream.
pub const GREETING_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a dial may take to connect.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a message on a run's stream may wait for the other side to take
/// it. The other side sets how much it will accept; one that accepts nothing
/// would otherwise hold the sender for good.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Pairing connections served at once, across knocks and links.
pub const MAX_INBOUND_CONNECTIONS: usize = 16;
/// Links a displaying listener holds at once. The displaying sheet itself
/// runs with one typing side at a time and turns the others away.
pub const MAX_DISPLAY_LINKS: usize = 4;
/// Links a typing listener holds at once: the device that approached it.
pub const MAX_TYPE_LINKS: usize = 1;
/// The longest message before a pairing has verified. Every exchange
/// message, and a Person's key-set frame, is a fraction of this.
pub const MAX_EXCHANGE_MESSAGE_BYTES: usize = 1024;
/// The longest verified-session frame.
pub const MAX_SESSION_FRAME_BYTES: usize = 1 << 20;

const LENGTH_PREFIX_BYTES: usize = 4;
/// How much is read from a stream at a time.
const READ_CHUNK_BYTES: usize = 4096;

/// QUIC application close codes. Diagnostic only: nothing reads them back.
const CLOSE_DONE: VarInt = VarInt::from_u32(0);
const CLOSE_REFUSED: VarInt = VarInt::from_u32(1);
const CLOSE_PROTOCOL: VarInt = VarInt::from_u32(2);

/// Why a pairing transport call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PairingTransportError {
    /// A link, an advertisement, an endpoint id or an address didn't parse.
    #[error("not a usable pairing address: {0}")]
    Address(String),
    /// The other endpoint couldn't be reached.
    #[error("couldn't reach the other device: {0}")]
    Unreachable(String),
    /// The other endpoint has no sheet open for this pairing.
    #[error("the other device isn't waiting for this pairing")]
    NotListening,
    /// The other endpoint's sheet is taken by someone else.
    #[error("the other device is busy with another pairing")]
    Busy,
    /// The other endpoint sent something the transport doesn't allow.
    #[error("the other device didn't follow the pairing transport")]
    Protocol,
    /// The stream, link or listener has closed, or the other device ended
    /// the connection without an answer.
    #[error("the pairing connection closed")]
    Closed,
    /// Nothing arrived in the time allowed.
    #[error("timed out waiting for the other device")]
    TimedOut,
    /// A message is longer than the stream allows.
    #[error("a pairing message was too large")]
    TooLarge,
    /// The call doesn't apply: wrong role for this link, a listener is
    /// already open, or the invite book is not open yet (or already is).
    #[error("that doesn't apply to this pairing link or listener")]
    WrongState,
    /// The invite couldn't be issued or restored.
    #[error("invite: {0}")]
    Invite(String),
}

type Result<T> = std::result::Result<T, PairingTransportError>;

/// Which side of a pairing this node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PairingRole {
    /// Shows the code.
    Display,
    /// Types the code.
    Type,
}

/// What is being paired. The same two kinds the exchange binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PairingTransportKind {
    Device,
    Person,
}

impl From<PairingTransportKind> for PairingKind {
    fn from(kind: PairingTransportKind) -> Self {
        match kind {
            PairingTransportKind::Device => Self::Device,
            PairingTransportKind::Person => Self::Person,
        }
    }
}

/// Where to dial. `direct_addresses` are socket addresses (`ip:port`)
/// learnt on the local network; a link never has any.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingTarget {
    pub endpoint_id: Vec<u8>,
    pub relay_url: Option<String>,
    pub direct_addresses: Vec<String>,
}

impl PairingTarget {
    fn from_address(address: &PairingAddress) -> Self {
        Self {
            endpoint_id: address.endpoint().to_vec(),
            relay_url: address.relay_url().map(str::to_owned),
            direct_addresses: Vec::new(),
        }
    }

    fn endpoint_addr(&self) -> Result<EndpointAddr> {
        let id: [u8; 32] = self
            .endpoint_id
            .as_slice()
            .try_into()
            .map_err(|_| PairingTransportError::Address("an endpoint id is 32 bytes".into()))?;
        let id = PublicKey::from_bytes(&id)
            .map_err(|_| PairingTransportError::Address("not an endpoint id".into()))?;
        let mut addrs = Vec::new();
        if let Some(relay) = &self.relay_url {
            // The same check a link's relay gets, then iroh's own parse.
            PairingAddress::new(*id.as_bytes(), Some(relay.clone()))
                .map_err(|e| PairingTransportError::Address(e.to_string()))?;
            let relay: RelayUrl = relay
                .parse()
                .map_err(|_| PairingTransportError::Address("not a relay URL".into()))?;
            // However it was spelt, what the URL parser made of the host
            // must be a name, not an address. The check above is meant to
            // refuse every spelling of an address already; this is here in
            // case the two ever read a host differently.
            if relay.domain().is_none() {
                return Err(PairingTransportError::Address(
                    "a relay is named by host, not by address".into(),
                ));
            }
            addrs.push(TransportAddr::Relay(relay));
        }
        for direct in &self.direct_addresses {
            let socket: SocketAddr = direct
                .parse()
                .map_err(|_| PairingTransportError::Address("not a socket address".into()))?;
            addrs.push(TransportAddr::Ip(socket));
        }
        Ok(EndpointAddr::from_parts(id, addrs))
    }
}

/// An invite as a link carried it. Nothing in it is verified.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingInvite {
    /// The account identity key the inviter claims. Open the displaying
    /// sheet expecting it.
    pub inviter_identity: Vec<u8>,
    /// The issuing device: where the knock goes.
    pub target: PairingTarget,
    pub invite_id: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub expires_at_unix: u64,
    /// The inviter's name for themself, sanitised. A claim, not a fact.
    pub inviter_name: String,
}

/// A parsed `keys://pair/…` link.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PairingParsedLink {
    /// A device waiting to join an account.
    Device { target: PairingTarget },
    /// An invite to pair as People.
    Person { invite: PairingInvite },
}

/// Reads a `keys://pair/…` link a person pasted or a camera scanned.
#[uniffi::export]
pub fn pairing_parse_link(text: String) -> Result<PairingParsedLink> {
    let link =
        ParsedLink::parse(&text).map_err(|e| PairingTransportError::Address(e.to_string()))?;
    Ok(match link {
        ParsedLink::Device(address) => PairingParsedLink::Device {
            target: PairingTarget::from_address(&address),
        },
        ParsedLink::Person(invite) => PairingParsedLink::Person {
            invite: PairingInvite {
                inviter_identity: invite.inviter_identity.to_vec(),
                target: PairingTarget::from_address(&invite.address),
                invite_id: invite.invite_id.to_vec(),
                expires_at_unix: invite.expires_at,
                inviter_name: invite.inviter_name,
            },
        },
    })
}

/// One entry of a DNS-SD TXT record.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingTxtEntry {
    pub key: String,
    pub value: String,
}

/// What a node with an open pairing sheet advertises on the local network:
/// a DNS-SD service of `service_type` on `port`, with `txt` as its record.
/// The platform does the advertising, and only while the sheet is open.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingAdvertisement {
    pub service_type: String,
    pub port: u16,
    pub txt: Vec<PairingTxtEntry>,
}

/// What separates a link-local IPv6 address from its interface's name.
const SCOPED_ADDRESS_MARK: char = '%';

/// Turns a discovered service into somewhere to dial: its TXT record, plus
/// the IP addresses and port the browser resolved for it. Only the IPv4
/// addresses are kept: the advertised port is the node's IPv4 socket's
/// ([`IrohNode::pairing_advertisement`]), and its IPv6 socket is bound on a
/// port of its own. Anything that isn't an IP address is an error.
#[uniffi::export]
pub fn pairing_target_from_advertisement(
    txt: Vec<PairingTxtEntry>,
    resolved_ip_addresses: Vec<String>,
    port: u16,
) -> Result<PairingTarget> {
    let entries: Vec<(String, String)> = txt
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect();
    let address = advert::address_from_txt(&entries)
        .map_err(|e| PairingTransportError::Address(e.to_string()))?;
    let mut target = PairingTarget::from_address(&address);
    for ip in resolved_ip_addresses {
        // A link-local IPv6 address comes with the interface it is on
        // (`fe80::1%en0`), which `IpAddr` doesn't parse. It is IPv6, so it
        // would be left out anyway.
        if ip.contains(SCOPED_ADDRESS_MARK) {
            continue;
        }
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|_| PairingTransportError::Address("not an IP address".into()))?;
        if ip.is_ipv4() {
            target
                .direct_addresses
                .push(SocketAddr::new(ip, port).to_string());
        }
    }
    Ok(target)
}

/// Makes a name from an unverified source (an invite, a discovered device)
/// safe to show as plain text.
#[uniffi::export]
#[must_use]
pub fn pairing_sanitize_display_name(name: String) -> String {
    keys_pairing::sanitize_display_name(&name)
}

/// An invite this node issued.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingIssuedInvite {
    /// The `keys://pair/person/…` link to send.
    pub link: String,
    pub invite_id: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub expires_at_unix: u64,
}

/// An outstanding invite, as a client stores it between launches.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingInviteRecord {
    pub invite_id: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub expires_at_unix: u64,
    /// The endpoint that opened the invite, once one has: the endpoint to
    /// call for the verification.
    pub opened_by: Option<Vec<u8>>,
}

impl From<InviteRecord> for PairingInviteRecord {
    fn from(record: InviteRecord) -> Self {
        Self {
            invite_id: record.invite_id.to_vec(),
            expires_at_unix: record.expires_at,
            opened_by: record.opened_by.map(|endpoint| endpoint.to_vec()),
        }
    }
}

/// What a knock was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PairingKnockAnswer {
    /// The invite is outstanding and this node is its opener.
    Opened,
    /// Nothing to open: the invite was never issued there, or was
    /// cancelled, used, expired or opened by another device. Don't knock
    /// again.
    NotOutstanding,
}

/// Told when one of this node's invites is opened for the first time: the
/// moment to store the invite's record with its opener. Each opening is
/// announced once and not again after a restart, so an opener that isn't
/// stored then is lost with the process, and the invite goes back to
/// having none. [`IrohNode::pairing_invites`] shows the current records at
/// any time.
///
/// The endpoint named is where to dial for the verification. It was set by
/// whichever device knocked first and proves nothing about who that was.
///
/// Called on a thread of its own, so a slow or failing listener harms
/// nothing else.
#[uniffi::export(with_foreign)]
pub trait PairingInviteListener: Send + Sync {
    fn invite_opened(&self, invite_id: Vec<u8>, opener_endpoint_id: Vec<u8>);
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invite_id_from(bytes: &[u8]) -> Result<InviteId> {
    bytes
        .try_into()
        .map_err(|_| PairingTransportError::Address("an invite id is 16 bytes".into()))
}

// ─── the node's pairing state ───────────────────────────────────────────────

/// What a node is listening for.
struct Listening {
    listener_id: u64,
    role: PairingRole,
    kind: PairingKind,
    slots: Arc<Semaphore>,
    accepted: Arc<Accepted>,
}

/// The links a listener has accepted, shared between the listener and the
/// handler that accepts for it.
#[derive(Default)]
struct Accepted {
    /// Accepted and not yet taken with [`PairingListener::next_link`]. Never
    /// longer than the listener has slots: a link holds a slot until it
    /// closes, and closed ones are dropped from here before one is added.
    waiting: Mutex<VecDeque<Arc<PairingLink>>>,
    /// Every link accepted, taken or not, so that closing the listener can
    /// close them all.
    all: Mutex<Vec<Weak<PairingLink>>>,
    /// Signalled when a link is added or the listener ends.
    changed: Notify,
    /// The listener was closed, or the node shut down.
    ended: AtomicBool,
}

impl Accepted {
    fn add(&self, link: Arc<PairingLink>) {
        {
            let mut all = lock(&self.all);
            all.retain(|earlier| earlier.strong_count() > 0);
            all.push(Arc::downgrade(&link));
        }
        {
            let mut waiting = lock(&self.waiting);
            waiting.retain(|earlier| !earlier.is_closed());
            waiting.push_back(link);
        }
        self.changed.notify_waiters();
    }

    /// The oldest waiting link that is still open.
    fn take(&self) -> Option<Arc<PairingLink>> {
        let mut waiting = lock(&self.waiting);
        while let Some(link) = waiting.pop_front() {
            if !link.is_closed() {
                return Some(link);
            }
        }
        None
    }

    /// Nothing more will be accepted: wakes whoever waits for a link.
    fn end(&self) {
        self.ended.store(true, Ordering::Relaxed);
        self.changed.notify_waiters();
    }

    /// Closes every link accepted, taken or not.
    fn close_all(&self) {
        lock(&self.waiting).clear();
        for link in lock(&self.all).drain(..) {
            if let Some(link) = link.upgrade() {
                link.close();
            }
        }
    }
}

/// The invite book once the client has opened it, with who hears of
/// openings.
struct OpenInvites {
    book: InviteBook,
    listener: Arc<dyn PairingInviteListener>,
}

struct HubState {
    /// `None` until the client opens the book: until then no knock is
    /// answered.
    invites: Mutex<Option<OpenInvites>>,
    listening: Mutex<Option<Listening>>,
    inbound: Arc<Semaphore>,
    next_listener_id: AtomicU64,
    /// Seconds added to the wall clock. Only test scaffolding moves it.
    clock_offset_secs: AtomicU64,
}

/// A node's pairing state and the handler for its pairing ALPN.
#[derive(Clone)]
pub(crate) struct PairingHub(Arc<HubState>);

impl std::fmt::Debug for PairingHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingHub")
    }
}

impl PairingHub {
    pub(crate) fn new() -> Self {
        Self(Arc::new(HubState {
            invites: Mutex::new(None),
            listening: Mutex::new(None),
            inbound: Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS)),
            next_listener_id: AtomicU64::new(0),
            clock_offset_secs: AtomicU64::new(0),
        }))
    }

    /// Seconds since the Unix epoch. A wall clock set before the epoch
    /// reads as the epoch.
    fn now(&self) -> u64 {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        wall.saturating_add(self.0.clock_offset_secs.load(Ordering::Relaxed))
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn advance_clock(&self, secs: u64) {
        self.0.clock_offset_secs.fetch_add(secs, Ordering::Relaxed);
    }

    /// Serves one inbound connection: reads its greeting and acts on it.
    async fn serve(&self, connection: Connection, inbound: OwnedSemaphorePermit) {
        let peer = *connection.remote_id().as_bytes();
        let greeting = tokio::time::timeout(GREETING_TIMEOUT, async {
            let (send, mut recv) = connection.accept_bi().await.ok()?;
            let message = read_one_message(&mut recv, MAX_GREETING_BYTES).await.ok()?;
            Some((send, Greeting::decode(&message)?))
        })
        .await;
        let Ok(Some((mut send, greeting))) = greeting else {
            connection.close(CLOSE_PROTOCOL, b"no greeting");
            return;
        };
        match greeting {
            Greeting::Knock { invite_id } => {
                let now = self.now();
                let answered = lock(&self.0.invites).as_mut().map(|open| {
                    let outcome = open.book.answer_knock(&invite_id, peer, now);
                    (outcome, Arc::clone(&open.listener))
                });
                let Some((outcome, listener)) = answered else {
                    // The book isn't open yet, so there is no true answer
                    // to give. Without one the knocker tries again later.
                    connection.close(CLOSE_REFUSED, b"not ready");
                    return;
                };
                // The book has recorded the opener whether or not the answer
                // gets through, so the listener hears of it either way: a
                // knock repeated after a lost answer isn't a first one. On a
                // thread of its own, because it is the client's code: if it
                // blocks or fails, that is all that does.
                if outcome == (KnockOutcome::Opened { first_time: true }) {
                    tokio::task::spawn_blocking(move || {
                        listener.invite_opened(invite_id.to_vec(), peer.to_vec());
                    });
                }
                if answer(&mut send, &KnockAnswer::from(outcome).encode()).await {
                    hang_up(&connection, CLOSE_DONE).await;
                } else {
                    connection.close(CLOSE_PROTOCOL, b"");
                }
            }
            Greeting::Approach { kind } => {
                self.meet(connection, send, peer, PairingRole::Type, kind, inbound)
                    .await;
            }
            Greeting::Call { kind } => {
                self.meet(connection, send, peer, PairingRole::Display, kind, inbound)
                    .await;
            }
        }
    }

    /// Answers a call or an approach that needs this node in `role`.
    async fn meet(
        &self,
        connection: Connection,
        mut send: SendStream,
        peer: [u8; 32],
        role: PairingRole,
        kind: PairingKind,
        inbound: OwnedSemaphorePermit,
    ) {
        let admitted = {
            let listening = lock(&self.0.listening);
            match listening.as_ref() {
                Some(open) if open.role == role && open.kind == kind => {
                    match open.slots.clone().try_acquire_owned() {
                        Ok(slot) => Ok((slot, open.listener_id)),
                        Err(_) => Err(MeetingAnswer::Busy),
                    }
                }
                _ => Err(MeetingAnswer::NotListening),
            }
        };
        match admitted {
            Ok((slot, listener_id)) => {
                if !answer(&mut send, &MeetingAnswer::Accepted.encode()).await {
                    connection.close(CLOSE_PROTOCOL, b"");
                    return;
                }
                let link = PairingLink::start(connection, peer, role, vec![slot, inbound]);
                // The listener may have closed while the answer went out.
                // It hands the link over only if it is still the one
                // listening, and under the lock its close takes, so a link
                // is either closed by that close or never handed over. One
                // that isn't handed over is dropped here, which closes it.
                let listening = lock(&self.0.listening);
                if let Some(open) = listening
                    .as_ref()
                    .filter(|open| open.listener_id == listener_id)
                {
                    open.accepted.add(link);
                }
            }
            Err(refusal) => {
                if answer(&mut send, &refusal.encode()).await {
                    hang_up(&connection, CLOSE_REFUSED).await;
                } else {
                    connection.close(CLOSE_PROTOCOL, b"");
                }
            }
        }
    }
}

impl ProtocolHandler for PairingHub {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        match self.0.inbound.clone().try_acquire_owned() {
            Ok(inbound) => self.serve(connection, inbound).await,
            Err(_) => connection.close(CLOSE_REFUSED, b"too many pairing connections"),
        }
        Ok(())
    }

    /// The node is shutting down: nothing is listening any more, and a
    /// listener waiting for a link is told so.
    fn shutdown(&self) -> impl Future<Output = ()> + Send {
        if let Some(open) = lock(&self.0.listening).take() {
            open.accepted.end();
        }
        std::future::ready(())
    }
}

/// Writes an answer and ends the stream. False if the peer has gone, or
/// won't take the answer in the time a greeting is allowed: how much a peer
/// accepts is the peer's to set, and one that accepts nothing must not keep
/// its place.
async fn answer(send: &mut SendStream, message: &[u8]) -> bool {
    let written = tokio::time::timeout(GREETING_TIMEOUT, write_message(send, message)).await;
    matches!(written, Ok(Ok(()))) && send.finish().is_ok()
}

/// Gives the peer a moment to read what was sent and close, then closes.
async fn hang_up(connection: &Connection, code: VarInt) {
    let _ = tokio::time::timeout(GREETING_TIMEOUT, connection.closed()).await;
    connection.close(code, b"");
}

// ─── framing ────────────────────────────────────────────────────────────────

async fn write_message(send: &mut SendStream, message: &[u8]) -> Result<()> {
    if message.len() > MAX_SESSION_FRAME_BYTES {
        return Err(PairingTransportError::TooLarge);
    }
    let length = u32::try_from(message.len()).map_err(|_| PairingTransportError::TooLarge)?;
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + message.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    send.write_all(&framed)
        .await
        .map_err(|_| PairingTransportError::Closed)
}

/// A whole message out of `buffered`, if one is there. A length over `max`
/// is refused as soon as the prefix is in.
fn take_message(buffered: &mut Vec<u8>, max: usize) -> Result<Option<Vec<u8>>> {
    let Some(prefix) = buffered.first_chunk::<LENGTH_PREFIX_BYTES>() else {
        return Ok(None);
    };
    let length = usize::try_from(u32::from_be_bytes(*prefix))
        .map_err(|_| PairingTransportError::TooLarge)?;
    if length > max {
        return Err(PairingTransportError::TooLarge);
    }
    let end = LENGTH_PREFIX_BYTES + length;
    if buffered.len() < end {
        return Ok(None);
    }
    let rest = buffered.split_off(end);
    let message = buffered.split_off(LENGTH_PREFIX_BYTES);
    *buffered = rest;
    Ok(Some(message))
}

/// The receiving half of a stream. What has arrived but isn't a whole
/// message yet is kept here, so dropping a wait part-way loses nothing.
struct Inbox {
    recv: RecvStream,
    buffered: Vec<u8>,
}

impl Inbox {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buffered: Vec::new(),
        }
    }

    async fn next(&mut self, max: usize) -> Result<Vec<u8>> {
        loop {
            if let Some(message) = take_message(&mut self.buffered, max)? {
                return Ok(message);
            }
            let mut chunk = [0u8; READ_CHUNK_BYTES];
            match self.recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffered.extend_from_slice(&chunk[..read]),
                Ok(None) | Err(_) => return Err(PairingTransportError::Closed),
            }
        }
    }
}

/// Reads one message from a stream that is dropped if this doesn't finish.
async fn read_one_message(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|_| PairingTransportError::Closed)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| PairingTransportError::TooLarge)?;
    if length > max {
        return Err(PairingTransportError::TooLarge);
    }
    let mut message = vec![0u8; length];
    recv.read_exact(&mut message)
        .await
        .map_err(|_| PairingTransportError::Closed)?;
    Ok(message)
}

// ─── a run's stream ─────────────────────────────────────────────────────────

/// One run's stream: the exchange's messages in order, then the verified
/// session's frames.
#[derive(uniffi::Object)]
pub struct PairingRunStream {
    peer: [u8; 32],
    send: tokio::sync::Mutex<SendStream>,
    inbox: tokio::sync::Mutex<Inbox>,
    closed: watch::Sender<bool>,
    session_frames: AtomicBool,
}

impl PairingRunStream {
    fn new(peer: [u8; 32], send: SendStream, inbox: Inbox) -> Arc<Self> {
        Arc::new(Self {
            peer,
            send: tokio::sync::Mutex::new(send),
            inbox: tokio::sync::Mutex::new(inbox),
            closed: watch::Sender::new(false),
            session_frames: AtomicBool::new(false),
        })
    }

    fn receive_limit(&self) -> usize {
        if self.session_frames.load(Ordering::Relaxed) {
            MAX_SESSION_FRAME_BYTES
        } else {
            MAX_EXCHANGE_MESSAGE_BYTES
        }
    }

    #[cfg(test)]
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Runs `work` for at most `limit`, giving up at once if the stream is
    /// closed meanwhile.
    async fn unless_closed<T>(
        &self,
        limit: Duration,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let mut closed = self.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|closed| *closed) => Err(PairingTransportError::Closed),
            finished = tokio::time::timeout(limit, work) => {
                finished.unwrap_or(Err(PairingTransportError::TimedOut))
            }
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PairingRunStream {
    /// The endpoint id the transport authenticated the other side of this
    /// stream as: the same as its link's.
    #[must_use]
    pub fn peer_endpoint_id(&self) -> Vec<u8> {
        self.peer.to_vec()
    }

    /// Sends one message to the other side.
    ///
    /// [`PairingTransportError::TimedOut`] if the other side doesn't take it
    /// within [`SEND_TIMEOUT`]; the stream is closed, since part of the
    /// message may have gone.
    pub async fn send(&self, message: Vec<u8>) -> Result<()> {
        let sent = {
            let mut send = self.send.lock().await;
            self.unless_closed(SEND_TIMEOUT, write_message(&mut send, &message))
                .await
        };
        if sent == Err(PairingTransportError::TimedOut) {
            self.close();
        }
        sent
    }

    /// Waits up to `timeout_ms` for the other side's next message.
    ///
    /// [`PairingTransportError::TimedOut`] leaves the stream usable: what
    /// had arrived is kept for the next call.
    /// [`PairingTransportError::TooLarge`] doesn't: close the stream.
    pub async fn receive(&self, timeout_ms: u64) -> Result<Vec<u8>> {
        let mut inbox = self.inbox.lock().await;
        let limit = self.receive_limit();
        self.unless_closed(Duration::from_millis(timeout_ms), inbox.next(limit))
            .await
    }

    /// The pairing has verified: frames of up to
    /// [`MAX_SESSION_FRAME_BYTES`] are accepted from here on.
    pub fn allow_session_frames(&self) {
        self.session_frames.store(true, Ordering::Relaxed);
    }

    /// This side has sent its last message: ends its half of the stream and
    /// waits up to `timeout_ms` for the other side to have received
    /// everything. Messages can still be received afterwards. Once this
    /// returns `Ok`, what was sent stays readable on the other side even if
    /// this side then closes the stream, its link or its listener.
    /// [`PairingTransportError::Closed`] if the other side had already
    /// ended the stream: the last message may not have been read.
    ///
    /// Call this before closing the stream, its link or its listener:
    /// closing discards whatever hasn't been delivered, the last message
    /// included.
    pub async fn finish(&self, timeout_ms: u64) -> Result<()> {
        let mut send = self.send.lock().await;
        send.finish().map_err(|_| PairingTransportError::Closed)?;
        let delivered = async {
            match send.stopped().await {
                // Everything sent has been received.
                Ok(None) => Ok(()),
                // The other side threw the stream away, read or not, or
                // the connection went.
                Ok(Some(_)) | Err(_) => Err(PairingTransportError::Closed),
            }
        };
        self.unless_closed(Duration::from_millis(timeout_ms), delivered)
            .await
    }

    /// Ends the stream at once. Anything waiting on it stops, and anything
    /// sent but not yet delivered is discarded (see [`Self::finish`]).
    pub fn close(&self) {
        self.closed.send_replace(true);
        // Best effort: a half that is in use ends when its user sees the
        // stream closed and lets go.
        if let Ok(mut send) = self.send.try_lock() {
            let _ = send.reset(CLOSE_DONE);
        }
        if let Ok(mut inbox) = self.inbox.try_lock() {
            let _ = inbox.recv.stop(CLOSE_DONE);
        }
    }
}

/// A run the other side started: its stream and its first message.
#[derive(uniffi::Record)]
pub struct PairingIncomingRun {
    pub stream: Arc<PairingRunStream>,
    /// The typing side's Hello, to hand to the displaying sheet.
    pub hello: Vec<u8>,
}

// ─── a link ─────────────────────────────────────────────────────────────────

/// A connection to one endpoint that agreed to pair: the result of a call or
/// an approach, on either end. It closes itself when its connection ends,
/// whichever side ended it.
#[derive(uniffi::Object)]
pub struct PairingLink {
    connection: Connection,
    peer: [u8; 32],
    role: PairingRole,
    current_run: Mutex<Option<Arc<PairingRunStream>>>,
    /// One accept at a time.
    accepting: tokio::sync::Mutex<()>,
    closed: watch::Sender<bool>,
    /// Places held until the link closes: the listener's slot and the
    /// node's inbound-connection count, on the accepting end.
    held: Mutex<Vec<OwnedSemaphorePermit>>,
}

impl PairingLink {
    /// Makes the link and starts watching its connection, so that a link
    /// whose peer has gone closes and gives up its places without anyone
    /// having to use it first.
    fn start(
        connection: Connection,
        peer: [u8; 32],
        role: PairingRole,
        held: Vec<OwnedSemaphorePermit>,
    ) -> Arc<Self> {
        let link = Arc::new(Self {
            connection: connection.clone(),
            peer,
            role,
            current_run: Mutex::new(None),
            accepting: tokio::sync::Mutex::new(()),
            closed: watch::Sender::new(false),
            held: Mutex::new(held),
        });
        let watched = Arc::downgrade(&link);
        tokio::spawn(async move {
            connection.closed().await;
            if let Some(link) = watched.upgrade() {
                link.connection_ended();
            }
        });
        link
    }

    /// The connection is over, whoever ended it: the link is closed and
    /// gives up its places. The run's stream is left as it is, so that
    /// what the other side sent before it closed can still be received;
    /// after that the stream reports the connection's end itself.
    fn connection_ended(&self) {
        lock(&self.held).clear();
        self.closed.send_replace(true);
    }

    /// Makes `stream` the link's run, ending the one before it.
    fn replace_run(&self, stream: &Arc<PairingRunStream>) {
        if let Some(previous) = lock(&self.current_run).replace(stream.clone()) {
            previous.close();
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PairingLink {
    /// The endpoint id the transport authenticated the other side as: the
    /// `peer` to hand to the sheets and the session.
    #[must_use]
    pub fn peer_endpoint_id(&self) -> Vec<u8> {
        self.peer.to_vec()
    }

    /// Which side of the pairing this node is on this link.
    #[must_use]
    pub fn role(&self) -> PairingRole {
        self.role
    }

    /// Whether the link has closed, from either end. A run's stream on a
    /// link the other side closed can still be read until it is empty.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Waits until the link closes, from either end: the other device went
    /// away or closed its sheet, or this side closed the link.
    pub async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        // The sender is this link's own, so the wait can't fail while the
        // link is there to be waited on.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Typing side: starts a run by sending `hello` (from the typing
    /// sheet's `submit_code`) on a new stream. The run before it, if any, is
    /// ended.
    pub async fn open_run(&self, hello: Vec<u8>) -> Result<Arc<PairingRunStream>> {
        if self.role != PairingRole::Type {
            return Err(PairingTransportError::WrongState);
        }
        if hello.len() > MAX_EXCHANGE_MESSAGE_BYTES {
            return Err(PairingTransportError::TooLarge);
        }
        let opened = tokio::time::timeout(SEND_TIMEOUT, async {
            let (mut send, recv) = self
                .connection
                .open_bi()
                .await
                .map_err(|_| PairingTransportError::Closed)?;
            write_message(&mut send, &hello).await?;
            Ok((send, recv))
        })
        .await
        .unwrap_or(Err(PairingTransportError::TimedOut));
        let (send, recv) = opened?;
        let stream = PairingRunStream::new(self.peer, send, Inbox::new(recv));
        self.replace_run(&stream);
        Ok(stream)
    }

    /// Displaying side: waits up to `timeout_ms` for the typing side to
    /// start a run. The run before it, if any, is ended.
    ///
    /// [`PairingTransportError::TimedOut`] means no run started in time and
    /// the link is still good (a Hello still arriving when the time runs out
    /// is lost with its stream, so allow more than a moment); [`PairingTransportError::Closed`] means the
    /// link is gone. A stream the other side opens and then abandons,
    /// stalls on or overfills before a whole first message is no run, and
    /// is passed over.
    pub async fn accept_run(&self, timeout_ms: u64) -> Result<PairingIncomingRun> {
        if self.role != PairingRole::Display {
            return Err(PairingTransportError::WrongState);
        }
        let _one_at_a_time = self.accepting.lock().await;
        // One wait for the whole call, however many streams are passed
        // over. `timeout` takes any length, `u64::MAX` included.
        tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            loop {
                let (send, recv) = self
                    .connection
                    .accept_bi()
                    .await
                    .map_err(|_| PairingTransportError::Closed)?;
                let mut inbox = Inbox::new(recv);
                let hello =
                    tokio::time::timeout(GREETING_TIMEOUT, inbox.next(MAX_EXCHANGE_MESSAGE_BYTES));
                if let Ok(Ok(hello)) = hello.await {
                    let stream = PairingRunStream::new(self.peer, send, inbox);
                    self.replace_run(&stream);
                    return Ok(PairingIncomingRun { stream, hello });
                }
            }
        })
        .await
        .map_err(|_| PairingTransportError::TimedOut)?
    }

    /// Ends the link and its run at once, and gives up the places it held.
    /// Anything sent but not yet delivered is discarded (see
    /// [`PairingRunStream::finish`]), and so is anything received on the
    /// run's stream but not yet taken.
    pub fn close(&self) {
        if let Some(run) = lock(&self.current_run).take() {
            run.close();
        }
        self.connection.close(CLOSE_DONE, b"");
        self.connection_ended();
    }
}

impl Drop for PairingLink {
    fn drop(&mut self) {
        self.close();
    }
}

// ─── listening ──────────────────────────────────────────────────────────────

/// A node's open pairing sheet, as the transport sees it. While it is open
/// the node accepts calls or approaches for its role and kind; closing it
/// stops that and closes every link it accepted.
///
/// Close it explicitly when the sheet closes. Dropping it closes it too,
/// but on a runtime that collects garbage the drop comes whenever the
/// collector gets to it, and until then the device is still taking part.
#[derive(uniffi::Object)]
pub struct PairingListener {
    hub: PairingHub,
    listener_id: u64,
    accepted: Arc<Accepted>,
}

#[uniffi::export(async_runtime = "tokio")]
impl PairingListener {
    /// Waits for the next endpoint to call or approach. A link whose other
    /// end left before it was taken is passed over.
    /// [`PairingTransportError::Closed`] once the listener is closed or the
    /// node has shut down.
    pub async fn next_link(&self) -> Result<Arc<PairingLink>> {
        loop {
            // Registered before looking, so a link added or an ending
            // signalled in between isn't missed.
            let changed = self.accepted.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.accepted.ended.load(Ordering::Relaxed) {
                return Err(PairingTransportError::Closed);
            }
            if let Some(link) = self.accepted.take() {
                return Ok(link);
            }
            changed.await;
        }
    }

    /// Stops listening and closes every link this listener accepted, taken
    /// with [`Self::next_link`] or not.
    pub fn close(&self) {
        // Deregister first: after this no link is added (see
        // `PairingHub::meet`), so closing them all below misses none.
        {
            let mut listening = lock(&self.hub.0.listening);
            if listening
                .as_ref()
                .is_some_and(|open| open.listener_id == self.listener_id)
            {
                *listening = None;
            }
        }
        self.accepted.end();
        self.accepted.close_all();
    }
}

impl Drop for PairingListener {
    fn drop(&mut self) {
        self.close();
    }
}

// ─── the node's side ────────────────────────────────────────────────────────

impl PairingHub {
    fn listen(&self, role: PairingRole, kind: PairingKind) -> Result<Arc<PairingListener>> {
        let mut listening = lock(&self.0.listening);
        if listening.is_some() {
            return Err(PairingTransportError::WrongState);
        }
        let slots = match role {
            PairingRole::Display => MAX_DISPLAY_LINKS,
            PairingRole::Type => MAX_TYPE_LINKS,
        };
        let listener_id = self.0.next_listener_id.fetch_add(1, Ordering::Relaxed);
        let accepted = Arc::new(Accepted::default());
        *listening = Some(Listening {
            listener_id,
            role,
            kind,
            slots: Arc::new(Semaphore::new(slots)),
            accepted: Arc::clone(&accepted),
        });
        Ok(Arc::new(PairingListener {
            hub: self.clone(),
            listener_id,
            accepted,
        }))
    }
}

/// Dials `target`, greets it and returns the connection, the greeting's
/// stream and the raw answer.
async fn greet(
    endpoint: &Endpoint,
    target: &PairingTarget,
    greeting: Greeting,
) -> Result<(Connection, Vec<u8>)> {
    let addr = target.endpoint_addr()?;
    if addr.id == endpoint.id() {
        return Err(PairingTransportError::Address(
            "that is this device's own address".into(),
        ));
    }
    let connection = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, PAIRING_ALPN))
        .await
        .map_err(|_| PairingTransportError::Unreachable("the dial timed out".into()))?
        .map_err(|e| PairingTransportError::Unreachable(e.to_string()))?;
    let answered = tokio::time::timeout(GREETING_TIMEOUT, async {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|_| PairingTransportError::Closed)?;
        write_message(&mut send, &greeting.encode()).await?;
        send.finish().map_err(|_| PairingTransportError::Closed)?;
        read_one_message(&mut recv, MAX_GREETING_BYTES).await
    })
    .await
    .unwrap_or(Err(PairingTransportError::TimedOut));
    match answered {
        Ok(answer) => Ok((connection, answer)),
        Err(error) => {
            connection.close(CLOSE_PROTOCOL, b"");
            Err(error)
        }
    }
}

/// Calls or approaches `target` and returns the link if it agrees.
async fn meet(
    endpoint: &Endpoint,
    target: &PairingTarget,
    greeting: Greeting,
    own_role: PairingRole,
) -> Result<Arc<PairingLink>> {
    let (connection, answer) = greet(endpoint, target, greeting).await?;
    let refusal = match MeetingAnswer::decode(&answer) {
        Some(MeetingAnswer::Accepted) => {
            let peer = *connection.remote_id().as_bytes();
            return Ok(PairingLink::start(connection, peer, own_role, Vec::new()));
        }
        Some(MeetingAnswer::NotListening) => PairingTransportError::NotListening,
        Some(MeetingAnswer::Busy) => PairingTransportError::Busy,
        None => PairingTransportError::Protocol,
    };
    connection.close(CLOSE_DONE, b"");
    Err(refusal)
}

#[uniffi::export(async_runtime = "tokio")]
impl IrohNode {
    /// Opens the transport's side of a pairing sheet: from now until the
    /// listener is closed, this node accepts approaches (as the side that
    /// types) or calls (as the side that shows the code) for `kind`.
    ///
    /// One listener at a time: [`PairingTransportError::WrongState`] if one
    /// is already open.
    pub fn pairing_listen(
        &self,
        role: PairingRole,
        kind: PairingTransportKind,
    ) -> Result<Arc<PairingListener>> {
        self.pairing_hub().listen(role, kind.into())
    }

    /// Calls the endpoint that shows the code, as the side that will type
    /// it. Succeeds only if a matching sheet is open there, so nothing is
    /// typed at a device that isn't waiting.
    pub async fn pairing_call(
        &self,
        target: PairingTarget,
        kind: PairingTransportKind,
    ) -> Result<Arc<PairingLink>> {
        let greeting = Greeting::Call { kind: kind.into() };
        meet(
            self.pairing_endpoint(),
            &target,
            greeting,
            PairingRole::Type,
        )
        .await
    }

    /// Approaches an endpoint that is waiting to type a code, as the side
    /// that shows it: how a device already in an account reaches a new one
    /// it discovered.
    pub async fn pairing_approach(
        &self,
        target: PairingTarget,
        kind: PairingTransportKind,
    ) -> Result<Arc<PairingLink>> {
        let greeting = Greeting::Approach { kind: kind.into() };
        meet(
            self.pairing_endpoint(),
            &target,
            greeting,
            PairingRole::Display,
        )
        .await
    }

    /// Knocks on the device that issued an invite, naming the invite id:
    /// "this device has opened it". Runs no exchange. An error means the
    /// device couldn't be reached, or isn't ready to answer yet, and the
    /// knock is worth trying again later; an answer is final.
    pub async fn pairing_knock(
        &self,
        target: PairingTarget,
        invite_id: Vec<u8>,
    ) -> Result<PairingKnockAnswer> {
        let invite_id = invite_id_from(&invite_id)?;
        let greeting = Greeting::Knock { invite_id };
        let (connection, answer) = greet(self.pairing_endpoint(), &target, greeting).await?;
        connection.close(CLOSE_DONE, b"");
        match KnockAnswer::decode(&answer) {
            Some(KnockAnswer::Opened) => Ok(PairingKnockAnswer::Opened),
            Some(KnockAnswer::NotOutstanding) => Ok(PairingKnockAnswer::NotOutstanding),
            None => Err(PairingTransportError::Protocol),
        }
    }

    /// This node's endpoint id: what a sheet opened on this device is given
    /// as its own endpoint.
    #[must_use]
    pub fn pairing_endpoint_id(&self) -> Vec<u8> {
        self.pairing_endpoint().id().as_bytes().to_vec()
    }

    /// This node's address as a `keys://pair/device/…` link: its endpoint id
    /// and relay, nothing else. Not a secret.
    ///
    /// The node's home relay must pass the rules a link's relay does (an
    /// `https://` URL naming a public host, see [`PairingAddress::new`]);
    /// otherwise this, the advertisement and issuing an invite all fail
    /// with [`PairingTransportError::Address`].
    pub fn pairing_device_link(&self) -> Result<String> {
        Ok(ParsedLink::Device(self.pairing_address()?).to_text())
    }

    /// What to advertise on the local network while a pairing sheet is open.
    /// The port is the node's IPv4 socket's, so a device that finds this
    /// dials it over IPv4 (or through the relay).
    pub fn pairing_advertisement(&self) -> Result<PairingAdvertisement> {
        let port = self
            .pairing_endpoint()
            .bound_sockets()
            .iter()
            .find(|socket| socket.is_ipv4())
            .map(SocketAddr::port)
            .ok_or_else(|| PairingTransportError::Address("no IPv4 socket is bound".into()))?;
        let txt = advert::txt_entries(&self.pairing_address()?)
            .into_iter()
            .map(|(key, value)| PairingTxtEntry { key, value })
            .collect();
        Ok(PairingAdvertisement {
            service_type: advert::SERVICE_TYPE.to_owned(),
            port,
            txt,
        })
    }

    /// Opens this node's invite book: hands back the invites the client
    /// stored in an earlier launch (none, on a first launch) and names who
    /// is told when one is opened. Call it once, as soon after binding as
    /// the stored records can be read.
    ///
    /// Until this is called the node answers no knock, so a knock that
    /// arrives while the device is starting up is tried again later instead
    /// of being told its invite isn't outstanding.
    ///
    /// Returns the stored records that were left out: expired ones, and any
    /// the book can't take (an id or endpoint of the wrong length, a second
    /// record of one invite, an expiry further off than any invite's
    /// lifetime allows, or more records than the book holds). When any come
    /// back, rewrite the store from [`Self::pairing_invites`]; don't prune
    /// it by invite id, because a second record of an invite is returned
    /// while the first was kept. A record that can't be used never
    /// keeps the book closed: one bad entry in a store must not stop every
    /// other invite's knock being answered.
    ///
    /// [`PairingTransportError::WrongState`] if the book is already open.
    pub fn pairing_open_invite_book(
        &self,
        stored: Vec<PairingInviteRecord>,
        listener: Arc<dyn PairingInviteListener>,
    ) -> Result<Vec<PairingInviteRecord>> {
        let hub = self.pairing_hub();
        let now = hub.now();
        let mut book = InviteBook::new();
        let left_out = stored
            .into_iter()
            .filter(|record| {
                let restored = invite_record_from(record.clone())
                    .is_ok_and(|usable| book.restore(usable, now).is_ok());
                !restored
            })
            .collect();
        let mut invites = lock(&hub.0.invites);
        if invites.is_some() {
            return Err(PairingTransportError::WrongState);
        }
        *invites = Some(OpenInvites { book, listener });
        Ok(left_out)
    }

    /// Issues an invite from the account whose identity public key is
    /// `inviter_identity`, answered by this node, lasting `lifetime_secs`.
    /// The link carries public values only.
    ///
    /// [`PairingTransportError::WrongState`] until the invite book is open.
    pub fn pairing_issue_invite(
        &self,
        inviter_identity: Vec<u8>,
        inviter_name: String,
        lifetime_secs: u64,
    ) -> Result<PairingIssuedInvite> {
        let inviter_identity: [u8; 32] = inviter_identity
            .as_slice()
            .try_into()
            .map_err(|_| PairingTransportError::Invite("an identity key is 32 bytes".into()))?;
        let address = self.pairing_address()?;
        let invite = self.pairing_hub().with_invites(|book, now| {
            book.issue(inviter_identity, address, &inviter_name, lifetime_secs, now)
                .map_err(|e| PairingTransportError::Invite(e.to_string()))
        })??;
        Ok(PairingIssuedInvite {
            invite_id: invite.invite_id.to_vec(),
            expires_at_unix: invite.expires_at,
            link: ParsedLink::Person(invite).to_text(),
        })
    }

    /// Retires an invite: it was cancelled, or its verification ended in a
    /// pairing or on the dead end. Its knocks are no longer answered as
    /// open. Returns whether it was outstanding. Remove it from the
    /// client's store too, or the next launch puts it back.
    ///
    /// [`PairingTransportError::WrongState`] until the invite book is open.
    pub fn pairing_retire_invite(&self, invite_id: Vec<u8>) -> Result<bool> {
        let invite_id = invite_id_from(&invite_id)?;
        self.pairing_hub()
            .with_invites(|book, now| book.retire(&invite_id, now))
    }

    /// Every outstanding invite, for the client to store.
    ///
    /// [`PairingTransportError::WrongState`] until the invite book is open.
    pub fn pairing_invites(&self) -> Result<Vec<PairingInviteRecord>> {
        self.pairing_hub().with_invites(|book, now| {
            book.records(now)
                .into_iter()
                .map(PairingInviteRecord::from)
                .collect()
        })
    }
}

fn invite_record_from(record: PairingInviteRecord) -> Result<InviteRecord> {
    let opened_by = record
        .opened_by
        .map(|endpoint| {
            endpoint
                .as_slice()
                .try_into()
                .map_err(|_| PairingTransportError::Address("an endpoint id is 32 bytes".into()))
        })
        .transpose()?;
    Ok(InviteRecord {
        invite_id: invite_id_from(&record.invite_id)?,
        expires_at: record.expires_at_unix,
        opened_by,
    })
}

impl PairingHub {
    /// Runs `work` on the open invite book, with the time.
    fn with_invites<T>(&self, work: impl FnOnce(&mut InviteBook, u64) -> T) -> Result<T> {
        let now = self.now();
        lock(&self.0.invites)
            .as_mut()
            .map(|open| work(&mut open.book, now))
            .ok_or(PairingTransportError::WrongState)
    }
}

impl IrohNode {
    /// This node's endpoint id and home relay.
    fn pairing_address(&self) -> Result<PairingAddress> {
        let endpoint = self.pairing_endpoint();
        let relay = endpoint.addr().relay_urls().next().map(ToString::to_string);
        PairingAddress::new(*endpoint.id().as_bytes(), relay)
            .map_err(|e| PairingTransportError::Address(e.to_string()))
    }
}

/// Test scaffolding: moves this node's pairing wall clock forward, so an
/// invite's expiry can be reached without waiting for it.
#[cfg(feature = "test-hooks")]
#[uniffi::export]
impl IrohNode {
    pub fn pairing_test_advance_clock(&self, secs: u64) {
        self.pairing_hub().advance_clock(secs);
    }
}

#[cfg(test)]
mod tests {
    use iroh::endpoint::{ConnectionError, QuicTransportConfig, presets};
    use keys_pairing::{
        Credentials, DisplaySheet, DisplayStatus, Outcome, PairingCode, SystemClock, TypeSheet,
        TypeStatus, VerifiedSession,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::identity::Identity;
    use crate::node::{NodeConfig, bind_loopback_for_test};

    /// Long enough for anything on the loopback interface.
    const WAIT_MS: u64 = 10_000;
    /// Short enough to wait out in a test.
    const BRIEF_MS: u64 = 200;
    const POLL: Duration = Duration::from_millis(10);
    /// A little longer than the node gives a greeting or its answer.
    const PAST_THE_GREETING_TIMEOUT: Duration = Duration::from_secs(15);
    const WEEK_SECS: u64 = 7 * 24 * 60 * 60;
    const IDENTITY: [u8; 32] = [0xa1; 32];

    struct TestNode {
        node: Arc<IrohNode>,
        /// What the node's invite listener has been told.
        heard: Arc<CountingListener>,
        _dirs: [TempDir; 2],
    }

    impl TestNode {
        /// A node whose invite book is open and empty, as a client's is
        /// once it has started up.
        async fn bind() -> Self {
            let node = Self::bind_before_the_book_opens().await;
            node.node
                .pairing_open_invite_book(Vec::new(), node.heard.clone())
                .unwrap();
            node
        }

        async fn bind_before_the_book_opens() -> Self {
            let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
            let node = bind_loopback_for_test(NodeConfig {
                identity: Identity::generate(),
                blob_dir: dirs[0].path().to_string_lossy().into_owned(),
                doc_dir: dirs[1].path().to_string_lossy().into_owned(),
                relay_urls: vec![],
            })
            .await
            .expect("bind a loopback node");
            Self {
                node,
                heard: Arc::new(CountingListener::default()),
                _dirs: dirs,
            }
        }

        fn id(&self) -> [u8; 32] {
            self.node.pairing_endpoint_id().try_into().unwrap()
        }

        /// Where to dial this node, by endpoint id alone, as a link gives it.
        fn target(&self) -> PairingTarget {
            PairingTarget {
                endpoint_id: self.id().to_vec(),
                relay_url: None,
                direct_addresses: Vec::new(),
            }
        }
    }

    #[derive(Default)]
    struct CountingListener {
        opened: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl PairingInviteListener for CountingListener {
        fn invite_opened(&self, invite_id: Vec<u8>, opener_endpoint_id: Vec<u8>) {
            lock(&self.opened).push((invite_id, opener_endpoint_id));
        }
    }

    impl CountingListener {
        /// What the listener has heard once it has heard of `count`
        /// openings. It is told on a thread of its own, so not at once.
        async fn after(&self, count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
            tokio::time::timeout(Duration::from_millis(WAIT_MS), async {
                while lock(&self.opened).len() < count {
                    tokio::time::sleep(POLL).await;
                }
            })
            .await
            .expect("the listener is told");
            lock(&self.opened).clone()
        }
    }

    /// A raw endpoint that isn't a node, for doing what the transport's own
    /// calls never would. With `zero_window` it tells its peers it will
    /// accept no data on any stream, so nothing written to it completes.
    async fn raw_endpoint(zero_window: bool) -> Endpoint {
        let mut transport = QuicTransportConfig::builder();
        if zero_window {
            transport = transport.stream_receive_window(VarInt::from_u32(0));
        }
        Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .transport_config(transport.build())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    /// Where `node` listens on the loopback interface.
    fn loopback_addr(node: &TestNode) -> EndpointAddr {
        let port = node.node.pairing_advertisement().unwrap().port;
        EndpointAddr::from_parts(
            node.node.pairing_endpoint().id(),
            [TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port)))],
        )
    }

    /// A connection that has sent its greeting and is not reading the
    /// answer. The streams are kept: dropping them would tell the node to
    /// stop sending, which is the easy way out this is here to deny it.
    struct Greeted {
        connection: Connection,
        _streams: (SendStream, RecvStream),
    }

    /// Connects `from` to `node` and sends `greeting`, without reading the
    /// answer.
    async fn greet_from(from: &Endpoint, node: &TestNode, greeting: Greeting) -> Greeted {
        let connection = from
            .connect(loopback_addr(node), PAIRING_ALPN)
            .await
            .unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        write_message(&mut send, &greeting.encode()).await.unwrap();
        Greeted {
            connection,
            _streams: (send, recv),
        }
    }

    /// Asserts the node closes `connection` within `limit`.
    async fn closed_by_the_node(connection: &Connection, limit: Duration) -> VarInt {
        let closed = tokio::time::timeout(limit, connection.closed())
            .await
            .expect("the node closes the connection");
        let ConnectionError::ApplicationClosed(close) = closed else {
            panic!("closed by the node, got {closed:?}");
        };
        close.error_code
    }

    fn shown_code(sheet: &mut DisplaySheet) -> PairingCode {
        match sheet.status().unwrap() {
            DisplayStatus::ShowingCode { code, .. } => code,
            other => panic!("a code on show, got {other:?}"),
        }
    }

    fn session_of(outcome: Outcome) -> VerifiedSession {
        match outcome {
            Outcome::Verified(session) => *session,
            other => panic!("a verified session, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_node_with_nothing_open_answers_only_knocks() {
        let quiet = TestNode::bind().await;
        let caller = TestNode::bind().await;
        for kind in [PairingTransportKind::Device, PairingTransportKind::Person] {
            assert_eq!(
                caller.node.pairing_call(quiet.target(), kind).await.err(),
                Some(PairingTransportError::NotListening)
            );
            assert_eq!(
                caller
                    .node
                    .pairing_approach(quiet.target(), kind)
                    .await
                    .err(),
                Some(PairingTransportError::NotListening)
            );
        }
        assert_eq!(
            caller
                .node
                .pairing_knock(quiet.target(), vec![0x99; 16])
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
    }

    #[tokio::test]
    async fn a_knock_opens_an_invite_for_its_first_endpoint_only() {
        let issuer = TestNode::bind().await;
        let opener = TestNode::bind().await;
        let other = TestNode::bind().await;

        let handed_out = issuer
            .node
            .pairing_issue_invite(IDENTITY.to_vec(), " Jeff\u{202e}\n".into(), WEEK_SECS)
            .unwrap();
        let PairingParsedLink::Person { invite } =
            pairing_parse_link(handed_out.link.clone()).unwrap()
        else {
            panic!("an invite link");
        };
        assert_eq!(invite.inviter_identity, IDENTITY);
        assert_eq!(invite.inviter_name, "Jeff");
        assert_eq!(invite.invite_id, handed_out.invite_id);
        assert_eq!(invite.expires_at_unix, handed_out.expires_at_unix);
        assert_eq!(invite.target.endpoint_id, issuer.id());
        assert_eq!(invite.target.direct_addresses, [] as [String; 0]);

        // No sheet is open on the issuer: the knock is answered all the same.
        for _ in 0..2 {
            assert_eq!(
                opener
                    .node
                    .pairing_knock(invite.target.clone(), invite.invite_id.clone())
                    .await,
                Ok(PairingKnockAnswer::Opened)
            );
        }
        assert_eq!(
            other
                .node
                .pairing_knock(invite.target.clone(), invite.invite_id.clone())
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
        // Two knocks from the opener and one from another endpoint: one
        // opening.
        assert_eq!(
            issuer.heard.after(1).await,
            [(handed_out.invite_id.clone(), opener.id().to_vec())]
        );
        assert_eq!(
            issuer.node.pairing_invites().unwrap(),
            [PairingInviteRecord {
                invite_id: handed_out.invite_id.clone(),
                expires_at_unix: handed_out.expires_at_unix,
                opened_by: Some(opener.id().to_vec()),
            }]
        );

        // A knock runs no exchange and opens no sheet.
        assert_eq!(
            opener
                .node
                .pairing_call(invite.target.clone(), PairingTransportKind::Person)
                .await
                .err(),
            Some(PairingTransportError::NotListening)
        );

        assert_eq!(
            issuer
                .node
                .pairing_retire_invite(handed_out.invite_id.clone()),
            Ok(true)
        );
        assert_eq!(
            opener
                .node
                .pairing_knock(invite.target, invite.invite_id)
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
    }

    #[tokio::test]
    async fn an_expired_invite_is_not_outstanding() {
        let issuer = TestNode::bind().await;
        let opener = TestNode::bind().await;
        let handed_out = issuer
            .node
            .pairing_issue_invite(IDENTITY.to_vec(), String::new(), WEEK_SECS)
            .unwrap();
        issuer.node.pairing_hub().advance_clock(WEEK_SECS);
        assert_eq!(
            opener
                .node
                .pairing_knock(issuer.target(), handed_out.invite_id)
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
        assert_eq!(issuer.node.pairing_invites().unwrap(), []);
        assert_eq!(issuer.heard.after(0).await, []);
    }

    /// A device starting up answers no knock until its client has handed
    /// back the invites it stored, so a knock in that window is tried again
    /// instead of being told, for good, that a live invite isn't there.
    #[tokio::test]
    async fn no_knock_is_answered_until_the_invite_book_is_open() {
        let issuer = TestNode::bind().await;
        let opener = TestNode::bind().await;
        let handed_out = issuer
            .node
            .pairing_issue_invite(IDENTITY.to_vec(), String::new(), WEEK_SECS)
            .unwrap();
        let opened_once = PairingInviteRecord {
            invite_id: vec![0x0b; 16],
            expires_at_unix: handed_out.expires_at_unix,
            opened_by: Some(opener.id().to_vec()),
        };
        let expired = PairingInviteRecord {
            invite_id: vec![0x0e; 16],
            expires_at_unix: 1,
            opened_by: None,
        };
        let mut stored = issuer.node.pairing_invites().unwrap();
        stored.extend([opened_once.clone(), expired.clone()]);

        // "Relaunch": a node that has bound but not yet opened its book.
        let relaunched = TestNode::bind_before_the_book_opens().await;
        for invite_id in [handed_out.invite_id.clone(), vec![0x99; 16]] {
            assert_eq!(
                opener
                    .node
                    .pairing_knock(relaunched.target(), invite_id)
                    .await,
                Err(PairingTransportError::Closed),
                "a knock was answered before the book opened"
            );
        }
        // Nothing else about invites works yet either.
        assert_eq!(
            relaunched.node.pairing_invites(),
            Err(PairingTransportError::WrongState)
        );
        assert_eq!(
            relaunched
                .node
                .pairing_issue_invite(IDENTITY.to_vec(), String::new(), WEEK_SECS)
                .err(),
            Some(PairingTransportError::WrongState)
        );
        assert_eq!(
            relaunched
                .node
                .pairing_retire_invite(handed_out.invite_id.clone()),
            Err(PairingTransportError::WrongState)
        );

        let left_out = relaunched
            .node
            .pairing_open_invite_book(stored.clone(), relaunched.heard.clone())
            .unwrap();
        // The expired record was left out, and the client is told which;
        // the others are back as stored.
        assert_eq!(left_out, [expired]);
        let mut restored = relaunched.node.pairing_invites().unwrap();
        restored.sort_by(|a, b| a.invite_id.cmp(&b.invite_id));
        let mut expected = vec![stored[0].clone(), opened_once.clone()];
        expected.sort_by(|a, b| a.invite_id.cmp(&b.invite_id));
        assert_eq!(restored, expected);

        assert_eq!(
            opener
                .node
                .pairing_knock(relaunched.target(), handed_out.invite_id.clone())
                .await,
            Ok(PairingKnockAnswer::Opened)
        );
        // An invite stored as already opened is the same opener's still,
        // and that isn't news.
        assert_eq!(
            opener
                .node
                .pairing_knock(relaunched.target(), opened_once.invite_id.clone())
                .await,
            Ok(PairingKnockAnswer::Opened)
        );
        assert_eq!(
            relaunched.heard.after(1).await,
            [(handed_out.invite_id, opener.id().to_vec())]
        );

        // Open once only.
        assert_eq!(
            relaunched
                .node
                .pairing_open_invite_book(Vec::new(), relaunched.heard.clone()),
            Err(PairingTransportError::WrongState)
        );
    }

    /// One bad entry in a client's store must not stop every other
    /// invite's knock being answered: what can't be used is left out and
    /// handed back, and the book opens with the rest.
    #[tokio::test]
    async fn stored_invites_that_cannot_be_used_are_left_out_and_handed_back() {
        let node = TestNode::bind_before_the_book_opens().await;
        let opener = TestNode::bind().await;
        let soon = node.node.pairing_hub().now() + WEEK_SECS;
        let good = PairingInviteRecord {
            invite_id: vec![0x02; 16],
            expires_at_unix: soon,
            opened_by: None,
        };
        // As a store written while the clock was far ahead would hold.
        let too_far = PairingInviteRecord {
            invite_id: vec![0x0f; 16],
            expires_at_unix: u64::MAX,
            opened_by: None,
        };
        let short_id = PairingInviteRecord {
            invite_id: vec![0x03; 15],
            ..good.clone()
        };
        let short_opener = PairingInviteRecord {
            invite_id: vec![0x04; 16],
            expires_at_unix: soon,
            opened_by: Some(vec![1; 31]),
        };
        let left_out = node
            .node
            .pairing_open_invite_book(
                vec![
                    too_far.clone(),
                    good.clone(),
                    short_id.clone(),
                    good.clone(),
                    short_opener.clone(),
                ],
                node.heard.clone(),
            )
            .unwrap();
        assert_eq!(left_out, [too_far, short_id, good.clone(), short_opener]);
        assert_eq!(
            node.node.pairing_invites().unwrap(),
            std::slice::from_ref(&good)
        );
        assert_eq!(
            opener
                .node
                .pairing_knock(node.target(), good.invite_id)
                .await,
            Ok(PairingKnockAnswer::Opened)
        );
    }

    #[tokio::test]
    async fn a_call_or_approach_needs_a_listener_of_the_other_role_and_the_same_kind() {
        let listening = TestNode::bind().await;
        let dialler = TestNode::bind().await;
        let listener = listening
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Person)
            .unwrap();
        // One listener at a time.
        assert_eq!(
            listening
                .node
                .pairing_listen(PairingRole::Type, PairingTransportKind::Device)
                .err(),
            Some(PairingTransportError::WrongState)
        );

        assert_eq!(
            dialler
                .node
                .pairing_call(listening.target(), PairingTransportKind::Device)
                .await
                .err(),
            Some(PairingTransportError::NotListening)
        );
        assert_eq!(
            dialler
                .node
                .pairing_approach(listening.target(), PairingTransportKind::Person)
                .await
                .err(),
            Some(PairingTransportError::NotListening)
        );

        let outgoing = dialler
            .node
            .pairing_call(listening.target(), PairingTransportKind::Person)
            .await
            .unwrap();
        let accepted = listener.next_link().await.unwrap();
        assert_eq!(outgoing.role(), PairingRole::Type);
        assert_eq!(accepted.role(), PairingRole::Display);
        assert_eq!(outgoing.peer_endpoint_id(), listening.id());
        assert_eq!(accepted.peer_endpoint_id(), dialler.id());

        // Each side may do only what its role does.
        assert_eq!(
            accepted.open_run(vec![1]).await.err(),
            Some(PairingTransportError::WrongState)
        );
        assert_eq!(
            outgoing.accept_run(BRIEF_MS).await.err(),
            Some(PairingTransportError::WrongState)
        );
    }

    #[tokio::test]
    async fn a_typing_listener_holds_one_approach_at_a_time() {
        let new_device = TestNode::bind().await;
        let first = TestNode::bind().await;
        let second = TestNode::bind().await;
        let listener = new_device
            .node
            .pairing_listen(PairingRole::Type, PairingTransportKind::Device)
            .unwrap();

        let first_link = first
            .node
            .pairing_approach(new_device.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        let held = listener.next_link().await.unwrap();
        assert_eq!(held.peer_endpoint_id(), first.id());
        assert_eq!(
            second
                .node
                .pairing_approach(new_device.target(), PairingTransportKind::Device)
                .await
                .err(),
            Some(PairingTransportError::Busy)
        );

        // The person turns the first one away. Closing is enough to free
        // the place: nothing waits for the link itself to be dropped.
        held.close();
        tokio::time::timeout(Duration::from_millis(WAIT_MS), first_link.closed())
            .await
            .expect("the approaching device learns it was turned away");
        let second_link = second
            .node
            .pairing_approach(new_device.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        assert_eq!(
            listener.next_link().await.unwrap().peer_endpoint_id(),
            second.id()
        );
        drop(second_link);
    }

    #[tokio::test]
    async fn closing_the_listener_ends_its_links_and_stops_accepting() {
        let listening = TestNode::bind().await;
        let dialler = TestNode::bind().await;
        let listener = listening
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Device)
            .unwrap();
        let outgoing = dialler
            .node
            .pairing_call(listening.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        let accepted = listener.next_link().await.unwrap();
        let run = outgoing.open_run(vec![1, 2, 3]).await.unwrap();
        let incoming = accepted.accept_run(WAIT_MS).await.unwrap();
        assert_eq!(incoming.hello, [1, 2, 3]);

        listener.close();
        assert_eq!(
            listener.next_link().await.err(),
            Some(PairingTransportError::Closed)
        );
        assert_eq!(
            incoming.stream.receive(WAIT_MS).await.err(),
            Some(PairingTransportError::Closed)
        );
        assert_eq!(
            run.receive(WAIT_MS).await.err(),
            Some(PairingTransportError::Closed)
        );
        assert_eq!(
            dialler
                .node
                .pairing_call(listening.target(), PairingTransportKind::Device)
                .await
                .err(),
            Some(PairingTransportError::NotListening)
        );
        // And a new sheet can open afterwards.
        listening
            .node
            .pairing_listen(PairingRole::Type, PairingTransportKind::Person)
            .unwrap();
    }

    /// Stands up a link with `typing` as the side that types, the way a
    /// Person pairing does: the displaying side listens, the typing side
    /// calls.
    async fn link_by_call(
        displaying: &TestNode,
        typing: &TestNode,
    ) -> (Arc<PairingListener>, Arc<PairingLink>, Arc<PairingLink>) {
        let listener = displaying
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Device)
            .unwrap();
        let typing_link = typing
            .node
            .pairing_call(displaying.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        let display_link = listener.next_link().await.unwrap();
        (listener, display_link, typing_link)
    }

    #[tokio::test]
    async fn a_new_run_gets_a_new_stream_and_ends_the_old_one() {
        let displaying = TestNode::bind().await;
        let typing = TestNode::bind().await;
        let (_listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;

        let first = typing_link.open_run(b"first hello".to_vec()).await.unwrap();
        let first_in = display_link.accept_run(WAIT_MS).await.unwrap();
        assert_eq!(first_in.hello, b"first hello");
        // A late message of the first run, sent before the second starts.
        first.send(b"late".to_vec()).await.unwrap();

        let second = typing_link
            .open_run(b"second hello".to_vec())
            .await
            .unwrap();
        let second_in = display_link.accept_run(WAIT_MS).await.unwrap();
        assert_eq!(second_in.hello, b"second hello");
        // Each side ended its own half of the first run when the second
        // began, without waiting to hear from the other.
        assert!(first.is_closed());
        assert!(first_in.stream.is_closed());
        assert_eq!(second_in.stream.peer_endpoint_id(), typing.id());

        // The first run's streams are closed on both sides, and its late
        // message never shows up in the second run.
        assert_eq!(
            first.send(b"more".to_vec()).await.err(),
            Some(PairingTransportError::Closed)
        );
        assert_eq!(
            first_in.stream.receive(WAIT_MS).await.err(),
            Some(PairingTransportError::Closed)
        );
        second.send(b"second run".to_vec()).await.unwrap();
        assert_eq!(
            second_in.stream.receive(WAIT_MS).await.unwrap(),
            b"second run"
        );
        assert_eq!(
            second_in.stream.receive(BRIEF_MS).await.err(),
            Some(PairingTransportError::TimedOut)
        );
        // A wait that timed out lost nothing.
        second.send(b"after the wait".to_vec()).await.unwrap();
        assert_eq!(
            second_in.stream.receive(WAIT_MS).await.unwrap(),
            b"after the wait"
        );
    }

    #[tokio::test]
    async fn messages_are_capped_until_the_pairing_has_verified() {
        let displaying = TestNode::bind().await;
        let typing = TestNode::bind().await;
        let (_listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;

        assert_eq!(
            typing_link
                .open_run(vec![0; MAX_EXCHANGE_MESSAGE_BYTES + 1])
                .await
                .err(),
            Some(PairingTransportError::TooLarge)
        );
        let run = typing_link.open_run(vec![1]).await.unwrap();
        let incoming = display_link.accept_run(WAIT_MS).await.unwrap();

        run.send(vec![7; MAX_EXCHANGE_MESSAGE_BYTES]).await.unwrap();
        assert_eq!(
            incoming.stream.receive(WAIT_MS).await.unwrap().len(),
            MAX_EXCHANGE_MESSAGE_BYTES
        );
        // An empty message is a message.
        run.send(Vec::new()).await.unwrap();
        assert_eq!(incoming.stream.receive(WAIT_MS).await.unwrap(), [0u8; 0]);

        // Verified: the larger cap, on the side that says so.
        incoming.stream.allow_session_frames();
        run.send(vec![8; MAX_SESSION_FRAME_BYTES]).await.unwrap();
        assert_eq!(
            incoming.stream.receive(WAIT_MS).await.unwrap().len(),
            MAX_SESSION_FRAME_BYTES
        );
        assert_eq!(
            run.send(vec![8; MAX_SESSION_FRAME_BYTES + 1]).await.err(),
            Some(PairingTransportError::TooLarge)
        );

        // The other direction still has the small cap.
        incoming
            .stream
            .send(vec![9; MAX_EXCHANGE_MESSAGE_BYTES + 1])
            .await
            .unwrap();
        assert_eq!(
            run.receive(WAIT_MS).await.err(),
            Some(PairingTransportError::TooLarge)
        );
    }

    /// A device already in an account discovers a new device and approaches
    /// it; the new device types the code. The whole exchange and a session
    /// frame each way, over real connections.
    #[tokio::test]
    async fn a_device_pairing_runs_end_to_end_over_the_transport() {
        let trusted = TestNode::bind().await;
        let new_device = TestNode::bind().await;

        // Discovery: the new device's sheet is open and advertising.
        let listener = new_device
            .node
            .pairing_listen(PairingRole::Type, PairingTransportKind::Device)
            .unwrap();
        let advert = new_device.node.pairing_advertisement().unwrap();
        assert_eq!(advert.service_type, "_keys-pair._udp");
        let target =
            pairing_target_from_advertisement(advert.txt, vec!["127.0.0.1".into()], advert.port)
                .unwrap();
        assert_eq!(target.endpoint_id, new_device.id());
        assert_eq!(
            target.direct_addresses,
            [format!("127.0.0.1:{}", advert.port)]
        );

        let display_link = trusted
            .node
            .pairing_approach(target, PairingTransportKind::Device)
            .await
            .unwrap();
        let type_link = listener.next_link().await.unwrap();
        let trusted_id: [u8; 32] = type_link.peer_endpoint_id().try_into().unwrap();
        let new_id: [u8; 32] = display_link.peer_endpoint_id().try_into().unwrap();
        assert_eq!(trusted_id, trusted.id());
        assert_eq!(new_id, new_device.id());

        let clock = Arc::new(SystemClock::new());
        let mut display =
            DisplaySheet::open(Credentials::Device, trusted_id, clock.clone()).unwrap();
        let mut typing = TypeSheet::open(Credentials::Device, new_id, trusted_id, clock);

        // A wrong code first: the run fails, and the next one is a new
        // stream on the same link.
        let right = shown_code(&mut display);
        let wrong = if &*right.digits() == "000000" {
            "000001"
        } else {
            "000000"
        };
        let hello = typing
            .submit_code(PairingCode::parse(wrong).unwrap())
            .unwrap();
        let run = type_link.open_run(hello).await.unwrap();
        let incoming = display_link.accept_run(WAIT_MS).await.unwrap();
        let share = display.handle(new_id, &incoming.hello).unwrap();
        incoming.stream.send(share.reply.unwrap()).await.unwrap();
        let reply = typing.handle(trusted_id, &run.receive(WAIT_MS).await.unwrap());
        run.send(reply.reply.unwrap()).await.unwrap();
        let refused = display
            .handle(new_id, &incoming.stream.receive(WAIT_MS).await.unwrap())
            .unwrap();
        assert!(matches!(refused.outcome, Outcome::RunFailed { .. }));
        incoming.stream.send(refused.reply.unwrap()).await.unwrap();
        let failed = typing.handle(trusted_id, &run.receive(WAIT_MS).await.unwrap());
        assert!(matches!(failed.outcome, Outcome::RunFailed { .. }));
        assert_eq!(typing.status(), TypeStatus::AwaitingCode { runs_left: 2 });

        // The right code, on a fresh stream.
        let hello = typing.submit_code(shown_code(&mut display)).unwrap();
        let run = type_link.open_run(hello).await.unwrap();
        let incoming = display_link.accept_run(WAIT_MS).await.unwrap();
        let share = display.handle(new_id, &incoming.hello).unwrap();
        incoming.stream.send(share.reply.unwrap()).await.unwrap();
        let reply = typing.handle(trusted_id, &run.receive(WAIT_MS).await.unwrap());
        run.send(reply.reply.unwrap()).await.unwrap();
        let confirm = display
            .handle(new_id, &incoming.stream.receive(WAIT_MS).await.unwrap())
            .unwrap();
        incoming.stream.send(confirm.reply.unwrap()).await.unwrap();
        let mut display_session = session_of(confirm.outcome);
        let verified = typing.handle(trusted_id, &run.receive(WAIT_MS).await.unwrap());
        let mut typing_session = session_of(verified.outcome);

        // The session's frames follow on the run's stream, the typing side
        // first.
        run.allow_session_frames();
        incoming.stream.allow_session_frames();
        run.send(typing_session.seal(b"new device keys").unwrap())
            .await
            .unwrap();
        let frame = incoming.stream.receive(WAIT_MS).await.unwrap();
        assert_eq!(
            &**display_session.open(new_id, &frame).unwrap(),
            b"new device keys"
        );
        incoming
            .stream
            .send(display_session.seal(b"the bundle").unwrap())
            .await
            .unwrap();
        let frame = run.receive(WAIT_MS).await.unwrap();
        assert_eq!(
            &**typing_session.open(trusted_id, &frame).unwrap(),
            b"the bundle"
        );
    }

    /// Dials `target` on the pairing ALPN with no greeting logic of the
    /// transport's own, for sending what the transport never would.
    async fn raw_connection(from: &TestNode, to: &TestNode) -> Connection {
        from.node
            .pairing_endpoint()
            .connect(to.target().endpoint_addr().unwrap(), PAIRING_ALPN)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_connection_that_does_not_greet_properly_is_closed() {
        let listening = TestNode::bind().await;
        let stranger = TestNode::bind().await;
        let _listener = listening
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Device)
            .unwrap();

        for garbage in [
            &b""[..],
            &[0xff],
            // An exchange message where a greeting belongs, short enough
            // to be read as one: refused for what it is, not for its length.
            &[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // A knock a byte short.
            &[7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // A call with a byte too many.
            &[10, 1, 0],
        ] {
            let connection = raw_connection(&stranger, &listening).await;
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            write_message(&mut send, garbage).await.unwrap();
            assert!(
                read_one_message(&mut recv, MAX_GREETING_BYTES)
                    .await
                    .is_err(),
                "{garbage:?} was answered"
            );
            connection.closed().await;
        }

        // A greeting longer than any greeting: refused on its length alone.
        let connection = raw_connection(&stranger, &listening).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(
            read_one_message(&mut recv, MAX_GREETING_BYTES)
                .await
                .is_err()
        );
        connection.closed().await;
    }

    #[tokio::test]
    async fn pairing_connections_are_capped() {
        let listening = TestNode::bind().await;
        let stranger = TestNode::bind().await;
        // Connections that never greet hold their place until the greeting
        // timeout.
        let mut silent = Vec::new();
        for _ in 0..MAX_INBOUND_CONNECTIONS {
            silent.push(raw_connection(&stranger, &listening).await);
        }
        // Give the node a moment to take them all in.
        tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
        let over = raw_connection(&stranger, &listening).await;
        let closed = tokio::time::timeout(Duration::from_millis(BRIEF_MS), over.closed())
            .await
            .expect("the connection over the cap is closed at once");
        let iroh::endpoint::ConnectionError::ApplicationClosed(close) = closed else {
            panic!("closed by the node, got {closed:?}");
        };
        assert_eq!(close.error_code, CLOSE_REFUSED);
        // The ones under the cap are still waiting to be greeted.
        assert!(silent.iter().all(|held| held.close_reason().is_none()));
    }

    #[tokio::test]
    async fn bad_targets_are_refused_before_any_dial() {
        let node = TestNode::bind().await;
        let other = TestNode::bind().await;
        let dial = |target: PairingTarget| {
            let node = node.node.clone();
            async move {
                node.pairing_call(target, PairingTransportKind::Device)
                    .await
                    .err()
            }
        };
        assert!(matches!(
            dial(node.target()).await,
            Some(PairingTransportError::Address(_))
        ));
        for target in [
            PairingTarget {
                endpoint_id: vec![1; 31],
                ..other.target()
            },
            PairingTarget {
                relay_url: Some("http://relay.example".into()),
                ..other.target()
            },
            // A relay named by address, plainly or in a spelling a URL
            // parser reads as one.
            PairingTarget {
                relay_url: Some("https://127.0.0.1/".into()),
                ..other.target()
            },
            PairingTarget {
                relay_url: Some("https://0x7f000001/".into()),
                ..other.target()
            },
            PairingTarget {
                direct_addresses: vec!["not an address".into()],
                ..other.target()
            },
        ] {
            assert!(matches!(
                dial(target).await,
                Some(PairingTransportError::Address(_))
            ));
        }
        assert!(matches!(
            node.node.pairing_knock(other.target(), vec![1; 15]).await,
            Err(PairingTransportError::Address(_))
        ));
    }

    #[tokio::test]
    async fn a_device_link_names_the_node_and_nothing_else() {
        let node = TestNode::bind().await;
        let link = node.node.pairing_device_link().unwrap();
        assert_eq!(
            pairing_parse_link(link),
            Ok(PairingParsedLink::Device {
                target: node.target()
            })
        );
        assert!(matches!(
            pairing_parse_link("https://example.com".into()),
            Err(PairingTransportError::Address(_))
        ));
        assert!(matches!(
            pairing_target_from_advertisement(Vec::new(), Vec::new(), 1),
            Err(PairingTransportError::Address(_))
        ));
        let advert = node.node.pairing_advertisement().unwrap();
        assert!(matches!(
            pairing_target_from_advertisement(advert.txt, vec!["localhost".into()], advert.port),
            Err(PairingTransportError::Address(_))
        ));
    }

    #[test]
    fn framing_takes_whole_messages_and_refuses_long_ones_early() {
        let mut buffered = Vec::new();
        assert_eq!(take_message(&mut buffered, 8), Ok(None));
        buffered.extend_from_slice(&[0, 0, 0]);
        assert_eq!(take_message(&mut buffered, 8), Ok(None));
        buffered.extend_from_slice(&[3, b'a', b'b']);
        assert_eq!(take_message(&mut buffered, 8), Ok(None));
        // The rest of the first message and all of a second arrive together.
        buffered.extend_from_slice(&[b'c', 0, 0, 0, 0, 0, 0, 0, 1, b'z']);
        assert_eq!(take_message(&mut buffered, 8), Ok(Some(b"abc".to_vec())));
        assert_eq!(take_message(&mut buffered, 8), Ok(Some(Vec::new())));
        assert_eq!(take_message(&mut buffered, 8), Ok(Some(b"z".to_vec())));
        assert_eq!(take_message(&mut buffered, 8), Ok(None));
        assert_eq!(buffered, [] as [u8; 0]);

        // Over the cap: refused from the prefix, before any of it arrives.
        let mut long = 9u32.to_be_bytes().to_vec();
        assert_eq!(
            take_message(&mut long, 8),
            Err(PairingTransportError::TooLarge)
        );
        let mut at_the_cap = 8u32.to_be_bytes().to_vec();
        assert_eq!(take_message(&mut at_the_cap, 8), Ok(None));
    }

    /// Every knock gives its place back: many more in a row than the node
    /// serves at once are all answered.
    #[tokio::test]
    async fn a_served_connection_gives_its_place_back() {
        let issuer = TestNode::bind().await;
        let opener = TestNode::bind().await;
        for _ in 0..3 * MAX_INBOUND_CONNECTIONS {
            assert_eq!(
                opener
                    .node
                    .pairing_knock(issuer.target(), vec![0x99; 16])
                    .await,
                Ok(PairingKnockAnswer::NotOutstanding)
            );
        }
    }

    /// A peer decides how much it will accept on a stream. One that accepts
    /// nothing can't be answered, and must not keep its place for that: it
    /// is dropped once its answer has had the time a greeting gets.
    #[tokio::test]
    async fn a_peer_that_takes_no_answer_cannot_hold_the_nodes_places() {
        let issuer = TestNode::bind().await;
        let opener = TestNode::bind().await;
        let invite = issuer
            .node
            .pairing_issue_invite(IDENTITY.to_vec(), String::new(), WEEK_SECS)
            .unwrap();
        let invite_id: InviteId = invite.invite_id.clone().try_into().unwrap();

        // Every place the node has, taken by knocks that can't be answered.
        // One of them is on a real invite.
        let deaf = raw_endpoint(true).await;
        let mut stuck = vec![greet_from(&deaf, &issuer, Greeting::Knock { invite_id }).await];
        for _ in 1..MAX_INBOUND_CONNECTIONS {
            let unknown = Greeting::Knock {
                invite_id: [0x99; 16],
            };
            stuck.push(greet_from(&deaf, &issuer, unknown).await);
        }
        // The opening was recorded and announced although its answer never
        // arrived.
        assert_eq!(
            issuer.heard.after(1).await,
            [(invite.invite_id.clone(), deaf.id().as_bytes().to_vec())]
        );
        // While they hold every place, nobody else gets in. (A moment
        // first, for the node to have taken them all in.)
        tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
        assert_eq!(
            opener
                .node
                .pairing_knock(issuer.target(), vec![0x99; 16])
                .await
                .err(),
            Some(PairingTransportError::Closed)
        );

        for greeted in &stuck {
            assert_eq!(
                closed_by_the_node(&greeted.connection, PAST_THE_GREETING_TIMEOUT).await,
                CLOSE_PROTOCOL
            );
        }
        assert_eq!(
            opener
                .node
                .pairing_knock(issuer.target(), vec![0x99; 16])
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
        // The first knocker is the invite's opener, heard of once; anyone
        // else is still told nothing is outstanding.
        assert_eq!(
            opener
                .node
                .pairing_knock(issuer.target(), invite.invite_id)
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
        assert_eq!(issuer.heard.after(1).await.len(), 1);
    }

    /// The same peer at a waiting device: it can't sit in the one place a
    /// typing listener has without ever becoming a link the person could
    /// turn away.
    #[tokio::test]
    async fn a_peer_that_takes_no_answer_cannot_hold_a_listeners_place() {
        let new_device = TestNode::bind().await;
        let trusted = TestNode::bind().await;
        let listener = new_device
            .node
            .pairing_listen(PairingRole::Type, PairingTransportKind::Device)
            .unwrap();
        let deaf = raw_endpoint(true).await;
        let approach = Greeting::Approach {
            kind: PairingKind::Device,
        };
        let stuck = greet_from(&deaf, &new_device, approach).await;
        // While its answer is parked, it has the listener's one place.
        tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
        assert_eq!(
            trusted
                .node
                .pairing_approach(new_device.target(), PairingTransportKind::Device)
                .await
                .err(),
            Some(PairingTransportError::Busy)
        );
        assert_eq!(
            closed_by_the_node(&stuck.connection, PAST_THE_GREETING_TIMEOUT).await,
            CLOSE_PROTOCOL
        );

        let link = trusted
            .node
            .pairing_approach(new_device.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        // The deaf peer never became a link: the first one is the real one.
        assert_eq!(
            listener.next_link().await.unwrap().peer_endpoint_id(),
            trusted.id()
        );
        drop(link);
    }

    #[tokio::test]
    async fn a_connection_that_never_greets_is_closed_and_gives_its_place_back() {
        let node = TestNode::bind().await;
        let other = TestNode::bind().await;
        let silent = raw_endpoint(false).await;
        let mut waiting = Vec::new();
        for _ in 0..MAX_INBOUND_CONNECTIONS {
            waiting.push(
                silent
                    .connect(loopback_addr(&node), PAIRING_ALPN)
                    .await
                    .unwrap(),
            );
        }
        for connection in &waiting {
            assert_eq!(
                closed_by_the_node(connection, PAST_THE_GREETING_TIMEOUT).await,
                CLOSE_PROTOCOL
            );
        }
        assert_eq!(
            other
                .node
                .pairing_knock(node.target(), vec![0x99; 16])
                .await,
            Ok(PairingKnockAnswer::NotOutstanding)
        );
    }

    /// A link whose other end has gone closes itself and frees its place,
    /// with nobody having to use it to find out.
    #[tokio::test]
    async fn a_link_whose_peer_has_gone_closes_and_frees_its_place() {
        let new_device = TestNode::bind().await;
        let first = TestNode::bind().await;
        let second = TestNode::bind().await;
        let listener = new_device
            .node
            .pairing_listen(PairingRole::Type, PairingTransportKind::Device)
            .unwrap();

        let first_link = first
            .node
            .pairing_approach(new_device.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        let held = listener.next_link().await.unwrap();
        assert!(!held.is_closed());

        // The approaching device closes its sheet. The waiting device never
        // touches its end.
        first_link.close();
        tokio::time::timeout(Duration::from_millis(WAIT_MS), held.closed())
            .await
            .expect("the link notices its peer has gone");
        assert!(held.is_closed());
        assert_eq!(
            held.open_run(vec![1]).await.err(),
            Some(PairingTransportError::Closed)
        );

        let second_link = second
            .node
            .pairing_approach(new_device.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        assert_eq!(
            listener.next_link().await.unwrap().peer_endpoint_id(),
            second.id()
        );
        // And it works the other way round: the dialler's link learns of
        // the waiting device closing its sheet.
        listener.close();
        tokio::time::timeout(Duration::from_millis(WAIT_MS), second_link.closed())
            .await
            .expect("the dialler's link notices too");
    }

    #[tokio::test]
    async fn a_displaying_listener_holds_a_few_links_and_closes_those_never_taken() {
        let displaying = TestNode::bind().await;
        let listener = displaying
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Person)
            .unwrap();
        let mut callers = Vec::new();
        let mut links = Vec::new();
        for _ in 0..MAX_DISPLAY_LINKS {
            let caller = TestNode::bind().await;
            links.push(
                caller
                    .node
                    .pairing_call(displaying.target(), PairingTransportKind::Person)
                    .await
                    .unwrap(),
            );
            callers.push(caller);
        }
        let one_too_many = TestNode::bind().await;
        assert_eq!(
            one_too_many
                .node
                .pairing_call(displaying.target(), PairingTransportKind::Person)
                .await
                .err(),
            Some(PairingTransportError::Busy)
        );

        // The client took only the first link; the rest wait in the queue.
        let taken = listener.next_link().await.unwrap();
        assert_eq!(taken.peer_endpoint_id(), callers[0].id());
        listener.close();
        for link in &links {
            tokio::time::timeout(Duration::from_millis(WAIT_MS), link.closed())
                .await
                .expect("closing the listener closes every link it accepted");
        }
    }

    /// `finish` is what makes the last message arrive: sent, finished, and
    /// only then is everything closed. The receiving side comes for it
    /// later, after its link has noticed the connection end, on a runtime
    /// with threads to notice it on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_finished_stream_delivers_its_last_message_after_the_close() {
        for _ in 0..5 {
            let displaying = TestNode::bind().await;
            let typing = TestNode::bind().await;
            let (listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;
            let run = typing_link.open_run(vec![1]).await.unwrap();
            let incoming = display_link.accept_run(WAIT_MS).await.unwrap();

            // The displaying side's last word, then its sheet closes.
            incoming
                .stream
                .send(b"the last word".to_vec())
                .await
                .unwrap();
            incoming.stream.finish(WAIT_MS).await.unwrap();
            listener.close();

            tokio::time::timeout(Duration::from_millis(WAIT_MS), typing_link.closed())
                .await
                .expect("the typing side's link notices the close");
            tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
            assert_eq!(run.receive(WAIT_MS).await.unwrap(), b"the last word");
            assert_eq!(
                run.receive(WAIT_MS).await.err(),
                Some(PairingTransportError::Closed)
            );
        }

        // And from the typing side, which closes its link.
        for _ in 0..5 {
            let displaying = TestNode::bind().await;
            let typing = TestNode::bind().await;
            let (_listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;
            let run = typing_link.open_run(vec![1]).await.unwrap();
            let incoming = display_link.accept_run(WAIT_MS).await.unwrap();

            run.send(b"the last word".to_vec()).await.unwrap();
            run.finish(WAIT_MS).await.unwrap();
            typing_link.close();

            tokio::time::timeout(Duration::from_millis(WAIT_MS), display_link.closed())
                .await
                .expect("the displaying side's link notices the close");
            tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
            assert_eq!(
                incoming.stream.receive(WAIT_MS).await.unwrap(),
                b"the last word"
            );
        }
    }

    #[tokio::test]
    async fn finishing_reports_a_stream_the_other_side_threw_away() {
        let displaying = TestNode::bind().await;
        let typing = TestNode::bind().await;
        let (_listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;
        let run = typing_link.open_run(vec![1]).await.unwrap();
        let incoming = display_link.accept_run(WAIT_MS).await.unwrap();

        // The displaying side ends the stream without reading further.
        incoming.stream.close();
        tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
        assert_eq!(
            run.finish(WAIT_MS).await,
            Err(PairingTransportError::Closed)
        );
    }

    /// Callers that come and go while nobody is taking links leave nothing
    /// behind: no place stays taken, and no dead link is handed out.
    #[tokio::test]
    async fn links_that_left_before_being_taken_cost_nothing() {
        let displaying = TestNode::bind().await;
        let caller = TestNode::bind().await;
        let listener = displaying
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Device)
            .unwrap();
        for _ in 0..3 * MAX_DISPLAY_LINKS {
            let link = caller
                .node
                .pairing_call(displaying.target(), PairingTransportKind::Device)
                .await
                .expect("a place is free again after each caller leaves");
            link.close();
            // The listening side notices before the next call.
            tokio::time::sleep(Duration::from_millis(BRIEF_MS)).await;
        }
        let stays = caller
            .node
            .pairing_call(displaying.target(), PairingTransportKind::Device)
            .await
            .unwrap();
        let taken = listener.next_link().await.unwrap();
        assert!(!taken.is_closed());
        assert!(!stays.is_closed());
        // Nothing else is waiting.
        assert!(
            tokio::time::timeout(Duration::from_millis(BRIEF_MS), listener.next_link())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_stream_that_is_no_run_is_passed_over() {
        let displaying = TestNode::bind().await;
        let typing = TestNode::bind().await;
        let (_listener, display_link, typing_link) = link_by_call(&displaying, &typing).await;

        // Streams the typing side opens and abandons: one cut off inside
        // its first message, one promising far more than a Hello.
        let (mut cut_short, _) = typing_link.connection.open_bi().await.unwrap();
        cut_short.write_all(&[0, 0, 0, 9, 1, 2]).await.unwrap();
        cut_short.finish().unwrap();
        let (mut overlong, _keep) = typing_link.connection.open_bi().await.unwrap();
        overlong.write_all(&u32::MAX.to_be_bytes()).await.unwrap();

        let run = typing_link
            .open_run(b"a real hello".to_vec())
            .await
            .unwrap();
        let incoming = display_link.accept_run(WAIT_MS).await.unwrap();
        assert_eq!(incoming.hello, b"a real hello");
        drop(run);

        // No run at all within the time allowed is a timeout, and the link
        // is still good afterwards.
        assert_eq!(
            display_link.accept_run(BRIEF_MS).await.err(),
            Some(PairingTransportError::TimedOut)
        );
        assert!(!display_link.is_closed());
        // A link that has gone says so instead, even to a caller that
        // asked to wait as long as there is.
        typing_link.close();
        assert_eq!(
            display_link.accept_run(u64::MAX).await.err(),
            Some(PairingTransportError::Closed)
        );
    }

    #[tokio::test]
    async fn a_listener_that_fails_harms_nothing_else() {
        struct Failing;
        impl PairingInviteListener for Failing {
            fn invite_opened(&self, _invite_id: Vec<u8>, _opener: Vec<u8>) {
                panic!("a client's listener failing");
            }
        }
        let issuer = TestNode::bind_before_the_book_opens().await;
        issuer
            .node
            .pairing_open_invite_book(Vec::new(), Arc::new(Failing))
            .unwrap();
        let opener = TestNode::bind().await;
        for _ in 0..2 {
            let invite = issuer
                .node
                .pairing_issue_invite(IDENTITY.to_vec(), String::new(), WEEK_SECS)
                .unwrap();
            assert_eq!(
                opener
                    .node
                    .pairing_knock(issuer.target(), invite.invite_id)
                    .await,
                Ok(PairingKnockAnswer::Opened)
            );
        }
        // The node is still serving, and the openings were recorded.
        assert!(
            issuer
                .node
                .pairing_invites()
                .unwrap()
                .iter()
                .all(|record| record.opened_by == Some(opener.id().to_vec()))
        );
    }

    #[tokio::test]
    async fn shutting_the_node_down_ends_a_wait_for_a_link() {
        let node = TestNode::bind().await;
        let listener = node
            .node
            .pairing_listen(PairingRole::Display, PairingTransportKind::Device)
            .unwrap();
        let waiting = tokio::spawn({
            let listener = listener.clone();
            async move { listener.next_link().await.err() }
        });
        node.node.shutdown().await.unwrap();
        let ended = tokio::time::timeout(Duration::from_millis(WAIT_MS), waiting)
            .await
            .expect("the wait ends")
            .unwrap();
        assert_eq!(ended, Some(PairingTransportError::Closed));
    }

    #[test]
    fn only_ipv4_addresses_are_dialled_on_the_advertised_port() {
        let txt = vec![
            PairingTxtEntry {
                key: "v".into(),
                value: "1".into(),
            },
            PairingTxtEntry {
                key: "id".into(),
                value: "e1".repeat(32),
            },
        ];
        let target = pairing_target_from_advertisement(
            txt.clone(),
            vec!["fe80::1%en0".into(), "192.168.1.20".into(), "::1".into()],
            4433,
        )
        .unwrap();
        assert_eq!(target.direct_addresses, ["192.168.1.20:4433"]);
        // Anything else that isn't an address is still an error.
        assert!(pairing_target_from_advertisement(txt, vec!["192.168.1".into()], 4433).is_err());
    }
}
