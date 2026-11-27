//! `pair-net` and `pair-link`: discovery, the invite knock and the pairing
//! transport, driven through the seam over real connections.
//!
//! `pair-net` stands up every party of a pairing as a node of its own in
//! this process, on the loopback interface (no relay, no network beyond this
//! machine), and plays the people: it opens and closes sheets, reads a code
//! off one device and types it on another, sends an invite and opens it.
//! The messages travel over the same transport a client uses, and each
//! side's sheet is given the endpoint id that transport authenticated.
//!
//! The loops in [`display_run`] and [`type_run`] are the client's contract
//! in code: carry each message to the sheet, send what it answers, stop
//! when it says the run is over, and tell it when the connection dies.
//!
//! Output is one line per event, `who: what`, for scenarios to grep. A code
//! is never printed. Links are: they are public by design.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, bail};
use keys_ffi::keys_iroh_sync::{
    Identity, IrohNode, NodeConfig, PairingInviteListener, PairingInviteRecord, PairingKnockAnswer,
    PairingLink, PairingListener, PairingParsedLink, PairingRole, PairingRunStream, PairingTarget,
    PairingTransportError, PairingTransportKind, bind_local_node_for_testing, pairing_parse_link,
    pairing_sanitize_display_name, pairing_target_from_advertisement,
};
use keys_ffi::{
    PairingAccountKeys, PairingCredentials, PairingDisplaySheet, PairingOutcomeFfi, PairingSession,
    PairingTypeSheet, PairingTypeStatus, generate_pairing_account,
};

use crate::pairing::{describe, hex, ok, wrong};

/// How long a scripted party waits for the other end. Everything here is on
/// the loopback interface, so this is only ever reached when something is
/// wrong.
const WAIT_MS: u64 = 10_000;
/// How long an invite in a scenario lasts: a week.
const INVITE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;
/// How long a scripted party gives an invite listener to have been told.
const LISTENER_SETTLE: std::time::Duration = std::time::Duration::from_millis(250);
/// Where the scripted "local network" resolves an advertised device.
const LOOPBACK_IP: &str = "127.0.0.1";
/// The inviter's name for themself, with what a hostile one might add: a
/// direction override, a control character and padding.
const INVITER_NAME: &str = "  Alice\u{202e}\u{7} ";
/// A bound on scripted attempts, above any sheet's run budget.
const MAX_ATTEMPTS: u32 = 10;
/// Leading bytes of an id shown in a trace line.
const ID_PREFIX_BYTES: usize = 4;
/// Longer than any message the transport carries before a pairing verifies.
const OVERSIZE_MESSAGE_BYTES: usize = 2048;

/// Which pairing to run.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetFlow {
    /// A new device on the same network: it advertises, the device already
    /// in the account approaches and shows the code, the new device types.
    DeviceNearby,
    /// A new device somewhere else: it shows its address link, the device
    /// already in the account approaches by it.
    DeviceLink,
    /// The direction flipped for a device that is awkward to type on: the
    /// new device shows the code, the device in the account calls and types.
    DeviceFlipped,
    /// Two people: an invite, its knock, then the code.
    Person,
}

/// Which of the inviter's devices types the code in a Person pairing.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetVerifier {
    /// The device that issued the invite.
    Issuer,
    /// Another device of the same account, which learnt the opener's
    /// endpoint from the account's data.
    Sibling,
}

/// What goes wrong, or who interferes.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetAttack {
    /// A stranger knocks with an invite id nobody issued.
    KnockUnknown,
    /// A second device knocks on an invite the first has opened.
    KnockSecondOpener,
    /// Someone who saw the invite knocks before the invited person does.
    KnockInterceptorFirst,
    /// The invite expires before it is opened.
    KnockExpired,
    /// The invite is cancelled before it is opened.
    KnockCancelled,
    /// The issuing device restarts between the invite and its knock.
    KnockRelaunch,
    /// An invite that claims the inviter's identity but names someone
    /// else's endpoint, whose owner then learns the code.
    ForgedInvite,
    /// A call, an approach and a knock at a device with no sheet open.
    NoSheet,
    /// A call for the wrong kind of pairing, and an approach where a call
    /// belongs.
    WrongKind,
    /// A stranger on the network approaches the new device first.
    StrangerFirst,
    /// The displaying side closes its sheet in the middle of a run.
    SheetClosedMidRun,
    /// A caller sends a message far longer than any exchange message.
    Oversize,
    /// A second endpoint calls the displaying side while a run is in flight
    /// with the first, is turned away, and hangs up.
    SecondCaller,
}

/// The script for one `pair-net` run.
pub struct NetScript {
    pub flow: NetFlow,
    pub typos: u32,
    pub verify_from: NetVerifier,
    pub attack: Option<NetAttack>,
    pub payload: Option<String>,
}

// ─── parties ────────────────────────────────────────────────────────────────

/// A scratch directory for one party's stores, removed when the run ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("keyhole-pair-net-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create scratch dir {}", path.display()))?;
        Ok(Self(path))
    }

    fn dir(&self, leaf: &str) -> String {
        self.0.join(leaf).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One device: a node on the loopback interface.
struct Party {
    name: &'static str,
    node: Arc<IrohNode>,
    identity: Identity,
    scratch: Scratch,
    /// What this device's invite listener has been told.
    opened: Arc<OpenedInvites>,
}

impl Party {
    /// Starts a device and opens its invite book, empty, as a client does
    /// once it is up.
    async fn start(name: &'static str) -> Result<Self> {
        let scratch = Scratch::new(name)?;
        let identity = Identity::generate();
        let node = bind(&identity, &scratch).await?;
        let party = Self {
            name,
            node,
            identity,
            scratch,
            opened: Arc::new(OpenedInvites::default()),
        };
        party.open_invite_book(Vec::new())?;
        Ok(party)
    }

    /// Opens the device's invite book with what its client had stored.
    /// Returns how many stored records the book left out.
    fn open_invite_book(&self, stored: Vec<PairingInviteRecord>) -> Result<usize> {
        Ok(self
            .node
            .pairing_open_invite_book(stored, self.opened.clone())?
            .len())
    }

    /// Quits and starts again as the same device: same identity, same
    /// stores, a fresh process's worth of memory. Its invite book is not
    /// open yet: that is the client's next step.
    async fn relaunch(&mut self) -> Result<()> {
        self.node.shutdown().await?;
        self.node = bind(&self.identity, &self.scratch).await?;
        Ok(())
    }

    /// How many invite openings this device has been told of. The listener
    /// is told on a thread of its own, so this waits a moment for it.
    async fn openings_heard(&self) -> usize {
        tokio::time::sleep(LISTENER_SETTLE).await;
        self.opened.count()
    }

    fn id(&self) -> Vec<u8> {
        self.node.pairing_endpoint_id()
    }

    /// Where to dial this party by endpoint id alone, as a link gives it.
    fn target(&self) -> PairingTarget {
        PairingTarget {
            endpoint_id: self.id(),
            relay_url: None,
            direct_addresses: Vec::new(),
        }
    }
}

async fn bind(identity: &Identity, scratch: &Scratch) -> Result<Arc<IrohNode>> {
    Ok(bind_local_node_for_testing(NodeConfig {
        identity: identity.clone(),
        blob_dir: scratch.dir("blobs"),
        doc_dir: scratch.dir("docs"),
        relay_urls: Vec::new(),
    })
    .await?)
}

/// The party whose endpoint id is `id`, by name, or `unknown`.
fn who(parties: &[&Party], id: &[u8]) -> &'static str {
    parties
        .iter()
        .find(|party| party.id() == id)
        .map_or("unknown", |party| party.name)
}

fn error_name(error: &PairingTransportError) -> &'static str {
    match error {
        PairingTransportError::Address(_) => "address",
        PairingTransportError::Unreachable(_) => "unreachable",
        PairingTransportError::NotListening => "not-listening",
        PairingTransportError::Busy => "busy",
        PairingTransportError::Protocol => "protocol",
        PairingTransportError::Closed => "closed",
        PairingTransportError::TimedOut => "timed-out",
        PairingTransportError::TooLarge => "too-large",
        PairingTransportError::WrongState => "wrong-state",
        PairingTransportError::Invite(_) => "invite",
    }
}

fn kind_name(kind: PairingTransportKind) -> &'static str {
    match kind {
        PairingTransportKind::Device => "device",
        PairingTransportKind::Person => "person",
    }
}

fn role_name(role: PairingRole) -> &'static str {
    match role {
        PairingRole::Display => "display",
        PairingRole::Type => "type",
    }
}

/// Opens the transport's side of a sheet on `party`.
fn listen(
    party: &Party,
    role: PairingRole,
    kind: PairingTransportKind,
) -> Result<Arc<PairingListener>> {
    let listener = party.node.pairing_listen(role, kind)?;
    println!(
        "{}: listening role={} kind={}",
        party.name,
        role_name(role),
        kind_name(kind)
    );
    Ok(listener)
}

/// `from` calls `to` as the side that types, and says how it went.
async fn call(
    from: &Party,
    target: PairingTarget,
    kind: PairingTransportKind,
) -> Option<Arc<PairingLink>> {
    report_meeting(from, "call", from.node.pairing_call(target, kind).await)
}

/// `from` approaches `to` as the side that shows the code.
async fn approach(
    from: &Party,
    target: PairingTarget,
    kind: PairingTransportKind,
) -> Option<Arc<PairingLink>> {
    report_meeting(
        from,
        "approach",
        from.node.pairing_approach(target, kind).await,
    )
}

fn report_meeting(
    from: &Party,
    what: &str,
    met: std::result::Result<Arc<PairingLink>, PairingTransportError>,
) -> Option<Arc<PairingLink>> {
    match met {
        Ok(link) => {
            println!("{}: {what} accepted", from.name);
            Some(link)
        }
        Err(error) => {
            println!("{}: {what} {}", from.name, error_name(&error));
            None
        }
    }
}

async fn knock(from: &Party, target: PairingTarget, invite_id: &[u8]) -> Result<()> {
    let answer = match from.node.pairing_knock(target, invite_id.to_vec()).await {
        Ok(PairingKnockAnswer::Opened) => "opened",
        Ok(PairingKnockAnswer::NotOutstanding) => "not-outstanding",
        // The other device ended the connection without answering: it
        // isn't ready to say. Worth trying again later.
        Err(PairingTransportError::Closed) => "unanswered",
        Err(error) => error_name(&error),
    };
    println!("{}: knock {answer}", from.name);
    Ok(())
}

// ─── carrying a run ─────────────────────────────────────────────────────────

/// How one side's run ended.
enum RunEnd {
    Verified {
        session: Arc<PairingSession>,
        stream: Arc<PairingRunStream>,
    },
    Failed,
    DeadEnd,
}

/// A run's stream died or misbehaved and the sheet has been told: reports
/// what the sheet made of it.
fn transport_failed(
    name: &str,
    error: &PairingTransportError,
    abandoned: std::result::Result<PairingOutcomeFfi, keys_ffi::PairingFfiError>,
) -> RunEnd {
    let outcome = match abandoned {
        Ok(PairingOutcomeFfi::Ignored) => {
            // The sheet had no run in flight with that endpoint: nothing
            // to count.
            println!(
                "{name}: transport {} -> no run in flight",
                error_name(error)
            );
            return RunEnd::Failed;
        }
        Ok(outcome) => outcome,
        Err(keys_ffi::PairingFfiError::Random) => {
            // The displaying sheet couldn't draw the next code: it is a
            // dead end, and nothing more can run.
            println!(
                "{name}: transport {} -> sheet dead end (random source failed)",
                error_name(error)
            );
            return RunEnd::DeadEnd;
        }
        Err(sheet_error) => {
            // The sheet had no run to abandon (a typing sheet whose run had
            // already ended): nothing to count, but worth seeing.
            println!(
                "{name}: transport {} -> sheet refused the abandon: {sheet_error}",
                error_name(error)
            );
            return RunEnd::Failed;
        }
    };
    println!(
        "{name}: transport {} -> {}",
        error_name(error),
        describe(&outcome)
    );
    if matches!(outcome, PairingOutcomeFfi::DeadEnd { .. }) {
        RunEnd::DeadEnd
    } else {
        RunEnd::Failed
    }
}

/// Says a run is over, after sending its last message: a run that ended
/// without a pairing has nothing more to say, so its stream is finished,
/// which is what gets that last message (a refusal, say) delivered before
/// anything is closed. A verified run keeps its stream for the session.
async fn run_end(
    name: &str,
    outcome: PairingOutcomeFfi,
    stream: &Arc<PairingRunStream>,
) -> Option<RunEnd> {
    if matches!(outcome, PairingOutcomeFfi::Continue) {
        return None;
    }
    println!("{name}: {}", describe(&outcome));
    Some(match outcome {
        PairingOutcomeFfi::Verified { session } => RunEnd::Verified {
            session,
            stream: Arc::clone(stream),
        },
        other => {
            let _ = stream.finish(WAIT_MS).await;
            if matches!(other, PairingOutcomeFfi::DeadEnd { .. }) {
                RunEnd::DeadEnd
            } else {
                RunEnd::Failed
            }
        }
    })
}

/// The displaying side of one run: waits for the typing side to start it,
/// then carries messages between the stream and the sheet until the sheet
/// says the run is over.
///
/// When the stream fails, the sheet is told which endpoint's it was
/// (`abandon_run_of`): a displaying sheet can hold links to several
/// endpoints, and only the one whose run is in flight may end it.
async fn display_run(
    name: &str,
    sheet: &PairingDisplaySheet,
    link: &PairingLink,
) -> Result<RunEnd> {
    let incoming = match link.accept_run(WAIT_MS).await {
        Ok(incoming) => incoming,
        Err(error) => {
            println!("{name}: no run ({})", error_name(&error));
            return Ok(RunEnd::Failed);
        }
    };
    let stream = incoming.stream;
    let mut message = incoming.hello;
    loop {
        let response = sheet.handle(stream.peer_endpoint_id(), message)?;
        if let Some(reply) = response.reply {
            // A reply that can't be sent shows up as the next receive
            // failing.
            let _ = stream.send(reply).await;
        }
        if let Some(end) = run_end(name, response.outcome, &stream).await {
            return Ok(end);
        }
        message = match stream.receive(WAIT_MS).await {
            Ok(next) => next,
            Err(error) => {
                let abandoned = sheet.abandon_run_of(stream.peer_endpoint_id());
                return Ok(transport_failed(name, &error, abandoned));
            }
        };
    }
}

/// The typing side of one run: the person has typed `code`.
async fn type_run(
    name: &str,
    sheet: &PairingTypeSheet,
    link: &PairingLink,
    code: String,
) -> Result<RunEnd> {
    let hello = sheet.submit_code(code)?;
    println!("{name}: submit");
    let stream = match link.open_run(hello).await {
        Ok(stream) => stream,
        Err(error) => return Ok(transport_failed(name, &error, sheet.abandon_run())),
    };
    loop {
        let message = match stream.receive(WAIT_MS).await {
            Ok(message) => message,
            Err(error) => return Ok(transport_failed(name, &error, sheet.abandon_run())),
        };
        let response = sheet.handle(stream.peer_endpoint_id(), message)?;
        if let Some(reply) = response.reply {
            let _ = stream.send(reply).await;
        }
        if let Some(end) = run_end(name, response.outcome, &stream).await {
            return Ok(end);
        }
    }
}

/// One side of a pairing: its name, its sheet and its link to the other.
struct Side<'a, Sheet> {
    name: &'static str,
    sheet: &'a Sheet,
    link: &'a PairingLink,
}

/// Both sides' sessions and streams, once a pairing has verified.
struct Paired {
    display_session: Arc<PairingSession>,
    display_stream: Arc<PairingRunStream>,
    type_session: Arc<PairingSession>,
    type_stream: Arc<PairingRunStream>,
}

/// Plays the person through a sheet's worth of attempts: reads the code
/// off the displaying side, types it (wrongly, `typos` times) on the typing
/// side, and carries each run. `None` if it ended without a pairing.
async fn pair(
    display: &Side<'_, PairingDisplaySheet>,
    typing: &Side<'_, PairingTypeSheet>,
    typos: u32,
) -> Result<Option<Paired>> {
    for attempt in 0..MAX_ATTEMPTS {
        let Some(code) = display.sheet.shown_code()? else {
            break;
        };
        if matches!(typing.sheet.status(), PairingTypeStatus::DeadEnd) {
            break;
        }
        let typed = if attempt < typos { wrong(&code) } else { code };
        // Boxed: each run's future carries a whole stream's worth of state.
        let (display_end, type_end) = tokio::join!(
            Box::pin(display_run(display.name, display.sheet, display.link)),
            Box::pin(type_run(typing.name, typing.sheet, typing.link, typed)),
        );
        match (display_end?, type_end?) {
            (
                RunEnd::Verified {
                    session: display_session,
                    stream: display_stream,
                },
                RunEnd::Verified {
                    session: type_session,
                    stream: type_stream,
                },
            ) => {
                return Ok(Some(Paired {
                    display_session,
                    display_stream,
                    type_session,
                    type_stream,
                }));
            }
            (RunEnd::DeadEnd, _) | (_, RunEnd::DeadEnd) => break,
            _ => {}
        }
    }
    Ok(None)
}

/// Sends `payload` both ways down the verified session, over the run's
/// stream, the typing side first.
async fn exchange_payload(
    paired: &Paired,
    display: &Side<'_, PairingDisplaySheet>,
    typing: &Side<'_, PairingTypeSheet>,
    payload: &str,
) -> Result<()> {
    paired.display_stream.allow_session_frames();
    paired.type_stream.allow_session_frames();
    let frame = paired.type_session.seal(payload.as_bytes().to_vec())?;
    paired.type_stream.send(frame).await?;
    let frame = paired.display_stream.receive(WAIT_MS).await?;
    let received = paired
        .display_session
        .open(display.link.peer_endpoint_id(), frame)?;
    println!(
        "session: type-to-display {}",
        ok(received == payload.as_bytes())
    );
    let frame = paired.display_session.seal(payload.as_bytes().to_vec())?;
    paired.display_stream.send(frame).await?;
    // The session's last frame: finished, so it arrives whatever is closed
    // next.
    paired.display_stream.finish(WAIT_MS).await?;
    let frame = paired.type_stream.receive(WAIT_MS).await?;
    let received = paired
        .type_session
        .open(typing.link.peer_endpoint_id(), frame)?;
    println!(
        "session: display-to-type {}",
        ok(received == payload.as_bytes())
    );
    paired.type_stream.finish(WAIT_MS).await?;
    Ok(())
}

fn report_result(paired: Option<&Paired>) {
    println!(
        "result: {}",
        if paired.is_some() {
            "verified"
        } else {
            "not-verified"
        }
    );
}

fn type_status(name: &str, sheet: &PairingTypeSheet) {
    let status = match sheet.status() {
        PairingTypeStatus::AwaitingCode { runs_left } => {
            format!("awaiting-code runs-left={runs_left}")
        }
        PairingTypeStatus::Running => "running".to_owned(),
        PairingTypeStatus::Verified => "verified".to_owned(),
        PairingTypeStatus::DeadEnd => "dead-end".to_owned(),
    };
    println!("{name}: status {status}");
}

// ─── device pairing ─────────────────────────────────────────────────────────

const DEVICE: PairingTransportKind = PairingTransportKind::Device;
const PERSON: PairingTransportKind = PairingTransportKind::Person;

/// Finishes a device pairing once both sides hold a link: opens the sheets
/// against the endpoint ids the transport authenticated, and runs the code.
async fn pair_devices(
    script: &NetScript,
    display: (&Party, &PairingLink),
    typing: (&Party, &PairingLink),
) -> Result<()> {
    let display_sheet = PairingDisplaySheet::open(PairingCredentials::Device, display.0.id())?;
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        typing.0.id(),
        typing.1.peer_endpoint_id(),
    )?;
    let display_side = Side {
        name: display.0.name,
        sheet: &*display_sheet,
        link: display.1,
    };
    let type_side = Side {
        name: typing.0.name,
        sheet: &*type_sheet,
        link: typing.1,
    };
    let paired = pair(&display_side, &type_side, script.typos).await?;
    if let (Some(paired), Some(payload)) = (&paired, &script.payload) {
        exchange_payload(paired, &display_side, &type_side, payload).await?;
    }
    type_status(typing.0.name, &type_sheet);
    report_result(paired.as_ref());
    Ok(())
}

/// The new device's sheet is open and it says so on the local network; the
/// device in the account finds it there. Returns where to dial.
fn discover_nearby(new_device: &Party) -> Result<PairingTarget> {
    let advert = new_device.node.pairing_advertisement()?;
    let keys: Vec<&str> = advert.txt.iter().map(|entry| entry.key.as_str()).collect();
    println!(
        "{}: advertising service={} txt-keys={}",
        new_device.name,
        advert.service_type,
        keys.join(",")
    );
    let target =
        pairing_target_from_advertisement(advert.txt, vec![LOOPBACK_IP.to_owned()], advert.port)?;
    println!(
        "trusted: discovered endpoint-matches={} direct-addresses={}",
        yes(target.endpoint_id == new_device.id()),
        target.direct_addresses.len()
    );
    Ok(target)
}

/// The new device shows its address link; the device in the account reads
/// it. Returns where to dial.
fn discover_by_link(new_device: &Party) -> Result<PairingTarget> {
    let link = new_device.node.pairing_device_link()?;
    println!("link: {link}");
    let PairingParsedLink::Device { target } = pairing_parse_link(link)? else {
        bail!("a device link parsed as something else");
    };
    println!(
        "trusted: parsed device-link endpoint-matches={}",
        yes(target.endpoint_id == new_device.id())
    );
    Ok(target)
}

fn yes(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

async fn device_flow(script: &NetScript) -> Result<()> {
    let trusted = Party::start("trusted").await?;
    let new_device = Party::start("new").await?;
    let stranger = Party::start("stranger").await?;
    let everyone = [&trusted, &new_device, &stranger];

    if script.flow == NetFlow::DeviceFlipped {
        // The new device shows the code; the device in the account types.
        let listener = listen(&new_device, PairingRole::Display, DEVICE)?;
        let target = discover_nearby(&new_device)?;
        let Some(type_link) = call(&trusted, target, DEVICE).await else {
            bail!("the call was refused");
        };
        let display_link = listener.next_link().await?;
        return pair_devices(script, (&new_device, &display_link), (&trusted, &type_link)).await;
    }

    let listener = listen(&new_device, PairingRole::Type, DEVICE)?;
    let target = match script.flow {
        NetFlow::DeviceLink => discover_by_link(&new_device)?,
        _ => discover_nearby(&new_device)?,
    };

    if script.attack == Some(NetAttack::StrangerFirst) {
        stranger_first(&stranger, &trusted, &new_device, &listener, &target).await?;
    }

    let Some(display_link) = approach(&trusted, target, DEVICE).await else {
        bail!("the approach was refused");
    };
    let type_link = listener.next_link().await?;
    println!(
        "{}: approached by={}",
        new_device.name,
        who(&everyone, &type_link.peer_endpoint_id())
    );
    pair_devices(script, (&trusted, &display_link), (&new_device, &type_link)).await
}

/// A stranger on the network reaches the new device before the device in
/// the account does. The person types the code their own device shows; the
/// stranger's sheet shows another, so the run fails, and the person turns
/// the stranger away.
async fn stranger_first(
    stranger: &Party,
    trusted: &Party,
    new_device: &Party,
    listener: &PairingListener,
    target: &PairingTarget,
) -> Result<()> {
    let Some(stranger_link) = approach(stranger, target.clone(), DEVICE).await else {
        bail!("the stranger's approach was refused");
    };
    let held = listener.next_link().await?;
    println!(
        "{}: approached by={}",
        new_device.name,
        who(&[stranger, trusted], &held.peer_endpoint_id())
    );
    // The place is taken: the device in the account is turned away.
    approach(trusted, target.clone(), DEVICE).await;

    let stranger_sheet = PairingDisplaySheet::open(PairingCredentials::Device, stranger.id())?;
    let trusted_sheet = PairingDisplaySheet::open(PairingCredentials::Device, trusted.id())?;
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        new_device.id(),
        held.peer_endpoint_id(),
    )?;
    // What the person reads is on their own device, which the new device
    // isn't talking to. If the two happen to match, type something else:
    // the point is a code the stranger didn't make.
    let own = trusted_sheet.shown_code()?.context("a code on show")?;
    let theirs = stranger_sheet.shown_code()?.context("a code on show")?;
    let typed = if own == theirs { wrong(&own) } else { own };
    let (stranger_end, type_end) = tokio::join!(
        Box::pin(display_run(stranger.name, &stranger_sheet, &stranger_link)),
        Box::pin(type_run(new_device.name, &type_sheet, &held, typed)),
    );
    stranger_end?;
    type_end?;
    type_status(new_device.name, &type_sheet);

    held.close();
    println!("{}: dismissed stranger", new_device.name);
    Ok(())
}

// ─── Person pairing ─────────────────────────────────────────────────────────

/// Collects what a node's invite listener is told.
#[derive(Default)]
struct OpenedInvites(Mutex<Vec<(Vec<u8>, Vec<u8>)>>);

impl PairingInviteListener for OpenedInvites {
    fn invite_opened(&self, invite_id: Vec<u8>, opener_endpoint_id: Vec<u8>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((invite_id, opener_endpoint_id));
    }
}

impl OpenedInvites {
    fn count(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

/// An invite as its issuer and its reader each see it.
struct SentInvite {
    invite_id: Vec<u8>,
    /// What the link said, parsed by the invited side.
    inviter_identity: Vec<u8>,
    target: PairingTarget,
}

/// `issuer` makes an invite for the account `account`; `reader` parses the
/// link.
fn send_invite(issuer: &Party, account: &PairingAccountKeys, reader: &str) -> Result<SentInvite> {
    let identity = account.public_keys().identity;
    let handed_out = issuer.node.pairing_issue_invite(
        identity.clone(),
        INVITER_NAME.to_owned(),
        INVITE_LIFETIME_SECS,
    )?;
    println!(
        "{}: invite handed_out id={}",
        issuer.name,
        hex(&handed_out.invite_id[..ID_PREFIX_BYTES])
    );
    println!("link: {}", handed_out.link);
    let PairingParsedLink::Person { invite } = pairing_parse_link(handed_out.link)? else {
        bail!("an invite link parsed as something else");
    };
    println!(
        "{reader}: parsed invite identity-matches={} endpoint-matches={} name={:?}",
        yes(invite.inviter_identity == identity),
        yes(invite.target.endpoint_id == issuer.id()),
        invite.inviter_name
    );
    Ok(SentInvite {
        invite_id: invite.invite_id,
        inviter_identity: invite.inviter_identity,
        target: invite.target,
    })
}

fn report_invites(issuer: &Party, everyone: &[&Party]) -> Vec<PairingInviteRecord> {
    let records = issuer.node.pairing_invites().unwrap_or_default();
    if records.is_empty() {
        println!("{}: no invites outstanding", issuer.name);
    }
    for record in &records {
        println!(
            "{}: invite id={} opened-by={}",
            issuer.name,
            hex(&record.invite_id[..ID_PREFIX_BYTES]),
            record
                .opened_by
                .as_deref()
                .map_or("nobody", |opener| who(everyone, opener))
        );
    }
    records
}

/// The verification of a Person pairing: `display` (the invite's opener)
/// shows the code expecting `expected_identity`, `typing` calls it and
/// types, wrongly for the first `typos` attempts.
async fn verify_person(
    display: (&Party, &Arc<PairingAccountKeys>, Option<Vec<u8>>),
    typing: (&Party, &Arc<PairingAccountKeys>),
    typos: u32,
    payload: Option<&String>,
) -> Result<Option<Paired>> {
    let (display_party, display_account, expected_identity) = display;
    let (type_party, type_account) = typing;
    let listener = listen(display_party, PairingRole::Display, PERSON)?;
    let Some(type_link) = call(type_party, display_party.target(), PERSON).await else {
        return Ok(None);
    };
    let display_link = listener.next_link().await?;
    let display_sheet = PairingDisplaySheet::open(
        PairingCredentials::Person {
            account: Arc::clone(display_account),
            expected_peer_identity: expected_identity,
        },
        display_party.id(),
    )?;
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Person {
            account: Arc::clone(type_account),
            expected_peer_identity: None,
        },
        type_party.id(),
        type_link.peer_endpoint_id(),
    )?;
    let display_side = Side {
        name: display_party.name,
        sheet: &*display_sheet,
        link: &display_link,
    };
    let type_side = Side {
        name: type_party.name,
        sheet: &*type_sheet,
        link: &type_link,
    };
    let paired = pair(&display_side, &type_side, typos).await?;
    if let Some(paired) = &paired {
        let seen_by_display = paired.display_session.peer_account();
        let seen_by_type = paired.type_session.peer_account();
        println!(
            "{}: peer-keys-match={}",
            display_party.name,
            yes(seen_by_display == Some(type_account.public_keys()))
        );
        println!(
            "{}: peer-keys-match={}",
            type_party.name,
            yes(seen_by_type == Some(display_account.public_keys()))
        );
        if let Some(payload) = payload {
            exchange_payload(paired, &display_side, &type_side, payload).await?;
        }
    }
    type_status(type_party.name, &type_sheet);
    Ok(paired)
}

#[allow(clippy::too_many_lines)] // one scripted story, told in order
async fn person_flow(script: &NetScript) -> Result<()> {
    let mut alice_mac = Party::start("alice-mac").await?;
    let alice_phone = Party::start("alice-phone").await?;
    let bob = Party::start("bob").await?;
    let mallory = Party::start("mallory").await?;
    let alice = generate_pairing_account()?.keys;
    let bob_account = generate_pairing_account()?.keys;
    let mallory_account = generate_pairing_account()?.keys;

    if script.attack == Some(NetAttack::KnockUnknown) {
        send_invite(&alice_mac, &alice, bob.name)?;
        knock(&mallory, alice_mac.target(), &[0x99; 16]).await?;
        println!(
            "alice-mac: invites-opened={}",
            alice_mac.openings_heard().await
        );
        report_invites(&alice_mac, &[&bob, &mallory]);
        return Ok(());
    }

    if script.attack == Some(NetAttack::ForgedInvite) {
        // Mallory's device issues an invite that claims Alice's identity.
        let forged = send_invite(&mallory, &alice, bob.name)?;
        knock(&bob, forged.target.clone(), &forged.invite_id).await?;
        // Bob reads his code to "Alice"; Mallory types it, correctly, as
        // the only account she can sign for.
        let paired = verify_person(
            (&bob, &bob_account, Some(forged.inviter_identity)),
            (&mallory, &mallory_account),
            0,
            None,
        )
        .await?;
        report_result(paired.as_ref());
        return Ok(());
    }

    let invite = send_invite(&alice_mac, &alice, bob.name)?;
    let everyone = [&alice_phone, &bob, &mallory];

    match script.attack {
        Some(NetAttack::KnockExpired) => {
            alice_mac
                .node
                .pairing_test_advance_clock(INVITE_LIFETIME_SECS);
            println!("clock: past invite expiry");
        }
        Some(NetAttack::KnockCancelled) => {
            println!(
                "alice-mac: invite retired={}",
                yes(alice_mac
                    .node
                    .pairing_retire_invite(invite.invite_id.clone())?)
            );
        }
        Some(NetAttack::KnockRelaunch) => {
            // What the client had stored when the device went down.
            let stored = alice_mac.node.pairing_invites()?;
            alice_mac.relaunch().await?;
            println!("alice-mac: relaunched");
            // Bob opens the invite while the device is up but its client
            // hasn't yet handed the stored invites back. There is no true
            // answer to give, so none is given: Bob's device will try again.
            knock(&bob, invite.target.clone(), &invite.invite_id).await?;
            // The client's store also holds an entry it can't use (one that
            // claims to expire long after any invite could). It is left
            // out; the invite beside it is not held up by it.
            let mut stored = stored;
            stored.push(PairingInviteRecord {
                invite_id: vec![0xbd; 16],
                expires_at_unix: u64::MAX,
                opened_by: None,
            });
            let left_out = alice_mac.open_invite_book(stored)?;
            println!(
                "alice-mac: invite book open invites-outstanding={} left-out={left_out}",
                alice_mac.node.pairing_invites()?.len()
            );
        }
        Some(NetAttack::KnockInterceptorFirst) => {
            knock(&mallory, invite.target.clone(), &invite.invite_id).await?;
        }
        _ => {}
    }

    // Bob opens the invite. No sheet is open on Alice's device.
    knock(&bob, invite.target.clone(), &invite.invite_id).await?;
    if script.attack == Some(NetAttack::KnockSecondOpener) {
        knock(&mallory, invite.target.clone(), &invite.invite_id).await?;
        // A lost answer: the first opener asks again and hears the same.
        knock(&bob, invite.target.clone(), &invite.invite_id).await?;
    }
    println!(
        "alice-mac: invites-opened={}",
        alice_mac.openings_heard().await
    );
    let records = report_invites(&alice_mac, &everyone);

    // A knock opens no sheet and runs no exchange.
    call(&bob, invite.target.clone(), PERSON).await;

    let Some(recorded) = records.first().and_then(|record| record.opened_by.clone()) else {
        println!("result: not-verified");
        return Ok(());
    };

    // Alice verifies, from the device that issued the invite or from
    // another of hers that read the opener's endpoint out of her account.
    let verifier = match script.verify_from {
        NetVerifier::Issuer => &alice_mac,
        NetVerifier::Sibling => &alice_phone,
    };
    let paired = if recorded == bob.id() {
        verify_person(
            (&bob, &bob_account, Some(invite.inviter_identity.clone())),
            (verifier, &alice),
            script.typos,
            script.payload.as_ref(),
        )
        .await?
    } else {
        // The opener on record is the interceptor. Bob's device was told
        // the invite isn't outstanding, so Bob has no code to read out;
        // whatever Alice types at the interceptor's sheet is a guess.
        call(verifier, mallory.target(), PERSON).await;
        verify_person(
            (&mallory, &mallory_account, None),
            (verifier, &alice),
            MAX_ATTEMPTS,
            None,
        )
        .await?
    };

    // Verified or dead-ended, the invite is spent.
    println!(
        "alice-mac: invite retired={}",
        yes(alice_mac
            .node
            .pairing_retire_invite(invite.invite_id.clone())?)
    );
    knock(&bob, invite.target, &invite.invite_id).await?;
    report_result(paired.as_ref());
    Ok(())
}

// ─── sheets that aren't open, and misbehaving callers ───────────────────────

async fn no_sheet() -> Result<()> {
    let quiet = Party::start("quiet").await?;
    let stranger = Party::start("stranger").await?;
    for kind in [DEVICE, PERSON] {
        call(&stranger, quiet.target(), kind).await;
        approach(&stranger, quiet.target(), kind).await;
    }
    knock(&stranger, quiet.target(), &[0x99; 16]).await?;
    println!(
        "quiet: invites-outstanding={}",
        quiet.node.pairing_invites()?.len()
    );
    Ok(())
}

async fn wrong_kind() -> Result<()> {
    let bob = Party::start("bob").await?;
    let stranger = Party::start("stranger").await?;
    let listener = listen(&bob, PairingRole::Display, PERSON)?;
    call(&stranger, bob.target(), DEVICE).await;
    approach(&stranger, bob.target(), PERSON).await;
    approach(&stranger, bob.target(), DEVICE).await;
    // The right greeting is still welcome afterwards.
    let link = call(&stranger, bob.target(), PERSON).await;
    println!(
        "bob: link from={}",
        who(
            &[&stranger],
            &listener.next_link().await?.peer_endpoint_id()
        )
    );
    drop(link);

    // The sheet closes: nothing is accepted any more.
    listener.close();
    println!("bob: sheet closed");
    call(&stranger, bob.target(), PERSON).await;
    Ok(())
}

async fn sheet_closed_mid_run() -> Result<()> {
    let display = Party::start("display").await?;
    let typing = Party::start("type").await?;
    let listener = listen(&display, PairingRole::Display, DEVICE)?;
    let Some(type_link) = call(&typing, display.target(), DEVICE).await else {
        bail!("the call was refused");
    };
    let display_link = listener.next_link().await?;
    let display_sheet = PairingDisplaySheet::open(PairingCredentials::Device, display.id())?;
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        typing.id(),
        type_link.peer_endpoint_id(),
    )?;
    let code = display_sheet.shown_code()?.context("a code on show")?;

    // The run starts: Hello across, Share back.
    let hello = type_sheet.submit_code(code)?;
    println!("type: submit");
    let stream = type_link.open_run(hello).await?;
    let incoming = display_link.accept_run(WAIT_MS).await?;
    let share = display_sheet.handle(display_link.peer_endpoint_id(), incoming.hello)?;
    incoming
        .stream
        .send(share.reply.context("a share")?)
        .await?;
    let share = stream.receive(WAIT_MS).await?;
    let reply = type_sheet.handle(type_link.peer_endpoint_id(), share)?;

    // The person closes the displaying sheet before the Reply lands.
    listener.close();
    println!("display: sheet closed");
    println!(
        "display: abandoned {}",
        describe(&display_sheet.abandon_run()?)
    );
    let _ = stream.send(reply.reply.context("a reply")?).await;
    let error = stream
        .receive(WAIT_MS)
        .await
        .err()
        .context("the stream should have closed")?;
    transport_failed("type", &error, type_sheet.abandon_run());
    type_status("type", &type_sheet);
    call(&typing, display.target(), DEVICE).await;
    println!("result: not-verified");
    Ok(())
}

async fn oversize() -> Result<()> {
    let display = Party::start("display").await?;
    let mallory = Party::start("mallory").await?;
    let listener = listen(&display, PairingRole::Display, DEVICE)?;
    let Some(type_link) = call(&mallory, display.target(), DEVICE).await else {
        bail!("the call was refused");
    };
    let display_link = listener.next_link().await?;
    let display_sheet = PairingDisplaySheet::open(PairingCredentials::Device, display.id())?;
    // A real Hello, so a run is in flight, then far more than a Reply.
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        mallory.id(),
        type_link.peer_endpoint_id(),
    )?;
    let code = display_sheet.shown_code()?.context("a code on show")?;
    let hello = type_sheet.submit_code(wrong(&code))?;
    let (display_end, sent) = tokio::join!(
        Box::pin(display_run(display.name, &display_sheet, &display_link)),
        async {
            let stream = type_link.open_run(hello).await?;
            stream.receive(WAIT_MS).await?;
            stream.send(vec![0; OVERSIZE_MESSAGE_BYTES]).await?;
            println!("mallory: sent {OVERSIZE_MESSAGE_BYTES} bytes where a reply belongs");
            anyhow::Ok(stream)
        },
    );
    display_end?;
    sent?;
    // The transport refuses a first message that long outright.
    let refused = type_link
        .open_run(vec![0; OVERSIZE_MESSAGE_BYTES])
        .await
        .err()
        .context("an oversize hello should be refused")?;
    println!("mallory: oversize hello {}", error_name(&refused));
    // And the sheet is still there for an honest run.
    println!(
        "display: showing-code={}",
        yes(display_sheet.shown_code()?.is_some())
    );
    println!("result: not-verified");
    Ok(())
}

/// A displaying sheet with two callers. The first's run is in flight when
/// the second calls, sends a Hello of its own, is told the sheet is busy,
/// and hangs up. The second's connection failing must not end the first's
/// run.
async fn second_caller() -> Result<()> {
    let display = Party::start("display").await?;
    let typing = Party::start("type").await?;
    let stranger = Party::start("stranger").await?;
    let listener = listen(&display, PairingRole::Display, DEVICE)?;
    let Some(type_link) = call(&typing, display.target(), DEVICE).await else {
        bail!("the call was refused");
    };
    let display_link = listener.next_link().await?;
    let display_sheet = PairingDisplaySheet::open(PairingCredentials::Device, display.id())?;
    let type_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        typing.id(),
        type_link.peer_endpoint_id(),
    )?;
    let code = display_sheet.shown_code()?.context("a code on show")?;

    // The first run starts: Hello across, Share back.
    let hello = type_sheet.submit_code(code.clone())?;
    println!("type: submit");
    let stream = type_link.open_run(hello).await?;
    let incoming = display_link.accept_run(WAIT_MS).await?;
    let share = display_sheet.handle(incoming.stream.peer_endpoint_id(), incoming.hello)?;
    incoming
        .stream
        .send(share.reply.context("a share")?)
        .await?;

    // The second caller arrives mid-run, on a link of its own.
    let Some(stranger_link) = call(&stranger, display.target(), DEVICE).await else {
        bail!("the second call was refused");
    };
    let second_link = listener.next_link().await?;
    let stranger_sheet = PairingTypeSheet::open(
        PairingCredentials::Device,
        stranger.id(),
        stranger_link.peer_endpoint_id(),
    )?;
    let stranger_stream = stranger_link
        .open_run(stranger_sheet.submit_code(wrong(&code))?)
        .await?;
    let second = second_link.accept_run(WAIT_MS).await?;
    let refused = display_sheet.handle(second.stream.peer_endpoint_id(), second.hello)?;
    println!("display: second-caller {}", describe(&refused.outcome));
    second
        .stream
        .send(refused.reply.context("a refusal")?)
        .await?;
    second.stream.finish(WAIT_MS).await?;
    let told = stranger_sheet.handle(
        stranger_stream.peer_endpoint_id(),
        stranger_stream.receive(WAIT_MS).await?,
    )?;
    println!("stranger: {}", describe(&told.outcome));
    type_status("stranger", &stranger_sheet);

    // It hangs up. Its stream fails on the displaying side, which tells the
    // sheet whose stream it was.
    stranger_link.close();
    let error = second
        .stream
        .receive(WAIT_MS)
        .await
        .err()
        .context("the second caller's stream should have closed")?;
    println!(
        "display: second-caller-gone transport {} -> {}",
        error_name(&error),
        describe(&display_sheet.abandon_run_of(second.stream.peer_endpoint_id())?)
    );

    // The first run goes on to verify.
    let reply = type_sheet.handle(stream.peer_endpoint_id(), stream.receive(WAIT_MS).await?)?;
    stream.send(reply.reply.context("a reply")?).await?;
    let confirm = display_sheet.handle(
        incoming.stream.peer_endpoint_id(),
        incoming.stream.receive(WAIT_MS).await?,
    )?;
    println!("display: {}", describe(&confirm.outcome));
    incoming
        .stream
        .send(confirm.reply.context("a confirm")?)
        .await?;
    let verified = type_sheet.handle(stream.peer_endpoint_id(), stream.receive(WAIT_MS).await?)?;
    println!("type: {}", describe(&verified.outcome));
    type_status("type", &type_sheet);
    println!(
        "result: {}",
        if matches!(verified.outcome, PairingOutcomeFfi::Verified { .. }) {
            "verified"
        } else {
            "not-verified"
        }
    );
    Ok(())
}

/// `pair-net`: runs a scripted pairing over the transport.
pub async fn run(script: &NetScript) -> Result<()> {
    match script.attack {
        Some(NetAttack::NoSheet) => return no_sheet().await,
        Some(NetAttack::WrongKind) => return wrong_kind().await,
        Some(NetAttack::SheetClosedMidRun) => return sheet_closed_mid_run().await,
        Some(NetAttack::Oversize) => return oversize().await,
        Some(NetAttack::SecondCaller) => return second_caller().await,
        _ => {}
    }
    match script.flow {
        NetFlow::Person => person_flow(script).await,
        _ => device_flow(script).await,
    }
}

// ─── pair-link ──────────────────────────────────────────────────────────────

/// `pair-link`: parses a `keys://pair/…` link and prints what it holds, or
/// why it holds nothing. Exits 0 either way: a refusal is an answer.
pub fn parse_link(text: &str) {
    match pairing_parse_link(text.to_owned()) {
        Ok(PairingParsedLink::Device { target }) => {
            println!("link: device");
            print_target(&target);
        }
        Ok(PairingParsedLink::Person { invite }) => {
            println!("link: person");
            print_target(&invite.target);
            println!("identity: {}", hex(&invite.inviter_identity));
            println!("invite-id: {}", hex(&invite.invite_id));
            println!("expires-at: {}", invite.expires_at_unix);
            println!("name: {:?}", invite.inviter_name);
        }
        Err(error) => println!("refused: {}", refusal_reason(&error)),
    }
}

fn print_target(target: &PairingTarget) {
    println!("endpoint: {}", hex(&target.endpoint_id));
    println!("relay: {}", target.relay_url.as_deref().unwrap_or("none"));
}

/// The reason inside an address error, in the words the seam uses.
fn refusal_reason(error: &PairingTransportError) -> String {
    match error {
        PairingTransportError::Address(reason) => reason.to_lowercase().replace(' ', "-"),
        other => error_name(other).to_owned(),
    }
}

/// `pair-name`: what a name from an unverified source is shown as.
pub fn sanitize_name(name: &str) {
    println!("name: {:?}", pairing_sanitize_display_name(name.to_owned()));
}
