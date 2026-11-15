//! Gossip transport and envelope dispatch.
//!
//! Rust counterpart of the C gossip package
//! (`src/packages/comm/gossip/gossip.c` / `gossip.h`,
//! `src/packages/comm/envelope_dispatcher.c` / `.h`) plus the
//! ingest pipeline wired in `src/main.c`
//! (`gossip_receive_envelope_handler` /
//! `gossip_receive_message_handler` and their helpers
//! `discover_peer_from_source` / `handle_node_announcement`).
//!
//! * [`GossipService`] is the `GossipService` UDP transport: it
//!   binds a UDP socket, runs the receive loop on a thread, keeps
//!   the 32-entry peer list with the C health fields, and
//!   broadcasts / rebroadcasts prost-encoded `Envelope` /
//!   `Message` protobufs. The prost encoding of these schemas is
//!   byte-identical to the C protobuf-c packing, so the wire bytes
//!   match what a C node sends.
//! * [`IngestPipeline`] is the `main.c` receive pipeline, exposed
//!   as handlers a later `main.rs` can install exactly like
//!   `main.c` installs its C callbacks: validate, trust check
//!   against the `node_trust` store, dedup via the store seen
//!   set, store, discover-peer-from-source, node-registration
//!   handling, content dispatch, rebroadcast to other peers.
//! * [`EnvelopeDispatcher`] is the content-type handler registry
//!   from `envelope_dispatcher.c`, with its two default handlers.
//!
//! Porting notes / deliberate deviations:
//!
//! * DESIGN.md 4.2: `gossip_envelopes` is the ONLY content store.
//!   The legacy `gossip_messages` table is retired and is never
//!   written here, even where older C code wrote to it. (Current
//!   C ingest already stores envelopes in `gossip_envelopes` and
//!   messages via `message_store_save` into `user_messages`; both
//!   are kept, `gossip_messages` is not touched.)
//! * `client_request_converter.c` is not ported (DESIGN.md 2.1
//!   retires the `ClientRequest` wire format); nothing here
//!   references it. The envelope path is kept faithful to C.
//! * The encryption and keystore Rust modules are not yet
//!   ported, so payload decryption (`decrypt_envelope_payload`)
//!   is an injectable hook ([`EnvelopeDecryptor`]). With no hook
//!   installed, decryption always "fails", which the C code
//!   treats as "we may not be a recipient": dispatch still runs
//!   its handlers with no plaintext, the location handler still
//!   stores the encrypted envelope, the emergency handler returns
//!   success, and node announcements are skipped (all non-fatal
//!   in C as well).
//! * C handlers take a `void* context`; Rust handlers are
//!   closures that capture their context instead.
//! * C `discover_peer_from_source` reverse-resolves the source
//!   IP with `gethostbyaddr`; std has no reverse-DNS, so the
//!   fallback C path (use the IP literal as the hostname) is
//!   what runs. The peer is still added at the fixed gossip
//!   port 9000 exactly as in C.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message as _;

use crate::discovery::{DiscoveryError, Peer, PeerSink};
use crate::proto::{EmergencyAlert, Envelope, Message, NodeRegistration};
use crate::store::{self, Store, GOSSIP_SEEN_DIGEST_SIZE};
use crate::validation::{
    self, GossipValidationConfig, GossipValidationError, MessageValidationError,
};

/// Maximum peers in the peer list (`GOSSIP_MAX_PEERS`).
pub const GOSSIP_MAX_PEERS: usize = 32;
/// Maximum serialized datagram size (`GOSSIP_MAX_MESSAGE_SIZE`).
pub const GOSSIP_MAX_MESSAGE_SIZE: usize = 8192;
/// Default gossip UDP port (`GOSSIP_PORT` in the C sources).
pub const GOSSIP_PORT: u16 = 9000;

/// `CONTENT_LOCATION_UPDATE` (`content.proto`).
pub const CONTENT_LOCATION_UPDATE: u32 = 33;
/// `CONTENT_GROUP_KEY_SHARE` (`envelope.proto`, Phase B4).
pub const CONTENT_GROUP_KEY_SHARE: u32 = 25;
/// `CONTENT_EMERGENCY_ALERT` (`content.proto`).
pub const CONTENT_EMERGENCY_ALERT: u32 = 34;
/// `CONTENT_NODE_REGISTRATION` (`content.proto`).
pub const CONTENT_NODE_REGISTRATION: u32 = 40;

/// Maximum registered content handlers (`MAX_HANDLERS`).
pub const MAX_HANDLERS: usize = 256;

/// Errors returned by the gossip service, ingest pipeline and
/// dispatcher. C collapses these to `-1` returns / log lines.
#[derive(Debug)]
pub enum Error {
    /// Underlying UDP socket failure.
    Io(std::io::Error),
    /// Caller supplied an invalid argument (C `-1` before any I/O).
    InvalidArgument(String),
    /// Serialized protobuf is empty or over
    /// [`GOSSIP_MAX_MESSAGE_SIZE`] (C rejects both in the send path).
    TooLarge(usize),
    /// Service socket is not running (C: `socket_fd < 0`).
    NotRunning,
    /// Peer table already holds [`GOSSIP_MAX_PEERS`] peers.
    PeerTableFull,
    /// Envelope/message validation failed (ingest rejection).
    Validation(String),
    /// Sender public key is not in the `node_trust` whitelist.
    Unauthorized,
    /// Persistence failure from the store layer.
    Store(store::Error),
    /// No handler registered for a content type (dispatcher).
    NoHandler(u32),
    /// A content handler reported failure.
    Handler(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "gossip io error: {e}"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::TooLarge(n) => write!(f, "serialized size {n} exceeds limit"),
            Error::NotRunning => write!(f, "gossip service is not running"),
            Error::PeerTableFull => write!(f, "peer table full ({GOSSIP_MAX_PEERS} peers)"),
            Error::Validation(m) => write!(f, "validation failed: {m}"),
            Error::Unauthorized => write!(f, "sender not in node_trust whitelist"),
            Error::Store(e) => write!(f, "store error: {e}"),
            Error::NoHandler(ct) => write!(f, "no handler for content type {ct}"),
            Error::Handler(m) => write!(f, "content handler failed: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Error::Store(e)
    }
}

impl From<GossipValidationError> for Error {
    fn from(e: GossipValidationError) -> Self {
        Error::Validation(e.to_string())
    }
}

impl From<MessageValidationError> for Error {
    fn from(e: MessageValidationError) -> Self {
        Error::Validation(e.to_string())
    }
}

/// Gossip result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex of a key, for ingest log lines.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Source label for ingest log lines (`local` when the
/// datagram did not come from the network).
fn source_label(source: Option<SocketAddr>) -> String {
    source
        .map(|s| s.to_string())
        .unwrap_or_else(|| "local".to_string())
}

/// One peer-list entry (C `GossipPeer`). Times are epoch seconds
/// (C `time_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipPeer {
    /// Hostname or address (`address[256]` in C).
    pub address: String,
    /// Gossip UDP port.
    pub port: u16,
    /// Last successful send (0 = never).
    pub last_success: i64,
    /// Last failed send (0 = never).
    pub last_failure: i64,
    /// Consecutive failed sends; 3 marks the peer unhealthy.
    pub consecutive_failures: i32,
    /// Health flag (circuit breaker in the C send path).
    pub is_healthy: bool,
    /// Last time an unhealthy peer was retried.
    pub last_health_check: i64,
}

impl GossipPeer {
    fn new(address: &str, port: u16) -> Self {
        GossipPeer {
            address: address.to_string(),
            port,
            last_success: 0,
            last_failure: 0,
            consecutive_failures: 0,
            is_healthy: true,
            last_health_check: 0,
        }
    }
}

/// Envelope handler signature (C `GossipEnvelopeHandler` without
/// the service/context pointers: the closure captures context,
/// and rebroadcast/store access goes through the captured
/// [`IngestPipeline`] or handle). `source` is the datagram's
/// sender (`const struct sockaddr_in*` in C).
pub type EnvelopeHandler =
    Arc<dyn Fn(&Envelope, SocketAddr) -> Result<()> + Send + Sync>;

/// Message handler signature (C `GossipMessageHandler`).
pub type MessageHandler =
    Arc<dyn Fn(&Message, SocketAddr) -> Result<()> + Send + Sync>;

/// Payload decryption hook standing in for C
/// `decrypt_envelope_payload` until the encryption module is
/// ported: `Some(plaintext)` on success, `None` when this node
/// cannot decrypt (not a recipient / no key), exactly the C
/// success/failure split the dispatcher and node-announcement
/// handling branch on.
pub type EnvelopeDecryptor =
    Arc<dyn Fn(&Envelope) -> Option<Vec<u8>> + Send + Sync>;

// ---------------------------------------------------------------------------
// Envelope dispatcher (`envelope_dispatcher.c`)
// ---------------------------------------------------------------------------

/// Content handler signature (C `EnvelopeContentHandler`):
/// the envelope, the decrypted payload when this node could
/// decrypt it (`None` otherwise, 0 length in C), and success /
/// failure in place of the C `0` / `-1` return.
pub type EnvelopeContentHandler =
    Arc<dyn Fn(&Envelope, Option<&[u8]>) -> Result<()> + Send + Sync>;

/// Human-readable content-type name (C
/// `envelope_content_type_name`); `"Unknown"` for unlisted types.
pub fn envelope_content_type_name(content_type: u32) -> &'static str {
    match content_type {
        1 => "UserRegistration",
        2 => "RoleAssignment",
        20 => "GroupCreate",
        21 => "GroupUpdate",
        22 => "GroupMemberAdd",
        23 => "GroupMemberRemove",
        24 => "GroupMemberLeave",
        25 => "GroupKeyShare",
        30 => "PermissionEdit",
        31 => "ParentalControl",
        32 => "ContentFilter",
        33 => "LocationUpdate",
        34 => "EmergencyAlert",
        35 => "ConversationMetadata",
        40 => "NodeRegistration",
        41 => "SystemConfig",
        50 => "AccessRequest",
        60 => "VoiceCallRequest",
        61 => "MediaDownload",
        62 => "ContentAccessUpdate",
        63 => "CreationUpload",
        64 => "CreationShareRequest",
        100 => "EducationalResourceAdd",
        101 => "ChallengeComplete",
        102 => "BookAddToLibrary",
        103 => "ChoreAssign",
        104 => "ChoreComplete",
        105 => "RewardDistribute",
        150 => "GeofenceCreate",
        151 => "GeofenceConfigUpdate",
        152 => "UsagePolicyUpdate",
        153 => "GameSessionStart",
        154 => "GamePermissionUpdate",
        155 => "EventCreate",
        156 => "EventInvite",
        157 => "EventRSVP",
        158 => "CommunityPostCreate",
        159 => "SharedAlbumCreate",
        160 => "MediaAddToAlbumRequest",
        162 => "CalendarEvent",
        161 => "CollaborativeProjectCreate",
        _ => "Unknown",
    }
}

/// The content-type handler registry (C's global `g_handlers`
/// table plus `envelope_dispatcher_init` / `_cleanup`). An
/// instance replaces the C global; [`EnvelopeDispatcher::new`]
/// registers the two default handlers like
/// `envelope_dispatcher_init` does.
pub struct EnvelopeDispatcher {
    handlers: RwLock<HashMap<u32, EnvelopeContentHandler>>,
    store: Option<Arc<Mutex<Store>>>,
    decryptor: Option<EnvelopeDecryptor>,
}

impl EnvelopeDispatcher {
    /// Dispatcher with the C default handlers registered
    /// (`envelope_dispatcher_init`): location updates and
    /// emergency alerts. `store` backs the location handler;
    /// `decryptor` is the `decrypt_envelope_payload` hook.
    pub fn new(
        store: Option<Arc<Mutex<Store>>>,
        decryptor: Option<EnvelopeDecryptor>,
    ) -> Self {
        let dispatcher = EnvelopeDispatcher {
            handlers: RwLock::new(HashMap::new()),
            store,
            decryptor,
        };
        dispatcher.register_default_handlers();
        dispatcher
    }

    /// Dispatcher with no handlers at all (the state after C
    /// `envelope_dispatcher_cleanup`).
    pub fn empty() -> Self {
        EnvelopeDispatcher {
            handlers: RwLock::new(HashMap::new()),
            store: None,
            decryptor: None,
        }
    }

    fn register_default_handlers(&self) {
        let store = self.store.clone();
        let _ = self.register_handler(
            CONTENT_LOCATION_UPDATE,
            Arc::new(move |envelope, _payload| {
                handle_location_update(envelope, store.as_ref())
            }),
        );
        let _ = self.register_handler(
            CONTENT_EMERGENCY_ALERT,
            Arc::new(|envelope, payload| handle_emergency_alert(envelope, payload)),
        );
    }

    /// Register (or replace) the handler for `content_type`
    /// (C `envelope_register_handler`); fails past
    /// [`MAX_HANDLERS`] distinct types, as in C.
    pub fn register_handler(
        &self,
        content_type: u32,
        handler: EnvelopeContentHandler,
    ) -> Result<()> {
        let mut handlers = self.handlers.write().unwrap();
        if !handlers.contains_key(&content_type) && handlers.len() >= MAX_HANDLERS {
            return Err(Error::InvalidArgument(format!(
                "handler table full ({MAX_HANDLERS} handlers)"
            )));
        }
        handlers.insert(content_type, handler);
        Ok(())
    }

    /// Remove the handler for `content_type`, if any
    /// (C `envelope_unregister_handler`).
    pub fn unregister_handler(&self, content_type: u32) {
        self.handlers.write().unwrap().remove(&content_type);
    }

    /// Number of registered content types.
    pub fn handler_count(&self) -> usize {
        self.handlers.read().unwrap().len()
    }

    /// Route an envelope to its content handler (C
    /// `envelope_dispatch`): look the handler up by header
    /// content type, attempt decryption, then call the handler
    /// with the plaintext or `None`. Decryption failure is not
    /// an error (we may not be a recipient), matching C.
    pub fn dispatch(&self, envelope: &Envelope) -> Result<()> {
        let header = envelope
            .header
            .as_ref()
            .ok_or_else(|| Error::InvalidArgument("invalid envelope".into()))?;
        let content_type = header.content_type;
        let handler = {
            let handlers = self.handlers.read().unwrap();
            handlers.get(&content_type).cloned()
        };
        let handler = handler.ok_or(Error::NoHandler(content_type))?;
        let decrypted = self
            .decryptor
            .as_ref()
            .and_then(|decrypt| decrypt(envelope));
        handler(envelope, decrypted.as_deref())
    }
}

/// Default `CONTENT_LOCATION_UPDATE` handler (C
/// `handle_location_update`): deduplicate by envelope digest,
/// then store the ENCRYPTED envelope via the location store
/// regardless of whether this node could decrypt it. The 7-day
/// TTL matches the C handler. Without a store this is the one
/// place the handler cannot run faithfully (C would fail the
/// SQL call and return -1), so it returns an error.
fn handle_location_update(
    envelope: &Envelope,
    store: Option<&Arc<Mutex<Store>>>,
) -> Result<()> {
    let header = envelope
        .header
        .as_ref()
        .ok_or_else(|| Error::InvalidArgument("invalid envelope".into()))?;
    let Some(store) = store else {
        return Err(Error::Handler(
            "location handler has no store configured".into(),
        ));
    };
    let digest: [u8; GOSSIP_SEEN_DIGEST_SIZE] =
        store::location_store_compute_digest_envelope(envelope);
    let mut store = store.lock().unwrap();
    if store.location_store_has_seen(&digest)? {
        return Ok(()); // Duplicate: not an error, as in C.
    }
    const LOCATION_TTL: u64 = 7 * 24 * 60 * 60;
    let expires_at = header.timestamp.wrapping_add(LOCATION_TTL);
    store.location_store_save_envelope(envelope, expires_at)?;
    store.location_store_mark_seen(&digest, expires_at)?;
    Ok(())
}

/// Default `CONTENT_EMERGENCY_ALERT` handler (C
/// `handle_emergency_alert`): parse and report the alert. With
/// no decrypted payload we are (probably) not a recipient,
/// which C treats as success.
fn handle_emergency_alert(envelope: &Envelope, payload: Option<&[u8]>) -> Result<()> {
    let Some(payload) = payload else {
        return Ok(());
    };
    let _ = envelope;
    let alert = EmergencyAlert::decode(payload)
        .map_err(|e| Error::Handler(format!("failed to parse EmergencyAlert: {e}")))?;
    eprintln!(
        "EMERGENCY ALERT (type {}): {}",
        alert.alert_type, alert.message
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Gossip transport (`gossip.c`)
// ---------------------------------------------------------------------------

/// State shared between the service handle, its receive thread,
/// the peer sink and the ingest pipeline (the C code shares one
/// `GossipService` struct + `peer_lock` the same way).
struct Shared {
    listen_port: u16,
    peers: Mutex<Vec<GossipPeer>>,
    socket: Mutex<Option<Arc<UdpSocket>>>,
    running: AtomicBool,
}

/// Add a peer to a shared peer list (C `gossip_service_add_peer`:
/// the capacity check runs before the duplicate check, so even
/// re-adding a known peer fails once the table is full).
fn shared_add_peer(shared: &Shared, address: &str, port: u16) -> Result<()> {
    let mut peers = shared.peers.lock().unwrap();
    if peers.len() >= GOSSIP_MAX_PEERS {
        return Err(Error::PeerTableFull);
    }
    if peers.iter().any(|p| p.address == address && p.port == port) {
        return Ok(());
    }
    peers.push(GossipPeer::new(address, port));
    Ok(())
}

/// Send `bytes` to every peer (C `gossip_service_send_data`),
/// honouring the health circuit breaker and skipping the peer
/// whose resolved address equals `exclude_source`.
fn shared_send_data(
    shared: &Shared,
    bytes: &[u8],
    exclude_source: Option<SocketAddr>,
) -> Result<()> {
    let socket = {
        let guard = shared.socket.lock().unwrap();
        guard.clone().ok_or(Error::NotRunning)?
    };
    let mut peers = shared.peers.lock().unwrap();
    for peer in peers.iter_mut() {
        if !peer.is_healthy {
            let now = now_epoch() as i64;
            if now - peer.last_health_check > 60 {
                peer.last_health_check = now;
            } else {
                continue;
            }
        }
        let addrs: Vec<SocketAddr> = match (peer.address.as_str(), peer.port).to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(_) => continue,
        };
        for addr in addrs {
            if exclude_source == Some(addr) {
                continue;
            }
            let now = now_epoch() as i64;
            match socket.send_to(bytes, addr) {
                Ok(_) => {
                    peer.last_success = now;
                    peer.consecutive_failures = 0;
                    peer.is_healthy = true;
                }
                Err(_) => {
                    peer.last_failure = now;
                    peer.consecutive_failures += 1;
                    if peer.consecutive_failures >= 3 {
                        peer.is_healthy = false;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serialize and send an envelope (C
/// `gossip_service_send_envelope`); empty or oversized
/// serializations are rejected before any send, as in C.
fn shared_send_envelope(
    shared: &Shared,
    envelope: &Envelope,
    exclude_source: Option<SocketAddr>,
) -> Result<()> {
    let bytes = envelope.encode_to_vec();
    if bytes.is_empty() || bytes.len() > GOSSIP_MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge(bytes.len()));
    }
    shared_send_data(shared, &bytes, exclude_source)
}

/// Serialize and send a message (C message send path in
/// `gossip_service_broadcast_message` / `_rebroadcast_message`).
fn shared_send_message(
    shared: &Shared,
    message: &Message,
    exclude_source: Option<SocketAddr>,
) -> Result<()> {
    let bytes = message.encode_to_vec();
    if bytes.is_empty() || bytes.len() > GOSSIP_MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge(bytes.len()));
    }
    shared_send_data(shared, &bytes, exclude_source)
}

/// The UDP gossip transport (C `GossipService`). Construct with
/// [`GossipService::new`] (C `gossip_service_init`), add peers,
/// then [`GossipService::start`] / [`GossipService::stop`]
/// (C `gossip_service_start` / `_stop`). Ingest handlers from an
/// [`IngestPipeline`] can be installed with
/// [`GossipService::set_handlers`], or all at once with
/// [`GossipService::with_ingest`].
pub struct GossipService {
    shared: Arc<Shared>,
    receive_thread: Option<JoinHandle<()>>,
    envelope_handler: Option<EnvelopeHandler>,
    message_handler: Option<MessageHandler>,
}

impl GossipService {
    /// C `gossip_service_init`: a stopped service bound (on
    /// start) to `listen_port`, dispatching datagrams to the
    /// given handlers (either may be `None`, as in C).
    pub fn new(
        listen_port: u16,
        envelope_handler: Option<EnvelopeHandler>,
        message_handler: Option<MessageHandler>,
    ) -> Self {
        GossipService {
            shared: Arc::new(Shared {
                listen_port,
                peers: Mutex::new(Vec::new()),
                socket: Mutex::new(None),
                running: AtomicBool::new(false),
            }),
            receive_thread: None,
            envelope_handler,
            message_handler,
        }
    }

    /// A service with the `main.c` ingest pipeline wired as its
    /// handlers: `store` is the shared node store (trust,
    /// dedup, persistence, peer records), `config` the gossip
    /// validation config, and `decryptor` the optional payload
    /// decryption hook. This is the wiring `start_gossip_service`
    /// + the two `gossip_receive_*_handler` callbacks perform
    /// in C.
    pub fn with_ingest(
        listen_port: u16,
        store: Arc<Mutex<Store>>,
        config: GossipValidationConfig,
        decryptor: Option<EnvelopeDecryptor>,
    ) -> Self {
        let mut service = GossipService::new(listen_port, None, None);
        service.attach_ingest(store, config, decryptor);
        service
    }

    /// Wire the `main.c` ingest pipeline into this service and
    /// return it, so callers can also invoke ingest directly
    /// (e.g. for envelopes arriving over another transport).
    pub fn attach_ingest(
        &mut self,
        store: Arc<Mutex<Store>>,
        config: GossipValidationConfig,
        decryptor: Option<EnvelopeDecryptor>,
    ) -> Arc<IngestPipeline> {
        let pipeline = Arc::new(IngestPipeline::new(
            self.shared.clone(),
            store,
            config,
            decryptor,
        ));
        self.set_handlers(
            Some(pipeline.envelope_handler()),
            Some(pipeline.message_handler()),
        );
        pipeline
    }

    /// Install/replace the datagram handlers.
    pub fn set_handlers(
        &mut self,
        envelope_handler: Option<EnvelopeHandler>,
        message_handler: Option<MessageHandler>,
    ) {
        self.envelope_handler = envelope_handler;
        self.message_handler = message_handler;
    }

    /// The configured listen port.
    pub fn listen_port(&self) -> u16 {
        self.shared.listen_port
    }

    /// The actual bound port once started (differs from
    /// [`GossipService::listen_port`] when 0 was configured).
    pub fn local_port(&self) -> Option<u16> {
        let guard = self.shared.socket.lock().unwrap();
        guard
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
    }

    /// Whether the receive loop is running.
    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::SeqCst)
    }

    /// C `gossip_service_add_peer`: deduplicated by
    /// address+port, at most [`GOSSIP_MAX_PEERS`] peers.
    pub fn add_peer(&self, address: &str, port: u16) -> Result<()> {
        shared_add_peer(&self.shared, address, port)
    }

    /// C `gossip_service_peer_count`.
    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().unwrap().len()
    }

    /// Snapshot of the current peer list.
    pub fn peers(&self) -> Vec<GossipPeer> {
        self.shared.peers.lock().unwrap().clone()
    }

    /// A cloneable peer sink so discovery results can be
    /// registered into this service (and, when `store` is given,
    /// the `gossip_peers` store) the way C `discover_peers`
    /// registers them via `gossip_service_add_peer` +
    /// `gossip_peers_add_or_update`. Usable before or after
    /// [`GossipService::start`].
    pub fn peer_sink(&self, store: Option<Arc<Mutex<Store>>>) -> GossipPeerSink {
        GossipPeerSink {
            shared: self.shared.clone(),
            store,
        }
    }

    /// C `gossip_service_start`: bind the UDP socket and spawn
    /// the receive thread. Starting a running service is a
    /// no-op success, as in C.
    pub fn start(&mut self) -> Result<()> {
        if self.shared.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let socket = UdpSocket::bind(("0.0.0.0", self.shared.listen_port))?;
        let socket = Arc::new(socket);
        *self.shared.socket.lock().unwrap() = Some(socket.clone());
        self.shared.running.store(true, Ordering::SeqCst);

        let shared = self.shared.clone();
        let envelope_handler = self.envelope_handler.clone();
        let message_handler = self.message_handler.clone();
        let handle = std::thread::spawn(move || {
            receive_loop(&shared, &socket, envelope_handler, message_handler);
        });
        self.receive_thread = Some(handle);
        Ok(())
    }

    /// C `gossip_service_stop`: wake and join the receive
    /// thread, close the socket and clear the peer list.
    pub fn stop(&mut self) {
        if self.shared.running.swap(false, Ordering::SeqCst) {
            // Wake the blocking recv, as the C one-byte send does.
            if let Some(port) = self.local_port() {
                if let Ok(wake) = UdpSocket::bind(("127.0.0.1", 0)) {
                    let _ = wake.send_to(b"\0", ("127.0.0.1", port));
                }
            }
            if let Some(handle) = self.receive_thread.take() {
                let _ = handle.join();
            }
        } else if let Some(handle) = self.receive_thread.take() {
            let _ = handle.join();
        }
        *self.shared.socket.lock().unwrap() = None;
        self.shared.peers.lock().unwrap().clear();
    }

    /// C `gossip_service_broadcast_envelope`: send to all peers.
    pub fn broadcast_envelope(&self, envelope: &Envelope) -> Result<()> {
        shared_send_envelope(&self.shared, envelope, None)
    }

    /// C `gossip_service_rebroadcast_envelope`: send to all
    /// peers except the one at `source`.
    pub fn rebroadcast_envelope(
        &self,
        envelope: &Envelope,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        shared_send_envelope(&self.shared, envelope, source)
    }

    /// C `gossip_service_broadcast_message`.
    pub fn broadcast_message(&self, message: &Message) -> Result<()> {
        shared_send_message(&self.shared, message, None)
    }

    /// C `gossip_service_rebroadcast_message`.
    pub fn rebroadcast_message(
        &self,
        message: &Message,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        shared_send_message(&self.shared, message, source)
    }

    /// Decode one received datagram and route it to the
    /// handlers, exactly like the C receive loop: try `Message`
    /// first (accepted only with a header whose sender key is
    /// 32 bytes), then fall back to `Envelope`. Exposed so the
    /// decode routing can be tested without sockets.
    pub fn handle_datagram(&self, data: &[u8], source: SocketAddr) {
        dispatch_datagram(
            data,
            source,
            self.envelope_handler.as_ref(),
            self.message_handler.as_ref(),
        );
    }
}

impl Drop for GossipService {
    fn drop(&mut self) {
        self.stop();
    }
}

/// C registration surface: discovery backends call
/// `PeerSink::add_peer`, which forwards to this service's peer
/// list (C `gossip_service_add_peer`).
impl PeerSink for GossipService {
    fn add_peer(&mut self, peer: &Peer) -> std::result::Result<(), DiscoveryError> {
        shared_add_peer(&self.shared, &peer.hostname, peer.port)
            .map_err(|e| DiscoveryError::Sink(e.to_string()))
    }
}

/// Cloneable [`PeerSink`] bound to a running (or stopped)
/// service's shared peer list plus, optionally, the
/// `gossip_peers` store. Registration counts only when both
/// succeed, mirroring the discovery module's sink contract
/// (and the C pair of calls).
#[derive(Clone)]
pub struct GossipPeerSink {
    shared: Arc<Shared>,
    store: Option<Arc<Mutex<Store>>>,
}

impl PeerSink for GossipPeerSink {
    fn add_peer(&mut self, peer: &Peer) -> std::result::Result<(), DiscoveryError> {
        shared_add_peer(&self.shared, &peer.hostname, peer.port)
            .map_err(|e| DiscoveryError::Sink(e.to_string()))?;
        if let Some(store) = &self.store {
            let store = store.lock().unwrap();
            store
                .gossip_peers_add_or_update(&peer.hostname, peer.port, 0, None)
                .map_err(|e| DiscoveryError::Sink(e.to_string()))?;
        }
        Ok(())
    }
}

/// The datagram decode routing of the C receive loop.
fn dispatch_datagram(
    data: &[u8],
    source: SocketAddr,
    envelope_handler: Option<&EnvelopeHandler>,
    message_handler: Option<&MessageHandler>,
) {
    // 1. Try unpacking as Message first (new standard in C).
    if let Ok(message) = Message::decode(data) {
        let sane = message
            .header
            .as_ref()
            .map(|h| h.sender_pubkey.len() == 32)
            .unwrap_or(false);
        if sane {
            if let Some(handler) = message_handler {
                let _ = handler(&message, source);
            }
            return;
        }
    }
    // 2. Fall back to legacy Envelope.
    if let Ok(envelope) = Envelope::decode(data) {
        if let Some(handler) = envelope_handler {
            let _ = handler(&envelope, source);
        }
        return;
    }
    // Undecodable datagram: C logs and drops it; so do we.
}

/// The receive thread (C `gossip_receive_loop`).
fn receive_loop(
    shared: &Shared,
    socket: &Arc<UdpSocket>,
    envelope_handler: Option<EnvelopeHandler>,
    message_handler: Option<MessageHandler>,
) {
    let mut buffer = vec![0u8; GOSSIP_MAX_MESSAGE_SIZE];
    while shared.running.load(Ordering::SeqCst) {
        let (bytes, source) = match socket.recv_from(&mut buffer) {
            Ok(v) => v,
            Err(_) => {
                if !shared.running.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
        };
        if bytes == 0 {
            continue;
        }
        // The one-byte wakeup datagram from stop() lands here;
        // it decodes as neither type and the loop condition
        // then exits, exactly as in C.
        dispatch_datagram(
            &buffer[..bytes],
            source,
            envelope_handler.as_ref(),
            message_handler.as_ref(),
        );
    }
}

// ---------------------------------------------------------------------------
// Ingest pipeline (`src/main.c` receive handlers)
// ---------------------------------------------------------------------------

/// The `main.c` ingest pipeline: the behaviour of
/// `gossip_receive_envelope_handler`,
/// `gossip_receive_message_handler`,
/// `discover_peer_from_source` and `handle_node_announcement`
/// as one reusable unit bound to a service's shared transport
/// state, a store and a validation config. Install it on a
/// service with [`GossipService::with_ingest`] or
/// [`GossipService::attach_ingest`], or drive it directly via
/// [`IngestPipeline::ingest_envelope`] /
/// [`IngestPipeline::ingest_message`].
pub struct IngestPipeline {
    shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    config: GossipValidationConfig,
    dispatcher: Arc<EnvelopeDispatcher>,
    decryptor: Option<EnvelopeDecryptor>,
}

impl IngestPipeline {
    fn new(
        shared: Arc<Shared>,
        store: Arc<Mutex<Store>>,
        config: GossipValidationConfig,
        decryptor: Option<EnvelopeDecryptor>,
    ) -> Self {
        let dispatcher = Arc::new(EnvelopeDispatcher::new(
            Some(store.clone()),
            decryptor.clone(),
        ));
        IngestPipeline {
            shared,
            store,
            config,
            dispatcher,
            decryptor,
        }
    }

    /// The dispatcher this pipeline routes stored envelopes to.
    pub fn dispatcher(&self) -> &Arc<EnvelopeDispatcher> {
        &self.dispatcher
    }

    /// This pipeline as an [`EnvelopeHandler`] closure.
    pub fn envelope_handler(self: &Arc<Self>) -> EnvelopeHandler {
        let pipeline = self.clone();
        Arc::new(move |envelope, source| pipeline.ingest_envelope(envelope, Some(source)))
    }

    /// This pipeline as a [`MessageHandler`] closure.
    pub fn message_handler(self: &Arc<Self>) -> MessageHandler {
        let pipeline = self.clone();
        Arc::new(move |message, source| pipeline.ingest_message(message, Some(source)))
    }

    /// Sender trust check shared by both C handlers: the
    /// sender key must be 32 bytes and present in the
    /// `node_trust` table. Trust is separate from the
    /// `gossip_peers` address book (DESIGN.md §10), so
    /// discovery/bootstrap writes can never grant or revoke it.
    fn check_whitelisted(&self, sender_pubkey: &[u8]) -> Result<()> {
        let Ok(key) = <[u8; 32]>::try_from(sender_pubkey) else {
            return Err(Error::Unauthorized);
        };
        let store = self.store.lock().unwrap();
        match store.node_trust_is_trusted(&key)? {
            true => Ok(()),
            false => Err(Error::Unauthorized),
        }
    }

    /// C `gossip_receive_envelope_handler`, in its exact order:
    /// validate, trust, dedup (seen digest of the serialized
    /// envelope), store envelope + recipients into
    /// `gossip_envelopes` (DESIGN.md 4.2: never
    /// `gossip_messages`), mark seen, discover peer from source,
    /// node-registration handling, content dispatch (failure is
    /// logged and ignored in C), rebroadcast excluding source.
    /// A duplicate returns `Ok` without re-storing or
    /// re-forwarding, as in C. Every rejection — and every
    /// duplicate drop — is logged with its reason
    /// (DESIGN.md §10); nothing is dropped silently.
    pub fn ingest_envelope(
        &self,
        envelope: &Envelope,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        let result = self.ingest_envelope_inner(envelope, source);
        if let Err(e) = &result {
            let sender = envelope
                .header
                .as_ref()
                .map(|h| hex(&h.sender_pubkey))
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
                "gossip ingest: rejected envelope from {} sender={sender}: {e}",
                source_label(source)
            );
        }
        result
    }

    fn ingest_envelope_inner(
        &self,
        envelope: &Envelope,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        // 1. Validate envelope.
        validation::gossip_validate_envelope(envelope, &self.config, now_epoch())?;

        // 2. Authorization: sender must be trusted.
        let header = envelope
            .header
            .as_ref()
            .ok_or_else(|| Error::Unauthorized)?;
        self.check_whitelisted(&header.sender_pubkey)?;

        // 2b. Group key shares (Phase B4, DESIGN.md §9) get
        // their content-level verification before anything is
        // stored or forwarded: the share signature must
        // verify, and both the sending device and the
        // recipient device must be enrolled and currently
        // trusted. A share that fails is rejected here — the
        // outer wrapper logs the reason — and never stored.
        if header.content_type == CONTENT_GROUP_KEY_SHARE {
            let store = self.store.lock().unwrap();
            crate::sessions::verify_share_envelope(&store, envelope, now_epoch())
                .map_err(|e| Error::Validation(format!("group key share rejected: {e}")))?;
        }

        // 2c. Calendar events (Phase C3) get the same
        // content-level verification before anything is stored
        // or forwarded: the record signature must verify, the
        // acting device must be enrolled and currently
        // trusted, the actor must be the creator or a recorded
        // parent of the creator, and the version must not
        // regress what this node already holds. (Like shares,
        // event envelopes name a device key as sender, so the
        // step-2 node-trust check above still gates which
        // *nodes* may relay them; cross-box event sync rides
        // the Phase E linking work, as share sync does.)
        if header.content_type == crate::events::CONTENT_CALENDAR_EVENT {
            let store = self.store.lock().unwrap();
            crate::events::verify_event_envelope(&store, envelope, now_epoch())
                .map_err(|e| Error::Validation(format!("calendar event rejected: {e}")))?;
        }

        // 3. Deduplication: SHA-256 of the serialized envelope.
        let digest = store::location_store_compute_digest_envelope(envelope);
        let expires_at = validation::gossip_validation_expiration(envelope, &self.config);
        {
            let store = self.store.lock().unwrap();
            if store.gossip_store_has_seen(&digest)? {
                eprintln!(
                    "gossip ingest: dropped duplicate envelope from {} sender={} (already seen)",
                    source_label(source),
                    hex(&header.sender_pubkey)
                );
                return Ok(());
            }
            // 4. Store envelope + recipients, then mark seen.
            store.gossip_store_save_envelope(envelope, expires_at)?;
            store.gossip_store_mark_seen(&digest, expires_at)?;
        }

        // 5. Dynamic peer discovery from the source address.
        if let Some(source) = source {
            self.discover_peer_from_source(source);
        }

        // 6. Node announcements register the announcer as a peer.
        if header.content_type == CONTENT_NODE_REGISTRATION {
            self.handle_node_announcement(envelope, source);
        }

        // 7. Dispatch to content-specific handlers; C logs a
        // dispatch failure and continues anyway.
        let _ = self.dispatcher.dispatch(envelope);

        // 8. Rebroadcast to other peers; failure is non-fatal.
        let _ = shared_send_envelope(&self.shared, envelope, source);
        Ok(())
    }

    /// C `gossip_receive_message_handler`, in its exact order:
    /// validate, trust, dedup, store, discover peer from
    /// source, rebroadcast. Storage goes through the store's
    /// message save (`user_messages`, as in C
    /// `message_store_save`); the retired `gossip_messages`
    /// table is never written (DESIGN.md 4.2). Rejections and
    /// duplicate drops are logged, as in
    /// [`IngestPipeline::ingest_envelope`].
    pub fn ingest_message(
        &self,
        message: &Message,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        let result = self.ingest_message_inner(message, source);
        if let Err(e) = &result {
            let sender = message
                .header
                .as_ref()
                .map(|h| hex(&h.sender_pubkey))
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
                "gossip ingest: rejected message from {} sender={sender}: {e}",
                source_label(source)
            );
        }
        result
    }

    fn ingest_message_inner(
        &self,
        message: &Message,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        // 1. Validate message (signature, timestamp, size).
        validation::message_validate(message)?;

        // 2. Authorization (trust).
        let header = message
            .header
            .as_ref()
            .ok_or_else(|| Error::Unauthorized)?;
        self.check_whitelisted(&header.sender_pubkey)?;

        // 3. Deduplication.
        let digest = store::message_store_compute_digest(message);
        let expires_at = validation::message_validation_get_expiration(message);
        {
            let mut store = self.store.lock().unwrap();
            if store.message_store_has_seen(&digest)? {
                eprintln!(
                    "gossip ingest: dropped duplicate message from {} sender={} (already seen)",
                    source_label(source),
                    hex(&header.sender_pubkey)
                );
                return Ok(());
            }
            // 4. Store, then mark seen.
            store.message_store_save(message, expires_at)?;
            store.message_store_mark_seen(&digest, expires_at)?;
        }

        // 5. Dynamic peer discovery.
        if let Some(source) = source {
            self.discover_peer_from_source(source);
        }

        // 6. Rebroadcast to other peers.
        let _ = shared_send_message(&self.shared, message, source);
        Ok(())
    }

    /// C `discover_peer_from_source`: if no known peer resolves
    /// to the source address+port, add the source as a new peer
    /// at the fixed gossip port 9000 and persist it in
    /// `gossip_peers`. (Reverse-DNS is unavailable in std, so
    /// the IP literal is used, C's own fallback.)
    pub fn discover_peer_from_source(&self, source: SocketAddr) {
        {
            let peers = self.shared.peers.lock().unwrap();
            for peer in peers.iter() {
                if let Ok(addrs) = (peer.address.as_str(), peer.port).to_socket_addrs() {
                    for addr in addrs {
                        if addr.ip() == source.ip() && peer.port == source.port() {
                            return; // Peer already known.
                        }
                    }
                }
                // Direct literal match (loopback / IP peers).
                if peer.address == source.ip().to_string() && peer.port == source.port() {
                    return;
                }
            }
        }
        let hostname = source.ip().to_string();
        if shared_add_peer(&self.shared, &hostname, GOSSIP_PORT).is_ok() {
            let store = self.store.lock().unwrap();
            let _ = store.gossip_peers_add_or_update(&hostname, GOSSIP_PORT, 0, None);
        }
    }

    /// C `handle_node_announcement`: decrypt the payload, parse
    /// `NodeRegistration`, and register the announcer as a peer
    /// at the fixed gossip port 9000 (C always uses 9000 here,
    /// whatever the announcement carries) plus its
    /// `gossip_peers` record. Without a decryptor the payload
    /// cannot be read, which C treats as non-fatal ("may not be
    /// a recipient"), so this returns silently.
    pub fn handle_node_announcement(
        &self,
        envelope: &Envelope,
        _source: Option<SocketAddr>,
    ) {
        let Some(decryptor) = &self.decryptor else {
            return;
        };
        let Some(decrypted) = decryptor(envelope) else {
            return;
        };
        let Ok(node_reg) = NodeRegistration::decode(decrypted.as_slice()) else {
            return;
        };
        if node_reg.node_address.is_empty() || node_reg.node_port == 0 {
            return;
        }
        let hostname = node_reg.node_address.as_str();
        if shared_add_peer(&self.shared, hostname, GOSSIP_PORT).is_ok() {
            let store = self.store.lock().unwrap();
            let _ = store.gossip_peers_add_or_update(hostname, GOSSIP_PORT, 0, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{EnvelopeHeader, RecipientKeyWrap};
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::Duration;

    fn test_config() -> GossipValidationConfig {
        GossipValidationConfig {
            max_clock_skew_seconds: 300,
            message_ttl_seconds: 7 * 24 * 60 * 60,
            max_payload_bytes: 1024 * 1024,
        }
    }

    fn test_store() -> Arc<Mutex<Store>> {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        Arc::new(Mutex::new(store))
    }

    /// A structurally valid, correctly signed envelope from the
    /// key derived from `seed`, as a trusted peer would send.
    fn signed_envelope(seed: u8, content_type: u32) -> (Envelope, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let mut envelope = Envelope {
            header: Some(EnvelopeHeader {
                version: 1,
                content_type,
                schema_version: 1,
                timestamp: now_epoch(),
                sender_pubkey: pubkey.to_vec(),
                recipients_pubkey: vec![pubkey.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![7u8; 24],
            ephemeral_pubkey: pubkey.to_vec(),
            payload_ciphertext: b"ciphertext".to_vec(),
            keywraps: vec![RecipientKeyWrap {
                recipient_pubkey: pubkey.to_vec(),
                key_nonce: vec![3u8; 24],
                wrapped_key: vec![9u8; 48],
            }],
            signature: Vec::new(),
        };
        let digest = validation::compute_envelope_signing_digest(&envelope).unwrap();
        envelope.signature = signing.sign(&digest).to_bytes().to_vec();
        (envelope, pubkey)
    }

    fn trust_sender(store: &Arc<Mutex<Store>>, pubkey: &[u8; 32]) {
        store
            .lock()
            .unwrap()
            .node_trust_add(pubkey, Some("sender-node"), "test")
            .unwrap();
    }

    fn stored_envelope_count(store: &Arc<Mutex<Store>>) -> usize {
        store
            .lock()
            .unwrap()
            .gossip_store_fetch_recent_envelopes(100)
            .unwrap()
            .len()
    }

    #[test]
    fn peer_add_dedup_and_health_defaults() {
        let service = GossipService::new(0, None, None);
        assert_eq!(service.peer_count(), 0);
        service.add_peer("node-a", 9000).unwrap();
        service.add_peer("node-b", 9001).unwrap();
        assert_eq!(service.peer_count(), 2);
        // Same address+port is a duplicate: success, no growth.
        service.add_peer("node-a", 9000).unwrap();
        assert_eq!(service.peer_count(), 2);
        // Same address, different port is a distinct peer.
        service.add_peer("node-a", 9002).unwrap();
        assert_eq!(service.peer_count(), 3);
        let peers = service.peers();
        assert_eq!(peers[0].address, "node-a");
        assert_eq!(peers[0].port, 9000);
        assert!(peers[0].is_healthy);
        assert_eq!(peers[0].last_success, 0);
        assert_eq!(peers[0].last_failure, 0);
        assert_eq!(peers[0].consecutive_failures, 0);
        assert_eq!(peers[0].last_health_check, 0);
    }

    #[test]
    fn peer_list_caps_at_max_peers() {
        let service = GossipService::new(0, None, None);
        for i in 0..GOSSIP_MAX_PEERS {
            service
                .add_peer(&format!("node-{i}"), 9000)
                .unwrap_or_else(|e| panic!("peer {i} should fit: {e}"));
        }
        assert_eq!(service.peer_count(), GOSSIP_MAX_PEERS);
        // The 33rd distinct peer is rejected...
        assert!(service.add_peer("one-too-many", 9000).is_err());
        // ...and so is a duplicate, because C checks capacity first.
        assert!(service.add_peer("node-0", 9000).is_err());
        assert_eq!(service.peer_count(), GOSSIP_MAX_PEERS);
    }

    #[test]
    fn envelope_encode_decode_round_trip() {
        let (envelope, _) = signed_envelope(42, CONTENT_LOCATION_UPDATE);
        let bytes = envelope.encode_to_vec();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= GOSSIP_MAX_MESSAGE_SIZE);
        let decoded = Envelope::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, envelope);
        // Re-encoding the decoded value is byte-identical, which
        // is what keeps the wire format protobuf-c compatible.
        assert_eq!(decoded.encode_to_vec(), bytes);
    }

    #[test]
    fn dispatcher_routes_by_content_type_and_names_types() {
        assert_eq!(envelope_content_type_name(33), "LocationUpdate");
        assert_eq!(envelope_content_type_name(34), "EmergencyAlert");
        assert_eq!(envelope_content_type_name(40), "NodeRegistration");
        assert_eq!(envelope_content_type_name(9999), "Unknown");

        let dispatcher = EnvelopeDispatcher::empty();
        let (envelope, _) = signed_envelope(7, 1234);
        assert!(matches!(
            dispatcher.dispatch(&envelope),
            Err(Error::NoHandler(1234))
        ));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        dispatcher
            .register_handler(
                1234,
                Arc::new(move |env, payload| {
                    seen2
                        .lock()
                        .unwrap()
                        .push((env.header.as_ref().unwrap().content_type, payload.is_none()));
                    Ok(())
                }),
            )
            .unwrap();
        dispatcher.dispatch(&envelope).unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![(1234, true)]);
        dispatcher.unregister_handler(1234);
        assert_eq!(dispatcher.handler_count(), 0);
    }

    #[test]
    fn second_ingest_does_not_restore_or_reforward() {
        let store = test_store();
        let (envelope, pubkey) = signed_envelope(9, 999);
        trust_sender(&store, &pubkey);

        // Capture socket standing in as the one known peer.
        let capture = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        capture
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let capture_addr = capture.local_addr().unwrap();

        let mut service = GossipService::new(0, None, None);
        let pipeline = service.attach_ingest(store.clone(), test_config(), None);
        service.add_peer("127.0.0.1", capture_addr.port()).unwrap();
        service.start().unwrap();

        let source: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        pipeline.ingest_envelope(&envelope, Some(source)).unwrap();
        assert_eq!(stored_envelope_count(&store), 1);
        let mut buf = [0u8; 2048];
        let (n, _) = capture
            .recv_from(&mut buf)
            .expect("first ingest should rebroadcast to the peer");
        assert_eq!(&buf[..n], envelope.encode_to_vec().as_slice());

        // Second ingest of the same envelope: accepted (Ok) but
        // neither re-stored nor re-forwarded.
        pipeline.ingest_envelope(&envelope, Some(source)).unwrap();
        assert_eq!(stored_envelope_count(&store), 1);
        assert!(
            capture.recv_from(&mut buf).is_err(),
            "duplicate ingest must not rebroadcast"
        );
        service.stop();
    }

    #[test]
    fn udp_loopback_broadcast_is_received_and_stored() {
        let receiver_store = test_store();
        let (envelope, pubkey) = signed_envelope(11, 999);
        trust_sender(&receiver_store, &pubkey);

        let mut receiver =
            GossipService::with_ingest(0, receiver_store.clone(), test_config(), None);
        receiver.start().unwrap();
        let receiver_port = receiver.local_port().unwrap();

        let mut sender = GossipService::new(0, None, None);
        sender.start().unwrap();
        sender.add_peer("127.0.0.1", receiver_port).unwrap();
        sender.broadcast_envelope(&envelope).unwrap();

        // The receiver's ingest pipeline validates, trust-checks,
        // dedups and stores asynchronously on its receive thread.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut count = 0;
        while std::time::Instant::now() < deadline {
            count = stored_envelope_count(&receiver_store);
            if count == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(count, 1, "receiver should store the broadcast envelope");

        sender.stop();
        receiver.stop();
    }

    /// DESIGN.md §10: an envelope whose sender is not trusted
    /// is rejected with `Unauthorized` and nothing is stored.
    /// (The rejection is also logged by `ingest_envelope`.)
    #[test]
    fn ingest_from_untrusted_sender_is_rejected() {
        let store = test_store();
        let (envelope, _pubkey) = signed_envelope(21, 999);
        // No trust granted for the sender.
        let mut service = GossipService::new(0, None, None);
        let pipeline = service.attach_ingest(store.clone(), test_config(), None);
        let source: SocketAddr = "127.0.0.1:59998".parse().unwrap();
        let err = pipeline
            .ingest_envelope(&envelope, Some(source))
            .unwrap_err();
        assert!(
            matches!(err, Error::Unauthorized),
            "expected Unauthorized, got {err}"
        );
        assert_eq!(stored_envelope_count(&store), 0);
    }

    /// A trusted sender whose envelope fails validation is
    /// rejected with a `Validation` error — a reason distinct
    /// from the trust rejection, so the log line can tell the
    /// two apart.
    #[test]
    fn ingest_with_bad_signature_is_rejected_as_validation() {
        let store = test_store();
        let (mut envelope, pubkey) = signed_envelope(22, 999);
        trust_sender(&store, &pubkey);
        // Tamper with the ciphertext: the signing digest covers
        // its hash, so the signature no longer verifies.
        envelope.payload_ciphertext.push(0xFF);
        let mut service = GossipService::new(0, None, None);
        let pipeline = service.attach_ingest(store.clone(), test_config(), None);
        let source: SocketAddr = "127.0.0.1:59997".parse().unwrap();
        let err = pipeline
            .ingest_envelope(&envelope, Some(source))
            .unwrap_err();
        assert!(
            matches!(err, Error::Validation(_)),
            "expected Validation, got {err}"
        );
        assert_eq!(stored_envelope_count(&store), 0);
    }

    /// The pipeline-level form of the DESIGN.md §10 regression:
    /// trust is granted, then discovery/bootstrap persists the
    /// sender's address through the peer sink (the exact write
    /// startup performs) — ingest from that sender must still
    /// be accepted.
    #[test]
    fn trust_survives_discovery_sink_registration() {
        let store = test_store();
        let (envelope, pubkey) = signed_envelope(23, 999);
        trust_sender(&store, &pubkey);

        let mut service = GossipService::new(0, None, None);
        let mut sink = service.peer_sink(Some(store.clone()));
        sink.add_peer(&Peer::new("sender-node", 9000)).unwrap();
        drop(sink);

        let pipeline = service.attach_ingest(store.clone(), test_config(), None);
        let source: SocketAddr = "127.0.0.1:59996".parse().unwrap();
        pipeline.ingest_envelope(&envelope, Some(source)).unwrap();
        assert_eq!(stored_envelope_count(&store), 1);
    }

    /// Phase B4 (DESIGN.md §9): a valid group key share from
    /// an enrolled device to an enrolled device passes ingest
    /// and is stored; the same share with a stripped share
    /// signature (envelope re-signed, so only the share
    /// signature is wrong) is rejected as a validation failure
    /// and nothing more is stored.
    #[test]
    fn group_key_share_ingest_verifies_share_signature_and_enrollment() {
        use crate::keystore::MemberKeystore;
        use crate::proto::GroupKeyShare;
        use prost::Message as _;

        let store = test_store();
        let now = now_epoch();
        let group_id: [u8; 16] = [0x6B; 16];

        // Two enrolled members with devices, in one conversation.
        let make_member = |store: &Store| {
            let mut ks = MemberKeystore::new();
            ks.generate_member_key().unwrap();
            let device_pk = ks.add_device_key("phone").unwrap();
            let cert = crate::identity::issue_device_certificate(&ks, "phone", now, 0).unwrap();
            store.device_add(&cert, now).unwrap();
            let member_pk = ks.member_public_key().unwrap();
            store.conversation_member_add(&group_id, &member_pk, now).unwrap();
            (ks, member_pk, device_pk)
        };
        let (a_ks, _a_member, a_device) = {
            let guard = store.lock().unwrap();
            make_member(&guard)
        };
        let (_b_ks, _b_member, b_device) = {
            let guard = store.lock().unwrap();
            make_member(&guard)
        };

        // A starts a session; the share for B is the test input.
        let share_envelope = {
            let guard = store.lock().unwrap();
            let started =
                crate::sessions::start_session(&guard, &a_ks, "phone", &group_id, now).unwrap();
            assert_eq!(started.shares.len(), 1);
            started.shares.into_iter().next().unwrap()
        };
        assert_eq!(
            share_envelope.header.as_ref().unwrap().recipients_pubkey,
            vec![b_device.to_vec()]
        );

        // The gossip trust check keys on the envelope sender —
        // the sender device.
        trust_sender(&store, &a_device);
        let mut service = GossipService::new(0, None, None);
        let pipeline = service.attach_ingest(store.clone(), test_config(), None);
        let source: SocketAddr = "127.0.0.1:59995".parse().unwrap();

        pipeline.ingest_envelope(&share_envelope, Some(source)).unwrap();
        assert_eq!(stored_envelope_count(&store), 1);

        // Strip the share signature and re-sign the envelope
        // with the sender device key: the envelope is valid,
        // the share is not, and ingest must refuse it.
        let mut share =
            GroupKeyShare::decode(share_envelope.payload_ciphertext.as_slice()).unwrap();
        share.signature = vec![0u8; 64];
        let mut tampered = share_envelope.clone();
        tampered.payload_ciphertext = share.encode_to_vec();
        let digest = validation::compute_envelope_signing_digest(&tampered).unwrap();
        let secret = a_ks
            .device_keystore("phone")
            .unwrap()
            .get_private_key()
            .unwrap();
        let signing = SigningKey::from_keypair_bytes(&secret).unwrap();
        tampered.signature = signing.sign(&digest).to_bytes().to_vec();

        let err = pipeline
            .ingest_envelope(&tampered, Some(source))
            .unwrap_err();
        assert!(
            matches!(err, Error::Validation(_)),
            "expected Validation, got {err}"
        );
        assert_eq!(stored_envelope_count(&store), 1);
    }
}
