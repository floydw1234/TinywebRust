//! HTTP API handlers.
//!
//! Rust counterpart of the C HTTP API in `src/packages/comm/`
//! (`gossipApi.c`, `messagesApi.c`, `userMessagesApi.c`,
//! `locationApi.c`, `authApi.c` and `request_auth.c`): the
//! TCP/8000 client-facing endpoints for submitting and fetching
//! messages, location updates, gossip peer listing, and health
//! checks.
//!
//! The wire behaviour mirrors the C Mongoose server: same paths,
//! methods, JSON/protobuf response shapes, status codes and CORS
//! headers. The server itself is hand-rolled on
//! `std::net::TcpListener` (one thread per connection) to keep
//! the port dependency-light; no HTTP crate is used.
//!
//! DESIGN.md 2.1: `ClientRequest` disappears as a wire format.
//! `POST /location/update` therefore takes a signed `Envelope`
//! (the shape [`client_request_to_envelope`] — the port of
//! `client_request_converter.c` — would have produced from a C
//! client request), stores it through the envelope location
//! store and broadcasts the envelope itself. Nothing here writes
//! the legacy `gossip_messages` table (DESIGN.md 4.2); messages
//! go to the `user_messages` projection via the store module.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message as _;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::gossip::GossipService;
use crate::proto::{
    CalendarEvent, ClientRequest, ConversationList, DeviceCertificate, Envelope, GroupKeyShare,
    Message, MessageList,
};
use crate::store::{
    DeviceStatus, EventRecord, GroupRecord, PermissionScope, Store, PERMISSION_VIEW_LOCATION,
    PUBKEY_SIZE,
};
use crate::validation::{
    self, GossipValidationConfig,
};

/// C `REQUEST_TIMESTAMP_WINDOW`: requests older than this many
/// seconds are rejected as expired.
pub const REQUEST_TIMESTAMP_WINDOW: u64 = 300;
/// Future clock skew tolerated for request timestamps (C: 60s).
pub const REQUEST_FUTURE_SKEW: u64 = 60;
/// Body size limit enforced before protobuf decoding (C: 1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Hex helpers (C: sodium_bin2hex / sodium_hex2bin)
// ---------------------------------------------------------------------------

/// Lowercase hex encoding (libsodium `sodium_bin2hex`).
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Strict hex decoding (libsodium `sodium_hex2bin` with no ignore
/// characters): odd length or a non-hex digit is an error.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex_decode(hex)?.as_slice()).ok()
}

// ---------------------------------------------------------------------------
// Signed request auth (`request_auth.c`)
// ---------------------------------------------------------------------------

/// Counterpart of C `RequestAuthResult` (the `OK` case is
/// `Ok(pubkey)` in [`validate_request_auth_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAuthResult {
    /// C `REQUEST_AUTH_MISSING_PUBKEY`.
    MissingPubkey,
    /// C `REQUEST_AUTH_MISSING_SIGNATURE`.
    MissingSignature,
    /// C `REQUEST_AUTH_MISSING_TIMESTAMP`.
    MissingTimestamp,
    /// C `REQUEST_AUTH_INVALID_PUBKEY`.
    InvalidPubkey,
    /// C `REQUEST_AUTH_INVALID_SIGNATURE`.
    InvalidSignature,
    /// C `REQUEST_AUTH_USER_NOT_REGISTERED`.
    UserNotRegistered,
    /// C `REQUEST_AUTH_EXPIRED_TIMESTAMP`.
    ExpiredTimestamp,
    /// C `REQUEST_AUTH_FUTURE_TIMESTAMP`.
    FutureTimestamp,
    /// C `REQUEST_AUTH_ERROR`.
    Error,
}

impl RequestAuthResult {
    /// C `request_auth_error_string`.
    pub fn error_string(self) -> &'static str {
        match self {
            RequestAuthResult::MissingPubkey => "Missing X-User-Pubkey header",
            RequestAuthResult::MissingSignature => "Missing X-Signature header",
            RequestAuthResult::MissingTimestamp => "Missing X-Timestamp header",
            RequestAuthResult::InvalidPubkey => "Invalid public key format",
            RequestAuthResult::InvalidSignature => "Invalid signature",
            RequestAuthResult::UserNotRegistered => "User not registered",
            RequestAuthResult::ExpiredTimestamp => "Request timestamp expired",
            RequestAuthResult::FutureTimestamp => "Request timestamp too far in future",
            RequestAuthResult::Error => "Authentication error",
        }
    }
}

/// The request signing digest (C `compute_request_digest`):
/// `SHA256("TWREQUEST\0" || method || uri || query || timestamp || pubkey32)`.
/// `query` is the raw query string without `?` (empty when absent),
/// `timestamp` is the literal `X-Timestamp` header value.
pub fn compute_request_digest(
    method: &str,
    uri: &str,
    query: &str,
    timestamp: &str,
    pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TWREQUEST\0");
    hasher.update(method.as_bytes());
    hasher.update(uri.as_bytes());
    hasher.update(query.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(pubkey);
    hasher.finalize().into()
}

/// C `strtoull` for the timestamp header: leading digits, 0 when
/// there are none.
fn parse_timestamp(value: &str) -> u64 {
    let digits: String = value
        .trim_start()
        .trim_start_matches('+')
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().unwrap_or(u64::MAX)
}

/// Validate a signed request at wall-clock time (C
/// `validate_request_auth`). On success returns the requester's
/// 32-byte public key.
pub fn validate_request_auth(
    request: &Request,
    store: &Store,
) -> Result<[u8; PUBKEY_SIZE], RequestAuthResult> {
    validate_request_auth_at(request, store, now_epoch())
}

/// [`validate_request_auth`] as of `now` (deterministic core for
/// tests; the C function reads `time(NULL)` internally).
///
/// Check order matches C: pubkey header, timestamp window,
/// signature header, Ed25519 verification over
/// [`compute_request_digest`], then the registered-user check
/// against the store.
pub fn validate_request_auth_at(
    request: &Request,
    store: &Store,
    now: u64,
) -> Result<[u8; PUBKEY_SIZE], RequestAuthResult> {
    // 1. Public key header.
    let pubkey_hex = match request.header("X-User-Pubkey") {
        Some(v) if !v.is_empty() => v,
        _ => return Err(RequestAuthResult::MissingPubkey),
    };
    let pubkey: [u8; PUBKEY_SIZE] = match hex_decode_32(pubkey_hex) {
        Some(k) => k,
        None => return Err(RequestAuthResult::InvalidPubkey),
    };

    // 2. Timestamp header and window (300s past, 60s future).
    let timestamp_str = match request.header("X-Timestamp") {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Err(RequestAuthResult::MissingTimestamp),
    };
    let timestamp = parse_timestamp(&timestamp_str);
    if timestamp > now.saturating_add(REQUEST_FUTURE_SKEW) {
        return Err(RequestAuthResult::FutureTimestamp);
    }
    if timestamp < now.saturating_sub(REQUEST_TIMESTAMP_WINDOW) {
        return Err(RequestAuthResult::ExpiredTimestamp);
    }

    // 3. Signature header.
    let signature_hex = match request.header("X-Signature") {
        Some(v) if !v.is_empty() => v,
        _ => return Err(RequestAuthResult::MissingSignature),
    };
    let signature = match hex_decode(signature_hex) {
        Some(s) if s.len() == 64 => s,
        _ => return Err(RequestAuthResult::InvalidSignature),
    };

    // 4+5. Digest and Ed25519 verification.
    let digest = compute_request_digest(
        &request.method,
        &request.path,
        &request.query,
        &timestamp_str,
        &pubkey,
    );
    if !validation::verify_signature(&signature, &digest, &pubkey) {
        return Err(RequestAuthResult::InvalidSignature);
    }

    // 6. The user must be registered.
    if !store.user_exists(&pubkey) {
        return Err(RequestAuthResult::UserNotRegistered);
    }
    Ok(pubkey)
}

// ---------------------------------------------------------------------------
// ClientRequest -> Envelope conversion (`client_request_converter.c`)
// ---------------------------------------------------------------------------

/// Port of `client_request_to_envelope`: field-for-field mapping
/// of a C client request onto an envelope (header fields,
/// payload nonce/ciphertext, ephemeral key, keywraps and the
/// signature are copied verbatim). Returns `None` exactly where
/// the C function returns NULL (missing header, a key field of
/// the wrong length, or an empty ciphertext/wrapped key).
pub fn client_request_to_envelope(request: &ClientRequest) -> Option<Envelope> {
    let req_hdr = request.header.as_ref()?;
    if req_hdr.sender_pubkey.len() != 32 {
        return None;
    }
    for recipient in &req_hdr.recipients_pubkey {
        if recipient.len() != 32 {
            return None;
        }
    }
    if request.payload_nonce.len() != 24
        || request.ephemeral_pubkey.len() != 32
        || request.payload_ciphertext.is_empty()
        || request.signature.len() != 64
    {
        return None;
    }
    let mut keywraps = Vec::with_capacity(request.keywraps.len());
    for wrap in &request.keywraps {
        if wrap.recipient_pubkey.len() != 32
            || wrap.key_nonce.len() != 24
            || wrap.wrapped_key.is_empty()
        {
            return None;
        }
        keywraps.push(crate::proto::RecipientKeyWrap {
            recipient_pubkey: wrap.recipient_pubkey.clone(),
            key_nonce: wrap.key_nonce.clone(),
            wrapped_key: wrap.wrapped_key.clone(),
        });
    }
    Some(Envelope {
        header: Some(crate::proto::EnvelopeHeader {
            version: req_hdr.version,
            content_type: req_hdr.content_type,
            schema_version: req_hdr.schema_version,
            timestamp: req_hdr.timestamp,
            sender_pubkey: req_hdr.sender_pubkey.clone(),
            recipients_pubkey: req_hdr.recipients_pubkey.clone(),
            group_id: req_hdr.group_id.clone(),
        }),
        payload_nonce: request.payload_nonce.clone(),
        ephemeral_pubkey: request.ephemeral_pubkey.clone(),
        payload_ciphertext: request.payload_ciphertext.clone(),
        keywraps,
        signature: request.signature.clone(),
    })
}

/// Every header recipient must have exactly one matching keywrap
/// (the envelope analogue of C `client_request_validate_recipients`,
/// applied to a converted submission).
fn envelope_recipients_have_keywraps(envelope: &Envelope) -> bool {
    let Some(header) = envelope.header.as_ref() else {
        return false;
    };
    if header.recipients_pubkey.is_empty()
        || envelope.keywraps.len() != header.recipients_pubkey.len()
    {
        return false;
    }
    header.recipients_pubkey.iter().all(|recipient| {
        envelope
            .keywraps
            .iter()
            .any(|w| w.recipient_pubkey.len() == 32 && &w.recipient_pubkey == recipient)
    })
}

// ---------------------------------------------------------------------------
// HTTP request/response types and routing
// ---------------------------------------------------------------------------

/// One parsed HTTP request. `path` is the URI without the query
/// string (Mongoose `hm->uri`), `query` the raw query without `?`
/// (Mongoose `hm->query`).
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header lookup (C `mg_http_get_header`).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|v| v.as_str())
    }

    /// One URL-decoded query variable (C `mg_http_get_var`).
    pub fn query_var(&self, name: &str) -> Option<String> {
        for pair in self.query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if url_decode(key) == name {
                return Some(url_decode(value));
            }
        }
        None
    }
}

/// Percent/`+` decoding for query variables.
fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One HTTP response: status, optional content type and raw body.
/// `Access-Control-Allow-Origin: *` is added on the wire for
/// every response, as every C handler does.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// Extra headers (used by the global OPTIONS reply).
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    fn json(status: u16, body: impl Into<String>) -> Self {
        Response {
            status,
            content_type: Some("application/json".to_string()),
            body: body.into().into_bytes(),
            extra_headers: Vec::new(),
        }
    }
    fn json_error(status: u16, error: &str) -> Self {
        // The exact literal shape the C handlers reply with.
        Response::json(status, format!("{{\"error\":\"{error}\"}}"))
    }
    fn plain(status: u16, body: &str) -> Self {
        Response {
            status,
            content_type: None,
            body: body.as_bytes().to_vec(),
            extra_headers: Vec::new(),
        }
    }
    fn protobuf(status: u16, body: Vec<u8>) -> Self {
        Response {
            status,
            content_type: Some("application/x-protobuf".to_string()),
            body,
            extra_headers: Vec::new(),
        }
    }
    fn empty(status: u16) -> Self {
        Response {
            status,
            content_type: None,
            body: Vec::new(),
            extra_headers: Vec::new(),
        }
    }
}

/// The routes the C dispatcher knows, in dispatch order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `POST /gossip/message` (gossipApi.c)
    GossipMessage,
    /// `GET /gossip/peers` (gossipApi.c)
    GossipPeers,
    /// `GET /health` (gossipApi.c)
    Health,
    /// `POST /messages/submit` (messagesApi.c)
    SubmitMessage,
    /// `GET /messages/recent` (userMessagesApi.c)
    RecentMessages,
    /// `GET /messages/conversation` (userMessagesApi.c)
    Conversation,
    /// `GET /messages/conversations` (userMessagesApi.c)
    Conversations,
    /// `GET /users` (userMessagesApi.c)
    Users,
    /// `POST /location/update` (locationApi.c)
    LocationUpdate,
    /// `GET /location/:user_id` (locationApi.c)
    Location { user_id: String },
    /// `GET /location/history/:user_id` (locationApi.c)
    LocationHistory { user_id: String },
    /// `POST /auth/login` (authApi.c)
    Login,
    /// `POST /enroll/begin` (Phase B3, DESIGN.md §5)
    EnrollBegin,
    /// `POST /enroll/approve` (Phase B3, DESIGN.md §5)
    EnrollApprove,
    /// `GET /enroll/status` (Phase B3, DESIGN.md §5)
    EnrollStatus,
    /// `GET|POST /groups` (Phase C1, DESIGN.md §5)
    Groups,
    /// `POST /groups/:id/members` (Phase C1, DESIGN.md §5)
    GroupMembers { group_id: String },
    /// `DELETE /groups/:id/members/:pubkey` (Phase C1)
    GroupMember { group_id: String, member: String },
    /// `GET /devices` (Phase C1, DESIGN.md §5)
    Devices,
    /// `POST /devices/revoke` (Phase C1, DESIGN.md §5)
    RevokeDevice,
    /// `GET /household/devices` (Phase C4, DESIGN.md §5)
    HouseholdDevices,
    /// `POST /content/submit` (Phase C2, DESIGN.md §5)
    ContentSubmit,
    /// `GET /content/recent` (Phase C2, DESIGN.md §5)
    ContentRecent,
    /// `GET /groups/:id/share-recipients` (Phase C2)
    GroupShareRecipients { group_id: String },
    /// `GET|POST /events` (Phase C3, DESIGN.md §5)
    Events,
    /// `GET|PUT|POST|DELETE /events/:id` (Phase C3)
    Event { event_id: String },
    /// No route matched: C replies 404.
    NotFound,
}

/// Match a path to its route, mirroring the C dispatch:
/// exact matches first, then the `/location/` prefix with
/// `/location/history/` taking precedence over `/location/:id`.
pub fn route(path: &str) -> Route {
    match path {
        "/gossip/message" => Route::GossipMessage,
        "/gossip/peers" => Route::GossipPeers,
        "/health" => Route::Health,
        "/messages/submit" => Route::SubmitMessage,
        "/messages/recent" => Route::RecentMessages,
        "/messages/conversation" => Route::Conversation,
        "/messages/conversations" => Route::Conversations,
        "/users" => Route::Users,
        "/location/update" => Route::LocationUpdate,
        "/auth/login" => Route::Login,
        "/enroll/begin" => Route::EnrollBegin,
        "/enroll/approve" => Route::EnrollApprove,
        "/enroll/status" => Route::EnrollStatus,
        "/groups" => Route::Groups,
        "/content/submit" => Route::ContentSubmit,
        "/content/recent" => Route::ContentRecent,
        "/devices" => Route::Devices,
        "/devices/revoke" => Route::RevokeDevice,
        "/household/devices" => Route::HouseholdDevices,
        "/events" => Route::Events,
        _ => {
            if let Some(rest) = path.strip_prefix("/events/") {
                if !rest.is_empty() && !rest.contains('/') {
                    return Route::Event {
                        event_id: rest.to_string(),
                    };
                }
            }
            if let Some(rest) = path.strip_prefix("/groups/") {
                let parts: Vec<&str> = rest.split('/').collect();
                match parts.as_slice() {
                    [id, "share-recipients"] if !id.is_empty() => {
                        return Route::GroupShareRecipients {
                            group_id: id.to_string(),
                        };
                    }
                    [id, "members"] if !id.is_empty() => {
                        return Route::GroupMembers {
                            group_id: id.to_string(),
                        };
                    }
                    [id, "members", member] if !id.is_empty() && !member.is_empty() => {
                        return Route::GroupMember {
                            group_id: id.to_string(),
                            member: member.to_string(),
                        };
                    }
                    _ => {}
                }
            }
            if let Some(rest) = path.strip_prefix("/location/history/") {
                if !rest.is_empty() && !rest.contains('/') {
                    return Route::LocationHistory {
                        user_id: rest.to_string(),
                    };
                }
            }
            if let Some(rest) = path.strip_prefix("/location/") {
                if !rest.is_empty() && !rest.contains('/') {
                    return Route::Location {
                        user_id: rest.to_string(),
                    };
                }
            }
            Route::NotFound
        }
    }
}

/// `Access-Control-Allow-Methods` for the global OPTIONS handler
/// in gossipApi.c.
fn allowed_methods_for(path: &str) -> &'static str {
    match path {
        "/messages/submit" | "/gossip/message" | "/location/update" | "/enroll/begin"
        | "/enroll/approve" | "/devices/revoke" | "/content/submit" => "POST, OPTIONS",
        "/groups" => "GET, POST, OPTIONS",
        _ if path.starts_with("/groups/") => "GET, POST, DELETE, OPTIONS",
        "/events" => "GET, POST, OPTIONS",
        _ if path.starts_with("/events/") => "GET, POST, PUT, DELETE, OPTIONS",
        "/content/recent" => "GET, OPTIONS",
        "/gossip/peers"
        | "/health"
        | "/messages/recent"
        | "/messages/conversation"
        | "/messages/conversations"
        | "/users"
        | "/devices"
        | "/household/devices"
        | "/enroll/status" => "GET, OPTIONS",
        _ if path.starts_with("/location/") => "GET, OPTIONS",
        _ => "GET, POST, OPTIONS",
    }
}

// ---------------------------------------------------------------------------
// Shared API state and the HTTP server
// ---------------------------------------------------------------------------

/// State shared by all API connections: the node store, the
/// gossip service (for broadcasts; `None` in tests) and the
/// gossip validation limits from the node config.
#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Mutex<Store>>,
    pub gossip: Option<Arc<Mutex<GossipService>>>,
    pub validation_config: GossipValidationConfig,
}

impl ApiState {
    pub fn new(
        store: Arc<Mutex<Store>>,
        gossip: Option<Arc<Mutex<GossipService>>>,
        validation_config: GossipValidationConfig,
    ) -> Self {
        ApiState {
            store,
            gossip,
            validation_config,
        }
    }
}

/// The HTTP API server (C `GossipApiServer` / `gossip_api_start`).
pub struct ApiServer {
    port: u16,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ApiServer {
    /// Bind `0.0.0.0:port` and serve on a background thread
    /// (C `gossip_api_start`).
    pub fn start(port: u16, state: ApiState) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        listener.set_nonblocking(true)?;
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let thread = std::thread::spawn(move || loop {
            if !thread_running.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let conn_state = state.clone();
                    std::thread::spawn(move || {
                        let _ = handle_connection(stream, &conn_state);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        });
        println!("Gossip HTTP API listening on http://0.0.0.0:{port}");
        Ok(ApiServer {
            port,
            running,
            thread: Some(thread),
        })
    }

    /// The port the server was started on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the accept loop is running (C `gossip_api_is_running`).
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop accepting and join the accept thread (C `gossip_api_stop`).
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason_phrase(response.status),
        response.body.len()
    );
    if let Some(content_type) = &response.content_type {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    for (name, value) in &response.extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

/// Read and parse one HTTP request (headers + Content-Length or
/// chunked body). Returns `None` on a malformed/empty request.
fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HashMap::new();
    let mut content_length: usize = 0;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
            headers.insert(name, value);
        }
    }
    let mut body = buf.split_off(header_end);
    if chunked {
        loop {
            match decode_chunked(&body) {
                Some((decoded, _consumed)) => {
                    body = decoded;
                    break;
                }
                None => match stream.read(&mut chunk) {
                    Ok(0) => return None,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                    Err(_) => return None,
                },
            }
        }
    } else {
        while body.len() < content_length {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        body.truncate(content_length);
    }
    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Decode a complete chunked body; `None` when more bytes are needed.
fn decode_chunked(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = find_subslice(&data[pos..], b"\r\n")? + pos;
        let size_str = std::str::from_utf8(&data[pos..line_end]).ok()?.trim();
        let size = usize::from_str_radix(size_str.split(';').next()?, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some((out, pos));
        }
        if data.len() < pos + size + 2 {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2; // chunk + trailing CRLF
    }
}

fn handle_connection(mut stream: TcpStream, state: &ApiState) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let Some(request) = read_request(&mut stream) else {
        return Ok(());
    };
    let response = handle_request(state, &request);
    write_response(&mut stream, &response)
}

// ---------------------------------------------------------------------------
// Route dispatch and endpoint handlers
// ---------------------------------------------------------------------------

/// Dispatch one parsed request, mirroring `gossip_api_handler`:
/// global OPTIONS first, then the gossipApi routes, then the
/// messages, user-messages, location and auth modules in order.
pub fn handle_request(state: &ApiState, request: &Request) -> Response {
    // Global CORS preflight (gossipApi.c, must be first).
    if request.method == "OPTIONS" {
        let mut response = Response::empty(200);
        response.extra_headers = vec![
            (
                "Access-Control-Allow-Methods".to_string(),
                allowed_methods_for(&request.path).to_string(),
            ),
            (
                "Access-Control-Allow-Headers".to_string(),
                "Content-Type, X-User-Pubkey, X-Signature, X-Timestamp".to_string(),
            ),
            ("Access-Control-Max-Age".to_string(), "86400".to_string()),
        ];
        return response;
    }

    match route(&request.path) {
        Route::GossipMessage => {
            if request.method == "POST" {
                handle_gossip_message(state, request)
            } else {
                Response::json_error(405, "Method Not Allowed")
            }
        }
        Route::GossipPeers => {
            if request.method == "GET" {
                handle_get_peers(state)
            } else {
                Response::json_error(405, "Method Not Allowed")
            }
        }
        Route::Health => {
            if request.method == "GET" {
                Response::json(200, "{\"status\":\"healthy\",\"service\":\"tinyweb\"}")
            } else {
                Response::json_error(405, "Method Not Allowed")
            }
        }
        Route::SubmitMessage => match request.method.as_str() {
            "POST" => handle_submit_message(state, request),
            _ => Response::plain(405, "Method Not Allowed"),
        },
        Route::RecentMessages => {
            if request.method == "GET" {
                handle_get_recent(state, request)
            } else {
                Response::json_error(404, "Not Found")
            }
        }
        Route::Conversation => {
            if request.method == "GET" {
                handle_get_conversation(state, request)
            } else {
                Response::json_error(404, "Not Found")
            }
        }
        Route::Conversations => {
            if request.method == "GET" {
                handle_get_conversations(state, request)
            } else {
                Response::json_error(404, "Not Found")
            }
        }
        Route::Users => {
            if request.method == "GET" {
                handle_get_users(state, request)
            } else {
                Response::json_error(404, "Not Found")
            }
        }
        Route::LocationUpdate => match request.method.as_str() {
            "POST" => handle_submit_location_update(state, request),
            _ => Response::plain(405, "Method Not Allowed"),
        },
        Route::Location { .. } => match request.method.as_str() {
            "GET" => handle_get_location(state, request),
            _ => Response::plain(405, "Method Not Allowed"),
        },
        Route::LocationHistory { .. } => match request.method.as_str() {
            "GET" => handle_get_location_history(state, request),
            _ => Response::plain(405, "Method Not Allowed"),
        },
        Route::Login => match request.method.as_str() {
            "POST" => handle_login(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::EnrollBegin => match request.method.as_str() {
            "POST" => handle_enroll_begin(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::EnrollApprove => match request.method.as_str() {
            "POST" => handle_enroll_approve(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::EnrollStatus => match request.method.as_str() {
            "GET" => handle_enroll_status(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::Groups => match request.method.as_str() {
            "POST" => handle_create_group(state, request),
            "GET" => handle_list_groups(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::GroupMembers { group_id } => match request.method.as_str() {
            "POST" => handle_add_group_member(state, request, &group_id),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::GroupMember { group_id, member } => match request.method.as_str() {
            "DELETE" => handle_remove_group_member(state, request, &group_id, &member),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::Devices => match request.method.as_str() {
            "GET" => handle_list_devices(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::RevokeDevice => match request.method.as_str() {
            "POST" => handle_revoke_device(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::HouseholdDevices => match request.method.as_str() {
            "GET" => handle_household_devices(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::ContentSubmit => match request.method.as_str() {
            "POST" => handle_content_submit(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::ContentRecent => match request.method.as_str() {
            "GET" => handle_content_recent(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::GroupShareRecipients { group_id } => match request.method.as_str() {
            "GET" => handle_group_share_recipients(state, request, &group_id),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::Events => match request.method.as_str() {
            "POST" => handle_create_event(state, request),
            "GET" => handle_list_events(state, request),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::Event { event_id } => match request.method.as_str() {
            "GET" => handle_get_event(state, request, &event_id),
            "PUT" | "POST" => handle_update_event(state, request, &event_id),
            "DELETE" => handle_delete_event(state, request, &event_id),
            _ => Response::json_error(405, "Method Not Allowed"),
        },
        Route::NotFound => Response::json_error(404, "Not Found"),
    }
}

/// Run request auth against the shared store; on failure the
/// 401 response the C handlers send (`{"error":"<reason>"}`).
fn authenticate(
    state: &ApiState,
    request: &Request,
) -> Result<[u8; PUBKEY_SIZE], Response> {
    let store = state.store.lock().unwrap();
    validate_request_auth(request, &store)
        .map_err(|e| Response::json_error(401, e.error_string()))
}

fn query_pubkey(request: &Request, name: &str) -> Option<[u8; PUBKEY_SIZE]> {
    let value = request.query_var(name)?;
    hex_decode_32(&value)
}

fn query_limit(request: &Request, default: u32) -> u32 {
    match request.query_var("limit") {
        Some(v) => match v.parse::<i64>() {
            Ok(parsed) if parsed > 0 && parsed <= 1000 => parsed as u32,
            _ => default,
        },
        None => default,
    }
}

// -- gossipApi.c -------------------------------------------------------------

fn handle_get_peers(state: &ApiState) -> Response {
    let peers = {
        let store = state.store.lock().unwrap();
        store.gossip_peers_fetch_all()
    };
    let peers = match peers {
        Ok(p) => p,
        Err(_) => return Response::json_error(500, "Failed to fetch peers"),
    };
    let mut peer_objs = Vec::new();
    for peer in &peers {
        let mut obj = json!({
            "hostname": peer.hostname,
            "gossip_port": peer.gossip_port,
            "api_port": peer.api_port,
            "first_seen": peer.first_seen,
            "last_seen": peer.last_seen,
        });
        if !peer.tags.is_empty() {
            obj["tags"] = json!(peer.tags);
        }
        // C adds the hex pubkey when any of its 32 bytes is set.
        if peer.node_pubkey.iter().any(|b| *b != 0) {
            obj["node_pubkey"] = json!(hex_encode(&peer.node_pubkey));
        }
        peer_objs.push(obj);
    }
    let body = json!({ "peers": peer_objs, "count": peers.len() });
    Response::json(200, body.to_string())
}

/// `POST /gossip/message` (gossipApi.c `handle_gossip_message`):
/// validate (422 on failure), dedup, store, rebroadcast.
fn handle_gossip_message(state: &ApiState, request: &Request) -> Response {
    if request.body.is_empty() {
        return Response::json_error(400, "Empty body");
    }
    let msg = match Message::decode(request.body.as_slice()) {
        Ok(m) => m,
        Err(_) => return Response::json_error(400, "Invalid protobuf"),
    };
    if let Err(e) = validation::message_validate(&msg) {
        let result = Err(e);
        return Response::json_error(
            422,
            validation::message_validation_result_to_string(&result),
        );
    }
    let digest = crate::store::message_store_compute_digest(&msg);
    let expires_at = validation::message_validation_get_expiration(&msg);
    {
        let mut store = state.store.lock().unwrap();
        match store.message_store_has_seen(&digest) {
            Ok(true) => return Response::json(200, "{\"status\":\"duplicate\"}"),
            Ok(false) => {}
            Err(_) => {}
        }
        if store.message_store_save(&msg, expires_at).is_err() {
            return Response::json_error(500, "Storage failed");
        }
        let _ = store.message_store_mark_seen(&digest, expires_at);
    }
    if let Some(gossip) = &state.gossip {
        let service = gossip.lock().unwrap();
        let _ = service.rebroadcast_message(&msg, None);
    }
    Response::json(202, "{\"status\":\"accepted\"}")
}

// -- messagesApi.c -----------------------------------------------------------

/// `POST /messages/submit`: signed `Message` protobuf, requester
/// must be the sender, sender/recipients must be registered.
fn handle_submit_message(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if request.body.is_empty() {
        return Response::json_error(400, "Empty body");
    }
    if request.body.len() > MAX_BODY_BYTES {
        return Response::json_error(413, "Payload too large");
    }
    let msg = match Message::decode(request.body.as_slice()) {
        Ok(m) => m,
        Err(_) => return Response::json_error(400, "Invalid protobuf"),
    };
    if let Err(e) = validation::message_validate(&msg) {
        let result = Err(e);
        return Response::json_error(
            400,
            validation::message_validation_result_to_string(&result),
        );
    }
    let header = msg.header.as_ref().expect("validated message has header");
    let sender: [u8; PUBKEY_SIZE] =
        match header.sender_pubkey.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => return Response::json_error(400, "Invalid message format"),
        };
    if requester != sender {
        return Response::json_error(403, "Requester must match message sender");
    }
    {
        let store = state.store.lock().unwrap();
        if !store.user_exists(&sender) {
            return Response::json_error(403, "Sender not registered");
        }
        for recipient in &header.recipients_pubkey {
            let Ok(recipient_key) =
                <[u8; PUBKEY_SIZE]>::try_from(recipient.as_slice())
            else {
                return Response::json_error(403, "Recipient not registered");
            };
            if !store.user_exists(&recipient_key) {
                return Response::json_error(403, "Recipient not registered");
            }
        }
    }
    // Group gates (Phase C1). A message carrying a group id is
    // a group message: the sender and every header recipient
    // must be current members of the conversation — so a
    // removed member is not even addressed by later messages —
    // and a sender-session message must not ride a session a
    // membership change has retired: the sender rotates first
    // (Phase B4), which is what keeps a removed member's
    // devices from ever receiving the new session's shares and
    // gets a new member included. Every refusal is logged.
    if !header.group_id.is_empty() {
        let store = state.store.lock().unwrap();
        let members = match store.conversation_members(&header.group_id) {
            Ok(m) => m,
            Err(_) => return Response::json_error(500, "Store error"),
        };
        if members.is_empty() {
            eprintln!(
                "api groups: rejected group message from {}: unknown group {}",
                hex_encode(&sender),
                hex_encode(&header.group_id)
            );
            return Response::json_error(403, "Unknown group");
        }
        if !members.contains(&sender) {
            eprintln!(
                "api groups: rejected group message from {}: sender is not a member of group {}",
                hex_encode(&sender),
                hex_encode(&header.group_id)
            );
            return Response::json_error(403, "Sender is not a group member");
        }
        for recipient in &header.recipients_pubkey {
            let Ok(recipient_key) =
                <[u8; PUBKEY_SIZE]>::try_from(recipient.as_slice())
            else {
                return Response::json_error(403, "Recipient is not a group member");
            };
            if !members.contains(&recipient_key) {
                eprintln!(
                    "api groups: rejected group message from {}: recipient {} is not a member of group {}",
                    hex_encode(&sender),
                    hex_encode(&recipient_key),
                    hex_encode(&header.group_id)
                );
                return Response::json_error(403, "Recipient is not a group member");
            }
        }
        if !msg.session_id.is_empty() {
            match store.group_session_is_retired(&msg.session_id) {
                Ok(true) => {
                    eprintln!(
                        "api groups: rejected group message from {}: session {} was retired by a membership change in group {}",
                        hex_encode(&sender),
                        hex_encode(&msg.session_id),
                        hex_encode(&header.group_id)
                    );
                    return Response::json_error(
                        403,
                        "Session retired by a membership change; rotate the session",
                    );
                }
                Ok(false) => {}
                Err(_) => return Response::json_error(500, "Store error"),
            }
        }
    } else if !msg.session_id.is_empty() {
        eprintln!(
            "api groups: rejected session message from {}: session id without a group id",
            hex_encode(&sender)
        );
        return Response::json_error(400, "Session message without a group id");
    }
    // C `message_permissions_check` currently allows all messaging
    // between registered users (checked above), so no further gate.
    let digest = crate::store::message_store_compute_digest(&msg);
    let expires_at = validation::message_validation_get_expiration(&msg);
    {
        let mut store = state.store.lock().unwrap();
        match store.message_store_has_seen(&digest) {
            Ok(true) => return Response::json(202, "{\"status\":\"duplicate\"}"),
            Ok(false) => {}
            Err(_) => return Response::json_error(500, "Internal error"),
        }
        if store.message_store_save(&msg, expires_at).is_err() {
            return Response::json_error(500, "Storage failed");
        }
        let _ = store.message_store_mark_seen(&digest, expires_at);
    }
    // Broadcast after the accept decision, as in C (which replies
    // first); the outcome is identical from the client's view.
    if let Some(gossip) = &state.gossip {
        let service = gossip.lock().unwrap();
        let _ = service.broadcast_message(&msg);
    }
    Response::json(202, "{\"status\":\"accepted\"}")
}

// -- userMessagesApi.c -------------------------------------------------------

fn handle_get_recent(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(user) = query_pubkey(request, "user") else {
        return Response::json_error(400, "Missing user");
    };
    let limit = query_limit(request, 50);
    if requester != user {
        return Response::json_error(
            403,
            "Unauthorized: can only access own messages",
        );
    }
    let messages = {
        let store = state.store.lock().unwrap();
        store.message_store_fetch_recent(&user, limit)
    };
    let messages = match messages {
        Ok(m) => m,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    let total_count = messages.len() as u32;
    let list = MessageList {
        messages,
        total_count,
    };
    Response::protobuf(200, list.encode_to_vec())
}

fn handle_get_conversation(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let (Some(user), Some(with)) = (
        query_pubkey(request, "user"),
        query_pubkey(request, "with"),
    ) else {
        return Response::json_error(400, "Missing params");
    };
    // C fixes this endpoint's limit at 100 (never parses `limit`).
    let limit = 100;
    if requester != user && requester != with {
        return Response::json_error(
            403,
            "Unauthorized: must be conversation participant",
        );
    }
    {
        let store = state.store.lock().unwrap();
        if !store.user_exists(&user) {
            return Response::json_error(403, "User not registered");
        }
        if !store.user_exists(&with) {
            return Response::json_error(403, "Conversation partner not registered");
        }
    }
    let messages = {
        let store = state.store.lock().unwrap();
        store.message_store_fetch_conversation(&user, &with, limit)
    };
    let messages = match messages {
        Ok(m) => m,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    let total_count = messages.len() as u32;
    let list = MessageList {
        messages,
        total_count,
    };
    Response::protobuf(200, list.encode_to_vec())
}

fn handle_get_conversations(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(user) = query_pubkey(request, "user") else {
        return Response::json_error(400, "Missing user");
    };
    // C fixes this endpoint's limit at 100 (never parses `limit`).
    let limit = 100;
    if requester != user {
        return Response::json_error(
            403,
            "Unauthorized: can only access own conversations",
        );
    }
    let list: ConversationList = {
        let store = state.store.lock().unwrap();
        match store.message_store_fetch_conversations(&user, limit) {
            Ok(l) => l,
            Err(_) => return Response::json_error(500, "Store error"),
        }
    };
    Response::protobuf(200, list.encode_to_vec())
}

fn handle_get_users(state: &ApiState, request: &Request) -> Response {
    if let Err(r) = authenticate(state, request) {
        return r;
    }
    let store = state.store.lock().unwrap();
    let conn = store.connection();
    let mut stmt = match conn
        .prepare("SELECT pubkey, username, age FROM users WHERE is_active = 1 ORDER BY username;")
    {
        Ok(s) => s,
        Err(_) => return Response::json_error(500, "Prepare error"),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<i64>>(2)?,
        ))
    });
    let rows = match rows {
        Ok(r) => r,
        Err(_) => return Response::json_error(500, "DB error"),
    };
    let mut users = Vec::new();
    for row in rows {
        let Ok((pubkey, username, age)) = row else {
            continue;
        };
        let mut obj = json!({});
        if let Some(pk) = pubkey {
            obj["pubkey"] = json!(pk);
        }
        if let Some(name) = username {
            obj["username"] = json!(name);
        }
        if let Some(age) = age {
            obj["age"] = json!(age);
        }
        users.push(obj);
    }
    Response::json(200, json!({ "users": users }).to_string())
}

// -- locationApi.c -----------------------------------------------------------

/// `POST /location/update`. DESIGN.md 2.1: the submission is a
/// signed `Envelope` (what [`client_request_to_envelope`] would
/// have produced from a C `ClientRequest`); it is validated as an
/// envelope, stored via the envelope location store and the
/// envelope itself is broadcast — no `ClientRequest` on the wire
/// and no legacy `gossip_messages` write.
fn handle_submit_location_update(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if request.body.is_empty() {
        return Response::json_error(400, "Empty body");
    }
    if request.body.len() > MAX_BODY_BYTES {
        return Response::json_error(413, "Payload too large");
    }
    let envelope = match Envelope::decode(request.body.as_slice()) {
        Ok(e) => e,
        Err(_) => return Response::json_error(400, "Invalid protobuf"),
    };
    if let Err(e) = validation::gossip_validate_envelope(
        &envelope,
        &state.validation_config,
        now_epoch(),
    ) {
        let result = Err(e);
        return Response::json_error(
            400,
            validation::gossip_validation_error_string(&result),
        );
    }
    if !envelope_recipients_have_keywraps(&envelope) {
        return Response::json_error(400, "Invalid recipients (missing keywraps)");
    }
    let header = envelope.header.as_ref().expect("validated envelope has header");
    let sender: [u8; PUBKEY_SIZE] =
        match header.sender_pubkey.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => return Response::json_error(400, "Invalid message format"),
        };
    if requester != sender {
        return Response::json_error(403, "Requester must match request sender");
    }
    {
        let store = state.store.lock().unwrap();
        // C `location_permissions_check_submit`: a registered user
        // may submit their own location updates.
        if !store.user_exists(&sender) {
            return Response::json_error(403, "Sender not registered");
        }
        for recipient in &header.recipients_pubkey {
            let Ok(recipient_key) =
                <[u8; PUBKEY_SIZE]>::try_from(recipient.as_slice())
            else {
                return Response::json_error(403, "Recipient not registered");
            };
            if !store.user_exists(&recipient_key) {
                return Response::json_error(403, "Recipient not registered");
            }
        }
    }
    let digest = crate::store::location_store_compute_digest_envelope(&envelope);
    // C `client_request_get_expiration`: header timestamp + 7 days.
    let expires_at = header
        .timestamp
        .wrapping_add(validation::CLIENT_REQUEST_TTL_SECONDS);
    {
        let mut store = state.store.lock().unwrap();
        match store.location_store_has_seen(&digest) {
            Ok(true) => return Response::json(202, "{\"status\":\"duplicate\"}"),
            Ok(false) => {}
            Err(_) => return Response::json_error(500, "Internal error"),
        }
        if store
            .location_store_save_envelope(&envelope, expires_at)
            .is_err()
        {
            return Response::json_error(500, "Storage failed");
        }
        let _ = store.location_store_mark_seen(&digest, expires_at);
    }
    if let Some(gossip) = &state.gossip {
        let service = gossip.lock().unwrap();
        let _ = service.broadcast_envelope(&envelope);
    }
    Response::json(202, "{\"status\":\"accepted\"}")
}

/// C `location_permissions_check_view`: self always, otherwise a
/// VIEW_LOCATION grant in a supervised/global/direct scope.
fn location_can_view(
    store: &Store,
    requester: &[u8; PUBKEY_SIZE],
    user: &[u8; PUBKEY_SIZE],
) -> bool {
    if requester == user {
        return true;
    }
    store.check_user_permission(
        requester,
        PERMISSION_VIEW_LOCATION,
        PermissionScope::SupervisedUsers,
    ) || store.check_user_permission(
        requester,
        PERMISSION_VIEW_LOCATION,
        PermissionScope::Global,
    ) || store.check_user_permission(
        requester,
        PERMISSION_VIEW_LOCATION,
        PermissionScope::Direct,
    )
}

fn path_user_pubkey(request: &Request) -> Option<[u8; PUBKEY_SIZE]> {
    let segment = request.path.rsplit('/').next()?;
    hex_decode_32(segment)
}

fn handle_get_location(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(user) = path_user_pubkey(request) else {
        return Response::json_error(400, "Invalid user_id format");
    };
    let latest = {
        let store = state.store.lock().unwrap();
        if !location_can_view(&store, &requester, &user) {
            return Response::json_error(403, "Forbidden");
        }
        store.location_store_get_latest(&user)
    };
    let latest = match latest {
        Ok(Some(d)) => d,
        _ => return Response::json_error(404, "Location not found"),
    };
    let body = json!({
        "is_envelope": latest.is_envelope,
        "data_hex": hex_encode(&latest.data),
    });
    Response::json(200, body.to_string())
}

fn handle_get_location_history(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(user) = path_user_pubkey(request) else {
        return Response::json_error(400, "Invalid user_id format");
    };
    let limit = query_limit(request, 50);
    let offset: u32 = match request.query_var("offset") {
        Some(v) => match v.parse::<i64>() {
            Ok(parsed) if parsed >= 0 => parsed as u32,
            _ => 0,
        },
        None => 0,
    };
    let history = {
        let store = state.store.lock().unwrap();
        if !location_can_view(&store, &requester, &user) {
            return Response::json_error(403, "Forbidden");
        }
        store.location_store_get_history(&user, limit, offset)
    };
    let history = match history {
        Ok(h) => h,
        Err(_) => return Response::json_error(500, "Failed to query history"),
    };
    let updates: Vec<_> = history
        .iter()
        .filter(|d| !d.data.is_empty())
        .map(|d| json!({ "is_envelope": d.is_envelope, "data_hex": hex_encode(&d.data) }))
        .collect();
    let count = updates.len();
    Response::json(
        200,
        json!({ "updates": updates, "count": count }).to_string(),
    )
}

// -- authApi.c ---------------------------------------------------------------

fn handle_login(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    // C re-checks registration after auth (auth already enforces it).
    {
        let store = state.store.lock().unwrap();
        if !store.user_exists(&requester) {
            return Response::json_error(403, "User not registered");
        }
    }
    Response::json(
        200,
        format!(
            "{{\"status\":\"success\",\"pubkey\":\"{}\"}}",
            hex_encode(&requester)
        ),
    )
}

// -- enrollment (Phase B3, DESIGN.md §3.2/§5) -------------------------------

/// Pairing code lifetime: single-use, ~10 minutes (DESIGN.md
/// §3.2, the same TTL tinywebStack chose for its app codes).
pub const PAIRING_CODE_TTL_SECONDS: u64 = 600;
/// Pairing code entropy: 128 random bits, hex-encoded for the
/// link/QR the joining device shows the parent.
pub const PAIRING_CODE_BYTES: usize = 16;

/// A fresh pairing code and the hash the store keys it by. The
/// code itself is returned to the joining device exactly once
/// (in the begin response) and never stored or logged.
fn generate_pairing_code() -> Option<(String, [u8; PUBKEY_SIZE])> {
    let mut raw = [0u8; PAIRING_CODE_BYTES];
    getrandom::getrandom(&mut raw).ok()?;
    let code = hex_encode(&raw);
    let hash: [u8; PUBKEY_SIZE] = Sha256::digest(code.as_bytes()).into();
    Some((code, hash))
}

/// The store lookup hash for a presented code. Codes are
/// case-insensitive hex; surrounding whitespace is ignored.
fn pairing_code_hash(code: &str) -> [u8; PUBKEY_SIZE] {
    let normalized = code.trim().to_ascii_lowercase();
    Sha256::digest(normalized.as_bytes()).into()
}

fn json_body(request: &Request) -> Option<serde_json::Value> {
    serde_json::from_slice(&request.body).ok()
}

fn json_hex_32(body: &serde_json::Value, field: &str) -> Option<[u8; PUBKEY_SIZE]> {
    hex_decode_32(body.get(field)?.as_str()?)
}

fn enroll_reject(context: &str, reason: &str) {
    eprintln!("api enroll: rejected {context}: {reason}");
}

/// `POST /enroll/begin` — the joining device opens a pairing.
/// Unauthenticated by design: the device has no credentials yet;
/// the pairing code it gets back is the capability, and nothing
/// is enrolled until an approver signs (see
/// [`handle_enroll_approve`]). Body (JSON): `member_pubkey`,
/// `device_pubkey`, `display_name`, and `device_cert` (hex of
/// the member-signed `DeviceCertificate` protobuf the device
/// made locally — its member key never leaves the device).
/// Replies `{status:"pending", code, expires_at, ...}`; the
/// device shows the code to the parent (typed or as a QR/link).
fn handle_enroll_begin(state: &ApiState, request: &Request) -> Response {
    let now = now_epoch();
    let Some(body) = json_body(request) else {
        enroll_reject("begin", "body is not valid JSON");
        return Response::json_error(400, "Invalid JSON body");
    };
    let Some(member_pubkey) = json_hex_32(&body, "member_pubkey") else {
        enroll_reject("begin", "missing or invalid member_pubkey");
        return Response::json_error(400, "Missing or invalid member_pubkey");
    };
    let Some(device_pubkey) = json_hex_32(&body, "device_pubkey") else {
        enroll_reject(
            &format!("begin member={}", hex_encode(&member_pubkey)),
            "missing or invalid device_pubkey",
        );
        return Response::json_error(400, "Missing or invalid device_pubkey");
    };
    let context = format!(
        "begin member={} device={}",
        hex_encode(&member_pubkey),
        hex_encode(&device_pubkey)
    );
    let display_name = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let display_name = if display_name.is_empty() {
        "Member".to_string()
    } else {
        display_name
    };
    let Some(cert_hex) = body.get("device_cert").and_then(|v| v.as_str()) else {
        enroll_reject(&context, "missing device_cert");
        return Response::json_error(400, "Missing device_cert");
    };
    let Some(cert_bytes) = hex_decode(cert_hex) else {
        enroll_reject(&context, "device_cert is not hex");
        return Response::json_error(400, "Invalid device_cert");
    };
    let cert = match DeviceCertificate::decode(cert_bytes.as_slice()) {
        Ok(c) => c,
        Err(_) => {
            enroll_reject(&context, "device_cert does not decode");
            return Response::json_error(400, "Invalid device certificate");
        }
    };
    if cert.member_pubkey != member_pubkey[..] || cert.device_pubkey != device_pubkey[..] {
        enroll_reject(
            &context,
            "device certificate names different keys than the request",
        );
        return Response::json_error(
            400,
            "Device certificate does not match member/device pubkey",
        );
    }
    let store = state.store.lock().unwrap();
    match store.device_is_trusted(&member_pubkey, &device_pubkey, now) {
        Ok(true) => {
            enroll_reject(&context, "device is already enrolled");
            return Response::json_error(400, "Device already enrolled");
        }
        Ok(false) => {}
        Err(e) => {
            enroll_reject(&context, &format!("store error checking device: {e}"));
            return Response::json_error(500, "Internal error");
        }
    }
    let Some((code, code_hash)) = generate_pairing_code() else {
        return Response::json_error(500, "Internal error");
    };
    let expires_at = now + PAIRING_CODE_TTL_SECONDS;
    match store.pairing_create(&code_hash, &cert, &display_name, now, expires_at) {
        Ok(()) => Response::json(
            200,
            json!({
                "status": "pending",
                "code": code,
                "expires_at": expires_at,
                "member_pubkey": hex_encode(&member_pubkey),
                "device_pubkey": hex_encode(&device_pubkey),
            })
            .to_string(),
        ),
        Err(e) => {
            // The store verified the certificate before storing;
            // its rejection reason was logged by `identity`.
            enroll_reject(&context, &format!("pairing not created: {e}"));
            Response::json_error(400, "Device certificate rejected")
        }
    }
}

/// `POST /enroll/approve` — an approver completes a pairing.
/// Body (JSON): `code`, `timestamp`, `signature` (hex), plus
/// either the parent path (`approver_member_pubkey` +
/// `approver_device_pubkey`) or the recovery path
/// (`recovery_pubkey`). The signature is the approver's device
/// key (or the recovery key) over the enrollment approval
/// digest, binding the joining member key, device key, and
/// certificate hash at `timestamp` (see
/// `crate::identity::enrollment_approval_digest`). On success
/// the member + device are enrolled atomically and can use the
/// whole API immediately — one join lights up every feature.
fn handle_enroll_approve(state: &ApiState, request: &Request) -> Response {
    let now = now_epoch();
    let Some(body) = json_body(request) else {
        enroll_reject("approve", "body is not valid JSON");
        return Response::json_error(400, "Invalid JSON body");
    };
    let Some(code) = body.get("code").and_then(|v| v.as_str()) else {
        enroll_reject("approve", "missing pairing code");
        return Response::json_error(400, "Missing pairing code");
    };
    let code_hash = pairing_code_hash(code);
    let Some(timestamp) = body.get("timestamp").and_then(|v| v.as_u64()) else {
        enroll_reject("approve", "missing or invalid timestamp");
        return Response::json_error(400, "Missing or invalid timestamp");
    };
    let Some(signature) = body
        .get("signature")
        .and_then(|v| v.as_str())
        .and_then(hex_decode)
        .filter(|s| s.len() == 64)
    else {
        enroll_reject("approve", "missing or invalid signature");
        return Response::json_error(400, "Missing or invalid signature");
    };

    let store = state.store.lock().unwrap();
    let record = match store.pairing_get(&code_hash) {
        Ok(Some(r)) => r,
        Ok(None) => {
            enroll_reject("approve", "unknown pairing code");
            return Response::json_error(404, "Unknown pairing code");
        }
        Err(e) => {
            enroll_reject("approve", &format!("store error loading pairing: {e}"));
            return Response::json_error(500, "Internal error");
        }
    };
    let context = format!(
        "approve member={} device={}",
        hex_encode(&record.member_pubkey),
        hex_encode(&record.device_pubkey)
    );
    if record.status == "used" {
        enroll_reject(&context, "pairing code already used");
        return Response::json_error(400, "Pairing code already used");
    }
    if record.status == "expired" || now >= record.expires_at {
        if record.status == "pending" {
            let _ = store.pairing_mark_expired(&code_hash);
        }
        enroll_reject(&context, "pairing code expired");
        return Response::json_error(400, "Pairing code expired");
    }
    if timestamp > now.saturating_add(REQUEST_FUTURE_SKEW)
        || timestamp < now.saturating_sub(REQUEST_TIMESTAMP_WINDOW)
    {
        enroll_reject(
            &context,
            &format!("approval timestamp {timestamp} outside the window at {now}"),
        );
        return Response::json_error(400, "Approval timestamp outside window");
    }

    let parent = (
        json_hex_32(&body, "approver_member_pubkey"),
        json_hex_32(&body, "approver_device_pubkey"),
    );
    let recovery = json_hex_32(&body, "recovery_pubkey");
    let approval = match (parent, recovery) {
        ((Some(approver_member), Some(approver_device)), None) => {
            // The approver must be an enrolled, active member
            // standing behind a currently trusted device.
            if !store.user_exists(&approver_member) {
                enroll_reject(
                    &context,
                    &format!(
                        "approver member={} is not an enrolled member",
                        hex_encode(&approver_member)
                    ),
                );
                return Response::json_error(403, "Approver is not an enrolled member");
            }
            match store.device_get(&approver_member, &approver_device) {
                Ok(Some(entry))
                    if entry.status == crate::store::DeviceStatus::Revoked =>
                {
                    enroll_reject(
                        &context,
                        &format!(
                            "approver device={} is revoked",
                            hex_encode(&approver_device)
                        ),
                    );
                    return Response::json_error(403, "Approver device revoked");
                }
                Ok(_) => {}
                Err(e) => {
                    enroll_reject(&context, &format!("store error loading approver device: {e}"));
                    return Response::json_error(500, "Internal error");
                }
            }
            match store.device_is_trusted(&approver_member, &approver_device, now) {
                Ok(true) => {}
                Ok(false) => {
                    enroll_reject(
                        &context,
                        &format!(
                            "approver device={} is not a trusted device of the approver",
                            hex_encode(&approver_device)
                        ),
                    );
                    return Response::json_error(403, "Approver device not trusted");
                }
                Err(e) => {
                    enroll_reject(&context, &format!("store error checking approver device: {e}"));
                    return Response::json_error(500, "Internal error");
                }
            }
            if let Err(e) = crate::identity::verify_enrollment_approval(
                &approver_device,
                &record.member_pubkey,
                &record.device_pubkey,
                &record.cert_hash,
                timestamp,
                &signature,
            ) {
                enroll_reject(&context, &format!("approval signature rejected: {e}"));
                return Response::json_error(401, "Invalid approval signature");
            }
            crate::store::PairingApproval {
                approver_kind: "parent".to_string(),
                approver_member_pubkey: Some(approver_member),
                approver_device_pubkey: Some(approver_device),
                recovery_pubkey: None,
                approval_signature: signature,
                approval_timestamp: timestamp,
            }
        }
        ((None, None), Some(recovery_pubkey)) => {
            // The printed backup card: its key is a registered
            // approver in its own right, so a family that lost
            // every phone still gets back in.
            match store.recovery_approver_is_registered(&recovery_pubkey) {
                Ok(true) => {}
                Ok(false) => {
                    enroll_reject(
                        &context,
                        &format!(
                            "recovery key={} is not a registered recovery approver",
                            hex_encode(&recovery_pubkey)
                        ),
                    );
                    return Response::json_error(403, "Unknown recovery key");
                }
                Err(e) => {
                    enroll_reject(&context, &format!("store error checking recovery key: {e}"));
                    return Response::json_error(500, "Internal error");
                }
            }
            if let Err(e) = crate::identity::verify_enrollment_approval(
                &recovery_pubkey,
                &record.member_pubkey,
                &record.device_pubkey,
                &record.cert_hash,
                timestamp,
                &signature,
            ) {
                enroll_reject(&context, &format!("recovery approval signature rejected: {e}"));
                return Response::json_error(401, "Invalid approval signature");
            }
            crate::store::PairingApproval {
                approver_kind: "recovery".to_string(),
                approver_member_pubkey: None,
                approver_device_pubkey: None,
                recovery_pubkey: Some(recovery_pubkey),
                approval_signature: signature,
                approval_timestamp: timestamp,
            }
        }
        _ => {
            enroll_reject(
                &context,
                "body must carry exactly one approver: approver_member_pubkey + approver_device_pubkey, or recovery_pubkey",
            );
            return Response::json_error(
                400,
                "Provide approver keys or a recovery key",
            );
        }
    };

    match store.pairing_complete(&code_hash, &approval, now) {
        Ok(crate::store::PairingCompleteOutcome::Completed) => Response::json(
            200,
            json!({
                "status": "approved",
                "member_pubkey": hex_encode(&record.member_pubkey),
                "device_pubkey": hex_encode(&record.device_pubkey),
                "approver": approval.approver_kind,
            })
            .to_string(),
        ),
        Ok(crate::store::PairingCompleteOutcome::UnknownCode) => {
            enroll_reject(&context, "pairing vanished before completion");
            Response::json_error(404, "Unknown pairing code")
        }
        Ok(crate::store::PairingCompleteOutcome::AlreadyUsed) => {
            enroll_reject(&context, "pairing code already used");
            Response::json_error(400, "Pairing code already used")
        }
        Ok(crate::store::PairingCompleteOutcome::Expired) => {
            enroll_reject(&context, "pairing code expired");
            Response::json_error(400, "Pairing code expired")
        }
        Err(e) => {
            enroll_reject(&context, &format!("enrollment completion failed: {e}"));
            Response::json_error(400, "Enrollment could not be completed")
        }
    }
}

/// `GET /enroll/status?code=...` — the joining device polls
/// its pairing. The code is the capability: knowing it is what
/// the device proved by displaying it. Replies `pending`,
/// `approved`, `expired`, or `unknown`.
fn handle_enroll_status(state: &ApiState, request: &Request) -> Response {
    let Some(code) = request.query_var("code") else {
        return Response::json_error(400, "Missing code");
    };
    let code_hash = pairing_code_hash(&code);
    let now = now_epoch();
    let store = state.store.lock().unwrap();
    let record = match store.pairing_get(&code_hash) {
        Ok(r) => r,
        Err(e) => {
            enroll_reject("status", &format!("store error loading pairing: {e}"));
            return Response::json_error(500, "Internal error");
        }
    };
    let Some(mut record) = record else {
        return Response::json(200, "{\"status\":\"unknown\"}");
    };
    if record.status == "pending" && now >= record.expires_at {
        let _ = store.pairing_mark_expired(&code_hash);
        record.status = "expired".to_string();
    }
    let status = if record.status == "used" {
        "approved"
    } else {
        record.status.as_str()
    };
    Response::json(
        200,
        json!({
            "status": status,
            "member_pubkey": hex_encode(&record.member_pubkey),
            "device_pubkey": hex_encode(&record.device_pubkey),
            "expires_at": record.expires_at,
        })
        .to_string(),
    )
}

// -- groups & devices (Phase C1, DESIGN.md §5) ----------------------------

fn groups_reject(context: &str, reason: &str) {
    eprintln!("api groups: rejected {context}: {reason}");
}

fn devices_reject(context: &str, reason: &str) {
    eprintln!("api devices: rejected {context}: {reason}");
}

/// The JSON shape one group is reported in (create/list and the
/// membership-change replies): the record plus its current
/// member list from `conversation_members`.
fn group_json(store: &Store, record: &GroupRecord) -> serde_json::Value {
    let members = store
        .conversation_members(&record.group_id)
        .unwrap_or_default();
    json!({
        "group_id": hex_encode(&record.group_id),
        "name": record.name,
        "creator": hex_encode(&record.creator_pubkey),
        "created_at": record.created_at,
        "members": members.iter().map(|m| hex_encode(m)).collect::<Vec<_>>(),
    })
}

/// "Enrolled" for group purposes: a registered user with at
/// least one device on record. Enrollment (Phase B3) writes
/// both atomically, so a bare `users` row (a pre-enrollment
/// legacy registration) has no device and cannot take part in
/// group crypto.
fn is_enrolled(store: &Store, member: &[u8; PUBKEY_SIZE]) -> bool {
    store.user_exists(member)
        && store
            .device_list(member)
            .map(|devices| !devices.is_empty())
            .unwrap_or(false)
}

/// Fire the Phase B4 rotation trigger for one group after a
/// membership change. Retiring is the store half (see
/// [`Store::group_retire_sessions`]): every session the store
/// knows for the group is registered as retired — the submit
/// path refuses further messages under it — and senders' local
/// "own" rows are dropped, so each existing sender must call
/// the B4 `start_session`/`rotate_session` before sending
/// again. That fresh session's distribution is computed from
/// the *new* membership by the B4 machinery itself; here we run
/// [`crate::sessions::compute_distribution`] for each affected
/// sender so the change (and the device set it now covers) is
/// on the log. Returns how many sessions were retired.
fn trigger_group_rotation(store: &Store, group_id: &[u8], now: u64) -> usize {
    let senders = store.group_own_senders(group_id).unwrap_or_default();
    let members = store.conversation_members(group_id).unwrap_or_default();
    let retired = store
        .group_retire_sessions(group_id, now)
        .unwrap_or_default();
    if !retired.is_empty() {
        eprintln!(
            "api groups: membership change in group {} retired {} session(s); senders must rotate",
            hex_encode(group_id),
            retired.len()
        );
    }
    for (member, device) in &senders {
        if !members.contains(member) {
            continue; // a removed sender does not rotate back in
        }
        match crate::sessions::compute_distribution(store, group_id, member, device, now) {
            Ok(dist) => eprintln!(
                "api groups: rotation for group {}: sender {} starts a fresh session covering {} device(s), {} metadata parent(s)",
                hex_encode(group_id),
                hex_encode(member),
                dist.devices.len(),
                dist.metadata_parents.len()
            ),
            Err(e) => eprintln!(
                "api groups: rotation for group {}: distribution for sender {} failed: {e}",
                hex_encode(group_id),
                hex_encode(member)
            ),
        }
    }
    retired.len()
}

/// `POST /groups` — create a group conversation. Body (JSON):
/// `name` (optional) and `members` (optional array of member
/// pubkey hex). The creator is always a member. Only enrolled
/// members may be added; anyone else is refused and logged.
fn handle_create_group(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(body) = json_body(request) else {
        groups_reject("create", "body is not valid JSON");
        return Response::json_error(400, "Invalid JSON body");
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut members: Vec<[u8; PUBKEY_SIZE]> = vec![requester];
    if let Some(raw_members) = body.get("members") {
        let Some(raw_members) = raw_members.as_array() else {
            groups_reject("create", "members is not an array");
            return Response::json_error(400, "members must be an array");
        };
        for item in raw_members {
            let Some(hex) = item.as_str() else {
                groups_reject("create", "member entry is not a string");
                return Response::json_error(400, "Invalid member pubkey");
            };
            let Some(pk) = hex_decode_32(hex) else {
                groups_reject("create", &format!("invalid member pubkey {hex}"));
                return Response::json_error(400, "Invalid member pubkey");
            };
            if !members.contains(&pk) {
                members.push(pk);
            }
        }
    }
    let mut group_id = [0u8; crate::sessions::GROUP_ID_SIZE];
    if getrandom::getrandom(&mut group_id).is_err() {
        return Response::json_error(500, "Internal error");
    }
    let now = now_epoch();
    let store = state.store.lock().unwrap();
    for pk in &members {
        if *pk != requester && !is_enrolled(&store, pk) {
            groups_reject(
                "create",
                &format!("member {} is not enrolled", hex_encode(pk)),
            );
            return Response::json_error(
                403,
                &format!("Member not enrolled: {}", hex_encode(pk)),
            );
        }
    }
    if store
        .group_create(&group_id, &name, &requester, now)
        .is_err()
    {
        return Response::json_error(500, "Store error");
    }
    for pk in &members {
        if store.conversation_member_add(&group_id, pk, now).is_err() {
            return Response::json_error(500, "Store error");
        }
    }
    let record = match store.group_get(&group_id) {
        Ok(Some(record)) => record,
        _ => return Response::json_error(500, "Store error"),
    };
    Response::json(200, group_json(&store, &record).to_string())
}

/// `GET /groups` — the caller's groups, with member lists.
fn handle_list_groups(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let store = state.store.lock().unwrap();
    let groups = match store.groups_for_member(&requester) {
        Ok(g) => g,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    let list: Vec<serde_json::Value> =
        groups.iter().map(|g| group_json(&store, g)).collect();
    let count = list.len();
    Response::json(200, json!({ "groups": list, "count": count }).to_string())
}

fn parse_group_id(context: &str, group_id_hex: &str) -> Result<Vec<u8>, Response> {
    match hex_decode(group_id_hex) {
        Some(id) if id.len() == crate::sessions::GROUP_ID_SIZE => Ok(id),
        _ => {
            groups_reject(context, &format!("invalid group id {group_id_hex}"));
            Err(Response::json_error(400, "Invalid group id"))
        }
    }
}

/// `POST /groups/:id/members` — add a member. The caller must
/// already be a member; the target must be enrolled. Adding
/// fires the rotation trigger: existing senders start fresh
/// sessions whose shares cover the new full device set, and
/// the new member receives no shares for earlier sessions (so
/// pre-join messages stay unreadable to them).
fn handle_add_group_member(
    state: &ApiState,
    request: &Request,
    group_id_hex: &str,
) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let group_id = match parse_group_id("add member", group_id_hex) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let Some(body) = json_body(request) else {
        groups_reject("add member", "body is not valid JSON");
        return Response::json_error(400, "Invalid JSON body");
    };
    let Some(target) = json_hex_32(&body, "member_pubkey") else {
        groups_reject("add member", "missing or invalid member_pubkey");
        return Response::json_error(400, "Missing or invalid member_pubkey");
    };
    let now = now_epoch();
    let store = state.store.lock().unwrap();
    let Some(record) = (match store.group_get(&group_id) {
        Ok(r) => r,
        Err(_) => return Response::json_error(500, "Store error"),
    }) else {
        groups_reject(
            "add member",
            &format!("unknown group {}", hex_encode(&group_id)),
        );
        return Response::json_error(404, "Group not found");
    };
    let members = match store.conversation_members(&group_id) {
        Ok(m) => m,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    if !members.contains(&requester) {
        groups_reject(
            "add member",
            &format!(
                "caller {} is not a member of group {}",
                hex_encode(&requester),
                hex_encode(&group_id)
            ),
        );
        return Response::json_error(403, "Caller is not a group member");
    }
    if members.contains(&target) {
        let mut out = group_json(&store, &record);
        out["status"] = json!("already_member");
        return Response::json(200, out.to_string());
    }
    if !is_enrolled(&store, &target) {
        groups_reject(
            "add member",
            &format!("member {} is not enrolled", hex_encode(&target)),
        );
        return Response::json_error(
            403,
            &format!("Member not enrolled: {}", hex_encode(&target)),
        );
    }
    if store
        .conversation_member_add(&group_id, &target, now)
        .is_err()
    {
        return Response::json_error(500, "Store error");
    }
    let retired = trigger_group_rotation(&store, &group_id, now);
    let mut out = group_json(&store, &record);
    out["status"] = json!("added");
    out["retired_sessions"] = json!(retired);
    Response::json(200, out.to_string())
}

/// `DELETE /groups/:id/members/:pubkey` — remove a member
/// (the caller must be a member; a member may remove
/// themselves). Removal fires the same rotation trigger, so
/// the removed member's devices receive no shares for later
/// sessions and cannot read later messages.
fn handle_remove_group_member(
    state: &ApiState,
    request: &Request,
    group_id_hex: &str,
    member_hex: &str,
) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let group_id = match parse_group_id("remove member", group_id_hex) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let Some(target) = hex_decode_32(member_hex) else {
        groups_reject(
            "remove member",
            &format!("invalid member pubkey {member_hex}"),
        );
        return Response::json_error(400, "Invalid member pubkey");
    };
    let now = now_epoch();
    let store = state.store.lock().unwrap();
    let Some(record) = (match store.group_get(&group_id) {
        Ok(r) => r,
        Err(_) => return Response::json_error(500, "Store error"),
    }) else {
        groups_reject(
            "remove member",
            &format!("unknown group {}", hex_encode(&group_id)),
        );
        return Response::json_error(404, "Group not found");
    };
    let members = match store.conversation_members(&group_id) {
        Ok(m) => m,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    if !members.contains(&requester) {
        groups_reject(
            "remove member",
            &format!(
                "caller {} is not a member of group {}",
                hex_encode(&requester),
                hex_encode(&group_id)
            ),
        );
        return Response::json_error(403, "Caller is not a group member");
    }
    if !members.contains(&target) {
        groups_reject(
            "remove member",
            &format!(
                "member {} is not in group {}",
                hex_encode(&target),
                hex_encode(&group_id)
            ),
        );
        return Response::json_error(404, "Member not in group");
    }
    if store
        .conversation_member_remove(&group_id, &target)
        .is_err()
    {
        return Response::json_error(500, "Store error");
    }
    let retired = trigger_group_rotation(&store, &group_id, now);
    let mut out = group_json(&store, &record);
    out["status"] = json!("removed");
    out["retired_sessions"] = json!(retired);
    Response::json(200, out.to_string())
}

/// The JSON shape one device is reported in — shared by the
/// C1 per-member list and the C4 household overview.
fn device_json(d: &crate::store::DeviceEntry) -> serde_json::Value {
    json!({
        "device_pubkey": hex_encode(&d.device_pubkey),
        "label": d.label,
        "status": match d.status {
            DeviceStatus::Active => "active",
            DeviceStatus::Revoked => "revoked",
        },
        "issued_at": d.issued_at,
        "expires_at": d.expires_at,
        "revoked_at": d.revoked_at,
    })
}

/// `GET /devices?member=<pubkey>` — one member's devices
/// (label, status, issued/expires). The caller must be that
/// member or a recorded parent of them; anyone else is refused
/// and logged.
fn handle_list_devices(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(member) = query_pubkey(request, "member") else {
        devices_reject("list", "missing or invalid member query variable");
        return Response::json_error(400, "Missing member");
    };
    let store = state.store.lock().unwrap();
    let allowed = requester == member
        || store
            .parents_of(&member)
            .map(|parents| parents.contains(&requester))
            .unwrap_or(false);
    if !allowed {
        devices_reject(
            "list",
            &format!(
                "{} may not list devices of {} (not the member or a recorded parent)",
                hex_encode(&requester),
                hex_encode(&member)
            ),
        );
        return Response::json_error(403, "Forbidden");
    }
    let devices = match store.device_list(&member) {
        Ok(d) => d,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    let list: Vec<serde_json::Value> = devices.iter().map(device_json).collect();
    Response::json(
        200,
        json!({ "member": hex_encode(&member), "devices": list }).to_string(),
    )
}

/// `GET /household/devices` — the whole household's members
/// with their devices (Phase C4). Unlike `GET /devices`, which
/// answers only for the member or a recorded parent, this
/// overview answers for ANY enrolled member: device pubkeys,
/// labels and statuses are household directory data — the
/// member list is already visible to every member via
/// `GET /users`, and device certificates are gossiped signed
/// records. No key material or private data is exposed, and
/// revocation permissions are unchanged (member or recorded
/// parent only, `POST /devices/revoke`). Each member's
/// recorded parents ride along so a client can offer a revoke
/// action exactly where the node will allow one, instead of
/// guessing. Unauthenticated and not-enrolled requesters are
/// refused and logged.
fn handle_household_devices(state: &ApiState, request: &Request) -> Response {
    let store = state.store.lock().unwrap();
    let requester = match validate_request_auth(request, &store) {
        Ok(k) => k,
        Err(e) => {
            devices_reject(
                "household",
                &format!("unauthenticated overview request: {}", e.error_string()),
            );
            return Response::json_error(401, e.error_string());
        }
    };
    if !is_enrolled(&store, &requester) {
        devices_reject(
            "household",
            &format!(
                "{} is registered but not enrolled (no device on record)",
                hex_encode(&requester)
            ),
        );
        return Response::json_error(403, "Not enrolled");
    }
    // The same member listing as `GET /users` (active users,
    // by name); the users table stores the pubkey as hex text.
    let rows: Vec<(Option<String>, Option<String>)> = {
        let conn = store.connection();
        let mut stmt = match conn.prepare(
            "SELECT pubkey, username FROM users WHERE is_active = 1 ORDER BY username;",
        ) {
            Ok(s) => s,
            Err(_) => return Response::json_error(500, "Prepare error"),
        };
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        });
        match mapped {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => return Response::json_error(500, "DB error"),
        }
    };
    let mut members = Vec::new();
    for (pubkey_hex, username) in &rows {
        let Some(member) = pubkey_hex.as_deref().and_then(hex_decode_32) else {
            continue; // a row without a usable pubkey has no devices to show
        };
        let devices = match store.device_list(&member) {
            Ok(d) => d.iter().map(device_json).collect::<Vec<_>>(),
            Err(_) => return Response::json_error(500, "Store error"),
        };
        let parents = store
            .parents_of(&member)
            .map(|ps| ps.iter().map(|p| hex_encode(p)).collect::<Vec<_>>())
            .unwrap_or_default();
        members.push(json!({
            "member": hex_encode(&member),
            "username": username,
            "parents": parents,
            "devices": devices,
        }));
    }
    Response::json(200, json!({ "members": members }).to_string())
}

/// `POST /devices/revoke` — revoke one device. Two
/// authorizations, per Phase C1: the member themselves (the
/// request's TWREQUEST signature *is* the member key's), or a
/// recorded parent of the member signing with their *device
/// key* over the B2 revocation digest — body fields
/// `parent_member_pubkey`, `parent_device_pubkey`, `timestamp`
/// and `signature` (the parent's device key is not a `users`
/// key, so, exactly as in `/enroll/approve`, the authorization
/// rides in the body rather than the request headers). The
/// revocation itself is the B2 store operation; revoked
/// devices are excluded from future B4 distributions by the
/// distribution machinery's trust check.
fn handle_revoke_device(state: &ApiState, request: &Request) -> Response {
    let Some(body) = json_body(request) else {
        devices_reject("revoke", "body is not valid JSON");
        return Response::json_error(400, "Invalid JSON body");
    };
    let Some(member) = json_hex_32(&body, "member_pubkey") else {
        devices_reject("revoke", "missing or invalid member_pubkey");
        return Response::json_error(400, "Missing or invalid member_pubkey");
    };
    let Some(device) = json_hex_32(&body, "device_pubkey") else {
        devices_reject("revoke", "missing or invalid device_pubkey");
        return Response::json_error(400, "Missing or invalid device_pubkey");
    };
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = now_epoch();

    if body.get("parent_member_pubkey").is_some()
        || body.get("parent_device_pubkey").is_some()
    {
        // Parent mode: a recorded parent's trusted device key
        // signs the revocation digest for the child's device.
        let (Some(parent_member), Some(parent_device)) = (
            json_hex_32(&body, "parent_member_pubkey"),
            json_hex_32(&body, "parent_device_pubkey"),
        ) else {
            devices_reject("revoke", "incomplete parent authorization");
            return Response::json_error(400, "Incomplete parent authorization");
        };
        let Some(timestamp) = body.get("timestamp").and_then(|v| v.as_u64()) else {
            devices_reject("revoke", "parent authorization has no timestamp");
            return Response::json_error(400, "Missing timestamp");
        };
        let Some(signature) = body
            .get("signature")
            .and_then(|v| v.as_str())
            .and_then(hex_decode)
            .filter(|s| s.len() == 64)
        else {
            devices_reject("revoke", "parent authorization has no valid signature");
            return Response::json_error(400, "Missing or invalid signature");
        };
        let store = state.store.lock().unwrap();
        let is_parent = store
            .parents_of(&member)
            .map(|parents| parents.contains(&parent_member))
            .unwrap_or(false);
        if !is_parent {
            devices_reject(
                "revoke",
                &format!(
                    "{} is not a recorded parent of {}",
                    hex_encode(&parent_member),
                    hex_encode(&member)
                ),
            );
            return Response::json_error(403, "Not a recorded parent of the member");
        }
        match store.device_is_trusted(&parent_member, &parent_device, now) {
            Ok(true) => {}
            _ => {
                devices_reject(
                    "revoke",
                    &format!(
                        "parent device {} of {} is not trusted",
                        hex_encode(&parent_device),
                        hex_encode(&parent_member)
                    ),
                );
                return Response::json_error(403, "Parent device not trusted");
            }
        }
        if timestamp > now.saturating_add(REQUEST_FUTURE_SKEW)
            || timestamp < now.saturating_sub(REQUEST_TIMESTAMP_WINDOW)
        {
            devices_reject("revoke", "parent authorization timestamp out of window");
            return Response::json_error(403, "Authorization timestamp out of window");
        }
        let digest = crate::identity::device_revocation_digest(
            &member, &device, timestamp, &reason,
        );
        if !validation::verify_signature(&signature, &digest, &parent_device) {
            devices_reject(
                "revoke",
                &format!(
                    "parent device signature does not verify for member {} device {}",
                    hex_encode(&member),
                    hex_encode(&device)
                ),
            );
            return Response::json_error(403, "Invalid parent device signature");
        }
    } else {
        // Member mode: TWREQUEST auth, and the requester must
        // be the member whose device is being revoked.
        let requester = match authenticate(state, request) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if requester != member {
            devices_reject(
                "revoke",
                &format!(
                    "requester {} is not member {} and presented no parent authorization",
                    hex_encode(&requester),
                    hex_encode(&member)
                ),
            );
            return Response::json_error(403, "Forbidden");
        }
    }

    let store = state.store.lock().unwrap();
    match store.device_get(&member, &device) {
        Ok(Some(_)) => {}
        Ok(None) => {
            devices_reject(
                "revoke",
                &format!(
                    "unknown device {} for member {}",
                    hex_encode(&device),
                    hex_encode(&member)
                ),
            );
            return Response::json_error(404, "Device not found");
        }
        Err(_) => return Response::json_error(500, "Store error"),
    }
    let changed = match store.device_revoke(&member, &device, now) {
        Ok(c) => c,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    Response::json(
        200,
        json!({
            "status": if changed { "revoked" } else { "already_revoked" },
            "member_pubkey": hex_encode(&member),
            "device_pubkey": hex_encode(&device),
        })
        .to_string(),
    )
}


// -- content path (Phase C2, DESIGN.md §5) -------------------------------

fn content_reject(context: &str, reason: &str) {
    eprintln!("api content: rejected {context}: {reason}");
}

/// `POST /content/submit` — the generalized content path
/// (DESIGN.md §5): one signed `Envelope` submitted by an
/// enrolled member over TWREQUEST auth, stored in the same
/// envelope store the gossip pipeline maintains. Until Phase
/// C2 the only envelope a client could submit was a location
/// update, and group key shares (Phase B4) had no client path
/// at all — they could only be produced by code running
/// against the node's own store.
///
/// Accepted content types:
/// - 25 (`CONTENT_GROUP_KEY_SHARE`): the share's sender member
///   must be the requester, and the share must pass the same
///   verification gossip ingest applies
///   ([`crate::sessions::verify_share_envelope`]: share and
///   envelope signatures, both devices enrolled and currently
///   trusted). The share is also written to the share audit
///   table, as `sessions::start_session` does for node-local
///   senders.
/// - 35 (`CONTENT_CONVERSATION_METADATA`): the recipients-and-
///   times visibility record for a non-member parent. The
///   envelope sender must be the requester (the envelope is
///   signed by the sender's member key), the requester must be
///   a member of the envelope's group, and every recipient
///   must be a registered user. (The payload is encrypted to
///   the parent; the node checks headers only.)
/// - 162 (`CONTENT_CALENDAR_EVENT`): a calendar event version
///   (Phase C3), verified in full by
///   [`crate::events::verify_event_envelope`]; the requester
///   must be the record's acting member. The stored envelope
///   is folded into the events projection before replying.
/// Anything else is refused and logged — the typed endpoints
/// (messages, location) remain the path for their own types.
fn handle_content_submit(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if request.body.is_empty() {
        content_reject("submit", "empty body");
        return Response::json_error(400, "Empty body");
    }
    if request.body.len() > MAX_BODY_BYTES {
        content_reject("submit", "body too large");
        return Response::json_error(413, "Payload too large");
    }
    let envelope = match Envelope::decode(request.body.as_slice()) {
        Ok(e) => e,
        Err(_) => {
            content_reject("submit", "body is not a valid Envelope protobuf");
            return Response::json_error(400, "Invalid protobuf");
        }
    };
    if let Err(e) = validation::gossip_validate_envelope(
        &envelope,
        &state.validation_config,
        now_epoch(),
    ) {
        let result = Err(e);
        let reason = validation::gossip_validation_error_string(&result);
        content_reject("submit", &format!("envelope validation failed: {reason}"));
        return Response::json_error(400, reason);
    }
    let header = envelope.header.as_ref().expect("validated envelope has header");
    let content_type = header.content_type;
    let now = now_epoch();

    // Per-type authorization and content verification, under
    // one store lock; storage happens below on success.
    let mut event_submit: Option<CalendarEvent> = None;
    let share_audit: Option<(GroupKeyShare, [u8; PUBKEY_SIZE], [u8; PUBKEY_SIZE], [u8; PUBKEY_SIZE], [u8; PUBKEY_SIZE])> = {
        let store = state.store.lock().unwrap();
        match content_type {
            crate::sessions::CONTENT_GROUP_KEY_SHARE => {
                let share = match GroupKeyShare::decode(envelope.payload_ciphertext.as_slice()) {
                    Ok(s) => s,
                    Err(_) => {
                        content_reject("submit share", "payload does not decode as GroupKeyShare");
                        return Response::json_error(400, "Invalid share payload");
                    }
                };
                if share.sender_member_pubkey != requester.as_slice() {
                    content_reject(
                        "submit share",
                        &format!(
                            "share sender member {} is not the requester {}",
                            hex_encode(&share.sender_member_pubkey),
                            hex_encode(&requester)
                        ),
                    );
                    return Response::json_error(
                        403,
                        "Share sender must be the requesting member",
                    );
                }
                if let Err(e) = crate::sessions::verify_share_envelope(&store, &envelope, now) {
                    content_reject("submit share", &format!("share rejected: {e}"));
                    return Response::json_error(
                        403,
                        &format!("Group key share rejected: {e}"),
                    );
                }
                let mut sm = [0u8; PUBKEY_SIZE];
                sm.copy_from_slice(&share.sender_member_pubkey);
                let mut sd = [0u8; PUBKEY_SIZE];
                sd.copy_from_slice(&share.sender_device_pubkey);
                let mut rm = [0u8; PUBKEY_SIZE];
                rm.copy_from_slice(&share.recipient_member_pubkey);
                let mut rd = [0u8; PUBKEY_SIZE];
                rd.copy_from_slice(&share.recipient_device_pubkey);
                Some((share, sm, sd, rm, rd))
            }
            crate::sessions::CONTENT_CONVERSATION_METADATA => {
                if header.sender_pubkey != requester.as_slice() {
                    content_reject(
                        "submit metadata",
                        "envelope sender is not the requester",
                    );
                    return Response::json_error(
                        403,
                        "Metadata sender must be the requesting member",
                    );
                }
                // The metadata payload itself is encrypted to
                // the parent's member key, so the node cannot
                // (and must not) inspect it; the checks here are
                // the header-level ones: signed by the requester
                // (gossip validation above), requester is a
                // group member, recipients are registered users.
                let members = match store.conversation_members(&header.group_id) {
                    Ok(m) => m,
                    Err(_) => return Response::json_error(500, "Store error"),
                };
                if !members.contains(&requester) {
                    content_reject(
                        "submit metadata",
                        &format!(
                            "requester {} is not a member of group {}",
                            hex_encode(&requester),
                            hex_encode(&header.group_id)
                        ),
                    );
                    return Response::json_error(403, "Sender is not a group member");
                }
                for recipient in &header.recipients_pubkey {
                    let Ok(recipient_key) =
                        <[u8; PUBKEY_SIZE]>::try_from(recipient.as_slice())
                    else {
                        return Response::json_error(403, "Recipient not registered");
                    };
                    if !store.user_exists(&recipient_key) {
                        content_reject(
                            "submit metadata",
                            &format!("recipient {} is not registered", hex_encode(&recipient_key)),
                        );
                        return Response::json_error(403, "Recipient not registered");
                    }
                }
                None
            }
            crate::events::CONTENT_CALENDAR_EVENT => {
                // Calendar events (Phase C3): the record is
                // verified in full (signatures, actor
                // enrollment, creator/parent authorization,
                // version rule) by the events module. The
                // requester must be the acting member — the
                // member whose device signed the record.
                let event = match crate::events::verify_event_envelope(&store, &envelope, now) {
                    Ok(e) => e,
                    Err(e) => {
                        content_reject("submit event", &format!("event rejected: {e}"));
                        return Response::json_error(
                            403,
                            &format!("Calendar event rejected: {e}"),
                        );
                    }
                };
                if event.actor_member_pubkey != requester.as_slice() {
                    content_reject(
                        "submit event",
                        &format!(
                            "event actor member {} is not the requester {}",
                            hex_encode(&event.actor_member_pubkey),
                            hex_encode(&requester)
                        ),
                    );
                    return Response::json_error(
                        403,
                        "Event actor must be the requesting member",
                    );
                }
                event_submit = Some(event);
                None
            }
            other => {
                content_reject(
                    "submit",
                    &format!("content type {other} is not accepted on /content/submit"),
                );
                return Response::json_error(
                    400,
                    &format!("Content type {other} is not accepted here"),
                );
            }
        }
    };

    // Dedup + store, mirroring gossip ingest steps 3-4.
    let digest = crate::store::location_store_compute_digest_envelope(&envelope);
    let expires_at = match &event_submit {
        // Events are retained until their end + a grace
        // period (DESIGN.md §4.3), not on the chat TTL.
        Some(event) => crate::events::event_expires_at(
            event,
            validation::gossip_validation_expiration(&envelope, &state.validation_config),
        ),
        None => validation::gossip_validation_expiration(&envelope, &state.validation_config),
    };
    {
        let store = state.store.lock().unwrap();
        match store.gossip_store_has_seen(&digest) {
            Ok(true) => return Response::json(202, "{\"status\":\"duplicate\"}"),
            Ok(false) => {}
            Err(_) => return Response::json_error(500, "Internal error"),
        }
        if store.gossip_store_save_envelope(&envelope, expires_at).is_err() {
            return Response::json_error(500, "Storage failed");
        }
        let _ = store.gossip_store_mark_seen(&digest, expires_at);
        if let Some((share, sm, sd, rm, rd)) = &share_audit {
            let _ = store.share_record_insert(
                &share.session_id,
                &share.group_id,
                sm,
                sd,
                rm,
                rd,
                request.body.as_slice(),
            );
        }
        if event_submit.is_some() {
            // Fold the new version into the events projection
            // right away (the projection pass would catch it on
            // the next read regardless).
            let _ = store.events_project_pending();
        }
    }
    // Rebroadcast to peer nodes, as the message path does; the
    // outcome is identical from the client's view.
    if let Some(gossip) = &state.gossip {
        let service = gossip.lock().unwrap();
        let _ = service.broadcast_envelope(&envelope);
    }
    Response::json(202, "{\"status\":\"accepted\"}")
}

// -- events (Phase C3, DESIGN.md §5) -------------------------------

fn events_reject(context: &str, reason: &str) {
    eprintln!("api events: rejected {context}: {reason}");
}

fn event_json(event: &EventRecord) -> serde_json::Value {
    json!({
        "event_id": hex_encode(&event.event_id),
        "title": event.title,
        "notes": event.notes,
        "location": event.location,
        "start_unix": event.start_unix,
        "end_unix": event.end_unix,
        "timezone": event.timezone,
        "all_day": event.all_day,
        "rrule": event.rrule,
        "recurring": !event.rrule.is_empty(),
        "created_by": hex_encode(&event.created_by),
        "created_at": event.created_at,
        "updated_at": event.updated_at,
        "deleted": event.deleted,
    })
}

fn parse_event_id(context: &str, event_id_hex: &str) -> Result<Vec<u8>, Response> {
    match hex_decode(event_id_hex) {
        Some(id) if id.len() == crate::events::EVENT_ID_SIZE => Ok(id),
        _ => {
            events_reject(context, &format!("invalid event id {event_id_hex}"));
            Err(Response::json_error(400, "Invalid event id"))
        }
    }
}

fn decode_event_envelope(context: &str, request: &Request) -> Result<Envelope, Response> {
    if request.body.is_empty() {
        events_reject(context, "empty body");
        return Err(Response::json_error(400, "Empty body"));
    }
    if request.body.len() > MAX_BODY_BYTES {
        events_reject(context, "body too large");
        return Err(Response::json_error(413, "Payload too large"));
    }
    let envelope = match Envelope::decode(request.body.as_slice()) {
        Ok(e) => e,
        Err(_) => {
            events_reject(context, "body is not a valid Envelope protobuf");
            return Err(Response::json_error(400, "Invalid protobuf"));
        }
    };
    match envelope.header.as_ref() {
        Some(h) if h.content_type == crate::events::CONTENT_CALENDAR_EVENT => Ok(envelope),
        Some(h) => {
            events_reject(
                context,
                &format!("content type {} is not a calendar event", h.content_type),
            );
            Err(Response::json_error(400, "Not a calendar event envelope"))
        }
        None => {
            events_reject(context, "envelope has no header");
            Err(Response::json_error(400, "Invalid envelope"))
        }
    }
}

/// The shared event submission core behind `POST /events`,
/// `PUT|POST /events/:id`, `DELETE /events/:id` (and, in its
/// own flow, `/content/submit`): envelope validation, full
/// event verification (signatures, actor enrollment,
/// creator/parent authorization, version rule), dedup,
/// storage with event retention, projection, broadcast.
/// Returns the verified record and whether the envelope was
/// already held (a duplicate, not an error).
fn submit_event_envelope(
    state: &ApiState,
    requester: &[u8; PUBKEY_SIZE],
    envelope: &Envelope,
) -> Result<(CalendarEvent, bool), Response> {
    if let Err(e) = validation::gossip_validate_envelope(
        envelope,
        &state.validation_config,
        now_epoch(),
    ) {
        events_reject("submit", &format!("envelope validation failed: {e}"));
        return Err(Response::json_error(400, &e.to_string()));
    }
    let event = {
        let store = state.store.lock().unwrap();
        match crate::events::verify_event_envelope(&store, envelope, now_epoch()) {
            Ok(event) => event,
            Err(e) => {
                events_reject("submit", &format!("event rejected: {e}"));
                return Err(Response::json_error(
                    403,
                    &format!("Calendar event rejected: {e}"),
                ));
            }
        }
    };
    if event.actor_member_pubkey != requester.as_slice() {
        events_reject(
            "submit",
            &format!(
                "event actor member {} is not the requester {}",
                hex_encode(&event.actor_member_pubkey),
                hex_encode(requester)
            ),
        );
        return Err(Response::json_error(
            403,
            "Event actor must be the requesting member",
        ));
    }
    let digest = crate::store::location_store_compute_digest_envelope(envelope);
    let expires_at = crate::events::event_expires_at(
        &event,
        validation::gossip_validation_expiration(envelope, &state.validation_config),
    );
    let duplicate = {
        let store = state.store.lock().unwrap();
        match store.gossip_store_has_seen(&digest) {
            Ok(true) => true,
            Ok(false) => {
                if store.gossip_store_save_envelope(envelope, expires_at).is_err() {
                    return Err(Response::json_error(500, "Storage failed"));
                }
                let _ = store.gossip_store_mark_seen(&digest, expires_at);
                let _ = store.events_project_pending();
                false
            }
            Err(_) => return Err(Response::json_error(500, "Internal error")),
        }
    };
    if !duplicate {
        if let Some(gossip) = &state.gossip {
            let service = gossip.lock().unwrap();
            let _ = service.broadcast_envelope(envelope);
        }
    }
    Ok((event, duplicate))
}

fn event_submit_response(state: &ApiState, event: &CalendarEvent, duplicate: bool) -> Response {
    let record = {
        let store = state.store.lock().unwrap();
        store.event_get(&event.event_id)
    };
    let status = if duplicate { "duplicate" } else { "accepted" };
    match record {
        Ok(Some(rec)) => Response::json(
            202,
            json!({ "status": status, "event": event_json(&rec) }).to_string(),
        ),
        _ => Response::json(202, json!({ "status": status }).to_string()),
    }
}

/// `POST /events` — create an event (or issue any version of
/// it): the body is one signed `CONTENT_CALENDAR_EVENT`
/// envelope, exactly as on the generalized `/content/submit`
/// path. Replies 202 with the projected record.
fn handle_create_event(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let envelope = match decode_event_envelope("create", request) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match submit_event_envelope(state, &requester, &envelope) {
        Ok((event, duplicate)) => event_submit_response(state, &event, duplicate),
        Err(r) => r,
    }
}

/// `PUT|POST /events/:id` — issue a new version of one event;
/// the envelope in the body must name the same event id as
/// the path.
fn handle_update_event(state: &ApiState, request: &Request, event_id_hex: &str) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let event_id = match parse_event_id("update", event_id_hex) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let envelope = match decode_event_envelope("update", request) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match CalendarEvent::decode(envelope.payload_ciphertext.as_slice()) {
        Ok(event) if event.event_id == event_id => {}
        Ok(event) => {
            events_reject(
                "update",
                &format!(
                    "path event id {} does not match envelope event id {}",
                    event_id_hex,
                    hex_encode(&event.event_id)
                ),
            );
            return Response::json_error(400, "Event id mismatch");
        }
        Err(_) => {
            events_reject("update", "payload does not decode as CalendarEvent");
            return Response::json_error(400, "Invalid event payload");
        }
    }
    match submit_event_envelope(state, &requester, &envelope) {
        Ok((event, duplicate)) => event_submit_response(state, &event, duplicate),
        Err(r) => r,
    }
}

/// `DELETE /events/:id` — delete an event by issuing its
/// tombstone version. A deletion is a family fact, so it is
/// content, not a bare API call (DESIGN.md §5): the body must
/// carry the signed tombstone envelope (`deleted = true`) for
/// the event named in the path, signed by the creator's — or
/// a recorded parent of the creator's — device.
fn handle_delete_event(state: &ApiState, request: &Request, event_id_hex: &str) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let event_id = match parse_event_id("delete", event_id_hex) {
        Ok(id) => id,
        Err(r) => return r,
    };
    if request.body.is_empty() {
        events_reject(
            "delete",
            "DELETE requires the signed tombstone envelope in the body",
        );
        return Response::json_error(
            400,
            "DELETE requires the signed tombstone envelope in the body",
        );
    }
    let envelope = match decode_event_envelope("delete", request) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match CalendarEvent::decode(envelope.payload_ciphertext.as_slice()) {
        Ok(event) if event.event_id == event_id && event.deleted => {}
        Ok(event) if event.event_id == event_id => {
            events_reject("delete", "envelope is not a tombstone version (deleted = false)");
            return Response::json_error(400, "Not a tombstone version");
        }
        Ok(event) => {
            events_reject(
                "delete",
                &format!(
                    "path event id {} does not match envelope event id {}",
                    event_id_hex,
                    hex_encode(&event.event_id)
                ),
            );
            return Response::json_error(400, "Event id mismatch");
        }
        Err(_) => {
            events_reject("delete", "payload does not decode as CalendarEvent");
            return Response::json_error(400, "Invalid event payload");
        }
    }
    match submit_event_envelope(state, &requester, &envelope) {
        Ok((event, duplicate)) => event_submit_response(state, &event, duplicate),
        Err(r) => r,
    }
}

/// `GET /events/:id` — one event's currently held version
/// (including a tombstone; the record says `deleted`).
fn handle_get_event(state: &ApiState, request: &Request, event_id_hex: &str) -> Response {
    if let Err(r) = authenticate(state, request) {
        return r;
    }
    let event_id = match parse_event_id("get", event_id_hex) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let record = {
        let store = state.store.lock().unwrap();
        store.event_get(&event_id)
    };
    match record {
        Ok(Some(rec)) => Response::json(200, event_json(&rec).to_string()),
        Ok(None) => Response::json_error(404, "Event not found"),
        Err(_) => Response::json_error(500, "Store error"),
    }
}

fn query_i64(request: &Request, name: &str, default: i64) -> Result<i64, Response> {
    match request.query_var(name) {
        Some(v) => match v.parse::<i64>() {
            Ok(n) => Ok(n),
            Err(_) => {
                events_reject("list", &format!("invalid {name} query variable"));
                Err(Response::json_error(400, &format!("Invalid {name}")))
            }
        },
        None => Ok(default),
    }
}

/// `GET /events?from=<unix>&to=<unix>&include_deleted=1` —
/// the household calendar in a range: the newest version of
/// every event whose start falls in `[from, to)`, plus every
/// recurring series that started before `to` (occurrences are
/// not expanded in this phase; the RRULE rides along).
/// Tombstones are hidden unless `include_deleted=1`.
/// Defaults: from = 0, to = 2100-01-01 UTC.
fn handle_list_events(state: &ApiState, request: &Request) -> Response {
    if let Err(r) = authenticate(state, request) {
        return r;
    }
    let from = match query_i64(request, "from", 0) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let to = match query_i64(request, "to", 4_102_444_800) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let include_deleted = matches!(
        request.query_var("include_deleted").as_deref(),
        Some("1") | Some("true")
    );
    let records = {
        let store = state.store.lock().unwrap();
        store.events_list_range(from, to, include_deleted)
    };
    match records {
        Ok(records) => {
            let events: Vec<serde_json::Value> = records.iter().map(event_json).collect();
            let count = events.len();
            Response::json(
                200,
                json!({ "events": events, "count": count }).to_string(),
            )
        }
        Err(_) => Response::json_error(500, "Store error"),
    }
}

/// `GET /content/recent?for=<pubkey>&content_type=<n>&limit=<n>`
/// — the client half of the sync path (DESIGN.md §5): envelopes
/// from the gossip envelope store that were sent by, or
/// addressed to, the `for` key. `for` must be the requester's
/// own member key or one of the requester's devices — this is
/// how a device picks up the group key shares addressed to it
/// (content type 25, the default). Returns the serialized
/// envelopes as hex in a JSON body, newest first.
fn handle_content_recent(state: &ApiState, request: &Request) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(for_key) = query_pubkey(request, "for") else {
        content_reject("recent", "missing or invalid for query variable");
        return Response::json_error(400, "Missing or invalid for");
    };
    let content_type: u32 = match request.query_var("content_type") {
        Some(v) => match v.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                content_reject("recent", "invalid content_type query variable");
                return Response::json_error(400, "Invalid content_type");
            }
        },
        None => crate::sessions::CONTENT_GROUP_KEY_SHARE,
    };
    let limit = query_limit(request, 100);
    {
        let store = state.store.lock().unwrap();
        let allowed = for_key == requester
            || store
                .device_list(&requester)
                .map(|devices| devices.iter().any(|d| d.device_pubkey == for_key))
                .unwrap_or(false);
        if !allowed {
            content_reject(
                "recent",
                &format!(
                    "{} may not fetch content for {} (not the member or their device)",
                    hex_encode(&requester),
                    hex_encode(&for_key)
                ),
            );
            return Response::json_error(403, "Forbidden");
        }
    }
    let stored = {
        let store = state.store.lock().unwrap();
        match store.gossip_store_fetch_recent_envelopes_for_user(&for_key, 1000) {
            Ok(s) => s,
            Err(_) => return Response::json_error(500, "Store error"),
        }
    };
    let envelopes: Vec<serde_json::Value> = stored
        .iter()
        .filter(|s| s.content_type == content_type)
        .take(limit as usize)
        .map(|s| {
            json!({
                "content_type": s.content_type,
                "timestamp": s.timestamp,
                "envelope": hex_encode(&s.envelope),
            })
        })
        .collect();
    let count = envelopes.len();
    Response::json(
        200,
        json!({
            "for": hex_encode(&for_key),
            "content_type": content_type,
            "envelopes": envelopes,
            "count": count,
        })
        .to_string(),
    )
}

/// `GET /groups/:id/share-recipients?sender_device=<hex>` —
/// the B4 share distribution for one group, computed by the
/// node's own machinery ([`crate::sessions::compute_distribution`])
/// for the requesting member as sender: every trusted device of
/// every member (except the sender's own sending device), plus
/// the non-member parents the visibility rule treats as `full`
/// (their devices are in the list) and as `recipients_and_times`
/// (member keys only — they receive metadata records, never a
/// share). `GET /devices` deliberately answers only for the
/// caller or their children, so a group member had no way to
/// learn the other members' device keys; this endpoint answers
/// exactly the distribution question, and only for a member of
/// the group. Every refusal is logged.
fn handle_group_share_recipients(
    state: &ApiState,
    request: &Request,
    group_id_hex: &str,
) -> Response {
    let requester = match authenticate(state, request) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(group_id) = hex_decode(group_id_hex).filter(|g| g.len() == crate::sessions::GROUP_ID_SIZE)
    else {
        groups_reject("share-recipients", &format!("invalid group id {group_id_hex}"));
        return Response::json_error(400, "Invalid group id");
    };
    let sender_device: [u8; PUBKEY_SIZE] = match request.query_var("sender_device") {
        Some(v) => match hex_decode_32(&v) {
            Some(d) => d,
            None => {
                groups_reject("share-recipients", "invalid sender_device query variable");
                return Response::json_error(400, "Invalid sender_device");
            }
        },
        None => [0u8; PUBKEY_SIZE],
    };
    let now = now_epoch();
    let store = state.store.lock().unwrap();
    match store.group_get(&group_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            groups_reject(
                "share-recipients",
                &format!("unknown group {}", hex_encode(&group_id)),
            );
            return Response::json_error(404, "Group not found");
        }
        Err(_) => return Response::json_error(500, "Store error"),
    }
    let members = match store.conversation_members(&group_id) {
        Ok(m) => m,
        Err(_) => return Response::json_error(500, "Store error"),
    };
    if !members.contains(&requester) {
        groups_reject(
            "share-recipients",
            &format!(
                "requester {} is not a member of group {}",
                hex_encode(&requester),
                hex_encode(&group_id)
            ),
        );
        return Response::json_error(403, "Not a group member");
    }
    if sender_device != [0u8; PUBKEY_SIZE] {
        let owns = store
            .device_list(&requester)
            .map(|devices| devices.iter().any(|d| d.device_pubkey == sender_device))
            .unwrap_or(false);
        if !owns {
            groups_reject(
                "share-recipients",
                &format!(
                    "sender_device {} is not a device of requester {}",
                    hex_encode(&sender_device),
                    hex_encode(&requester)
                ),
            );
            return Response::json_error(403, "sender_device is not the requester's device");
        }
    }
    let distribution = match crate::sessions::compute_distribution(
        &store,
        &group_id,
        &requester,
        &sender_device,
        now,
    ) {
        Ok(d) => d,
        Err(e) => {
            groups_reject(
                "share-recipients",
                &format!("distribution failed for group {}: {e}", hex_encode(&group_id)),
            );
            return Response::json_error(500, "Distribution failed");
        }
    };
    let devices: Vec<serde_json::Value> = distribution
        .devices
        .iter()
        .map(|(member, device)| {
            json!({
                "member_pubkey": hex_encode(member),
                "device_pubkey": hex_encode(device),
            })
        })
        .collect();
    Response::json(
        200,
        json!({
            "group_id": hex_encode(&group_id),
            "devices": devices,
            "metadata_parents": distribution
                .metadata_parents
                .iter()
                .map(|p| hex_encode(p))
                .collect::<Vec<_>>(),
            "full_parents": distribution
                .full_parents
                .iter()
                .map(|p| hex_encode(p))
                .collect::<Vec<_>>(),
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_state() -> (ApiState, [u8; 32], SigningKey) {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        // Register the test user (users.pubkey is hex text in the DB).
        store
            .connection()
            .execute(
                "INSERT INTO users (pubkey, username, is_active) VALUES (?1, 'alice', 1)",
                rusqlite::params![hex_encode(&pubkey)],
            )
            .unwrap();
        let state = ApiState::new(
            Arc::new(Mutex::new(store)),
            None,
            GossipValidationConfig {
                max_clock_skew_seconds: 300,
                message_ttl_seconds: 30 * 24 * 60 * 60,
                max_payload_bytes: 1024 * 1024,
            },
        );
        (state, pubkey, signing)
    }

    fn signed_request(
        signing: &SigningKey,
        pubkey: &[u8; 32],
        method: &str,
        path: &str,
        query: &str,
        timestamp: u64,
    ) -> Request {
        let digest = compute_request_digest(
            method,
            path,
            query,
            &timestamp.to_string(),
            pubkey,
        );
        let signature = signing.sign(&digest).to_bytes();
        let mut headers = HashMap::new();
        headers.insert("x-user-pubkey".to_string(), hex_encode(pubkey));
        headers.insert("x-signature".to_string(), hex_encode(&signature));
        headers.insert("x-timestamp".to_string(), timestamp.to_string());
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    fn bare_request(method: &str, path: &str) -> Request {
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn request_digest_matches_manual_sha256() {
        // Independent recomputation of the C digest layout.
        let pubkey = [3u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"TWREQUEST\0");
        hasher.update(b"GET");
        hasher.update(b"/messages/recent");
        hasher.update(b"user=ab");
        hasher.update(b"1700000000");
        hasher.update(pubkey);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            compute_request_digest(
                "GET",
                "/messages/recent",
                "user=ab",
                "1700000000",
                &pubkey
            ),
            expected
        );
    }

    #[test]
    fn valid_signed_request_accepted() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let req = signed_request(
            &signing,
            &pubkey,
            "GET",
            "/messages/recent",
            &format!("user={}", hex_encode(&pubkey)),
            now,
        );
        let store = state.store.lock().unwrap();
        assert_eq!(validate_request_auth_at(&req, &store, now), Ok(pubkey));
    }

    #[test]
    fn stale_and_future_timestamps_rejected() {
        let (state, pubkey, signing) = test_state();
        let now = 1_700_000_000u64;
        let store = state.store.lock().unwrap();
        let stale = signed_request(&signing, &pubkey, "GET", "/health", "", now - 301);
        assert_eq!(
            validate_request_auth_at(&stale, &store, now),
            Err(RequestAuthResult::ExpiredTimestamp)
        );
        // Boundary: exactly 300s old is still inside the window.
        let edge = signed_request(&signing, &pubkey, "GET", "/health", "", now - 300);
        assert_eq!(validate_request_auth_at(&edge, &store, now), Ok(pubkey));
        let future = signed_request(&signing, &pubkey, "GET", "/health", "", now + 61);
        assert_eq!(
            validate_request_auth_at(&future, &store, now),
            Err(RequestAuthResult::FutureTimestamp)
        );
    }

    #[test]
    fn tampered_signature_and_wrong_path_rejected() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let store = state.store.lock().unwrap();
        // Signed for one path, presented for another.
        let mut req = signed_request(&signing, &pubkey, "GET", "/messages/recent", "", now);
        req.path = "/messages/conversations".to_string();
        assert_eq!(
            validate_request_auth_at(&req, &store, now),
            Err(RequestAuthResult::InvalidSignature)
        );
        // Query is part of the digest too.
        let mut req = signed_request(&signing, &pubkey, "GET", "/messages/recent", "user=aa", now);
        req.query = "user=bb".to_string();
        assert_eq!(
            validate_request_auth_at(&req, &store, now),
            Err(RequestAuthResult::InvalidSignature)
        );
    }

    #[test]
    fn missing_headers_and_unregistered_user_rejected() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let store = state.store.lock().unwrap();
        let bare = bare_request("GET", "/messages/recent");
        assert_eq!(
            validate_request_auth_at(&bare, &store, now),
            Err(RequestAuthResult::MissingPubkey)
        );
        let mut no_sig = signed_request(&signing, &pubkey, "GET", "/x", "", now);
        no_sig.headers.remove("x-signature");
        assert_eq!(
            validate_request_auth_at(&no_sig, &store, now),
            Err(RequestAuthResult::MissingSignature)
        );
        let mut bad_pk = signed_request(&signing, &pubkey, "GET", "/x", "", now);
        bad_pk
            .headers
            .insert("x-user-pubkey".to_string(), "zzzz".to_string());
        assert_eq!(
            validate_request_auth_at(&bad_pk, &store, now),
            Err(RequestAuthResult::InvalidPubkey)
        );
        // A correctly self-signed request from an unknown key.
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let stranger_pk = stranger.verifying_key().to_bytes();
        let req = signed_request(&stranger, &stranger_pk, "GET", "/x", "", now);
        assert_eq!(
            validate_request_auth_at(&req, &store, now),
            Err(RequestAuthResult::UserNotRegistered)
        );
    }

    #[test]
    fn route_matching_matches_c_dispatch() {
        assert_eq!(route("/messages/submit"), Route::SubmitMessage);
        assert_eq!(route("/messages/recent"), Route::RecentMessages);
        assert_eq!(route("/messages/conversations"), Route::Conversations);
        assert_eq!(route("/messages/conversation"), Route::Conversation);
        assert_eq!(route("/location/update"), Route::LocationUpdate);
        assert_eq!(route("/gossip/peers"), Route::GossipPeers);
        assert_eq!(route("/health"), Route::Health);
        assert_eq!(route("/gossip/message"), Route::GossipMessage);
        assert_eq!(route("/auth/login"), Route::Login);
        assert_eq!(route("/users"), Route::Users);
        let id = "ab".repeat(32);
        assert_eq!(
            route(&format!("/location/{id}")),
            Route::Location { user_id: id.clone() }
        );
        assert_eq!(
            route(&format!("/location/history/{id}")),
            Route::LocationHistory { user_id: id }
        );
        // History must not fall through to the plain location route.
        assert_ne!(
            route("/location/history/aa"),
            Route::Location {
                user_id: "history".to_string()
            }
        );
        assert_eq!(route("/nope"), Route::NotFound);
        assert_eq!(route("/location/"), Route::NotFound);
        assert_eq!(route("/messages/submit/"), Route::NotFound);
    }

    #[test]
    fn health_peers_404_and_options_without_live_node() {
        let (state, _pubkey, _signing) = test_state();
        let health = handle_request(&state, &bare_request("GET", "/health"));
        assert_eq!(health.status, 200);
        assert_eq!(
            String::from_utf8(health.body).unwrap(),
            "{\"status\":\"healthy\",\"service\":\"tinyweb\"}"
        );
        let peers = handle_request(&state, &bare_request("GET", "/gossip/peers"));
        assert_eq!(peers.status, 200);
        let v: serde_json::Value =
            serde_json::from_slice(&peers.body).unwrap();
        assert_eq!(v["count"], 0);
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);

        let missing = handle_request(&state, &bare_request("GET", "/nope"));
        assert_eq!(missing.status, 404);

        let wrong_method = handle_request(&state, &bare_request("POST", "/health"));
        assert_eq!(wrong_method.status, 405);

        let submit_get = handle_request(&state, &bare_request("GET", "/messages/submit"));
        assert_eq!(submit_get.status, 405);
        assert_eq!(String::from_utf8(submit_get.body).unwrap(), "Method Not Allowed");

        // Global preflight: POST-only and GET-only method sets.
        let pre = handle_request(&state, &bare_request("OPTIONS", "/messages/submit"));
        assert_eq!(pre.status, 200);
        assert!(pre.body.is_empty());
        let methods = &pre
            .extra_headers
            .iter()
            .find(|(n, _)| n == "Access-Control-Allow-Methods")
            .unwrap()
            .1;
        assert_eq!(methods, "POST, OPTIONS");
        let pre = handle_request(&state, &bare_request("OPTIONS", "/location/abcd"));
        let methods = &pre
            .extra_headers
            .iter()
            .find(|(n, _)| n == "Access-Control-Allow-Methods")
            .unwrap()
            .1;
        assert_eq!(methods, "GET, OPTIONS");
    }

    #[test]
    fn unauthenticated_protected_route_is_401() {
        let (state, _pubkey, _signing) = test_state();
        let resp = handle_request(&state, &bare_request("GET", "/messages/recent"));
        assert_eq!(resp.status, 401);
        assert_eq!(
            String::from_utf8(resp.body).unwrap(),
            "{\"error\":\"Missing X-User-Pubkey header\"}"
        );
    }

    #[test]
    fn authenticated_recent_and_login_round_trip() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let query = format!("user={}", hex_encode(&pubkey));
        let req = signed_request(&signing, &pubkey, "GET", "/messages/recent", &query, now);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/x-protobuf")
        );
        let list = MessageList::decode(resp.body.as_slice()).unwrap();
        assert_eq!(list.total_count, 0);

        let req = signed_request(&signing, &pubkey, "POST", "/auth/login", "", now);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["pubkey"], hex_encode(&pubkey));
    }

    #[test]
    fn client_request_conversion_copies_fields() {
        let req = ClientRequest {
            header: Some(crate::proto::ClientRequestHeader {
                version: 1,
                content_type: 33,
                schema_version: 1,
                timestamp: 42,
                sender_pubkey: vec![1u8; 32],
                recipients_pubkey: vec![vec![2u8; 32]],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![3u8; 24],
            ephemeral_pubkey: vec![4u8; 32],
            payload_ciphertext: b"cipher".to_vec(),
            keywraps: vec![crate::proto::ClientRequestKeyWrap {
                recipient_pubkey: vec![2u8; 32],
                key_nonce: vec![5u8; 24],
                wrapped_key: vec![6u8; 48],
            }],
            signature: vec![7u8; 64],
        };
        let env = client_request_to_envelope(&req).unwrap();
        assert_eq!(env.header.as_ref().unwrap().content_type, 33);
        assert_eq!(env.payload_ciphertext, b"cipher".to_vec());
        assert_eq!(env.keywraps.len(), 1);
        assert!(envelope_recipients_have_keywraps(&env));
        // A bad nonce length is rejected, as in C.
        let mut bad = req.clone();
        bad.payload_nonce = vec![0u8; 3];
        assert!(client_request_to_envelope(&bad).is_none());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build a location-update envelope (content type 33, self as
    /// sole recipient, dummy ciphertext — the node never decrypts).
    /// With `client_request_digest` the signature is computed over
    /// the C-era client-request digest instead of the envelope
    /// digest; everything else is identical.
    fn build_location_envelope(
        signing: &SigningKey,
        pubkey: &[u8; 32],
        timestamp: u64,
        client_request_digest: bool,
    ) -> Envelope {
        let mut env = Envelope {
            header: Some(crate::proto::EnvelopeHeader {
                version: 1,
                content_type: 33,
                schema_version: 1,
                timestamp,
                sender_pubkey: pubkey.to_vec(),
                recipients_pubkey: vec![pubkey.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![9u8; 24],
            ephemeral_pubkey: vec![8u8; 32],
            payload_ciphertext: b"location-ciphertext".to_vec(),
            keywraps: vec![crate::proto::RecipientKeyWrap {
                recipient_pubkey: pubkey.to_vec(),
                key_nonce: vec![7u8; 24],
                wrapped_key: vec![6u8; 48],
            }],
            signature: Vec::new(),
        };
        let digest = if client_request_digest {
            let req = ClientRequest {
                header: Some(crate::proto::ClientRequestHeader {
                    version: 1,
                    content_type: 33,
                    schema_version: 1,
                    timestamp,
                    sender_pubkey: pubkey.to_vec(),
                    recipients_pubkey: vec![pubkey.to_vec()],
                    group_id: Vec::new(),
                }),
                payload_nonce: env.payload_nonce.clone(),
                ephemeral_pubkey: env.ephemeral_pubkey.clone(),
                payload_ciphertext: env.payload_ciphertext.clone(),
                keywraps: vec![crate::proto::ClientRequestKeyWrap {
                    recipient_pubkey: pubkey.to_vec(),
                    key_nonce: vec![7u8; 24],
                    wrapped_key: vec![6u8; 48],
                }],
                signature: Vec::new(),
            };
            validation::compute_client_request_signing_digest(&req).unwrap()
        } else {
            validation::compute_envelope_signing_digest(&env).unwrap()
        };
        env.signature = signing.sign(&digest).to_bytes().to_vec();
        env
    }

    /// Regression test (Nov 14): a location update submitted through
    /// the API layer, signed over the envelope digest as the wire
    /// contract requires, is accepted and reads back through the
    /// latest + history endpoints.
    #[test]
    fn location_update_round_trip_through_api() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let env = build_location_envelope(&signing, &pubkey, now, false);
        let mut req = signed_request(&signing, &pubkey, "POST", "/location/update", "", now);
        req.body = env.encode_to_vec();
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 202,
            "submit body: {}",
            String::from_utf8_lossy(&resp.body)
        );

        let path = format!("/location/{}", hex_encode(&pubkey));
        let req = signed_request(&signing, &pubkey, "GET", &path, "", now);
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 200,
            "latest body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["is_envelope"], true);
        let stored = Envelope::decode(unhex(v["data_hex"].as_str().unwrap()).as_slice()).unwrap();
        assert_eq!(stored.payload_ciphertext, env.payload_ciphertext);
        assert_eq!(stored.header.unwrap().content_type, 33);

        let path = format!("/location/history/{}", hex_encode(&pubkey));
        let req = signed_request(&signing, &pubkey, "GET", &path, "", now);
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 200,
            "history body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["updates"][0]["is_envelope"], true);
    }

    /// Regression test (Nov 14): the exact failure the test page hit —
    /// a location submission signed over the client-request digest
    /// (TWCLIENTREQ, the C web-ui's scheme) instead of the envelope
    /// digest (TWENVELOPE) is rejected with "invalid signature". The
    /// wire layouts are identical, so this pins the signing domain
    /// as the contract.
    #[test]
    fn location_update_signed_as_client_request_is_rejected() {
        let (state, pubkey, signing) = test_state();
        let now = now_epoch();
        let env = build_location_envelope(&signing, &pubkey, now, true);
        let mut req = signed_request(&signing, &pubkey, "POST", "/location/update", "", now);
        req.body = env.encode_to_vec();
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 400);
        assert!(
            String::from_utf8(resp.body)
                .unwrap()
                .contains("invalid signature")
        );
    }

    // -- enrollment (Phase B3) -----------------------------------

    /// A member + device identity with its member-signed device
    /// certificate, built the way a joining phone builds it:
    /// keys generated locally, certificate signed by the member
    /// key, private keys never leaving the "device".
    struct TestIdentity {
        member: SigningKey,
        device: SigningKey,
        member_pk: [u8; 32],
        device_pk: [u8; 32],
        cert: DeviceCertificate,
    }

    fn make_identity(member_seed: u8, device_seed: u8, label: &str, issued_at: u64) -> TestIdentity {
        let member = SigningKey::from_bytes(&[member_seed; 32]);
        let device = SigningKey::from_bytes(&[device_seed; 32]);
        let member_pk = member.verifying_key().to_bytes();
        let device_pk = device.verifying_key().to_bytes();
        let mut ks = crate::keystore::Keystore::new();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&member.to_bytes());
        secret[32..].copy_from_slice(&member_pk);
        ks.load_raw_ed25519_keypair(&secret).unwrap();
        let cert =
            crate::identity::create_device_certificate(&ks, &device_pk, label, issued_at, 0)
                .unwrap();
        TestIdentity {
            member,
            device,
            member_pk,
            device_pk,
            cert,
        }
    }

    fn empty_state() -> ApiState {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        ApiState::new(
            Arc::new(Mutex::new(store)),
            None,
            GossipValidationConfig {
                max_clock_skew_seconds: 300,
                message_ttl_seconds: 30 * 24 * 60 * 60,
                max_payload_bytes: 1024 * 1024,
            },
        )
    }

    /// The founding household at the store level (what the
    /// `bootstrap-founder` CLI writes): founder member + device
    /// enrolled, recovery key registered as an approver.
    fn seed_founder(state: &ApiState, founder: &TestIdentity, recovery_pk: &[u8; 32], now: u64) {
        let store = state.store.lock().unwrap();
        store.user_register(&founder.member_pk, "Founder").unwrap();
        store.device_add(&founder.cert, now).unwrap();
        store
            .recovery_approver_add(recovery_pk, "backup card", now)
            .unwrap();
    }

    fn enroll_begin(state: &ApiState, id: &TestIdentity, name: &str) -> (u16, serde_json::Value) {
        let mut req = bare_request("POST", "/enroll/begin");
        req.body = json!({
            "member_pubkey": hex_encode(&id.member_pk),
            "device_pubkey": hex_encode(&id.device_pk),
            "display_name": name,
            "device_cert": hex_encode(&id.cert.encode_to_vec()),
        })
        .to_string()
        .into_bytes();
        let resp = handle_request(state, &req);
        let value: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
        (resp.status, value)
    }

    fn enroll_status(state: &ApiState, code: &str) -> String {
        let mut req = bare_request("GET", "/enroll/status");
        req.query = format!("code={code}");
        let resp = handle_request(state, &req);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        v["status"].as_str().unwrap().to_string()
    }

    fn approve_with_body(state: &ApiState, body: serde_json::Value) -> Response {
        let mut req = bare_request("POST", "/enroll/approve");
        req.body = body.to_string().into_bytes();
        handle_request(state, &req)
    }

    /// A parent approval: the approver's device key signs the
    /// enrollment approval digest for `target`'s certificate.
    fn approve_as_parent(
        state: &ApiState,
        code: &str,
        approver: &TestIdentity,
        target: &TestIdentity,
        timestamp: u64,
    ) -> Response {
        let cert_hash: [u8; 32] = Sha256::digest(target.cert.encode_to_vec()).into();
        let digest = crate::identity::enrollment_approval_digest(
            &target.member_pk,
            &target.device_pk,
            &cert_hash,
            timestamp,
        );
        let signature = approver.device.sign(&digest).to_bytes();
        approve_with_body(
            state,
            json!({
                "code": code,
                "timestamp": timestamp,
                "signature": hex_encode(&signature),
                "approver_member_pubkey": hex_encode(&approver.member_pk),
                "approver_device_pubkey": hex_encode(&approver.device_pk),
            }),
        )
    }

    /// A recovery approval: the backup-card key signs the same
    /// digest (what the other parent being unreachable looks
    /// like — and also how a replacement member gets in).
    fn approve_as_recovery(
        state: &ApiState,
        code: &str,
        recovery: &SigningKey,
        target: &TestIdentity,
        timestamp: u64,
    ) -> Response {
        let cert_hash: [u8; 32] = Sha256::digest(target.cert.encode_to_vec()).into();
        let digest = crate::identity::enrollment_approval_digest(
            &target.member_pk,
            &target.device_pk,
            &cert_hash,
            timestamp,
        );
        let signature = recovery.sign(&digest).to_bytes();
        approve_with_body(
            state,
            json!({
                "code": code,
                "timestamp": timestamp,
                "signature": hex_encode(&signature),
                "recovery_pubkey": hex_encode(&recovery.verifying_key().to_bytes()),
            }),
        )
    }

    fn founder_and_state() -> (ApiState, TestIdentity, SigningKey) {
        let now = now_epoch();
        let state = empty_state();
        let founder = make_identity(11, 12, "phone", now);
        let recovery = SigningKey::from_bytes(&[99u8; 32]);
        seed_founder(
            &state,
            &founder,
            &recovery.verifying_key().to_bytes(),
            now,
        );
        (state, founder, recovery)
    }

    #[test]
    fn enroll_happy_path_new_member_can_immediately_use_the_api() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);

        let (status, begin) = enroll_begin(&state, &newcomer, "New Member");
        assert_eq!(status, 200, "begin body: {begin}");
        assert_eq!(begin["status"], "pending");
        let code = begin["code"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 32);
        assert_eq!(enroll_status(&state, &code), "pending");
        // Not enrolled yet: signed API calls still fail auth.
        let req = signed_request(
            &newcomer.member,
            &newcomer.member_pk,
            "GET",
            "/users",
            "",
            now_epoch(),
        );
        assert_eq!(handle_request(&state, &req).status, 401);

        let resp = approve_as_parent(&state, &code, &founder, &newcomer, now_epoch());
        assert_eq!(
            resp.status, 200,
            "approve body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "approved");
        assert_eq!(v["approver"], "parent");
        assert_eq!(enroll_status(&state, &code), "approved");

        // The audit record carries the approval binding.
        {
            let store = state.store.lock().unwrap();
            let enrollments = store
                .enrollments_for_member(&newcomer.member_pk)
                .unwrap();
            assert_eq!(enrollments.len(), 1);
            assert_eq!(enrollments[0].approver_kind, "parent");
            assert_eq!(
                enrollments[0].approver_member_pubkey,
                Some(founder.member_pk)
            );
            assert_eq!(
                enrollments[0].approver_device_pubkey,
                Some(founder.device_pk)
            );
            assert_eq!(enrollments[0].approval_signature.len(), 64);
            assert!(store
                .device_is_trusted(&newcomer.member_pk, &newcomer.device_pk, now_epoch())
                .unwrap());
        }

        // One join, everything works: user list...
        let req = signed_request(
            &newcomer.member,
            &newcomer.member_pk,
            "GET",
            "/users",
            "",
            now_epoch(),
        );
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 200);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("New Member"));

        // ...message submit...
        let mut msg = Message {
            header: Some(crate::proto::MessageHeader {
                version: 1,
                timestamp: now_epoch(),
                sender_pubkey: newcomer.member_pk.to_vec(),
                recipients_pubkey: vec![newcomer.member_pk.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![9u8; 24],
            ephemeral_pubkey: vec![8u8; 32],
            payload_ciphertext: b"hello from the new member".to_vec(),
            keywraps: Vec::new(),
            signature: Vec::new(),
            session_id: Vec::new(),
            message_index: 0,
        };
        let digest = validation::compute_message_signing_digest(&msg).unwrap();
        msg.signature = newcomer.member.sign(&digest).to_bytes().to_vec();
        let mut req = signed_request(
            &newcomer.member,
            &newcomer.member_pk,
            "POST",
            "/messages/submit",
            "",
            now_epoch(),
        );
        req.body = msg.encode_to_vec();
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 202,
            "submit body: {}",
            String::from_utf8_lossy(&resp.body)
        );

        // ...and location.
        let env = build_location_envelope(
            &newcomer.member,
            &newcomer.member_pk,
            now_epoch(),
            false,
        );
        let mut req = signed_request(
            &newcomer.member,
            &newcomer.member_pk,
            "POST",
            "/location/update",
            "",
            now_epoch(),
        );
        req.body = env.encode_to_vec();
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 202,
            "location body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let path = format!("/location/{}", hex_encode(&newcomer.member_pk));
        let req = signed_request(
            &newcomer.member,
            &newcomer.member_pk,
            "GET",
            &path,
            "",
            now_epoch(),
        );
        assert_eq!(handle_request(&state, &req).status, 200);
    }

    #[test]
    fn enroll_new_device_for_existing_member() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let member = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &member, "Member");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        let resp = approve_as_parent(&state, &code, &founder, &member, now_epoch());
        assert_eq!(resp.status, 200);

        // Same member key, second device (new cert), same flow.
        let second = make_identity(21, 23, "tablet", now_epoch());
        assert_eq!(second.member_pk, member.member_pk);
        assert_ne!(second.device_pk, member.device_pk);
        let (status, begin) = enroll_begin(&state, &second, "Member");
        assert_eq!(status, 200, "begin body: {begin}");
        let code = begin["code"].as_str().unwrap().to_string();
        let resp = approve_as_parent(&state, &code, &founder, &second, now_epoch());
        assert_eq!(
            resp.status, 200,
            "approve body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let store = state.store.lock().unwrap();
        assert!(store
            .device_is_trusted(&member.member_pk, &member.device_pk, now_epoch())
            .unwrap());
        assert!(store
            .device_is_trusted(&second.member_pk, &second.device_pk, now_epoch())
            .unwrap());
        assert_eq!(store.device_list(&member.member_pk).unwrap().len(), 2);
        assert_eq!(store.enrollments_for_member(&member.member_pk).unwrap().len(), 2);
        // Still exactly one user row for the member.
        assert_eq!(store.user_count().unwrap(), 2); // founder + member
    }

    #[test]
    fn enroll_expired_code_is_rejected() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &newcomer, "Late");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        // Force the pairing past its expiry (the 10-minute TTL
        // is too long to wait out in a test).
        {
            let store = state.store.lock().unwrap();
            store
                .connection()
                .execute(
                    "UPDATE pairing_codes SET expires_at = 1",
                    [],
                )
                .unwrap();
        }
        assert_eq!(enroll_status(&state, &code), "expired");
        let resp = approve_as_parent(&state, &code, &founder, &newcomer, now_epoch());
        assert_eq!(resp.status, 400);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("Pairing code expired"));
        let store = state.store.lock().unwrap();
        assert!(!store.user_exists(&newcomer.member_pk));
    }

    #[test]
    fn enroll_code_reuse_is_rejected() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &newcomer, "Member");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        let resp = approve_as_parent(&state, &code, &founder, &newcomer, now_epoch());
        assert_eq!(resp.status, 200);
        // A second approval with a fresh signature changes
        // nothing: the code is spent.
        let resp = approve_as_parent(&state, &code, &founder, &newcomer, now_epoch());
        assert_eq!(resp.status, 400);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("Pairing code already used"));
        // Unknown codes are a distinct, visible failure.
        let resp = approve_as_parent(
            &state,
            "00000000000000000000000000000000",
            &founder,
            &newcomer,
            now_epoch(),
        );
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn enroll_unenrolled_approver_is_rejected() {
        let (state, _founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &newcomer, "Member");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        // The stranger's keys are well-formed and the signature
        // is valid — but the stranger is not an enrolled member.
        let stranger = make_identity(41, 42, "phone", now);
        let resp = approve_as_parent(&state, &code, &stranger, &newcomer, now_epoch());
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("Approver is not an enrolled member"));
        let store = state.store.lock().unwrap();
        assert!(!store.user_exists(&newcomer.member_pk));
    }

    #[test]
    fn enroll_revoked_approver_device_is_rejected() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &newcomer, "Member");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        // The founder's phone is lost and its device revoked
        // before it can approve anything.
        {
            let store = state.store.lock().unwrap();
            assert!(store
                .device_revoke(&founder.member_pk, &founder.device_pk, now_epoch())
                .unwrap());
        }
        let resp = approve_as_parent(&state, &code, &founder, &newcomer, now_epoch());
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("Approver device revoked"));
        let store = state.store.lock().unwrap();
        assert!(!store.user_exists(&newcomer.member_pk));
    }

    #[test]
    fn enroll_recovery_key_can_approve_a_replacement_member() {
        let (state, _founder, recovery) = founder_and_state();
        let now = now_epoch();
        // Both parents lost their phones: a brand-new member
        // identity gets in on the backup card alone.
        let replacement = make_identity(51, 52, "phone", now);
        let (status, begin) = enroll_begin(&state, &replacement, "Replacement");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        let resp = approve_as_recovery(&state, &code, &recovery, &replacement, now_epoch());
        assert_eq!(
            resp.status, 200,
            "approve body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["approver"], "recovery");
        let store = state.store.lock().unwrap();
        assert!(store.user_exists(&replacement.member_pk));
        let enrollments = store
            .enrollments_for_member(&replacement.member_pk)
            .unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].approver_kind, "recovery");
        assert_eq!(
            enrollments[0].recovery_pubkey,
            Some(recovery.verifying_key().to_bytes())
        );
        drop(store);

        // An unregistered "recovery" key approves nothing.
        let bogus = SigningKey::from_bytes(&[77u8; 32]);
        let another = make_identity(61, 62, "phone", now_epoch());
        let (status, begin) = enroll_begin(&state, &another, "Another");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        let resp = approve_as_recovery(&state, &code, &bogus, &another, now_epoch());
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8(resp.body)
            .unwrap()
            .contains("Unknown recovery key"));
    }

    #[test]
    fn enroll_bad_approval_signature_is_rejected() {
        let (state, founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let (status, begin) = enroll_begin(&state, &newcomer, "Member");
        assert_eq!(status, 200);
        let code = begin["code"].as_str().unwrap().to_string();
        // The approver fields name the founder, but the
        // signature comes from a different device key.
        let impostor_device = SigningKey::from_bytes(&[55u8; 32]);
        let cert_hash: [u8; 32] = Sha256::digest(newcomer.cert.encode_to_vec()).into();
        let timestamp = now_epoch();
        let digest = crate::identity::enrollment_approval_digest(
            &newcomer.member_pk,
            &newcomer.device_pk,
            &cert_hash,
            timestamp,
        );
        let signature = impostor_device.sign(&digest).to_bytes();
        let resp = approve_with_body(
            &state,
            json!({
                "code": code,
                "timestamp": timestamp,
                "signature": hex_encode(&signature),
                "approver_member_pubkey": hex_encode(&founder.member_pk),
                "approver_device_pubkey": hex_encode(&founder.device_pk),
            }),
        );
        assert_eq!(resp.status, 401);
        let store = state.store.lock().unwrap();
        assert!(!store.user_exists(&newcomer.member_pk));
    }

    #[test]
    fn enroll_begin_rejects_a_certificate_that_does_not_match() {
        let (state, _founder, _recovery) = founder_and_state();
        let now = now_epoch();
        let newcomer = make_identity(21, 22, "phone", now);
        let other = make_identity(31, 32, "phone", now);
        // Body names the newcomer but carries someone else's
        // certificate: rejected before any pairing exists.
        let mut req = bare_request("POST", "/enroll/begin");
        req.body = json!({
            "member_pubkey": hex_encode(&newcomer.member_pk),
            "device_pubkey": hex_encode(&newcomer.device_pk),
            "display_name": "Mismatch",
            "device_cert": hex_encode(&other.cert.encode_to_vec()),
        })
        .to_string()
        .into_bytes();
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 400);
        let store = state.store.lock().unwrap();
        store.pairings_init().unwrap();
        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM pairing_codes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // -- Phase C1: groups & devices --------------------------------

    use crate::keystore::MemberKeystore;
    use crate::proto::GroupMessage;

    /// A group-capable test member: a `MemberKeystore` (member
    /// key + one "phone" device key) enrolled in the state's
    /// store at the store level (user row + device certificate),
    /// mirroring `sessions::tests::make_member` but usable
    /// through the HTTP handlers.
    struct GroupTestMember {
        ks: MemberKeystore,
        member_pk: [u8; PUBKEY_SIZE],
        device_pk: [u8; PUBKEY_SIZE],
        signing: SigningKey,
    }

    fn group_test_member(state: &ApiState, name: &str) -> GroupTestMember {
        let mut ks = MemberKeystore::new();
        ks.generate_member_key().unwrap();
        let device_pk = ks.add_device_key("phone").unwrap();
        let member_pk = ks.member_public_key().unwrap();
        let now = now_epoch();
        let cert =
            crate::identity::issue_device_certificate(&ks, "phone", now, 0).unwrap();
        let secret = ks.member_keystore().get_private_key().unwrap();
        let signing = SigningKey::from_keypair_bytes(&secret).unwrap();
        {
            let store = state.store.lock().unwrap();
            store.user_register(&member_pk, name).unwrap();
            store.device_add(&cert, now).unwrap();
        }
        GroupTestMember {
            ks,
            member_pk,
            device_pk,
            signing,
        }
    }

    fn device_signing(member: &GroupTestMember) -> SigningKey {
        let secret = member
            .ks
            .device_keystore("phone")
            .unwrap()
            .get_private_key()
            .unwrap();
        SigningKey::from_keypair_bytes(&secret).unwrap()
    }

    fn signed_json(
        member: &GroupTestMember,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> Request {
        let mut req = signed_request(
            &member.signing,
            &member.member_pk,
            method,
            path,
            "",
            now_epoch(),
        );
        req.body = body.to_string().into_bytes();
        req
    }

    fn signed_get(member: &GroupTestMember, path: &str, query: &str) -> Request {
        signed_request(
            &member.signing,
            &member.member_pk,
            "GET",
            path,
            query,
            now_epoch(),
        )
    }

    fn create_group(
        state: &ApiState,
        creator: &GroupTestMember,
        name: &str,
        others: &[&GroupTestMember],
    ) -> (u16, serde_json::Value) {
        let members: Vec<String> =
            others.iter().map(|m| hex_encode(&m.member_pk)).collect();
        let resp = handle_request(
            state,
            &signed_json(
                creator,
                "POST",
                "/groups",
                json!({ "name": name, "members": members }),
            ),
        );
        let value: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
        (resp.status, value)
    }

    fn list_groups(state: &ApiState, member: &GroupTestMember) -> serde_json::Value {
        let resp = handle_request(state, &signed_get(member, "/groups", ""));
        assert_eq!(resp.status, 200);
        serde_json::from_slice(&resp.body).unwrap()
    }

    fn submit(state: &ApiState, member: &GroupTestMember, msg: &Message) -> Response {
        let mut req = signed_request(
            &member.signing,
            &member.member_pk,
            "POST",
            "/messages/submit",
            "",
            now_epoch(),
        );
        req.body = msg.encode_to_vec();
        handle_request(state, &req)
    }

    fn fetch_recent(state: &ApiState, member: &GroupTestMember) -> Vec<Message> {
        let query = format!("user={}", hex_encode(&member.member_pk));
        let resp = handle_request(state, &signed_get(member, "/messages/recent", &query));
        assert_eq!(resp.status, 200);
        MessageList::decode(resp.body.as_slice())
            .unwrap()
            .messages
    }

    fn group_plaintext(group_id: &[u8], text: &str) -> Vec<u8> {
        GroupMessage {
            text: text.to_string(),
            group_id: group_id.to_vec(),
            media_ref: Vec::new(),
            reply_to_timestamp: 0,
        }
        .encode_to_vec()
    }

    /// Start the sender's B4 session against the shared store
    /// and have every recipient accept their share (the client
    /// half of the flow; distribution is computed by the B4
    /// machinery from the store's current membership).
    fn start_and_accept(
        state: &ApiState,
        sender: &GroupTestMember,
        group_id: &[u8; 16],
        recipients: &[&GroupTestMember],
    ) -> [u8; 16] {
        let store = state.store.lock().unwrap();
        let started =
            crate::sessions::start_session(&store, &sender.ks, "phone", group_id, now_epoch())
                .unwrap();
        for recipient in recipients {
            let envelope = started
                .shares
                .iter()
                .find(|e| {
                    e.header.as_ref().unwrap().recipients_pubkey
                        == vec![recipient.device_pk.to_vec()]
                })
                .expect("a share envelope for every recipient");
            crate::sessions::accept_share(
                &store,
                envelope,
                &recipient.ks,
                "phone",
                now_epoch(),
            )
            .unwrap();
        }
        started.session_id
    }

    fn encrypt_group_msg(
        state: &ApiState,
        sender: &GroupTestMember,
        session_id: &[u8; 16],
        group_id: &[u8; 16],
        recipients: &[&GroupTestMember],
        text: &str,
    ) -> Message {
        let store = state.store.lock().unwrap();
        let recipient_pks: Vec<[u8; PUBKEY_SIZE]> =
            recipients.iter().map(|m| m.member_pk).collect();
        crate::sessions::encrypt_session_message(
            &store,
            session_id,
            &sender.ks,
            "phone",
            &recipient_pks,
            &group_plaintext(group_id, text),
            now_epoch(),
            now_epoch(),
        )
        .unwrap()
    }

    fn decrypt_text(
        state: &ApiState,
        member: &GroupTestMember,
        msg: &Message,
    ) -> Result<String, crate::sessions::Error> {
        let store = state.store.lock().unwrap();
        let plaintext = crate::sessions::decrypt_session_message(
            &store,
            &member.device_pk,
            msg,
            now_epoch(),
        )?;
        Ok(GroupMessage::decode(plaintext.as_slice()).unwrap().text)
    }

    fn group_id_of(created: &serde_json::Value) -> ([u8; 16], String) {
        let hex = created["group_id"].as_str().unwrap().to_string();
        let bytes: [u8; 16] = hex_decode(&hex).unwrap().try_into().unwrap();
        (bytes, hex)
    }

    #[test]
    fn group_and_device_routes_match() {
        assert_eq!(route("/groups"), Route::Groups);
        assert_eq!(route("/devices"), Route::Devices);
        assert_eq!(route("/devices/revoke"), Route::RevokeDevice);
        assert_eq!(route("/household/devices"), Route::HouseholdDevices);
        let gid = "ab".repeat(16);
        assert_eq!(
            route(&format!("/groups/{gid}/members")),
            Route::GroupMembers {
                group_id: gid.clone()
            }
        );
        let member = "cd".repeat(32);
        assert_eq!(
            route(&format!("/groups/{gid}/members/{member}")),
            Route::GroupMember {
                group_id: gid,
                member
            }
        );
        assert_eq!(route("/groups/"), Route::NotFound);
        assert_eq!(route("/groups/ab"), Route::NotFound);
        assert_eq!(route("/groups/ab/members/"), Route::NotFound);
    }

    #[test]
    fn group_create_list_and_membership_rules() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let c = group_test_member(&state, "C");
        let d = group_test_member(&state, "D"); // enrolled, never added

        let (status, created) = create_group(&state, &a, "Family", &[&b, &c]);
        assert_eq!(status, 200, "create body: {created}");
        let group_id = created["group_id"].as_str().unwrap().to_string();
        assert_eq!(created["members"].as_array().unwrap().len(), 3);
        assert_eq!(created["creator"], hex_encode(&a.member_pk));

        // Every member lists it; a non-member does not.
        for m in [&a, &b, &c] {
            let list = list_groups(&state, m);
            assert_eq!(list["count"], 1);
            assert_eq!(list["groups"][0]["group_id"], group_id);
            assert_eq!(list["groups"][0]["name"], "Family");
            assert_eq!(list["groups"][0]["members"].as_array().unwrap().len(), 3);
        }
        assert_eq!(list_groups(&state, &d)["count"], 0);

        // An unenrolled pubkey cannot be added at create time.
        let ghost = [0x77; 32];
        let resp = handle_request(
            &state,
            &signed_json(
                &a,
                "POST",
                "/groups",
                json!({ "name": "Nope", "members": [hex_encode(&ghost)] }),
            ),
        );
        assert_eq!(resp.status, 403);

        // A non-member cannot add members to the group.
        let path = format!("/groups/{group_id}/members");
        let resp = handle_request(
            &state,
            &signed_json(
                &d,
                "POST",
                &path,
                json!({ "member_pubkey": hex_encode(&d.member_pk) }),
            ),
        );
        assert_eq!(resp.status, 403);

        // Unknown group: 404.
        let bogus = "00".repeat(16);
        let resp = handle_request(
            &state,
            &signed_json(
                &a,
                "POST",
                &format!("/groups/{bogus}/members"),
                json!({ "member_pubkey": hex_encode(&d.member_pk) }),
            ),
        );
        assert_eq!(resp.status, 404);

        // Unauthenticated create is refused.
        assert_eq!(
            handle_request(&state, &bare_request("POST", "/groups")).status,
            401
        );
    }

    #[test]
    fn group_session_messages_end_to_end_via_api() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let c = group_test_member(&state, "C");
        let d = group_test_member(&state, "D"); // enrolled, not a member
        let (_, created) = create_group(&state, &a, "Chat", &[&b, &c]);
        let (group_id, _hex) = group_id_of(&created);
        let all = [&a, &b, &c];

        // A and B each start a sender session; the other members
        // accept their shares (B4 machinery, client side).
        let session_a = start_and_accept(&state, &a, &group_id, &[&b, &c]);
        let session_b = start_and_accept(&state, &b, &group_id, &[&a, &c]);

        let msg_a = encrypt_group_msg(&state, &a, &session_a, &group_id, &all, "hello from A");
        let resp = submit(&state, &a, &msg_a);
        assert_eq!(
            resp.status, 202,
            "submit A: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let msg_b = encrypt_group_msg(&state, &b, &session_b, &group_id, &all, "hello from B");
        assert_eq!(submit(&state, &b, &msg_b).status, 202);

        // Every member reads both messages back through the API,
        // intact: session fields set, full member recipient list
        // preserved, and decryptable with their own ratchet state.
        for reader in [&a, &b, &c] {
            let recent = fetch_recent(&state, reader);
            let session_msgs: Vec<&Message> =
                recent.iter().filter(|m| !m.session_id.is_empty()).collect();
            assert_eq!(
                session_msgs.len(),
                2,
                "reader {} sees both group messages",
                hex_encode(&reader.member_pk)
            );
            for m in &session_msgs {
                let header = m.header.as_ref().unwrap();
                assert_eq!(header.recipients_pubkey.len(), 3);
                assert_eq!(header.group_id, group_id.to_vec());
                assert!(m.keywraps.is_empty());
            }
        }
        // Decryption matrix: everyone decrypts the others'
        // messages (a sender does not re-decrypt its own).
        assert_eq!(decrypt_text(&state, &b, &msg_a).unwrap(), "hello from A");
        assert_eq!(decrypt_text(&state, &c, &msg_a).unwrap(), "hello from A");
        assert_eq!(decrypt_text(&state, &a, &msg_b).unwrap(), "hello from B");
        assert_eq!(decrypt_text(&state, &c, &msg_b).unwrap(), "hello from B");

        // The pairwise conversation read carries them too.
        let query = format!(
            "user={}&with={}",
            hex_encode(&b.member_pk),
            hex_encode(&a.member_pk)
        );
        let resp = handle_request(&state, &signed_get(&b, "/messages/conversation", &query));
        assert_eq!(resp.status, 200);
        let conv = MessageList::decode(resp.body.as_slice()).unwrap();
        assert!(conv
            .messages
            .iter()
            .any(|m| m.session_id == session_a.to_vec()));

        // Non-member D: the group messages never appear in their
        // reads, and there is no session state to decrypt with.
        let recent_d = fetch_recent(&state, &d);
        assert!(recent_d.iter().all(|m| m.session_id.is_empty()));
        assert!(decrypt_text(&state, &d, &msg_a).is_err());
    }

    #[test]
    fn group_add_member_rotates_sessions() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let c = group_test_member(&state, "C");
        let (_, created) = create_group(&state, &a, "Rotating", &[&b]);
        let (group_id, group_id_hex) = group_id_of(&created);

        let session1 = start_and_accept(&state, &a, &group_id, &[&b]);
        let pair = [&a, &b];
        let m1 = encrypt_group_msg(&state, &a, &session1, &group_id, &pair, "before C joined");
        assert_eq!(submit(&state, &a, &m1).status, 202);
        assert_eq!(decrypt_text(&state, &b, &m1).unwrap(), "before C joined");
        // A second message under the same session, held back
        // until after the join.
        let m1b = encrypt_group_msg(
            &state,
            &a,
            &session1,
            &group_id,
            &pair,
            "still the old session",
        );

        // C joins through the API.
        let resp = handle_request(
            &state,
            &signed_json(
                &a,
                "POST",
                &format!("/groups/{group_id_hex}/members"),
                json!({ "member_pubkey": hex_encode(&c.member_pk) }),
            ),
        );
        assert_eq!(
            resp.status, 200,
            "add body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "added");
        assert!(v["retired_sessions"].as_u64().unwrap() >= 1);
        assert_eq!(v["members"].as_array().unwrap().len(), 3);

        // The held-back old-session message is refused at submit:
        // the membership change retired the session.
        let resp = submit(&state, &a, &m1b);
        assert_eq!(
            resp.status, 403,
            "old session submit: {}",
            String::from_utf8_lossy(&resp.body)
        );

        // A rotates: a fresh session whose shares cover B *and* C.
        let all = [&a, &b, &c];
        let session2 = start_and_accept(&state, &a, &group_id, &[&b, &c]);
        assert_ne!(session1, session2);
        let m2 = encrypt_group_msg(&state, &a, &session2, &group_id, &all, "after C joined");
        assert_eq!(submit(&state, &a, &m2).status, 202);
        assert_eq!(decrypt_text(&state, &b, &m2).unwrap(), "after C joined");
        assert_eq!(decrypt_text(&state, &c, &m2).unwrap(), "after C joined");

        // C never held the first session, so the pre-join message
        // does not decrypt for them.
        assert!(decrypt_text(&state, &c, &m1).is_err());
    }

    #[test]
    fn group_remove_member_rotates_sessions() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let c = group_test_member(&state, "C");
        let (_, created) = create_group(&state, &a, "Rotating", &[&b, &c]);
        let (group_id, group_id_hex) = group_id_of(&created);

        let session1 = start_and_accept(&state, &a, &group_id, &[&b, &c]);
        let all = [&a, &b, &c];
        let m1 = encrypt_group_msg(&state, &a, &session1, &group_id, &all, "before removal");
        assert_eq!(submit(&state, &a, &m1).status, 202);
        assert_eq!(decrypt_text(&state, &b, &m1).unwrap(), "before removal");
        assert_eq!(decrypt_text(&state, &c, &m1).unwrap(), "before removal");
        let m1b = encrypt_group_msg(
            &state,
            &a,
            &session1,
            &group_id,
            &all,
            "still the old session",
        );

        // Remove C through the API.
        let path = format!(
            "/groups/{group_id_hex}/members/{}",
            hex_encode(&c.member_pk)
        );
        let req = signed_request(&a.signing, &a.member_pk, "DELETE", &path, "", now_epoch());
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 200,
            "remove body: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "removed");
        assert!(v["retired_sessions"].as_u64().unwrap() >= 1);
        assert_eq!(v["members"].as_array().unwrap().len(), 2);
        // C no longer lists the group.
        assert_eq!(list_groups(&state, &c)["count"], 0);

        // The held-back old-session message is refused at submit.
        assert_eq!(submit(&state, &a, &m1b).status, 403);

        // A rotates: the fresh distribution covers B only — no
        // share is addressed to C's device.
        let session2 = {
            let store = state.store.lock().unwrap();
            let started = crate::sessions::start_session(
                &store,
                &a.ks,
                "phone",
                &group_id,
                now_epoch(),
            )
            .unwrap();
            assert_eq!(started.shares.len(), 1, "only B receives a share");
            assert_eq!(
                started.shares[0].header.as_ref().unwrap().recipients_pubkey,
                vec![b.device_pk.to_vec()]
            );
            crate::sessions::accept_share(
                &store,
                &started.shares[0],
                &b.ks,
                "phone",
                now_epoch(),
            )
            .unwrap();
            started.session_id
        };
        let pair = [&a, &b];
        let m2 = encrypt_group_msg(&state, &a, &session2, &group_id, &pair, "after removal");
        assert_eq!(submit(&state, &a, &m2).status, 202);
        assert_eq!(decrypt_text(&state, &b, &m2).unwrap(), "after removal");
        // C holds no state for the new session: no decryption.
        assert!(decrypt_text(&state, &c, &m2).is_err());

        // A member may remove themselves.
        let path = format!(
            "/groups/{group_id_hex}/members/{}",
            hex_encode(&b.member_pk)
        );
        let req = signed_request(&b.signing, &b.member_pk, "DELETE", &path, "", now_epoch());
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 200);
        assert_eq!(
            list_groups(&state, &a)["groups"][0]["members"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn devices_list_permissions() {
        let state = empty_state();
        let parent = group_test_member(&state, "Parent");
        let child = group_test_member(&state, "Child");
        let stranger = group_test_member(&state, "Stranger");
        {
            let store = state.store.lock().unwrap();
            store
                .parent_link_add(&parent.member_pk, &child.member_pk)
                .unwrap();
        }
        let query = format!("member={}", hex_encode(&child.member_pk));

        // The member themselves.
        let resp = handle_request(&state, &signed_get(&child, "/devices", &query));
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["member"], hex_encode(&child.member_pk));
        assert_eq!(v["devices"].as_array().unwrap().len(), 1);
        assert_eq!(v["devices"][0]["label"], "phone");
        assert_eq!(v["devices"][0]["status"], "active");
        assert_eq!(
            v["devices"][0]["device_pubkey"],
            hex_encode(&child.device_pk)
        );

        // A recorded parent.
        assert_eq!(
            handle_request(&state, &signed_get(&parent, "/devices", &query)).status,
            200
        );
        // A stranger is refused.
        assert_eq!(
            handle_request(&state, &signed_get(&stranger, "/devices", &query)).status,
            403
        );
        // Missing member variable: 400. Unauthenticated: 401.
        assert_eq!(
            handle_request(&state, &signed_get(&child, "/devices", "")).status,
            400
        );
        assert_eq!(
            handle_request(&state, &bare_request("GET", "/devices")).status,
            401
        );
    }

    #[test]
    fn household_devices_overview_for_any_enrolled_member() {
        let state = empty_state();
        let parent = group_test_member(&state, "Parent");
        let child = group_test_member(&state, "Child");
        let stranger = group_test_member(&state, "Stranger");
        {
            let store = state.store.lock().unwrap();
            store
                .parent_link_add(&parent.member_pk, &child.member_pk)
                .unwrap();
            // One revoked device in the household: the child's.
            store
                .device_revoke(&child.member_pk, &child.device_pk, now_epoch())
                .unwrap();
        }

        // Even a member who is neither the device owner nor a
        // recorded parent may read the overview — it is
        // household directory data.
        let resp = handle_request(&state, &signed_get(&stranger, "/household/devices", ""));
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        let members = v["members"].as_array().unwrap();
        assert_eq!(members.len(), 3);
        let by_member = |pk: &[u8; 32]| {
            members
                .iter()
                .find(|m| m["member"] == hex_encode(pk))
                .unwrap()
                .clone()
        };
        let child_view = by_member(&child.member_pk);
        assert_eq!(child_view["username"], "Child");
        assert_eq!(
            child_view["parents"],
            json!([hex_encode(&parent.member_pk)])
        );
        assert_eq!(child_view["devices"].as_array().unwrap().len(), 1);
        assert_eq!(
            child_view["devices"][0]["device_pubkey"],
            hex_encode(&child.device_pk)
        );
        assert_eq!(child_view["devices"][0]["label"], "phone");
        // Revoked devices show as revoked, with the time.
        assert_eq!(child_view["devices"][0]["status"], "revoked");
        assert!(child_view["devices"][0]["revoked_at"].as_u64().is_some());
        let parent_view = by_member(&parent.member_pk);
        assert_eq!(parent_view["devices"][0]["status"], "active");
        assert!(parent_view["parents"].as_array().unwrap().is_empty());
    }

    #[test]
    fn household_devices_rejects_unknown_and_unenrolled() {
        let state = empty_state();
        let _member = group_test_member(&state, "Member");

        // Unknown requester: correctly signed, but the key is
        // not registered at all — refused 401.
        let ghost = SigningKey::from_bytes(&[77u8; 32]);
        let ghost_pk = ghost.verifying_key().to_bytes();
        let req = signed_request(
            &ghost,
            &ghost_pk,
            "GET",
            "/household/devices",
            "",
            now_epoch(),
        );
        assert_eq!(handle_request(&state, &req).status, 401);

        // Registered but not enrolled (a bare `users` row with
        // no device on record) — refused 403.
        let bare = SigningKey::from_bytes(&[78u8; 32]);
        let bare_pk = bare.verifying_key().to_bytes();
        {
            let store = state.store.lock().unwrap();
            store.user_register(&bare_pk, "Bare").unwrap();
        }
        let req = signed_request(
            &bare,
            &bare_pk,
            "GET",
            "/household/devices",
            "",
            now_epoch(),
        );
        assert_eq!(handle_request(&state, &req).status, 403);

        // No auth headers at all — refused 401.
        assert_eq!(
            handle_request(&state, &bare_request("GET", "/household/devices")).status,
            401
        );
    }

    #[test]
    fn devices_revoke_by_member_parent_and_stranger() {
        let state = empty_state();
        let parent = group_test_member(&state, "Parent");
        let child = group_test_member(&state, "Child");
        let stranger = group_test_member(&state, "Stranger");

        // The child's second device ("tablet"), enrolled at the
        // store level with a member-signed certificate.
        let tablet_signing = SigningKey::from_bytes(&[0x55; 32]);
        let tablet_pk = tablet_signing.verifying_key().to_bytes();
        {
            let now = now_epoch();
            let cert = crate::identity::create_device_certificate(
                child.ks.member_keystore(),
                &tablet_pk,
                "tablet",
                now,
                0,
            )
            .unwrap();
            let store = state.store.lock().unwrap();
            store.device_add(&cert, now).unwrap();
            store
                .parent_link_add(&parent.member_pk, &child.member_pk)
                .unwrap();
        }
        let trusted = |pk: &[u8; PUBKEY_SIZE]| {
            let store = state.store.lock().unwrap();
            store
                .device_is_trusted(&child.member_pk, pk, now_epoch())
                .unwrap()
        };
        assert!(trusted(&tablet_pk));
        assert!(trusted(&child.device_pk));

        // A stranger in member mode (not the member, no parent
        // authorization): refused, nothing changes.
        let resp = handle_request(
            &state,
            &signed_json(
                &stranger,
                "POST",
                "/devices/revoke",
                json!({
                    "member_pubkey": hex_encode(&child.member_pk),
                    "device_pubkey": hex_encode(&tablet_pk),
                }),
            ),
        );
        assert_eq!(resp.status, 403);
        assert!(trusted(&tablet_pk));

        // A forged parent claim (the stranger is not a recorded
        // parent, whatever their device key signs): refused.
        let ts = now_epoch();
        let digest = crate::identity::device_revocation_digest(
            &child.member_pk,
            &child.device_pk,
            ts,
            "",
        );
        let forged_sig = device_signing(&stranger).sign(&digest).to_bytes();
        let mut req = bare_request("POST", "/devices/revoke");
        req.body = json!({
            "member_pubkey": hex_encode(&child.member_pk),
            "device_pubkey": hex_encode(&child.device_pk),
            "parent_member_pubkey": hex_encode(&stranger.member_pk),
            "parent_device_pubkey": hex_encode(&stranger.device_pk),
            "timestamp": ts,
            "signature": hex_encode(&forged_sig),
        })
        .to_string()
        .into_bytes();
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 403);
        assert!(trusted(&child.device_pk));

        // The real parent, but a signature over the wrong
        // timestamp: refused.
        let wrong_digest = crate::identity::device_revocation_digest(
            &child.member_pk,
            &child.device_pk,
            ts + 5,
            "",
        );
        let wrong_sig = device_signing(&parent).sign(&wrong_digest).to_bytes();
        let mut req = bare_request("POST", "/devices/revoke");
        req.body = json!({
            "member_pubkey": hex_encode(&child.member_pk),
            "device_pubkey": hex_encode(&child.device_pk),
            "parent_member_pubkey": hex_encode(&parent.member_pk),
            "parent_device_pubkey": hex_encode(&parent.device_pk),
            "timestamp": ts,
            "signature": hex_encode(&wrong_sig),
        })
        .to_string()
        .into_bytes();
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 403);
        assert!(trusted(&child.device_pk));

        // Member mode: the child revokes their own tablet with
        // the member key (the TWREQUEST signature).
        let resp = handle_request(
            &state,
            &signed_json(
                &child,
                "POST",
                "/devices/revoke",
                json!({
                    "member_pubkey": hex_encode(&child.member_pk),
                    "device_pubkey": hex_encode(&tablet_pk),
                }),
            ),
        );
        assert_eq!(
            resp.status, 200,
            "member revoke: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "revoked");
        assert!(!trusted(&tablet_pk));
        // The audit row remains, marked revoked.
        {
            let store = state.store.lock().unwrap();
            let devices = store.device_list(&child.member_pk).unwrap();
            let tablet = devices
                .iter()
                .find(|d| d.device_pubkey == tablet_pk)
                .unwrap();
            assert_eq!(tablet.status, DeviceStatus::Revoked);
        }

        // Parent mode: the recorded parent revokes the child's
        // phone with their device key — no TWREQUEST headers
        // involved, the device signature is the authorization.
        let ts = now_epoch();
        let digest = crate::identity::device_revocation_digest(
            &child.member_pk,
            &child.device_pk,
            ts,
            "lost",
        );
        let sig = device_signing(&parent).sign(&digest).to_bytes();
        let mut req = bare_request("POST", "/devices/revoke");
        req.body = json!({
            "member_pubkey": hex_encode(&child.member_pk),
            "device_pubkey": hex_encode(&child.device_pk),
            "reason": "lost",
            "parent_member_pubkey": hex_encode(&parent.member_pk),
            "parent_device_pubkey": hex_encode(&parent.device_pk),
            "timestamp": ts,
            "signature": hex_encode(&sig),
        })
        .to_string()
        .into_bytes();
        let resp = handle_request(&state, &req);
        assert_eq!(
            resp.status, 200,
            "parent revoke: {}",
            String::from_utf8_lossy(&resp.body)
        );
        assert!(!trusted(&child.device_pk));

        // Unknown device: 404.
        let resp = handle_request(
            &state,
            &signed_json(
                &child,
                "POST",
                "/devices/revoke",
                json!({
                    "member_pubkey": hex_encode(&child.member_pk),
                    "device_pubkey": hex_encode(&[0x99; 32]),
                }),
            ),
        );
        assert_eq!(resp.status, 404);

        // Both devices revoked: the B4 distribution for a group
        // containing parent + child now offers the child nothing
        // (revocation feeds distribution through the trust check
        // — verified here, not reimplemented).
        let (_, created) = create_group(&state, &parent, "Family", &[&child]);
        let (group_id, _hex) = group_id_of(&created);
        let store = state.store.lock().unwrap();
        let dist = crate::sessions::compute_distribution(
            &store,
            &group_id,
            &parent.member_pk,
            &parent.device_pk,
            now_epoch(),
        )
        .unwrap();
        assert!(
            dist.devices.is_empty(),
            "revoked devices receive no shares: {dist:?}"
        );
    }

    // -- Phase C1 live proof (ignored: needs the running node) --

    /// Minimal HTTP client for the live proof: one request per
    /// connection, `Connection: close`, status + body back.
    fn http_request(
        addr: &str,
        method: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(addr).expect("connect to node");
        let target = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let mut req = format!(
            "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let head = String::from_utf8_lossy(&raw).into_owned();
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .expect("status line")
            .parse()
            .unwrap();
        let split = head.find("\r\n\r\n").expect("header terminator");
        (status, raw[split + 4..].to_vec())
    }

    fn tw_headers(
        signing: &SigningKey,
        pubkey: &[u8; PUBKEY_SIZE],
        method: &str,
        path: &str,
        query: &str,
    ) -> Vec<(String, String)> {
        let ts = now_epoch();
        let digest = compute_request_digest(method, path, query, &ts.to_string(), pubkey);
        let signature = signing.sign(&digest).to_bytes();
        vec![
            ("X-User-Pubkey".to_string(), hex_encode(pubkey)),
            ("X-Signature".to_string(), hex_encode(&signature)),
            ("X-Timestamp".to_string(), ts.to_string()),
        ]
    }

    /// Live proof for Phase C1, against the real node over real
    /// HTTP with real encryption: enroll three fresh members
    /// (founder-approved, via the backup card's device key),
    /// form a group through `POST /groups`, exchange B4 session
    /// messages through the message endpoints, and read them
    /// back decrypted on every side. Client-side session state
    /// lives in a scratch store (what a member's own device
    /// would hold); enrollment facts are mirrored into it the
    /// way gossip replication will eventually carry them.
    ///
    /// Ignored by default. Run with:
    /// `cargo test group_live_proof_over_http -- --ignored --nocapture`
    /// Env: `C1_PROOF_ADDR` (default 127.0.0.1:8000),
    /// `C1_PROOF_CARD` (default the node1 founder card),
    /// `C1_PROOF_CLIENT_DB` (default /tmp/c1_proof_client.db),
    /// `C1_PROOF_MANIFEST` (default /tmp/c1_proof_cleanup.txt —
    /// receives the fresh member pubkeys + group id so the
    /// operator can remove the proof rows from the node DB).
    #[test]
    #[ignore = "live proof against the running node (Phase C1)"]
    fn group_live_proof_over_http() {
        let addr = std::env::var("C1_PROOF_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        let card_path = std::env::var("C1_PROOF_CARD").unwrap_or_else(|_| {
            "/home/william/tinywebc-node1/founder-backup-card.txt".to_string()
        });
        let client_db = std::env::var("C1_PROOF_CLIENT_DB")
            .unwrap_or_else(|_| "/tmp/c1_proof_client.db".to_string());
        let manifest_path = std::env::var("C1_PROOF_MANIFEST")
            .unwrap_or_else(|_| "/tmp/c1_proof_cleanup.txt".to_string());

        // The founder's card: approver identity for enrollment.
        let card = std::fs::read_to_string(&card_path).expect("read founder card");
        let card_field = |label: &str| -> Vec<u8> {
            let line = card
                .lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("card missing {label}"));
            hex_decode(line.split(':').nth(1).unwrap().trim()).unwrap()
        };
        let founder_member: [u8; PUBKEY_SIZE] =
            card_field("Member pubkey:").try_into().unwrap();
        let founder_device: [u8; PUBKEY_SIZE] =
            card_field("Device pubkey:").try_into().unwrap();
        let founder_seed: [u8; PUBKEY_SIZE] =
            card_field("Device secret (seed):").try_into().unwrap();
        let founder_device_signing = SigningKey::from_bytes(&founder_seed);
        assert_eq!(
            founder_device_signing.verifying_key().to_bytes(),
            founder_device
        );

        // Scratch client store (the members' "own devices").
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{client_db}{suffix}"));
        }
        let client_store = Store::open(&client_db).unwrap();
        client_store.init_schema().unwrap();

        // Enroll three fresh members over real HTTP.
        struct ProofMember {
            ks: MemberKeystore,
            member_pk: [u8; PUBKEY_SIZE],
            device_pk: [u8; PUBKEY_SIZE],
            signing: SigningKey,
        }
        let mut members: Vec<ProofMember> = Vec::new();
        for name in ["Proof One", "Proof Two", "Proof Three"] {
            let mut ks = MemberKeystore::new();
            ks.generate_member_key().unwrap();
            let device_pk = ks.add_device_key("phone").unwrap();
            let member_pk = ks.member_public_key().unwrap();
            let now = now_epoch();
            let cert =
                crate::identity::issue_device_certificate(&ks, "phone", now, 0).unwrap();
            let (status, body) = http_request(
                &addr,
                "POST",
                "/enroll/begin",
                "",
                &[],
                json!({
                    "member_pubkey": hex_encode(&member_pk),
                    "device_pubkey": hex_encode(&device_pk),
                    "display_name": name,
                    "device_cert": hex_encode(&cert.encode_to_vec()),
                })
                .to_string()
                .as_bytes(),
            );
            assert_eq!(status, 200, "begin {name}: {}", String::from_utf8_lossy(&body));
            let begin: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let code = begin["code"].as_str().unwrap().to_string();
            let cert_hash: [u8; 32] = Sha256::digest(cert.encode_to_vec()).into();
            let ts = now_epoch();
            let digest = crate::identity::enrollment_approval_digest(
                &member_pk, &device_pk, &cert_hash, ts,
            );
            let signature = founder_device_signing.sign(&digest).to_bytes();
            let (status, body) = http_request(
                &addr,
                "POST",
                "/enroll/approve",
                "",
                &[],
                json!({
                    "code": code,
                    "timestamp": ts,
                    "signature": hex_encode(&signature),
                    "approver_member_pubkey": hex_encode(&founder_member),
                    "approver_device_pubkey": hex_encode(&founder_device),
                })
                .to_string()
                .as_bytes(),
            );
            assert_eq!(
                status, 200,
                "approve {name}: {}",
                String::from_utf8_lossy(&body)
            );
            client_store.user_register(&member_pk, name).unwrap();
            client_store.device_add(&cert, now).unwrap();
            let secret = ks.member_keystore().get_private_key().unwrap();
            let signing = SigningKey::from_keypair_bytes(&secret).unwrap();
            println!("PROOF enrolled {name}: member={}", hex_encode(&member_pk));
            members.push(ProofMember {
                ks,
                member_pk,
                device_pk,
                signing,
            });
        }

        // Create the group over HTTP (member One is the creator).
        let creator = &members[0];
        let headers = tw_headers(&creator.signing, &creator.member_pk, "POST", "/groups", "");
        let (status, body) = http_request(
            &addr,
            "POST",
            "/groups",
            "",
            &headers,
            json!({
                "name": "Proof Group",
                "members": [
                    hex_encode(&members[1].member_pk),
                    hex_encode(&members[2].member_pk)
                ],
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(status, 200, "create group: {}", String::from_utf8_lossy(&body));
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let group_id_hex = created["group_id"].as_str().unwrap().to_string();
        let group_id: [u8; 16] = hex_decode(&group_id_hex).unwrap().try_into().unwrap();
        println!("PROOF group created: {group_id_hex}");
        for m in &members {
            client_store
                .conversation_member_add(&group_id, &m.member_pk, now_epoch())
                .unwrap();
        }
        // GET /groups over HTTP shows it to another member.
        let m1 = &members[1];
        let headers = tw_headers(&m1.signing, &m1.member_pk, "GET", "/groups", "");
        let (status, body) = http_request(&addr, "GET", "/groups", "", &headers, &[]);
        assert_eq!(status, 200);
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["groups"][0]["members"].as_array().unwrap().len(), 3);
        println!("PROOF GET /groups lists the group with 3 members");

        // Every member starts a sender session; all shares are
        // accepted by their recipients (client-side B4 flow).
        let mut session_ids: Vec<[u8; 16]> = Vec::new();
        let mut all_shares: Vec<Envelope> = Vec::new();
        for m in &members {
            let started = crate::sessions::start_session(
                &client_store,
                &m.ks,
                "phone",
                &group_id,
                now_epoch(),
            )
            .unwrap();
            session_ids.push(started.session_id);
            all_shares.extend(started.shares);
        }
        assert_eq!(all_shares.len(), 6, "3 senders x 2 recipients");
        for share in &all_shares {
            let recipient_device: [u8; PUBKEY_SIZE] = share
                .header
                .as_ref()
                .unwrap()
                .recipients_pubkey[0]
                .clone()
                .try_into()
                .unwrap();
            let recipient = members
                .iter()
                .find(|m| m.device_pk == recipient_device)
                .unwrap();
            crate::sessions::accept_share(
                &client_store,
                share,
                &recipient.ks,
                "phone",
                now_epoch(),
            )
            .unwrap();
        }
        println!("PROOF sessions started and all 6 shares accepted");

        // Each member sends one session message through the API.
        let recipient_pks: Vec<[u8; PUBKEY_SIZE]> =
            members.iter().map(|m| m.member_pk).collect();
        for (i, m) in members.iter().enumerate() {
            let text = format!("proof message from member {}", i + 1);
            let msg = crate::sessions::encrypt_session_message(
                &client_store,
                &session_ids[i],
                &m.ks,
                "phone",
                &recipient_pks,
                &group_plaintext(&group_id, &text),
                now_epoch(),
                now_epoch(),
            )
            .unwrap();
            let headers =
                tw_headers(&m.signing, &m.member_pk, "POST", "/messages/submit", "");
            let (status, body) = http_request(
                &addr,
                "POST",
                "/messages/submit",
                "",
                &headers,
                &msg.encode_to_vec(),
            );
            assert_eq!(
                status, 202,
                "submit member {}: {}",
                i + 1,
                String::from_utf8_lossy(&body)
            );
            println!("PROOF member {} submitted '{text}' -> 202", i + 1);
        }

        // Each member fetches recent over HTTP and decrypts the
        // other two members' messages.
        for (i, m) in members.iter().enumerate() {
            let query = format!("user={}", hex_encode(&m.member_pk));
            let headers = tw_headers(&m.signing, &m.member_pk, "GET", "/messages/recent", &query);
            let (status, body) =
                http_request(&addr, "GET", "/messages/recent", &query, &headers, &[]);
            assert_eq!(status, 200);
            let list = MessageList::decode(body.as_slice()).unwrap();
            let group_msgs: Vec<&Message> = list
                .messages
                .iter()
                .filter(|x| !x.session_id.is_empty())
                .collect();
            assert_eq!(group_msgs.len(), 3, "member {} recent", i + 1);
            let mut texts: Vec<String> = Vec::new();
            for gm in &group_msgs {
                if gm.header.as_ref().unwrap().sender_pubkey == m.member_pk.to_vec() {
                    continue;
                }
                let plaintext = crate::sessions::decrypt_session_message(
                    &client_store,
                    &m.device_pk,
                    gm,
                    now_epoch(),
                )
                .unwrap();
                texts.push(GroupMessage::decode(plaintext.as_slice()).unwrap().text);
            }
            texts.sort();
            let expected: Vec<String> = (1..=3)
                .filter(|n| *n != i + 1)
                .map(|n| format!("proof message from member {n}"))
                .collect();
            assert_eq!(texts, expected, "member {} decrypted the others", i + 1);
            println!(
                "PROOF member {} decrypted both other messages: {texts:?}",
                i + 1
            );
        }

        // Devices over HTTP: self-list works, a fellow group
        // member (not a parent) is refused, member-mode revoke
        // works and shows up in the list.
        let m2 = &members[2];
        let query = format!("member={}", hex_encode(&m2.member_pk));
        let headers = tw_headers(&m2.signing, &m2.member_pk, "GET", "/devices", &query);
        let (status, body) = http_request(&addr, "GET", "/devices", &query, &headers, &[]);
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["devices"][0]["status"], "active");
        let headers = tw_headers(&m1.signing, &m1.member_pk, "GET", "/devices", &query);
        let (status, _) = http_request(&addr, "GET", "/devices", &query, &headers, &[]);
        assert_eq!(status, 403, "non-parent member may not list devices");
        let headers = tw_headers(&m2.signing, &m2.member_pk, "POST", "/devices/revoke", "");
        let (status, body) = http_request(
            &addr,
            "POST",
            "/devices/revoke",
            "",
            &headers,
            json!({
                "member_pubkey": hex_encode(&m2.member_pk),
                "device_pubkey": hex_encode(&m2.device_pk),
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(status, 200, "revoke: {}", String::from_utf8_lossy(&body));
        let headers = tw_headers(&m2.signing, &m2.member_pk, "GET", "/devices", &query);
        let (status, body) = http_request(&addr, "GET", "/devices", &query, &headers, &[]);
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["devices"][0]["status"], "revoked");
        println!("PROOF devices list/revoke over HTTP verified");

        // Cleanup manifest for the operator: the fresh members
        // and the proof group to remove from the node DB (the
        // three household members are untouched).
        let mut manifest = format!("group_id={group_id_hex}\n");
        for m in &members {
            manifest.push_str(&format!(
                "member={} device={}\n",
                hex_encode(&m.member_pk),
                hex_encode(&m.device_pk)
            ));
        }
        std::fs::write(&manifest_path, manifest).unwrap();
        println!("PROOF PASS — cleanup manifest written to {manifest_path}");
    }
    // -- Phase C2: content path + share recipients -----------------

    fn submit_content(
        state: &ApiState,
        member: &GroupTestMember,
        envelope: &Envelope,
    ) -> Response {
        let mut req = signed_request(
            &member.signing,
            &member.member_pk,
            "POST",
            "/content/submit",
            "",
            now_epoch(),
        );
        req.body = envelope.encode_to_vec();
        handle_request(state, &req)
    }

    fn fetch_content(
        state: &ApiState,
        member: &GroupTestMember,
        for_key: &[u8; PUBKEY_SIZE],
        content_type: u32,
    ) -> (u16, serde_json::Value) {
        let query = format!(
            "for={}&content_type={}",
            hex_encode(for_key),
            content_type
        );
        let resp = handle_request(state, &signed_get(member, "/content/recent", &query));
        let value: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
        (resp.status, value)
    }

    #[test]
    fn content_routes_match() {
        assert_eq!(route("/content/submit"), Route::ContentSubmit);
        assert_eq!(route("/content/recent"), Route::ContentRecent);
        let gid = "ab".repeat(16);
        assert_eq!(
            route(&format!("/groups/{gid}/share-recipients")),
            Route::GroupShareRecipients { group_id: gid }
        );
    }

    #[test]
    fn share_submit_and_fetch_round_trip() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let c = group_test_member(&state, "C");
        let (status, created) = create_group(&state, &a, "Shares", &[&b, &c]);
        assert_eq!(status, 200);
        let (group_id, group_id_hex) = group_id_of(&created);

        // Share-recipients: B's and C's devices are in A's
        // distribution; A's own device is excluded when named.
        let query = format!("sender_device={}", hex_encode(&a.device_pk));
        let resp = handle_request(
            &state,
            &signed_get(
                &a,
                &format!("/groups/{group_id_hex}/share-recipients"),
                &query,
            ),
        );
        assert_eq!(resp.status, 200, "recipients: {}", String::from_utf8_lossy(&resp.body));
        let dist: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        let devices = dist["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2, "distribution: {dist}");
        assert!(devices
            .iter()
            .any(|d| d["device_pubkey"] == hex_encode(&b.device_pk)));
        assert!(devices
            .iter()
            .any(|d| d["device_pubkey"] == hex_encode(&c.device_pk)));

        // A non-member may not ask.
        let d = group_test_member(&state, "D");
        let resp = handle_request(
            &state,
            &signed_get(
                &d,
                &format!("/groups/{group_id_hex}/share-recipients"),
                "",
            ),
        );
        assert_eq!(resp.status, 403);

        // A builds a share for B's device (B4 machinery) and
        // submits it over the content path.
        let root_key = [0x42u8; 32];
        let session_id = [0x24u8; 16];
        let share_env = crate::sessions::build_share_envelope(
            &a.ks,
            "phone",
            &b.member_pk,
            &b.device_pk,
            &group_id,
            &session_id,
            &root_key,
            now_epoch(),
        )
        .unwrap();
        let resp = submit_content(&state, &a, &share_env);
        assert_eq!(
            resp.status, 202,
            "submit: {}",
            String::from_utf8_lossy(&resp.body)
        );

        // Resubmission is a duplicate, not an error.
        let resp = submit_content(&state, &a, &share_env);
        assert_eq!(resp.status, 202);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "duplicate");

        // B fetches shares addressed to B's device and gets the
        // exact envelope back; B accepts it (B4) and holds the
        // session state.
        let (status, fetched) = fetch_content(&state, &b, &b.device_pk, 25);
        assert_eq!(status, 200);
        assert_eq!(fetched["count"], 1, "fetched: {fetched}");
        let env_hex = fetched["envelopes"][0]["envelope"].as_str().unwrap();
        let env_bytes = hex_decode(env_hex).unwrap();
        assert_eq!(env_bytes, share_env.encode_to_vec());
        let fetched_env = Envelope::decode(env_bytes.as_slice()).unwrap();
        {
            let store = state.store.lock().unwrap();
            let accepted = crate::sessions::accept_share(
                &store,
                &fetched_env,
                &b.ks,
                "phone",
                now_epoch(),
            )
            .unwrap();
            assert_eq!(accepted, session_id);
        }

        // C cannot fetch content addressed to B's device.
        let (status, _) = fetch_content(&state, &c, &b.device_pk, 25);
        assert_eq!(status, 403);

        // A share may not be submitted by someone other than its
        // sender member.
        let share_env_c = crate::sessions::build_share_envelope(
            &a.ks,
            "phone",
            &c.member_pk,
            &c.device_pk,
            &group_id,
            &[0x25u8; 16],
            &root_key,
            now_epoch(),
        )
        .unwrap();
        let resp = submit_content(&state, &b, &share_env_c);
        assert_eq!(resp.status, 403);

        // A tampered share (envelope signature stripped) is
        // rejected at envelope validation.
        let mut tampered = share_env_c.clone();
        tampered.signature = vec![0u8; 64];
        let resp = submit_content(&state, &a, &tampered);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn metadata_submit_and_fetch() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let (status, created) = create_group(&state, &a, "Meta", &[&b]);
        assert_eq!(status, 200);
        let (group_id, _) = group_id_of(&created);
        let envelope = {
            let store = state.store.lock().unwrap();
            crate::sessions::build_metadata_envelope(
                &store,
                &a.ks,
                &group_id,
                &[0x31u8; 16],
                0,
                now_epoch(),
                &b.member_pk,
            )
            .unwrap()
        };
        let resp = submit_content(&state, &a, &envelope);
        assert_eq!(
            resp.status, 202,
            "metadata submit: {}",
            String::from_utf8_lossy(&resp.body)
        );
        // B (the addressed parent) fetches it by member key.
        let (status, fetched) = fetch_content(&state, &b, &b.member_pk, 35);
        assert_eq!(status, 200);
        assert_eq!(fetched["count"], 1, "fetched: {fetched}");
    }

    // -- Phase C3: calendar events -------------------------------

    fn sample_event(id_byte: u8, title: &str, start: i64, updated_at: u64) -> CalendarEvent {
        CalendarEvent {
            event_id: vec![id_byte; 16],
            title: title.to_string(),
            notes: String::new(),
            location: String::new(),
            start_unix: start,
            end_unix: start + 3600,
            timezone: "America/Denver".to_string(),
            all_day: false,
            rrule: String::new(),
            created_by: Vec::new(),
            actor_member_pubkey: Vec::new(),
            actor_device_pubkey: Vec::new(),
            created_at: updated_at,
            updated_at,
            deleted: false,
            signature: Vec::new(),
        }
    }

    fn build_event_for(member: &GroupTestMember, event: &CalendarEvent) -> Envelope {
        crate::events::build_event_envelope(&member.ks, "phone", event).unwrap()
    }

    fn send_event(
        state: &ApiState,
        member: &GroupTestMember,
        method: &str,
        path: &str,
        envelope: &Envelope,
    ) -> Response {
        let mut req = signed_request(
            &member.signing,
            &member.member_pk,
            method,
            path,
            "",
            now_epoch(),
        );
        req.body = envelope.encode_to_vec();
        handle_request(state, &req)
    }

    fn list_events(
        state: &ApiState,
        member: &GroupTestMember,
        from: i64,
        to: i64,
        include_deleted: bool,
    ) -> (u16, serde_json::Value) {
        let query = format!(
            "from={from}&to={to}{}",
            if include_deleted { "&include_deleted=1" } else { "" }
        );
        let resp = handle_request(state, &signed_get(member, "/events", &query));
        let value: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
        (resp.status, value)
    }

    #[test]
    fn event_routes_match() {
        assert_eq!(route("/events"), Route::Events);
        let id = "ab".repeat(16);
        assert_eq!(
            route(&format!("/events/{id}")),
            Route::Event { event_id: id }
        );
    }

    #[test]
    fn event_create_list_update_delete_via_api() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let now = now_epoch();
        let start = 1_900_000_000i64;
        let id_hex = hex_encode(&[0xE1u8; 16]);

        // Create via POST /events; the projected record comes
        // back with the 202.
        let create = sample_event(0xE1, "Picnic", start, now);
        let resp = send_event(&state, &a, "POST", "/events", &build_event_for(&a, &create));
        assert_eq!(resp.status, 202, "create: {}", String::from_utf8_lossy(&resp.body));
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["event"]["title"], "Picnic");
        assert_eq!(v["event"]["event_id"], id_hex);
        assert_eq!(v["event"]["created_by"], hex_encode(&a.member_pk));

        // Another household member lists it (household calendar).
        let (status, list) = list_events(&state, &b, start - 10, start + 10, false);
        assert_eq!(status, 200);
        assert_eq!(list["count"], 1, "list: {list}");
        // Range boundaries: start == from is in, start == to is out.
        let (_, list) = list_events(&state, &b, start, start + 10, false);
        assert_eq!(list["count"], 1);
        let (_, list) = list_events(&state, &b, 0, start, false);
        assert_eq!(list["count"], 0);

        // Update via PUT /events/:id — the new title wins.
        let mut update = sample_event(0xE1, "Picnic (moved)", start, now + 10);
        update.created_at = now;
        let resp = send_event(
            &state,
            &a,
            "PUT",
            &format!("/events/{id_hex}"),
            &build_event_for(&a, &update),
        );
        assert_eq!(resp.status, 202, "update: {}", String::from_utf8_lossy(&resp.body));
        let (_, list) = list_events(&state, &b, start - 10, start + 10, false);
        assert_eq!(list["events"][0]["title"], "Picnic (moved)");
        assert_eq!(list["events"][0]["created_at"], now);

        // GET /events/:id returns the held version.
        let resp = handle_request(&state, &signed_get(&a, &format!("/events/{id_hex}"), ""));
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["title"], "Picnic (moved)");

        // A stranger (not creator, not a recorded parent)
        // may not update it.
        let c = group_test_member(&state, "C");
        let mut hijack = sample_event(0xE1, "Hijacked", start, now + 20);
        hijack.created_at = now;
        hijack.created_by = a.member_pk.to_vec();
        let resp = send_event(
            &state,
            &c,
            "PUT",
            &format!("/events/{id_hex}"),
            &build_event_for(&c, &hijack),
        );
        assert_eq!(resp.status, 403, "hijack: {}", String::from_utf8_lossy(&resp.body));

        // A stale version from the creator is refused.
        let mut stale = sample_event(0xE1, "Picnic (old)", start, now + 5);
        stale.created_at = now;
        let resp = send_event(
            &state,
            &a,
            "PUT",
            &format!("/events/{id_hex}"),
            &build_event_for(&a, &stale),
        );
        assert_eq!(resp.status, 403, "stale: {}", String::from_utf8_lossy(&resp.body));

        // A recorded parent may update and delete a child's
        // event.
        let child = group_test_member(&state, "Child");
        let parent = group_test_member(&state, "Parent");
        {
            let store = state.store.lock().unwrap();
            store
                .parent_link_add(&parent.member_pk, &child.member_pk)
                .unwrap();
        }
        let kid_start = start + 100_000;
        let kid_id_hex = hex_encode(&[0xE2u8; 16]);
        let kid = sample_event(0xE2, "Soccer practice", kid_start, now);
        let resp = send_event(&state, &child, "POST", "/events", &build_event_for(&child, &kid));
        assert_eq!(resp.status, 202, "kid create: {}", String::from_utf8_lossy(&resp.body));
        let mut kid_update = sample_event(0xE2, "Soccer practice (field 2)", kid_start, now + 10);
        kid_update.created_at = now;
        kid_update.created_by = child.member_pk.to_vec();
        let resp = send_event(
            &state,
            &parent,
            "PUT",
            &format!("/events/{kid_id_hex}"),
            &build_event_for(&parent, &kid_update),
        );
        assert_eq!(resp.status, 202, "parent update: {}", String::from_utf8_lossy(&resp.body));
        let mut kid_tombstone = kid_update.clone();
        kid_tombstone.updated_at = now + 20;
        kid_tombstone.deleted = true;
        let resp = send_event(
            &state,
            &parent,
            "DELETE",
            &format!("/events/{kid_id_hex}"),
            &build_event_for(&parent, &kid_tombstone),
        );
        assert_eq!(resp.status, 202, "parent delete: {}", String::from_utf8_lossy(&resp.body));
        let (_, list) = list_events(&state, &a, kid_start - 10, kid_start + 10, false);
        assert_eq!(list["count"], 0);
        let (_, list) = list_events(&state, &a, kid_start - 10, kid_start + 10, true);
        assert_eq!(list["count"], 1);
        assert_eq!(list["events"][0]["deleted"], true);

        // DELETE without the tombstone envelope is a 400.
        let req = signed_request(
            &a.signing,
            &a.member_pk,
            "DELETE",
            &format!("/events/{id_hex}"),
            "",
            now_epoch(),
        );
        let resp = handle_request(&state, &req);
        assert_eq!(resp.status, 400);

        // The creator deletes their own event.
        let mut tombstone = update.clone();
        tombstone.updated_at = now + 30;
        tombstone.deleted = true;
        let resp = send_event(
            &state,
            &a,
            "DELETE",
            &format!("/events/{id_hex}"),
            &build_event_for(&a, &tombstone),
        );
        assert_eq!(resp.status, 202, "delete: {}", String::from_utf8_lossy(&resp.body));
        let (_, list) = list_events(&state, &b, start - 10, start + 10, false);
        assert_eq!(list["count"], 0);
        let (_, list) = list_events(&state, &b, start - 10, start + 10, true);
        assert_eq!(list["count"], 1);
        assert_eq!(list["events"][0]["deleted"], true);
    }

    #[test]
    fn event_bad_signatures_and_wrong_requester_rejected() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let now = now_epoch();
        let event = sample_event(0xE4, "Dentist", 1_900_000_000, now);
        let envelope = build_event_for(&a, &event);

        // Envelope signature stripped: envelope validation
        // refuses it (400).
        let mut tampered = envelope.clone();
        tampered.signature = vec![0u8; 64];
        let resp = send_event(&state, &a, "POST", "/events", &tampered);
        assert_eq!(resp.status, 400, "tampered envelope: {}", String::from_utf8_lossy(&resp.body));

        // Record signature corrupted, envelope re-signed so
        // only the record-level check can catch it (403).
        let mut record = CalendarEvent::decode(envelope.payload_ciphertext.as_slice()).unwrap();
        record.signature[0] ^= 0xFF;
        let mut forged = envelope.clone();
        forged.payload_ciphertext = record.encode_to_vec();
        forged.signature = Vec::new();
        let digest = validation::compute_envelope_signing_digest(&forged).unwrap();
        let device = device_signing(&a);
        forged.signature = device.sign(&digest).to_bytes().to_vec();
        let resp = send_event(&state, &a, "POST", "/events", &forged);
        assert_eq!(resp.status, 403, "forged record: {}", String::from_utf8_lossy(&resp.body));

        // A's envelope submitted under B's request auth: the
        // actor is not the requester (403).
        let resp = send_event(&state, &b, "POST", "/events", &envelope);
        assert_eq!(resp.status, 403, "wrong requester: {}", String::from_utf8_lossy(&resp.body));

        // None of the attempts stored anything.
        let (_, list) = list_events(&state, &a, 0, 4_102_444_800, true);
        assert_eq!(list["count"], 0);
    }

    #[test]
    fn event_recurring_returned_for_later_range_via_api() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let now = now_epoch();
        let start = 1_900_000_000i64;
        let mut recurring = sample_event(0xE5, "Weekly standup", start, now);
        recurring.rrule = "FREQ=WEEKLY".to_string();
        let resp = send_event(&state, &a, "POST", "/events", &build_event_for(&a, &recurring));
        assert_eq!(resp.status, 202);
        let one_off = sample_event(0xE6, "One-off", start, now);
        let resp = send_event(&state, &a, "POST", "/events", &build_event_for(&a, &one_off));
        assert_eq!(resp.status, 202);

        // A range well after both starts: only the series is
        // surfaced, RRULE intact.
        let (_, list) = list_events(&state, &a, start + 100_000, start + 200_000, false);
        assert_eq!(list["count"], 1, "list: {list}");
        assert_eq!(list["events"][0]["title"], "Weekly standup");
        assert_eq!(list["events"][0]["rrule"], "FREQ=WEEKLY");
        assert_eq!(list["events"][0]["recurring"], true);
    }

    #[test]
    fn event_submit_via_content_path() {
        let state = empty_state();
        let a = group_test_member(&state, "A");
        let b = group_test_member(&state, "B");
        let now = now_epoch();
        let event = sample_event(0xE7, "Via content path", 1_900_000_000, now);
        let envelope = build_event_for(&a, &event);
        let resp = submit_content(&state, &a, &envelope);
        assert_eq!(resp.status, 202, "content submit: {}", String::from_utf8_lossy(&resp.body));
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "accepted");
        // Resubmission is a duplicate, not an error.
        let resp = submit_content(&state, &a, &envelope);
        assert_eq!(resp.status, 202);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"], "duplicate");
        // B may not submit A's event.
        let other = sample_event(0xE8, "Not yours", 1_900_000_000, now);
        let other_env = build_event_for(&a, &other);
        let resp = submit_content(&state, &b, &other_env);
        assert_eq!(resp.status, 403);
        // The accepted event is listed.
        let (_, list) = list_events(&state, &b, 1_900_000_000 - 10, 1_900_000_000 + 10, false);
        assert_eq!(list["count"], 1);
        assert_eq!(list["events"][0]["title"], "Via content path");
    }

    /// Live proof for Phase C3, against the real node over
    /// real HTTP: enroll one fresh member (founder-approved
    /// via the backup card), then run the full event lifecycle
    /// through the HTTP endpoints — create (POST /events),
    /// read back in range, update (PUT /events/:id), delete
    /// (DELETE /events/:id with the tombstone envelope) — and
    /// confirm the default list is empty while include_deleted
    /// shows the tombstone. Finally the FOUNDER creates the
    /// one event that stays on the node for Muse's browser
    /// check ("C3 proof event — family hike", 2026-11-22
    /// 16:00 America/Denver, Deer Ridge Trailhead, Draper).
    ///
    /// Ignored by default. Run with:
    /// `cargo test events_live_proof_over_http -- --ignored --nocapture`
    /// Env: `C3_PROOF_ADDR` (default 127.0.0.1:8000),
    /// `C3_PROOF_CARD` (default the node1 founder card),
    /// `C3_PROOF_MANIFEST` (default /tmp/c3_proof_cleanup.txt —
    /// receives the fresh member pubkey + the proof event ids
    /// so the operator can remove the proof rows from the
    /// node DB; the founder's leftover event is NOT in it).
    #[test]
    #[ignore = "live proof against the running node (Phase C3)"]
    fn events_live_proof_over_http() {
        let addr = std::env::var("C3_PROOF_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        let card_path = std::env::var("C3_PROOF_CARD").unwrap_or_else(|_| {
            "/home/william/tinywebc-node1/founder-backup-card.txt".to_string()
        });
        let manifest_path = std::env::var("C3_PROOF_MANIFEST")
            .unwrap_or_else(|_| "/tmp/c3_proof_cleanup.txt".to_string());

        let card = std::fs::read_to_string(&card_path).expect("read founder card");
        let card_field = |label: &str| -> Vec<u8> {
            let line = card
                .lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("card missing {label}"));
            hex_decode(line.split(':').nth(1).unwrap().trim()).unwrap()
        };
        let founder_member: [u8; PUBKEY_SIZE] =
            card_field("Member pubkey:").try_into().unwrap();
        let founder_member_seed: [u8; PUBKEY_SIZE] =
            card_field("Member secret (seed):").try_into().unwrap();
        let founder_device: [u8; PUBKEY_SIZE] =
            card_field("Device pubkey:").try_into().unwrap();
        let founder_device_seed: [u8; PUBKEY_SIZE] =
            card_field("Device secret (seed):").try_into().unwrap();
        let founder_member_signing = SigningKey::from_bytes(&founder_member_seed);
        let founder_device_signing = SigningKey::from_bytes(&founder_device_seed);
        assert_eq!(founder_member_signing.verifying_key().to_bytes(), founder_member);
        assert_eq!(founder_device_signing.verifying_key().to_bytes(), founder_device);

        // Enroll one fresh member over real HTTP.
        let mut ks = MemberKeystore::new();
        ks.generate_member_key().unwrap();
        let device_pk = ks.add_device_key("phone").unwrap();
        let member_pk = ks.member_public_key().unwrap();
        let now = now_epoch();
        let cert = crate::identity::issue_device_certificate(&ks, "phone", now, 0).unwrap();
        let (status, body) = http_request(
            &addr,
            "POST",
            "/enroll/begin",
            "",
            &[],
            json!({
                "member_pubkey": hex_encode(&member_pk),
                "device_pubkey": hex_encode(&device_pk),
                "display_name": "C3 Proof Member",
                "device_cert": hex_encode(&cert.encode_to_vec()),
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(status, 200, "begin: {}", String::from_utf8_lossy(&body));
        let begin: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = begin["code"].as_str().unwrap().to_string();
        let cert_hash: [u8; 32] = Sha256::digest(cert.encode_to_vec()).into();
        let ts = now_epoch();
        let digest = crate::identity::enrollment_approval_digest(
            &member_pk, &device_pk, &cert_hash, ts,
        );
        let signature = founder_device_signing.sign(&digest).to_bytes();
        let (status, body) = http_request(
            &addr,
            "POST",
            "/enroll/approve",
            "",
            &[],
            json!({
                "code": code,
                "timestamp": ts,
                "signature": hex_encode(&signature),
                "approver_member_pubkey": hex_encode(&founder_member),
                "approver_device_pubkey": hex_encode(&founder_device),
            })
            .to_string()
            .as_bytes(),
        );
        assert_eq!(status, 200, "approve: {}", String::from_utf8_lossy(&body));
        let member_secret = ks.member_keystore().get_private_key().unwrap();
        let member_signing = SigningKey::from_keypair_bytes(&member_secret).unwrap();

        let send = |method: &str,
                    path: &str,
                    query: &str,
                    body: &[u8]|
         -> (u16, serde_json::Value) {
            let headers = tw_headers(&member_signing, &member_pk, method, path, query);
            let (status, raw) = http_request(&addr, method, path, query, &headers, body);
            let value: serde_json::Value =
                serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
            (status, value)
        };

        // Create → read back → update → delete, over HTTP.
        let start = 1_893_000_000i64; // 2030-01-05, arbitrary future slot
        let mut event = sample_event(0xD3, "C3 live proof event", start, now_epoch());
        event.location = "Proof Park".to_string();
        let envelope = crate::events::build_event_envelope(&ks, "phone", &event).unwrap();
        let (status, v) = send("POST", "/events", "", &envelope.encode_to_vec());
        assert_eq!(status, 202, "create: {v}");
        assert_eq!(v["event"]["title"], "C3 live proof event");
        let event_id_hex = hex_encode(&event.event_id);
        println!("proof event created: id={event_id_hex}");

        let query = format!("from={}&to={}", start - 10, start + 10);
        let (status, v) = send("GET", "/events", &query, &[]);
        assert_eq!(status, 200);
        assert_eq!(v["count"], 1, "read back: {v}");
        assert_eq!(v["events"][0]["location"], "Proof Park");

        event.title = "C3 live proof event (updated)".to_string();
        event.updated_at = now_epoch() + 1;
        let envelope = crate::events::build_event_envelope(&ks, "phone", &event).unwrap();
        let (status, v) = send(
            "PUT",
            &format!("/events/{event_id_hex}"),
            "",
            &envelope.encode_to_vec(),
        );
        assert_eq!(status, 202, "update: {v}");
        assert_eq!(v["event"]["title"], "C3 live proof event (updated)");

        event.updated_at = now_epoch() + 2;
        event.deleted = true;
        let envelope = crate::events::build_event_envelope(&ks, "phone", &event).unwrap();
        let (status, v) = send(
            "DELETE",
            &format!("/events/{event_id_hex}"),
            "",
            &envelope.encode_to_vec(),
        );
        assert_eq!(status, 202, "delete: {v}");
        let (status, v) = send("GET", "/events", &query, &[]);
        assert_eq!(status, 200);
        assert_eq!(v["count"], 0, "default list after delete: {v}");
        let query_deleted = format!("{query}&include_deleted=1");
        let (status, v) = send("GET", "/events", &query_deleted, &[]);
        assert_eq!(status, 200);
        assert_eq!(v["count"], 1, "include_deleted after delete: {v}");
        assert_eq!(v["events"][0]["deleted"], true);
        println!("proof lifecycle PASS: create/read/update/delete over HTTP");

        // The leftover event, created by the founder: stays on
        // the node for Muse's browser check.
        // 2026-11-22T16:00:00 in America/Denver (MST, UTC-7) =
        // 2026-11-22T23:00:00Z = 1795388400.
        let leftover = CalendarEvent {
            event_id: vec![0xC3; 16],
            title: "C3 proof event — family hike".to_string(),
            notes: "Left by the Phase C3 live proof for the browser check.".to_string(),
            location: "Deer Ridge Trailhead, Draper".to_string(),
            start_unix: 1_795_388_400,
            end_unix: 1_795_388_400 + 5400,
            timezone: "America/Denver".to_string(),
            all_day: false,
            rrule: String::new(),
            created_by: founder_member.to_vec(),
            actor_member_pubkey: Vec::new(),
            actor_device_pubkey: Vec::new(),
            created_at: now_epoch(),
            updated_at: now_epoch(),
            deleted: false,
            signature: Vec::new(),
        };
        let envelope = crate::events::build_event_envelope_with_keys(
            &founder_member,
            &founder_device_signing,
            &leftover,
        )
        .unwrap();
        let headers = tw_headers(
            &founder_member_signing,
            &founder_member,
            "POST",
            "/events",
            "",
        );
        let (status, raw) = http_request(
            &addr,
            "POST",
            "/events",
            "",
            &headers,
            &envelope.encode_to_vec(),
        );
        let v: serde_json::Value =
            serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
        assert_eq!(status, 202, "leftover create: {v}");
        let leftover_id = hex_encode(&leftover.event_id);
        println!("leftover event for browser check: id={leftover_id} title={:?}", leftover.title);

        // Cleanup manifest: the fresh member + the proof event
        // (all its versions) — NOT the leftover.
        let manifest = format!(
            "member={}\ndevice={}\nproof_event_id={}\nleftover_event_id={}\n",
            hex_encode(&member_pk),
            hex_encode(&device_pk),
            event_id_hex,
            leftover_id,
        );
        std::fs::write(&manifest_path, manifest).unwrap();
        println!("PROOF PASS — cleanup manifest written to {manifest_path}");
    }
}
