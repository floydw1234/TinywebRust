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
    ClientRequest, ConversationList, DeviceCertificate, Envelope, Message, MessageList,
};
use crate::store::{
    PermissionScope, Store, PERMISSION_VIEW_LOCATION, PUBKEY_SIZE,
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
        _ => {
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
        | "/enroll/approve" => "POST, OPTIONS",
        "/gossip/peers"
        | "/health"
        | "/messages/recent"
        | "/messages/conversation"
        | "/messages/conversations"
        | "/users"
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
}
