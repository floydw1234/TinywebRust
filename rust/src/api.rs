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
    ClientRequest, ConversationList, Envelope, Message, MessageList,
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
        "/messages/submit" | "/gossip/message" | "/location/update" => "POST, OPTIONS",
        "/gossip/peers"
        | "/health"
        | "/messages/recent"
        | "/messages/conversation"
        | "/messages/conversations"
        | "/users" => "GET, OPTIONS",
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
}
