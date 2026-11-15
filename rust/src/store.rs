//! SQLite persistence.
//!
//! Rust counterpart of the C storage package `src/packages/sql/`
//! (`schema.c`, `database_gossip.c`, `message_store.c`,
//! `location_store.c`, `gossip_peers.c`, `permissions.c`): schema
//! creation/migration, storing and fetching envelopes/messages and
//! locations, seen-digest deduplication, peer records, and TTL
//! cleanup (default 30 days). Backed by `rusqlite` (bundled SQLite).
//!
//! The C package keeps one global `sqlite3*` handle
//! (`db_init_gossip`/`db_get_handle`/`db_close` in
//! `database_gossip.c`); the Rust port replaces that global with an
//! owned [`Store`] wrapping a `rusqlite::Connection`. Every other
//! public function mirrors the C header it ports (named in its doc
//! comment), with `Result<T, Error>` in place of `int` error codes
//! and owned structs in place of out-params. SQL text, table/column
//! names, index names and pragmas are copied verbatim from the C
//! sources so a database file created by either build is readable
//! by the other.

use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message as _;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::proto::{
    ClientRequest, ClientRequestHeader, ClientRequestKeyWrap, ConversationList,
    ConversationSummary, DeviceCertificate, DeviceRevocation, Envelope, EnvelopeHeader,
    Message, MessageHeader, MessageRecipientKeyWrap, RecipientKeyWrap, StoredEnvelope,
};

/// Ed25519 public key size (`PUBKEY_SIZE` in the C headers).
pub const PUBKEY_SIZE: usize = 32;
/// Seen-digest size (`GOSSIP_SEEN_DIGEST_SIZE` in the C headers).
pub const GOSSIP_SEEN_DIGEST_SIZE: usize = 32;
/// Current schema version (`CURRENT_SCHEMA_VERSION` in `schema.h`).
pub const CURRENT_SCHEMA_VERSION: i32 = 2;
/// Default TTL in seconds: 30 days. This is the `NodeConfig`
/// default `message_ttl_seconds = 60*60*24*30` in
/// `src/packages/utils/config.c`, also written as `2592000` by
/// `scripts/init.c`. The sql package itself never computes a TTL:
/// callers pass `expires_at` explicitly and
/// [`Store::gossip_store_cleanup`] deletes rows at/past it.
pub const DEFAULT_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// `CONTENT_LOCATION_UPDATE` from `envelope.proto`; hard-coded by
/// the C location store when reconstructing rows, because
/// `location_updates` has no content-type column.
pub const CONTENT_LOCATION_UPDATE: u32 = 33;

/// Expiry instant for a payload created at `timestamp` under the
/// default 30-day TTL.
pub fn default_expires_at(timestamp: u64) -> u64 {
    timestamp.saturating_add(DEFAULT_TTL_SECS)
}

/// Error type for all store operations.
#[derive(Debug)]
pub enum Error {
    /// Underlying SQLite failure.
    Sqlite(rusqlite::Error),
    /// Caller supplied a structurally invalid protobuf (the cases
    /// where the C code returns `-1` before touching SQL).
    InvalidArgument(String),
    /// `schema_migrate` was asked for a path the C code does not
    /// implement (`schema.c` prints "No migration path ...").
    NoMigrationPath { from: i32, to: i32 },
    /// More than 32 distinct permission groups for one role
    /// (`permissions.c` caps `PermissionGroup groups[32]`).
    TooManyPermissionGroups,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::NoMigrationPath { from, to } => {
                write!(f, "no migration path from version {from} to {to}")
            }
            Error::TooManyPermissionGroups => {
                write!(f, "too many permission groups for one role")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

/// Store result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn invalid(msg: &str) -> Error {
    Error::InvalidArgument(msg.to_string())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex encoding of a 32-byte pubkey (`hex_encode_pubkey`
/// in `permissions.c`; users are keyed by hex text in the DB).
fn hex_encode_pubkey(pubkey: &[u8; PUBKEY_SIZE]) -> String {
    let mut out = String::with_capacity(64);
    for b in pubkey {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
// ---------------------------------------------------------------------------
// SHA-256 (minimal equivalent of OpenSSL `SHA256()`, used by the C
// `*_compute_digest` functions over the protobuf-c packed bytes; here
// over the prost encoding of the same message, which is byte-identical
// for these schemas). Implemented in-file so the port needs no extra
// crate for one hash.
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; GOSSIP_SEEN_DIGEST_SIZE] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; GOSSIP_SEEN_DIGEST_SIZE];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// `message_store_compute_digest`: SHA-256 of the serialized message.
pub fn message_store_compute_digest(message: &Message) -> [u8; GOSSIP_SEEN_DIGEST_SIZE] {
    sha256(&message.encode_to_vec())
}

/// `location_store_compute_digest_client_request`.
pub fn location_store_compute_digest_client_request(
    request: &ClientRequest,
) -> [u8; GOSSIP_SEEN_DIGEST_SIZE] {
    sha256(&request.encode_to_vec())
}

/// `location_store_compute_digest_envelope`.
pub fn location_store_compute_digest_envelope(
    envelope: &Envelope,
) -> [u8; GOSSIP_SEEN_DIGEST_SIZE] {
    sha256(&envelope.encode_to_vec())
}
// ---------------------------------------------------------------------------
// Permission model (`src/structs/permission/permission.h`, consumed by
// `permissions.c`). Flag values are copied exactly.
// ---------------------------------------------------------------------------

pub const PERMISSION_SEND_MESSAGE: u64 = 1 << 0;
pub const PERMISSION_READ_MESSAGE: u64 = 1 << 1;
pub const PERMISSION_DELETE_MESSAGE: u64 = 1 << 2;
pub const PERMISSION_EDIT_MESSAGE: u64 = 1 << 3;
pub const PERMISSION_FORWARD_MESSAGE: u64 = 1 << 4;
pub const PERMISSION_SEND_EMERGENCY: u64 = 1 << 5;
pub const PERMISSION_CREATE_GROUP: u64 = 1 << 16;
pub const PERMISSION_DELETE_GROUP: u64 = 1 << 17;
pub const PERMISSION_EDIT_GROUP: u64 = 1 << 18;
pub const PERMISSION_INVITE_USERS: u64 = 1 << 19;
pub const PERMISSION_REMOVE_USERS: u64 = 1 << 20;
pub const PERMISSION_APPROVE_MEMBERS: u64 = 1 << 21;
pub const PERMISSION_MODERATE_GROUP: u64 = 1 << 22;
pub const PERMISSION_VIEW_STATUS: u64 = 1 << 32;
pub const PERMISSION_VIEW_LOCATION: u64 = 1 << 33;
pub const PERMISSION_TRACK_LOCATION: u64 = 1 << 34;
pub const PERMISSION_MANAGE_CONTACTS: u64 = 1 << 35;
pub const PERMISSION_APPROVE_CONTACTS: u64 = 1 << 36;
pub const PERMISSION_MONITOR_ACTIVITY: u64 = 1 << 37;
pub const PERMISSION_SET_BOUNDARIES: u64 = 1 << 38;
pub const PERMISSION_SET_CONTROLS: u64 = 1 << 48;
pub const PERMISSION_VIEW_CONTROLS: u64 = 1 << 49;
pub const PERMISSION_SET_CONTENT_FILTERS: u64 = 1 << 50;
pub const PERMISSION_VIEW_CONTENT_FILTERS: u64 = 1 << 51;
pub const PERMISSION_MANAGE_ROLES: u64 = 1 << 52;
pub const PERMISSION_VIEW_LOGS: u64 = 1 << 53;
pub const PERMISSION_MANAGE_SETTINGS: u64 = 1 << 54;
pub const PERMISSION_VIEW_SETTINGS: u64 = 1 << 55;

pub const CONDITION_ALWAYS: u64 = 1 << 0;
pub const CONDITION_TIME_RESTRICTED: u64 = 1 << 1;
pub const CONDITION_APPROVAL_REQUIRED: u64 = 1 << 2;
pub const CONDITION_EMERGENCY_ONLY: u64 = 1 << 3;

/// `permission_scope_t` from `permission.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionScope {
    SelfScope = 0,
    Direct = 1,
    PrimaryGroup = 2,
    ExtendedGroup = 3,
    ContactGroup = 4,
    Community = 5,
    Organization = 6,
    Global = 7,
    SupervisedUsers = 8,
    PeerUsers = 9,
}

impl PermissionScope {
    /// Scope bitmask bit (`1 << scope` in C).
    pub fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// C `PermissionSet`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermissionSet {
    pub permissions: u64,
    pub scopes: u32,
    pub conditions: u64,
    pub time_start: u64,
    pub time_end: u64,
}

/// C `Role`. `permission_set_count` is `permission_sets.len()`;
/// the C `created/modified_timestamp` are always 0 for DB-loaded
/// roles ("Not stored in DB" in `permissions.c`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Role {
    pub role_name: String,
    pub permission_sets: Vec<PermissionSet>,
    pub created_timestamp: u64,
    pub modified_timestamp: u64,
}

/// `is_permission_set_active` from `permission.c`.
pub fn is_permission_set_active(set: &PermissionSet, current_time: u64) -> bool {
    if set.conditions & CONDITION_TIME_RESTRICTED == 0 {
        return true;
    }
    if set.time_start > 0 && current_time < set.time_start {
        return false;
    }
    if set.time_end > 0 && current_time > set.time_end {
        return false;
    }
    true
}

/// `has_permission_in_scope` from `permission.c`, over a set list.
pub fn has_permission_in_scope(
    sets: &[PermissionSet],
    permission: u64,
    scope: PermissionScope,
    current_time: u64,
) -> bool {
    sets.iter().any(|s| {
        s.permissions & permission != 0
            && s.scopes & scope.bit() != 0
            && is_permission_set_active(s, current_time)
    })
}

/// C `GossipPeerInfo` (`gossip_peers.h`). The address-book row;
/// `node_pubkey` is display-only and is filled from the
/// `node_trust` table (see [`NodeTrustEntry`]), never stored in
/// `gossip_peers` anymore (DESIGN.md §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipPeerInfo {
    pub hostname: String,
    pub gossip_port: u16,
    pub api_port: u16,
    pub node_pubkey: [u8; PUBKEY_SIZE],
    pub first_seen: u64,
    pub last_seen: u64,
    pub tags: String,
}

/// One row of the `node_trust` table: a node/member public key
/// whose gossip this node accepts (the ingest whitelist).
/// Trust lives apart from the `gossip_peers` address book
/// (DESIGN.md §10): discovery/bootstrap write addresses only and
/// can never modify trust; trust rows are written only by
/// explicit trust operations (enrollment, seeding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTrustEntry {
    pub node_pubkey: [u8; PUBKEY_SIZE],
    /// Address hint recorded when trust was granted (may be
    /// empty when the grant was not tied to an address).
    pub hostname: String,
    /// Epoch seconds when trust was first granted.
    pub trusted_at: u64,
    /// How trust was granted (`enrollment`, `seed`, `migrated`,
    /// ...), free-form.
    pub source: String,
}

/// Lifecycle status of a row in the `devices` table
/// (DESIGN.md §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// The member's certificate for this device is on record
    /// and has not been revoked.
    Active,
    /// The device was revoked. The row is kept as an audit
    /// trail; the device is not trusted.
    Revoked,
}

impl DeviceStatus {
    fn as_str(&self) -> &'static str {
        match self {
            DeviceStatus::Active => "active",
            DeviceStatus::Revoked => "revoked",
        }
    }

    /// Parse a stored status. Anything that is not exactly
    /// `active` reads as [`DeviceStatus::Revoked`] — an
    /// unrecognized status must fail closed, never grant trust.
    fn from_db(text: &str) -> DeviceStatus {
        if text == DeviceStatus::Active.as_str() {
            DeviceStatus::Active
        } else {
            DeviceStatus::Revoked
        }
    }
}

/// One row of the `devices` table: a device key a member has
/// vouched for with a device certificate (DESIGN.md §3.1),
/// recorded by enrollment. The certificate itself is stored
/// (serialized `DeviceCertificate` protobuf plus its SHA-256)
/// so trust checks can re-verify it instead of trusting the
/// row's say-so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// The member who vouched for the device.
    pub member_pubkey: [u8; PUBKEY_SIZE],
    /// The device's public key.
    pub device_pubkey: [u8; PUBKEY_SIZE],
    /// The device label from its certificate.
    pub label: String,
    /// Serialized `DeviceCertificate` protobuf, as stored.
    pub cert: Vec<u8>,
    /// SHA-256 of `cert`.
    pub cert_hash: [u8; 32],
    /// Active or revoked (revocation keeps the row).
    pub status: DeviceStatus,
    /// Certificate `issued_at` (epoch seconds).
    pub issued_at: u64,
    /// Certificate `expires_at` (epoch seconds; 0 = never).
    pub expires_at: u64,
    /// When the device was revoked, if it was.
    pub revoked_at: Option<u64>,
    /// Row creation time (epoch seconds).
    pub created_at: u64,
    /// Last row modification (epoch seconds).
    pub updated_at: u64,
}

/// Parental visibility level for a child's group conversations
/// (William's decision, Nov 14, 2026): how much of the child's
/// group chats a parent who is NOT a conversation member may
/// see. Stored per child in `visibility_settings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityLevel {
    /// The parent receives nothing: no key, no metadata.
    None,
    /// The parent receives content-free metadata records
    /// (conversation id, sender, recipients, timestamp) but
    /// no session key.
    RecipientsAndTimes,
    /// The parent's devices receive session shares like a
    /// member's and can read the content.
    Full,
}

impl VisibilityLevel {
    /// The stored text form.
    pub fn as_str(&self) -> &'static str {
        match self {
            VisibilityLevel::None => "none",
            VisibilityLevel::RecipientsAndTimes => "recipients_and_times",
            VisibilityLevel::Full => "full",
        }
    }

    /// Parse a stored level. Anything unrecognized reads as
    /// [`VisibilityLevel::None`] — visibility fails closed,
    /// never open.
    fn from_db(text: &str) -> VisibilityLevel {
        match text {
            "recipients_and_times" => VisibilityLevel::RecipientsAndTimes,
            "full" => VisibilityLevel::Full,
            _ => VisibilityLevel::None,
        }
    }
}

/// One row of the `sessions` table (Phase B4, DESIGN.md §9):
/// one device's ratchet state for one sender session. The row
/// is keyed by (session, owning device) because every device
/// keeps its own copy of the state: the sender's device holds
/// the `own` row it encrypts with, and every recipient device
/// holds a `received` row it decrypts with. `chain_key` is the
/// current hash-ratchet chain key (the session root key before
/// the first message); it only ever moves forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// 16-byte session identifier.
    pub session_id: Vec<u8>,
    /// The device whose local state this row is.
    pub owner_device_pubkey: [u8; PUBKEY_SIZE],
    /// 16-byte conversation (group) identifier.
    pub group_id: Vec<u8>,
    /// The member who sends in this session.
    pub sender_member_pubkey: [u8; PUBKEY_SIZE],
    /// The device of that member which sends in this session.
    pub sender_device_pubkey: [u8; PUBKEY_SIZE],
    /// `own` (we send) or `received` (we read).
    pub direction: String,
    /// Current ratchet chain key (32 bytes).
    pub chain_key: Vec<u8>,
    /// Index of the next message under the current chain key.
    pub next_index: u64,
    /// Row creation time (epoch seconds).
    pub created_at: u64,
    /// Last state advance (epoch seconds).
    pub updated_at: u64,
}

/// One row of the `pairing_codes` table (Phase B3 enrollment,
/// DESIGN.md §3.2/§4.2): a pending join request. The table is
/// server-side only and never gossiped; the code itself is never
/// stored, only its SHA-256 (`code_hash`), so a database leak
/// does not leak usable codes. A pairing is created by the
/// joining device's `/enroll/begin`, completed exactly once by
/// an approved `/enroll/approve`, and otherwise dies at
/// `expires_at` (~10 minutes after creation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// SHA-256 of the pairing code (the lookup key).
    pub code_hash: [u8; 32],
    /// The joining member key (from the device certificate).
    pub member_pubkey: [u8; PUBKEY_SIZE],
    /// The joining device key (from the device certificate).
    pub device_pubkey: [u8; PUBKEY_SIZE],
    /// Display name the member will be registered under.
    pub display_name: String,
    /// Serialized `DeviceCertificate` protobuf, as submitted.
    pub cert: Vec<u8>,
    /// SHA-256 of `cert` (the value approvals bind).
    pub cert_hash: [u8; 32],
    /// `pending`, `used`, or `expired`.
    pub status: String,
    /// Pairing creation time (epoch seconds).
    pub created_at: u64,
    /// Pairing expiry (epoch seconds); approvals at or after
    /// this instant are rejected.
    pub expires_at: u64,
    /// When the pairing was completed, if it was.
    pub used_at: Option<u64>,
}

/// One row of the `enrollments` table (Phase B3): the audit
/// record of one completed enrollment — the UserRegistration
/// (content type 1) and device certificate (content type 3) a
/// member/device pair entered the household with, and who
/// authorized it. For a parent approval, `approval_signature`
/// is the approver's device key over the enrollment approval
/// digest (see `crate::identity::enrollment_approval_digest`);
/// for a recovery approval it is the household recovery key's
/// signature over the same digest; for the founding bootstrap
/// (`approver_kind = "founder"`) there is no approver and the
/// signature is empty — the setup-time CLI is the authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRecord {
    /// Row id (0 before insertion).
    pub id: i64,
    /// The enrolled member key.
    pub member_pubkey: [u8; PUBKEY_SIZE],
    /// The enrolled device key.
    pub device_pubkey: [u8; PUBKEY_SIZE],
    /// SHA-256 of the enrolled device certificate.
    pub cert_hash: [u8; 32],
    /// `founder`, `parent`, or `recovery`.
    pub approver_kind: String,
    /// Approving parent's member key (parent approvals only).
    pub approver_member_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// Approving parent's device key (parent approvals only).
    pub approver_device_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// Household recovery key (recovery approvals only).
    pub recovery_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// The approval signature over the enrollment approval
    /// digest (empty for the founding bootstrap).
    pub approval_signature: Vec<u8>,
    /// Timestamp the approval signature covers.
    pub approval_timestamp: u64,
    /// When the enrollment completed (epoch seconds).
    pub created_at: u64,
}

/// The approver half of a pairing completion, handed to
/// [`Store::pairing_complete`] after the API layer has verified
/// the approval signature and the approver's standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingApproval {
    /// `parent` or `recovery`.
    pub approver_kind: String,
    /// Approving parent's member key (parent approvals only).
    pub approver_member_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// Approving parent's device key (parent approvals only).
    pub approver_device_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// Household recovery key (recovery approvals only).
    pub recovery_pubkey: Option<[u8; PUBKEY_SIZE]>,
    /// The verified approval signature, stored as evidence.
    pub approval_signature: Vec<u8>,
    /// Timestamp the approval signature covers.
    pub approval_timestamp: u64,
}

/// Outcome of [`Store::pairing_complete`]: the completion is
/// atomic, so a pairing either enrolls fully or not at all, and
/// a code completes at most once however many approvals race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingCompleteOutcome {
    /// User row, device row, and enrollment record written;
    /// the pairing is now `used`.
    Completed,
    /// No pairing exists for the code hash.
    UnknownCode,
    /// The pairing was already completed.
    AlreadyUsed,
    /// The pairing expired before completion.
    Expired,
}

/// One row of the C `nodes` table (`nodes_get_by_id` out-params).
/// Nullable text columns surface as empty strings, as in C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_name: String,
    pub hostname: String,
    pub gossip_port: u16,
    pub api_port: u16,
    pub discovery_mode: String,
    pub hostname_prefix: String,
    pub dns_domain: String,
}

/// Serialized location payload (`location_store_get_latest` outputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationData {
    /// Prost encoding of a `ClientRequest` or an `Envelope`.
    pub data: Vec<u8>,
    /// True if `data` is an `Envelope`, false if a `ClientRequest`.
    pub is_envelope: bool,
}
// ---------------------------------------------------------------------------
// SQL text, copied verbatim from the C sources (same tables, columns,
// types, indexes). Query constants keep their C names.
// ---------------------------------------------------------------------------

/// `SQL_SELECT_USER_BY_PUBKEY` (`schema.c`).
pub const SQL_SELECT_USER_BY_PUBKEY: &str =
    "SELECT id, pubkey, username, age, created_at, updated_at, is_active FROM users WHERE pubkey = ?;";
/// `SQL_SELECT_USER_ROLES` (`schema.c`).
pub const SQL_SELECT_USER_ROLES: &str = "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, r.name as role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ? AND ur.is_active = 1;";
/// `SQL_SELECT_ROLE_PERMISSIONS` (`schema.c`).
pub const SQL_SELECT_ROLE_PERMISSIONS: &str = "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, rp.scope_flags, rp.condition_flags, rp.time_start, rp.time_end, p.name as permission_name, p.permission_flags, p.category FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ? AND rp.is_active = 1;";
/// `SQL_INSERT_ROLE_PERMISSION` (`schema.c`).
pub const SQL_INSERT_ROLE_PERMISSION: &str = "INSERT OR REPLACE INTO role_permissions (role_id, permission_id, granted_by_user_id, scope_flags, condition_flags, time_start, time_end) VALUES (?, ?, ?, ?, ?, ?, ?);";
/// `SQL_INSERT_OR_UPDATE_NODE` (`schema.c`).
pub const SQL_INSERT_OR_UPDATE_NODE: &str = "INSERT INTO nodes (node_id, node_name, hostname, gossip_port, api_port, discovery_mode, hostname_prefix, dns_domain, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now')) ON CONFLICT(node_id) DO UPDATE SET node_name=excluded.node_name, hostname=excluded.hostname, gossip_port=excluded.gossip_port, api_port=excluded.api_port, discovery_mode=excluded.discovery_mode, hostname_prefix=excluded.hostname_prefix, dns_domain=excluded.dns_domain, updated_at=strftime('%s','now');";
/// `SQL_SELECT_NODE_BY_ID` (`schema.c`).
pub const SQL_SELECT_NODE_BY_ID: &str = "SELECT node_id, node_name, hostname, gossip_port, api_port, discovery_mode, hostname_prefix, dns_domain FROM nodes WHERE node_id = ?;";

const CREATE_GOSSIP_MESSAGES: &str = "CREATE TABLE IF NOT EXISTS gossip_messages (id INTEGER PRIMARY KEY AUTOINCREMENT,type INTEGER NOT NULL,sender BLOB NOT NULL,timestamp INTEGER NOT NULL,payload BLOB NOT NULL,payload_size INTEGER NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_IDX_GOSSIP_EXPIRES: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_expires_at ON gossip_messages(expires_at);";
const CREATE_IDX_GOSSIP_SENDER: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_sender ON gossip_messages(sender);";
const CREATE_GOSSIP_ENVELOPES: &str = "CREATE TABLE IF NOT EXISTS gossip_envelopes (id INTEGER PRIMARY KEY AUTOINCREMENT,version INTEGER NOT NULL,content_type INTEGER NOT NULL,schema_version INTEGER NOT NULL,timestamp INTEGER NOT NULL,sender BLOB NOT NULL,group_id BLOB,payload_nonce BLOB NOT NULL,ephemeral_pubkey BLOB NOT NULL,encrypted_payload BLOB NOT NULL,signature BLOB NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_IDX_ENV_EXPIRES: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_env_expires ON gossip_envelopes(expires_at);";
const CREATE_IDX_ENV_SENDER: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_env_sender ON gossip_envelopes(sender);";
const CREATE_ENVELOPE_RECIPIENTS: &str = "CREATE TABLE IF NOT EXISTS gossip_envelope_recipients (envelope_id INTEGER NOT NULL,recipient_pubkey BLOB NOT NULL,key_nonce BLOB NOT NULL,wrapped_key BLOB NOT NULL,PRIMARY KEY (envelope_id, recipient_pubkey),FOREIGN KEY (envelope_id) REFERENCES gossip_envelopes(id) ON DELETE CASCADE);";
const CREATE_IDX_ENV_RECIPIENT: &str = "CREATE INDEX IF NOT EXISTS idx_gossip_env_recipient ON gossip_envelope_recipients(recipient_pubkey);";
const CREATE_USERS: &str = "CREATE TABLE IF NOT EXISTS users (    id INTEGER PRIMARY KEY AUTOINCREMENT,    pubkey TEXT NOT NULL UNIQUE,    username TEXT NOT NULL,    age INTEGER,    registration_transaction_id INTEGER,    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    is_active INTEGER DEFAULT 1);";
const CREATE_ROLES: &str = "CREATE TABLE IF NOT EXISTS roles (    id INTEGER PRIMARY KEY AUTOINCREMENT,    name TEXT NOT NULL UNIQUE,    description TEXT,    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_PERMISSIONS: &str = "CREATE TABLE IF NOT EXISTS permissions (    id INTEGER PRIMARY KEY AUTOINCREMENT,    name TEXT NOT NULL UNIQUE,    permission_flags INTEGER NOT NULL,    scope_flags INTEGER NOT NULL,    condition_flags INTEGER NOT NULL,    category INTEGER NOT NULL,    description TEXT,    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_USER_ROLES: &str = "CREATE TABLE IF NOT EXISTS user_roles (    id INTEGER PRIMARY KEY AUTOINCREMENT,    user_id INTEGER NOT NULL,    role_id INTEGER NOT NULL,    assigned_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    assigned_by_user_id INTEGER,    assignment_transaction_id INTEGER,    is_active INTEGER DEFAULT 1,    UNIQUE(user_id, role_id));";
const CREATE_ROLE_PERMISSIONS: &str = "CREATE TABLE IF NOT EXISTS role_permissions (    id INTEGER PRIMARY KEY AUTOINCREMENT,    role_id INTEGER NOT NULL,    permission_id INTEGER NOT NULL,    granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    granted_by_user_id INTEGER,    grant_transaction_id INTEGER,    scope_flags INTEGER NOT NULL DEFAULT 0,    condition_flags INTEGER NOT NULL DEFAULT 0,    time_start INTEGER,    time_end INTEGER,    is_active INTEGER DEFAULT 1,    UNIQUE(role_id, permission_id));";
const CREATE_TRANSACTION_PERMISSIONS: &str = "CREATE TABLE IF NOT EXISTS transaction_permissions (    txn_type INTEGER PRIMARY KEY,    required_permission INTEGER NOT NULL,    required_scope INTEGER NOT NULL);";
const CREATE_GOSSIP_SEEN: &str =
    "CREATE TABLE IF NOT EXISTS gossip_seen (    digest BLOB PRIMARY KEY,    expires_at INTEGER NOT NULL);";
const CREATE_NODES: &str = "CREATE TABLE IF NOT EXISTS nodes (    node_id TEXT PRIMARY KEY,    node_name TEXT NOT NULL,    hostname TEXT NOT NULL,    gossip_port INTEGER NOT NULL,    api_port INTEGER NOT NULL,    discovery_mode TEXT NOT NULL,    hostname_prefix TEXT,    dns_domain TEXT,    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_IDX_USERS_PUBKEY: &str =
    "CREATE INDEX IF NOT EXISTS idx_users_pubkey ON users(pubkey);";
const CREATE_IDX_ROLES_NAME: &str = "CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);";
const CREATE_IDX_USER_ROLES_USER: &str =
    "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);";
const CREATE_IDX_USER_ROLES_ROLE: &str =
    "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);";
const CREATE_IDX_ROLE_PERMS_ROLE: &str =
    "CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);";
const CREATE_IDX_SEEN_EXPIRES: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_seen_expires ON gossip_seen(expires_at);";
const CREATE_IDX_NODES_ID: &str =
    "CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id);";

const CREATE_USER_MESSAGES: &str = "CREATE TABLE IF NOT EXISTS user_messages (id INTEGER PRIMARY KEY AUTOINCREMENT,version INTEGER NOT NULL,timestamp INTEGER NOT NULL,sender_pubkey BLOB NOT NULL,recipient_pubkey BLOB NOT NULL,group_id BLOB,payload_nonce BLOB NOT NULL,ephemeral_pubkey BLOB NOT NULL,encrypted_payload BLOB NOT NULL,signature BLOB NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_MESSAGE_RECIPIENTS: &str = "CREATE TABLE IF NOT EXISTS message_recipients (message_id INTEGER NOT NULL,recipient_pubkey BLOB NOT NULL,key_nonce BLOB NOT NULL,wrapped_key BLOB NOT NULL,PRIMARY KEY (message_id, recipient_pubkey),FOREIGN KEY (message_id) REFERENCES user_messages(id) ON DELETE CASCADE);";
const CREATE_IDX_MSG_TIMESTAMP: &str =
    "CREATE INDEX IF NOT EXISTS idx_user_messages_timestamp ON user_messages(timestamp DESC);";
const CREATE_IDX_MSG_SENDER: &str = "CREATE INDEX IF NOT EXISTS idx_user_messages_sender ON user_messages(sender_pubkey, timestamp DESC);";
const CREATE_IDX_MSG_RECIPIENT: &str = "CREATE INDEX IF NOT EXISTS idx_user_messages_recipient ON user_messages(recipient_pubkey, timestamp DESC);";
const CREATE_IDX_MSG_CONVERSATION: &str = "CREATE INDEX IF NOT EXISTS idx_user_messages_conversation ON user_messages(sender_pubkey, recipient_pubkey, timestamp DESC);";
const CREATE_IDX_MSG_GROUP: &str = "CREATE INDEX IF NOT EXISTS idx_user_messages_group ON user_messages(group_id, timestamp DESC) WHERE group_id IS NOT NULL;";
const CREATE_IDX_MSG_EXPIRES: &str =
    "CREATE INDEX IF NOT EXISTS idx_user_messages_expires ON user_messages(expires_at);";
const CREATE_IDX_MSG_RECIPIENTS: &str = "CREATE INDEX IF NOT EXISTS idx_message_recipients_recipient ON message_recipients(recipient_pubkey);";

const CREATE_LOCATION_UPDATES: &str = "CREATE TABLE IF NOT EXISTS location_updates (id INTEGER PRIMARY KEY AUTOINCREMENT,user_pubkey BLOB NOT NULL,timestamp INTEGER NOT NULL,payload_nonce BLOB NOT NULL,ephemeral_pubkey BLOB NOT NULL,encrypted_payload BLOB NOT NULL,signature BLOB NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),is_envelope INTEGER NOT NULL DEFAULT 0);";
const CREATE_LOCATION_KEYWRAPS: &str = "CREATE TABLE IF NOT EXISTS location_keywraps (location_id INTEGER NOT NULL,recipient_pubkey BLOB NOT NULL,key_nonce BLOB NOT NULL,wrapped_key BLOB NOT NULL,PRIMARY KEY (location_id, recipient_pubkey),FOREIGN KEY (location_id) REFERENCES location_updates(id) ON DELETE CASCADE);";
const CREATE_IDX_LOC_USER_TS: &str = "CREATE INDEX IF NOT EXISTS idx_location_updates_user_timestamp ON location_updates(user_pubkey, timestamp DESC);";
const CREATE_IDX_LOC_EXPIRES: &str =
    "CREATE INDEX IF NOT EXISTS idx_location_updates_expires ON location_updates(expires_at);";
const CREATE_IDX_LOC_KEYWRAPS: &str = "CREATE INDEX IF NOT EXISTS idx_location_keywraps_recipient ON location_keywraps(recipient_pubkey);";

const CREATE_GOSSIP_PEERS: &str = "CREATE TABLE IF NOT EXISTS gossip_peers ( hostname TEXT PRIMARY KEY, gossip_port INTEGER NOT NULL, api_port INTEGER NOT NULL, node_pubkey BLOB, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, tags TEXT);";
const ADD_PEERS_API_PORT: &str =
    "ALTER TABLE gossip_peers ADD COLUMN api_port INTEGER NOT NULL DEFAULT 0;";
const CREATE_IDX_PEERS_LAST_SEEN: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_peers_last_seen ON gossip_peers(last_seen);";
const CREATE_IDX_PEERS_PUBKEY: &str =
    "CREATE INDEX IF NOT EXISTS idx_gossip_peers_node_pubkey ON gossip_peers(node_pubkey);";
const CREATE_NODE_TRUST: &str = "CREATE TABLE IF NOT EXISTS node_trust ( node_pubkey BLOB PRIMARY KEY, hostname TEXT, trusted_at INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '');";
const CREATE_DEVICES: &str = "CREATE TABLE IF NOT EXISTS devices ( member_pubkey BLOB NOT NULL, device_pubkey BLOB NOT NULL, label TEXT NOT NULL DEFAULT '', cert BLOB NOT NULL, cert_hash BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active', issued_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY (member_pubkey, device_pubkey));";
const CREATE_PAIRING_CODES: &str = "CREATE TABLE IF NOT EXISTS pairing_codes ( code_hash BLOB PRIMARY KEY, member_pubkey BLOB NOT NULL, device_pubkey BLOB NOT NULL, display_name TEXT NOT NULL DEFAULT '', cert BLOB NOT NULL, cert_hash BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);";
const CREATE_ENROLLMENTS: &str = "CREATE TABLE IF NOT EXISTS enrollments ( id INTEGER PRIMARY KEY AUTOINCREMENT, member_pubkey BLOB NOT NULL, device_pubkey BLOB NOT NULL, cert_hash BLOB NOT NULL, approver_kind TEXT NOT NULL, approver_member_pubkey BLOB, approver_device_pubkey BLOB, recovery_pubkey BLOB, approval_signature BLOB NOT NULL, approval_timestamp INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);";
const CREATE_RECOVERY_APPROVERS: &str = "CREATE TABLE IF NOT EXISTS recovery_approvers ( recovery_pubkey BLOB PRIMARY KEY, label TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);";
const CREATE_MESSAGE_SESSIONS: &str = "CREATE TABLE IF NOT EXISTS message_sessions ( message_id INTEGER PRIMARY KEY, session_id BLOB NOT NULL, message_index INTEGER NOT NULL, FOREIGN KEY (message_id) REFERENCES user_messages(id) ON DELETE CASCADE);";
const CREATE_SESSIONS: &str = "CREATE TABLE IF NOT EXISTS sessions ( session_id BLOB NOT NULL, owner_device_pubkey BLOB NOT NULL, group_id BLOB NOT NULL, sender_member_pubkey BLOB NOT NULL, sender_device_pubkey BLOB NOT NULL, direction TEXT NOT NULL DEFAULT 'received', chain_key BLOB NOT NULL, next_index INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY (session_id, owner_device_pubkey));";
const CREATE_SESSION_SKIPPED_KEYS: &str = "CREATE TABLE IF NOT EXISTS session_skipped_keys ( session_id BLOB NOT NULL, owner_device_pubkey BLOB NOT NULL, message_index INTEGER NOT NULL, message_key BLOB NOT NULL, PRIMARY KEY (session_id, owner_device_pubkey, message_index));";
const CREATE_GROUP_KEY_SHARES: &str = "CREATE TABLE IF NOT EXISTS group_key_shares ( id INTEGER PRIMARY KEY AUTOINCREMENT, session_id BLOB NOT NULL, group_id BLOB NOT NULL, sender_member_pubkey BLOB NOT NULL, sender_device_pubkey BLOB NOT NULL, recipient_member_pubkey BLOB NOT NULL, recipient_device_pubkey BLOB NOT NULL, envelope BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_PARENT_LINKS: &str = "CREATE TABLE IF NOT EXISTS parent_links ( parent_member_pubkey BLOB NOT NULL, child_member_pubkey BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY (parent_member_pubkey, child_member_pubkey));";
const CREATE_VISIBILITY_SETTINGS: &str = "CREATE TABLE IF NOT EXISTS visibility_settings ( child_member_pubkey BLOB PRIMARY KEY, level TEXT NOT NULL DEFAULT 'none', set_by BLOB NOT NULL, updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));";
const CREATE_CONVERSATION_MEMBERS: &str = "CREATE TABLE IF NOT EXISTS conversation_members ( group_id BLOB NOT NULL, member_pubkey BLOB NOT NULL, joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY (group_id, member_pubkey));";

/// Statements of `gossip_store_init`, in C execution order.
const GOSSIP_SCHEMA: &[&str] = &[
    CREATE_GOSSIP_MESSAGES,
    CREATE_IDX_GOSSIP_EXPIRES,
    CREATE_IDX_GOSSIP_SENDER,
    CREATE_GOSSIP_ENVELOPES,
    CREATE_IDX_ENV_EXPIRES,
    CREATE_IDX_ENV_SENDER,
    CREATE_ENVELOPE_RECIPIENTS,
    CREATE_IDX_ENV_RECIPIENT,
    CREATE_USERS,
    CREATE_ROLES,
    CREATE_PERMISSIONS,
    CREATE_USER_ROLES,
    CREATE_ROLE_PERMISSIONS,
    CREATE_TRANSACTION_PERMISSIONS,
    CREATE_GOSSIP_SEEN,
    CREATE_NODES,
    CREATE_IDX_USERS_PUBKEY,
    CREATE_IDX_ROLES_NAME,
    CREATE_IDX_USER_ROLES_USER,
    CREATE_IDX_USER_ROLES_ROLE,
    CREATE_IDX_ROLE_PERMS_ROLE,
    CREATE_IDX_SEEN_EXPIRES,
    CREATE_IDX_NODES_ID,
];

/// Statements of `schema_migrate` 0 -> 1. Note: like the C code,
/// this omits `gossip_envelope_recipients` and `nodes`.
const MIGRATE_0_TO_1: &[&str] = &[
    CREATE_GOSSIP_MESSAGES,
    CREATE_IDX_GOSSIP_EXPIRES,
    CREATE_IDX_GOSSIP_SENDER,
    CREATE_GOSSIP_ENVELOPES,
    CREATE_IDX_ENV_EXPIRES,
    CREATE_IDX_ENV_SENDER,
    CREATE_USERS,
    CREATE_ROLES,
    CREATE_PERMISSIONS,
    CREATE_USER_ROLES,
    CREATE_ROLE_PERMISSIONS,
    CREATE_TRANSACTION_PERMISSIONS,
    CREATE_GOSSIP_SEEN,
    CREATE_IDX_USERS_PUBKEY,
    CREATE_IDX_ROLES_NAME,
    CREATE_IDX_USER_ROLES_USER,
    CREATE_IDX_USER_ROLES_ROLE,
    CREATE_IDX_ROLE_PERMS_ROLE,
    CREATE_IDX_SEEN_EXPIRES,
];

const MESSAGE_SCHEMA: &[&str] = &[
    CREATE_USER_MESSAGES,
    CREATE_MESSAGE_RECIPIENTS,
    CREATE_MESSAGE_SESSIONS,
    CREATE_IDX_MSG_TIMESTAMP,
    CREATE_IDX_MSG_SENDER,
    CREATE_IDX_MSG_RECIPIENT,
    CREATE_IDX_MSG_CONVERSATION,
    CREATE_IDX_MSG_GROUP,
    CREATE_IDX_MSG_EXPIRES,
    CREATE_IDX_MSG_RECIPIENTS,
];

const LOCATION_SCHEMA: &[&str] = &[
    CREATE_LOCATION_UPDATES,
    CREATE_LOCATION_KEYWRAPS,
    CREATE_IDX_LOC_USER_TS,
    CREATE_IDX_LOC_EXPIRES,
    CREATE_IDX_LOC_KEYWRAPS,
];
// ---------------------------------------------------------------------------
// Store (`database_gossip.c` global handle, as an owned connection)
// ---------------------------------------------------------------------------

/// SQLite store. Replaces the C global handle: [`Store::open`] is
/// `db_init_gossip`, dropping the store is `db_close`.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// `db_init_gossip`: open (or create) a database file and switch
    /// it to WAL mode, exactly like the C code. Unlike C, opening a
    /// second store is fine; there is no global state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        // C: `PRAGMA journal_mode=WAL;` via sqlite3_exec, fatal on error.
        let _: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
        Ok(Store { conn })
    }

    /// In-memory database, for tests. No WAL pragma (meaningless for
    /// `:memory:`, which reports mode `memory`).
    pub fn open_in_memory() -> Result<Self> {
        Ok(Store {
            conn: Connection::open_in_memory()?,
        })
    }

    /// Borrow the raw connection (`db_get_handle`). Mainly so callers
    /// (and tests) can seed/query tables this module only reads,
    /// such as `users`/`roles` for the permission checks.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn exec_all(&self, statements: &[&str]) -> Result<()> {
        for sql in statements {
            self.conn.execute_batch(sql)?;
        }
        Ok(())
    }

    /// Create every table of the package (convenience combining
    /// `gossip_store_init` + `message_store_init` +
    /// `location_store_init` + `gossip_peers_init`, the combination
    /// the C test harness sets up). Idempotent.
    pub fn init_schema(&self) -> Result<()> {
        self.gossip_store_init()?;
        self.message_store_init()?;
        self.location_store_init()?;
        self.gossip_peers_init()?;
        Ok(())
    }

    // -- schema.c: gossip store -------------------------------------

    /// `gossip_store_init`: gossip_messages/gossip_envelopes/
    /// recipients, users/roles/permissions family, gossip_seen, nodes.
    pub fn gossip_store_init(&self) -> Result<()> {
        self.exec_all(GOSSIP_SCHEMA)
    }

    /// `message_store_init`.
    pub fn message_store_init(&self) -> Result<()> {
        self.exec_all(MESSAGE_SCHEMA)
    }

    /// `location_store_init`.
    pub fn location_store_init(&self) -> Result<()> {
        self.exec_all(LOCATION_SCHEMA)
    }

    /// `gossip_store_cleanup`: delete rows with
    /// `expires_at <= now_epoch` from gossip_envelopes and
    /// user_messages (missing tables ignored, as in C) and
    /// gossip_seen (error if missing, as in C). Like the C code this
    /// does NOT touch gossip_messages or location_updates.
    pub fn gossip_store_cleanup(&self, now_epoch: u64) -> Result<()> {
        let now = now_epoch as i64;
        let _ = self.conn.execute(
            "DELETE FROM gossip_envelopes WHERE expires_at <= ?;",
            params![now],
        );
        let _ = self.conn.execute(
            "DELETE FROM user_messages WHERE expires_at <= ?;",
            params![now],
        );
        self.conn.execute(
            "DELETE FROM gossip_seen WHERE expires_at <= ?;",
            params![now],
        )?;
        Ok(())
    }

    /// `gossip_store_has_seen` (also backs `message_store_has_seen`
    /// and `location_store_has_seen`, which delegate to it in C).
    pub fn gossip_store_has_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM gossip_seen WHERE digest = ? LIMIT 1")?;
        let mut rows = stmt.query(params![&digest[..]])?;
        Ok(rows.next()?.is_some())
    }

    /// `gossip_store_mark_seen` (`INSERT OR REPLACE`).
    pub fn gossip_store_mark_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
        expires_at: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO gossip_seen (digest, expires_at) VALUES (?, ?);",
            params![&digest[..], expires_at as i64],
        )?;
        Ok(())
    }

    /// `message_store_has_seen`: delegates to the gossip seen table.
    pub fn message_store_has_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
    ) -> Result<bool> {
        self.gossip_store_has_seen(digest)
    }

    /// `message_store_mark_seen`: delegates to the gossip seen table.
    pub fn message_store_mark_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
        expires_at: u64,
    ) -> Result<()> {
        self.gossip_store_mark_seen(digest, expires_at)
    }

    /// `location_store_has_seen`: delegates to the gossip seen table.
    pub fn location_store_has_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
    ) -> Result<bool> {
        self.gossip_store_has_seen(digest)
    }

    /// `location_store_mark_seen`: delegates to the gossip seen table.
    pub fn location_store_mark_seen(
        &self,
        digest: &[u8; GOSSIP_SEEN_DIGEST_SIZE],
        expires_at: u64,
    ) -> Result<()> {
        self.gossip_store_mark_seen(digest, expires_at)
    }
    /// `gossip_store_save_envelope`. Header fields and the encrypted
    /// payload are stored in separate columns; keywraps go to the
    /// recipients junction table. Invalid keywraps are skipped, as
    /// in C. Like C, this is not wrapped in a transaction.
    pub fn gossip_store_save_envelope(
        &self,
        envelope: &Envelope,
        expires_at: u64,
    ) -> Result<()> {
        let header = envelope
            .header
            .as_ref()
            .ok_or_else(|| invalid("envelope header missing"))?;
        if header.sender_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid sender_pubkey length"));
        }
        if envelope.payload_nonce.len() != 24 {
            return Err(invalid("invalid payload_nonce"));
        }
        if envelope.ephemeral_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid ephemeral_pubkey"));
        }
        if envelope.payload_ciphertext.is_empty() {
            return Err(invalid("invalid payload_ciphertext"));
        }
        if envelope.signature.len() != 64 {
            return Err(invalid("invalid signature"));
        }
        let group_id: Option<&[u8]> = if header.group_id.is_empty() {
            None
        } else {
            Some(&header.group_id[..])
        };
        self.conn.execute(
            "INSERT INTO gossip_envelopes(version, content_type, schema_version, timestamp, sender, group_id, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            params![
                header.version as i64,
                header.content_type as i64,
                header.schema_version as i64,
                header.timestamp as i64,
                &header.sender_pubkey[..],
                group_id,
                &envelope.payload_nonce[..],
                &envelope.ephemeral_pubkey[..],
                &envelope.payload_ciphertext[..],
                &envelope.signature[..],
                expires_at as i64,
            ],
        )?;
        let envelope_id = self.conn.last_insert_rowid();
        for wrap in &envelope.keywraps {
            if wrap.recipient_pubkey.len() != PUBKEY_SIZE {
                continue;
            }
            if wrap.key_nonce.len() != 24 {
                continue;
            }
            if wrap.wrapped_key.is_empty() {
                continue;
            }
            // C logs and continues on recipient insert failure.
            let _ = self.conn.execute(
                "INSERT INTO gossip_envelope_recipients(envelope_id, recipient_pubkey, key_nonce, wrapped_key) VALUES (?, ?, ?, ?);",
                params![
                    envelope_id,
                    &wrap.recipient_pubkey[..],
                    &wrap.key_nonce[..],
                    &wrap.wrapped_key[..]
                ],
            );
        }
        Ok(())
    }

    /// `gossip_store_fetch_recent_envelopes`. Preserves the C quirk:
    /// `envelope` carries only the `encrypted_payload` column here,
    /// not a serialized envelope (unlike the for-user variant).
    pub fn gossip_store_fetch_recent_envelopes(
        &self,
        limit: u32,
    ) -> Result<Vec<StoredEnvelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, version, content_type, schema_version, timestamp, sender, encrypted_payload, expires_at FROM gossip_envelopes ORDER BY timestamp DESC LIMIT ?;",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let sender: Vec<u8> = row.get(5)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                sender,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, version, content_type, schema_version, timestamp, sender, payload, exp) =
                row?;
            out.push(StoredEnvelope {
                id: id as u64,
                version: version as u32,
                content_type: content_type as u32,
                schema_version: schema_version as u32,
                timestamp: timestamp as u64,
                // C zero-fills sender unless the blob is exactly 32 bytes.
                sender: if sender.len() == PUBKEY_SIZE {
                    sender
                } else {
                    vec![0u8; PUBKEY_SIZE]
                },
                envelope: payload,
                expires_at: exp as u64,
            });
        }
        Ok(out)
    }

    fn envelope_keywraps(
        &self,
        envelope_id: i64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT recipient_pubkey, key_nonce, wrapped_key FROM gossip_envelope_recipients WHERE envelope_id = ?;",
        )?;
        let rows = stmt.query_map(params![envelope_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// `reconstruct_envelope_from_db` (`schema.c`). Returns `None`
    /// for malformed rows, which the C fetch then skips.
    #[allow(clippy::too_many_arguments)]
    fn reconstruct_envelope(
        &self,
        id: i64,
        version: u32,
        content_type: u32,
        schema_version: u32,
        timestamp: u64,
        sender: &[u8],
        group_id: Option<&[u8]>,
        payload_nonce: &[u8],
        ephemeral_pubkey: &[u8],
        encrypted_payload: &[u8],
        signature: &[u8],
    ) -> Result<Option<Envelope>> {
        if sender.len() != PUBKEY_SIZE
            || payload_nonce.len() != 24
            || ephemeral_pubkey.len() != PUBKEY_SIZE
            || signature.len() != 64
        {
            return Ok(None);
        }
        let wraps = self.envelope_keywraps(id)?;
        let mut recipients: Vec<Vec<u8>> = Vec::new();
        let mut keywraps: Vec<RecipientKeyWrap> = Vec::new();
        for (pk, nonce, key) in wraps {
            if pk.len() != PUBKEY_SIZE {
                continue;
            }
            recipients.push(pk.clone());
            keywraps.push(RecipientKeyWrap {
                recipient_pubkey: pk,
                key_nonce: nonce,
                wrapped_key: key,
            });
        }
        Ok(Some(Envelope {
            header: Some(EnvelopeHeader {
                version,
                content_type,
                schema_version,
                timestamp,
                sender_pubkey: sender.to_vec(),
                recipients_pubkey: recipients,
                group_id: group_id.map(|g| g.to_vec()).unwrap_or_default(),
            }),
            payload_nonce: payload_nonce.to_vec(),
            ephemeral_pubkey: ephemeral_pubkey.to_vec(),
            payload_ciphertext: encrypted_payload.to_vec(),
            keywraps,
            signature: signature.to_vec(),
        }))
    }

    /// `gossip_store_fetch_recent_envelopes_for_user`: envelopes the
    /// user sent or is a recipient of, newest first. Here `envelope`
    /// is the prost-serialized reconstructed envelope, as in C.
    pub fn gossip_store_fetch_recent_envelopes_for_user(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        limit: u32,
    ) -> Result<Vec<StoredEnvelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT e.id, e.version, e.content_type, e.schema_version, e.timestamp, e.sender, e.group_id, e.payload_nonce, e.ephemeral_pubkey, e.encrypted_payload, e.signature, e.expires_at FROM gossip_envelopes e LEFT JOIN gossip_envelope_recipients r ON e.id = r.envelope_id WHERE e.sender = ? OR r.recipient_pubkey = ? ORDER BY e.timestamp DESC LIMIT ?;",
        )?;
        let rows = stmt.query_map(
            params![&user_pubkey[..], &user_pubkey[..], limit as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )?;
        let mut raw = Vec::new();
        for r in rows {
            raw.push(r?);
        }
        let mut out = Vec::new();
        for (id, v, ct, sv, ts, sender, gid, nonce, eph, payload, sig, exp) in &raw {
            let env = self.reconstruct_envelope(
                *id,
                *v as u32,
                *ct as u32,
                *sv as u32,
                *ts as u64,
                sender,
                gid.as_deref(),
                nonce,
                eph,
                payload,
                sig,
            )?;
            if let Some(env) = env {
                out.push(StoredEnvelope {
                    id: *id as u64,
                    version: *v as u32,
                    content_type: *ct as u32,
                    schema_version: *sv as u32,
                    timestamp: *ts as u64,
                    sender: sender.clone(),
                    envelope: env.encode_to_vec(),
                    expires_at: *exp as u64,
                });
            }
        }
        Ok(out)
    }

    // -- schema.c: versioning and nodes ------------------------------

    /// `schema_check_version`: 0 when no `schema_version` table/row.
    pub fn schema_check_version(&self) -> Result<i32> {
        let mut stmt = self.conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';",
        )?;
        let exists = stmt.query(params![])?.next()?.is_some();
        drop(stmt);
        if !exists {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM schema_version WHERE id = 1;")?;
        let mut rows = stmt.query(params![])?;
        match rows.next()? {
            Some(row) => Ok(row.get::<_, i64>(0)? as i32),
            None => Ok(0),
        }
    }

    /// `schema_set_version`.
    pub fn schema_set_version(&self, version: i32) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (    id INTEGER PRIMARY KEY,    version INTEGER NOT NULL,    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));",
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO schema_version (id, version, updated_at) VALUES (1, ?, strftime('%s','now'));",
            params![version as i64],
        )?;
        Ok(())
    }

    /// `schema_migrate`. Faithful to C, including its quirk that a
    /// 0 -> 2 request stops at version 1.
    pub fn schema_migrate(&self, from_version: i32, to_version: i32) -> Result<()> {
        if from_version == 0 && to_version >= 1 {
            self.exec_all(MIGRATE_0_TO_1)?;
            self.schema_set_version(1)?;
            return Ok(());
        }
        if from_version == 1 && to_version >= 2 {
            self.conn.execute_batch(CREATE_NODES)?;
            self.conn.execute_batch(CREATE_IDX_NODES_ID)?;
            self.schema_set_version(2)?;
            return Ok(());
        }
        Err(Error::NoMigrationPath {
            from: from_version,
            to: to_version,
        })
    }

    /// `nodes_insert_or_update`. `None` prefix/domain bind as the
    /// empty string, exactly as the C code does.
    pub fn nodes_insert_or_update(&self, node: &NodeRecord) -> Result<()> {
        self.conn.execute(
            SQL_INSERT_OR_UPDATE_NODE,
            params![
                node.node_id,
                node.node_name,
                node.hostname,
                node.gossip_port as i64,
                node.api_port as i64,
                node.discovery_mode,
                node.hostname_prefix.as_str(),
                node.dns_domain.as_str(),
            ],
        )?;
        Ok(())
    }

    /// `nodes_get_by_id`: `Ok(None)` is C's "not found" (return 1).
    pub fn nodes_get_by_id(&self, node_id: &str) -> Result<Option<NodeRecord>> {
        let mut stmt = self.conn.prepare(SQL_SELECT_NODE_BY_ID)?;
        let mut rows = stmt.query(params![node_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(NodeRecord {
                node_id: row.get(0)?,
                node_name: row.get(1)?,
                hostname: row.get(2)?,
                gossip_port: row.get::<_, i64>(3)? as u16,
                api_port: row.get::<_, i64>(4)? as u16,
                discovery_mode: row.get(5)?,
                hostname_prefix: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                dns_domain: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })),
            None => Ok(None),
        }
    }
    // -- message_store.c ----------------------------------------------

    /// `message_store_save`. The primary recipient column is the
    /// first header recipient; all keywraps go to
    /// `message_recipients`. Runs in a transaction, as in C;
    /// individual keywrap insert failures are logged-and-skipped
    /// in C and likewise ignored here.
    pub fn message_store_save(&mut self, message: &Message, expires_at: u64) -> Result<()> {
        self.message_sessions_init()?;
        let header = message
            .header
            .as_ref()
            .ok_or_else(|| invalid("message header missing"))?;
        if header.sender_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid sender_pubkey length"));
        }
        if header.recipients_pubkey.is_empty() {
            return Err(invalid("no recipients"));
        }
        if header.recipients_pubkey[0].len() != PUBKEY_SIZE {
            return Err(invalid("invalid primary recipient_pubkey"));
        }
        if message.payload_nonce.len() != 24 {
            return Err(invalid("invalid payload_nonce"));
        }
        if message.ephemeral_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid ephemeral_pubkey"));
        }
        if message.payload_ciphertext.is_empty() {
            return Err(invalid("invalid payload_ciphertext"));
        }
        if message.signature.len() != 64 {
            return Err(invalid("invalid signature"));
        }
        let group_id: Option<&[u8]> = if header.group_id.is_empty() {
            None
        } else {
            Some(&header.group_id[..])
        };
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO user_messages(version, timestamp, sender_pubkey, recipient_pubkey, group_id, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            params![
                header.version as i64,
                header.timestamp as i64,
                &header.sender_pubkey[..],
                &header.recipients_pubkey[0][..],
                group_id,
                &message.payload_nonce[..],
                &message.ephemeral_pubkey[..],
                &message.payload_ciphertext[..],
                &message.signature[..],
                expires_at as i64,
            ],
        )?;
        let message_id = tx.last_insert_rowid();
        // Sender-session messages (Phase B4) carry their session
        // id + ratchet index in a side table, so the frozen
        // `user_messages` shape does not change.
        if !message.session_id.is_empty() {
            tx.execute(
                "INSERT INTO message_sessions(message_id, session_id, message_index) VALUES (?, ?, ?);",
                params![message_id, &message.session_id[..], message.message_index as i64],
            )?;
        }
        for wrap in &message.keywraps {
            if wrap.recipient_pubkey.len() != PUBKEY_SIZE {
                continue;
            }
            let _ = tx.execute(
                "INSERT INTO message_recipients(message_id, recipient_pubkey, key_nonce, wrapped_key) VALUES (?, ?, ?, ?);",
                params![
                    message_id,
                    &wrap.recipient_pubkey[..],
                    &wrap.key_nonce[..],
                    &wrap.wrapped_key[..]
                ],
            );
        }
        tx.commit()?;
        Ok(())
    }

    fn query_message_rows(
        &self,
        sql: &str,
        args: &[&[u8]],
        limit: u32,
    ) -> Result<Vec<RawMessageRow>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut all: Vec<&dyn rusqlite::ToSql> = Vec::new();
        for a in args {
            all.push(a as &dyn rusqlite::ToSql);
        }
        let limit_val = limit as i64;
        all.push(&limit_val as &dyn rusqlite::ToSql);
        let rows = stmt.query_map(all.as_slice(), |row| {
            Ok(RawMessageRow {
                id: row.get(0)?,
                version: row.get::<_, i64>(1)? as u32,
                timestamp: row.get::<_, i64>(2)? as u64,
                sender: row.get(3)?,
                recipient: row.get(4)?,
                group_id: row.get(5)?,
                payload_nonce: row.get(6)?,
                ephemeral_pubkey: row.get(7)?,
                encrypted_payload: row.get(8)?,
                signature: row.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn reconstruct_message(&self, raw: &RawMessageRow) -> Result<Option<Message>> {
        if raw.sender.len() != PUBKEY_SIZE
            || raw.payload_nonce.len() != 24
            || raw.ephemeral_pubkey.len() != PUBKEY_SIZE
            || raw.signature.len() != 64
        {
            return Ok(None);
        }
        let mut stmt = self.conn.prepare(
            "SELECT recipient_pubkey, key_nonce, wrapped_key FROM message_recipients WHERE message_id = ? ORDER BY recipient_pubkey;",
        )?;
        let rows = stmt.query_map(params![raw.id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut recipients: Vec<Vec<u8>> = Vec::new();
        let mut keywraps: Vec<MessageRecipientKeyWrap> = Vec::new();
        for r in rows {
            let (pk, nonce, key) = r?;
            if pk.len() != PUBKEY_SIZE || nonce.len() != 24 {
                continue;
            }
            recipients.push(pk.clone());
            keywraps.push(MessageRecipientKeyWrap {
                recipient_pubkey: pk,
                key_nonce: nonce,
                wrapped_key: key,
            });
        }
        // Sender-session fields (Phase B4), when this message
        // was stored with them.
        self.message_sessions_init()?;
        let (session_id, message_index) = {
            let mut stmt = self.conn.prepare(
                "SELECT session_id, message_index FROM message_sessions WHERE message_id = ?",
            )?;
            let mut rows = stmt.query(params![raw.id])?;
            match rows.next()? {
                Some(row) => (
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)? as u64,
                ),
                None => (Vec::new(), 0),
            }
        };
        Ok(Some(Message {
            header: Some(MessageHeader {
                version: raw.version,
                timestamp: raw.timestamp,
                sender_pubkey: raw.sender.clone(),
                recipients_pubkey: recipients,
                group_id: raw.group_id.clone().unwrap_or_default(),
            }),
            payload_nonce: raw.payload_nonce.clone(),
            ephemeral_pubkey: raw.ephemeral_pubkey.clone(),
            payload_ciphertext: raw.encrypted_payload.clone(),
            keywraps,
            signature: raw.signature.clone(),
            session_id,
            message_index,
        }))
    }

    fn messages_from_rows(&self, raw: &[RawMessageRow]) -> Result<Vec<Message>> {
        let mut out = Vec::new();
        for r in raw {
            if let Some(m) = self.reconstruct_message(r)? {
                out.push(m);
            }
        }
        Ok(out)
    }

    /// `message_store_fetch_recent`: messages the user sent, is the
    /// primary recipient of, or is a keywrap recipient of.
    pub fn message_store_fetch_recent(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        limit: u32,
    ) -> Result<Vec<Message>> {
        let raw = self.query_message_rows(
            "SELECT id, version, timestamp, sender_pubkey, recipient_pubkey, group_id, payload_nonce, ephemeral_pubkey, encrypted_payload, signature FROM user_messages WHERE sender_pubkey = ? OR recipient_pubkey = ? OR id IN (SELECT message_id FROM message_recipients WHERE recipient_pubkey = ?) ORDER BY timestamp DESC LIMIT ?;",
            &[&user_pubkey[..], &user_pubkey[..], &user_pubkey[..]],
            limit,
        )?;
        self.messages_from_rows(&raw)
    }

    /// `message_store_fetch_conversation`, both directions,
    /// including multi-recipient messages via the junction table.
    pub fn message_store_fetch_conversation(
        &self,
        user1_pubkey: &[u8; PUBKEY_SIZE],
        user2_pubkey: &[u8; PUBKEY_SIZE],
        limit: u32,
    ) -> Result<Vec<Message>> {
        let raw = self.query_message_rows(
            "SELECT DISTINCT m.id, m.version, m.timestamp, m.sender_pubkey, m.recipient_pubkey, m.group_id, m.payload_nonce, m.ephemeral_pubkey, m.encrypted_payload, m.signature FROM user_messages m LEFT JOIN message_recipients mr ON m.id = mr.message_id WHERE ((m.sender_pubkey = ? AND m.recipient_pubkey = ?) OR (m.sender_pubkey = ? AND m.recipient_pubkey = ?)) OR ((m.sender_pubkey = ? AND mr.recipient_pubkey = ?) OR (m.sender_pubkey = ? AND mr.recipient_pubkey = ?)) ORDER BY m.timestamp DESC LIMIT ?;",
            &[
                &user1_pubkey[..],
                &user2_pubkey[..],
                &user2_pubkey[..],
                &user1_pubkey[..],
                &user1_pubkey[..],
                &user2_pubkey[..],
                &user2_pubkey[..],
                &user1_pubkey[..],
            ],
            limit,
        )?;
        self.messages_from_rows(&raw)
    }

    /// `message_store_fetch_conversations`: conversation partners
    /// with last-message timestamps (`unread_count` always 0, as
    /// in C: "Future use").
    pub fn message_store_fetch_conversations(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        limit: u32,
    ) -> Result<ConversationList> {
        let mut stmt = self.conn.prepare(
            "SELECT partner, MAX(timestamp) as last_ts FROM (  SELECT * FROM (SELECT recipient_pubkey as partner, timestamp FROM user_messages WHERE sender_pubkey = ? ORDER BY timestamp DESC LIMIT 1000)  UNION ALL  SELECT * FROM (SELECT sender_pubkey as partner, timestamp FROM user_messages WHERE recipient_pubkey = ? ORDER BY timestamp DESC LIMIT 1000)  UNION ALL  SELECT * FROM (SELECT sender_pubkey as partner, timestamp FROM user_messages WHERE id IN (SELECT message_id FROM message_recipients WHERE recipient_pubkey = ?) ORDER BY timestamp DESC LIMIT 1000)) GROUP BY partner ORDER BY last_ts DESC LIMIT ?;",
        )?;
        let rows = stmt.query_map(
            params![&user_pubkey[..], &user_pubkey[..], &user_pubkey[..], limit as i64],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)? as u64,
                ))
            },
        )?;
        let mut conversations = Vec::new();
        for r in rows {
            let (partner, last_ts) = r?;
            conversations.push(ConversationSummary {
                partner_pubkey: partner,
                last_message_timestamp: last_ts,
                unread_count: 0,
                last_message_preview: Vec::new(),
            });
        }
        let total_count = conversations.len() as u32;
        Ok(ConversationList {
            conversations,
            total_count,
        })
    }
    // -- location_store.c ---------------------------------------------

    /// `location_store_save` (HTTP API path, `is_envelope = 0`).
    /// Keywrap insert failure aborts the transaction, as in C.
    pub fn location_store_save(
        &mut self,
        request: &ClientRequest,
        expires_at: u64,
    ) -> Result<()> {
        let header = request
            .header
            .as_ref()
            .ok_or_else(|| invalid("client request header missing"))?;
        if header.sender_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid sender_pubkey length"));
        }
        if header.recipients_pubkey.is_empty() {
            return Err(invalid("no recipients"));
        }
        if request.payload_nonce.len() != 24 {
            return Err(invalid("invalid payload_nonce"));
        }
        if request.ephemeral_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid ephemeral_pubkey"));
        }
        if request.payload_ciphertext.is_empty() {
            return Err(invalid("invalid payload_ciphertext"));
        }
        if request.signature.len() != 64 {
            return Err(invalid("invalid signature"));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO location_updates(user_pubkey, timestamp, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, expires_at, is_envelope) VALUES (?, ?, ?, ?, ?, ?, ?, 0);",
            params![
                &header.sender_pubkey[..],
                header.timestamp as i64,
                &request.payload_nonce[..],
                &request.ephemeral_pubkey[..],
                &request.payload_ciphertext[..],
                &request.signature[..],
                expires_at as i64,
            ],
        )?;
        let location_id = tx.last_insert_rowid();
        for wrap in &request.keywraps {
            if wrap.recipient_pubkey.len() != PUBKEY_SIZE {
                continue;
            }
            tx.execute(
                "INSERT INTO location_keywraps(location_id, recipient_pubkey, key_nonce, wrapped_key) VALUES (?, ?, ?, ?);",
                params![
                    location_id,
                    &wrap.recipient_pubkey[..],
                    &wrap.key_nonce[..],
                    &wrap.wrapped_key[..]
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// `location_store_save_envelope` (gossip path, `is_envelope = 1`).
    pub fn location_store_save_envelope(
        &mut self,
        envelope: &Envelope,
        expires_at: u64,
    ) -> Result<()> {
        let header = envelope
            .header
            .as_ref()
            .ok_or_else(|| invalid("envelope header missing"))?;
        if header.sender_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid sender_pubkey length"));
        }
        if envelope.payload_nonce.len() != 24 {
            return Err(invalid("invalid payload_nonce"));
        }
        if envelope.ephemeral_pubkey.len() != PUBKEY_SIZE {
            return Err(invalid("invalid ephemeral_pubkey"));
        }
        if envelope.payload_ciphertext.is_empty() {
            return Err(invalid("invalid payload_ciphertext"));
        }
        if envelope.signature.len() != 64 {
            return Err(invalid("invalid signature"));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO location_updates(user_pubkey, timestamp, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, expires_at, is_envelope) VALUES (?, ?, ?, ?, ?, ?, ?, 1);",
            params![
                &header.sender_pubkey[..],
                header.timestamp as i64,
                &envelope.payload_nonce[..],
                &envelope.ephemeral_pubkey[..],
                &envelope.payload_ciphertext[..],
                &envelope.signature[..],
                expires_at as i64,
            ],
        )?;
        let location_id = tx.last_insert_rowid();
        for wrap in &envelope.keywraps {
            if wrap.recipient_pubkey.len() != PUBKEY_SIZE {
                continue;
            }
            tx.execute(
                "INSERT INTO location_keywraps(location_id, recipient_pubkey, key_nonce, wrapped_key) VALUES (?, ?, ?, ?);",
                params![
                    location_id,
                    &wrap.recipient_pubkey[..],
                    &wrap.key_nonce[..],
                    &wrap.wrapped_key[..]
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn location_keywraps(
        &self,
        location_id: i64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT recipient_pubkey, key_nonce, wrapped_key FROM location_keywraps WHERE location_id = ?;",
        )?;
        let rows = stmt.query_map(params![location_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn query_location_rows(
        &self,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<RawLocationRow>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(args, |row| {
            Ok(RawLocationRow {
                id: row.get(0)?,
                timestamp: row.get::<_, i64>(1)? as u64,
                payload_nonce: row.get(2)?,
                ephemeral_pubkey: row.get(3)?,
                encrypted_payload: row.get(4)?,
                signature: row.get(5)?,
                is_envelope: row.get::<_, i64>(6)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Rebuild the serialized payload for one location row. The C
    /// reconstruction hard-codes header version 1, content type
    /// `CONTENT_LOCATION_UPDATE` and schema version 1, because
    /// `location_updates` stores none of them; mirrored here.
    fn reconstruct_location(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        raw: &RawLocationRow,
    ) -> Result<Option<LocationData>> {
        if raw.payload_nonce.len() != 24
            || raw.ephemeral_pubkey.len() != PUBKEY_SIZE
            || raw.signature.len() != 64
        {
            return Ok(None);
        }
        let wraps = self.location_keywraps(raw.id)?;
        let mut recipients: Vec<Vec<u8>> = Vec::new();
        for (pk, _, _) in &wraps {
            if pk.len() == PUBKEY_SIZE {
                recipients.push(pk.clone());
            }
        }
        if raw.is_envelope {
            let keywraps: Vec<RecipientKeyWrap> = wraps
                .into_iter()
                .filter(|(pk, _, _)| pk.len() == PUBKEY_SIZE)
                .map(|(pk, nonce, key)| RecipientKeyWrap {
                    recipient_pubkey: pk,
                    key_nonce: nonce,
                    wrapped_key: key,
                })
                .collect();
            let env = Envelope {
                header: Some(EnvelopeHeader {
                    version: 1,
                    content_type: CONTENT_LOCATION_UPDATE,
                    schema_version: 1,
                    timestamp: raw.timestamp,
                    sender_pubkey: user_pubkey.to_vec(),
                    recipients_pubkey: recipients,
                    group_id: Vec::new(),
                }),
                payload_nonce: raw.payload_nonce.clone(),
                ephemeral_pubkey: raw.ephemeral_pubkey.clone(),
                payload_ciphertext: raw.encrypted_payload.clone(),
                keywraps,
                signature: raw.signature.clone(),
            };
            Ok(Some(LocationData {
                data: env.encode_to_vec(),
                is_envelope: true,
            }))
        } else {
            let keywraps: Vec<ClientRequestKeyWrap> = wraps
                .into_iter()
                .filter(|(pk, _, _)| pk.len() == PUBKEY_SIZE)
                .map(|(pk, nonce, key)| ClientRequestKeyWrap {
                    recipient_pubkey: pk,
                    key_nonce: nonce,
                    wrapped_key: key,
                })
                .collect();
            let req = ClientRequest {
                header: Some(ClientRequestHeader {
                    version: 1,
                    content_type: CONTENT_LOCATION_UPDATE,
                    schema_version: 1,
                    timestamp: raw.timestamp,
                    sender_pubkey: user_pubkey.to_vec(),
                    recipients_pubkey: recipients,
                    group_id: Vec::new(),
                }),
                payload_nonce: raw.payload_nonce.clone(),
                ephemeral_pubkey: raw.ephemeral_pubkey.clone(),
                payload_ciphertext: raw.encrypted_payload.clone(),
                keywraps,
                signature: raw.signature.clone(),
            };
            Ok(Some(LocationData {
                data: req.encode_to_vec(),
                is_envelope: false,
            }))
        }
    }

    /// `location_store_get_latest`: `Ok(None)` is C's "not found"
    /// (return 1).
    pub fn location_store_get_latest(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Option<LocationData>> {
        let user: &[u8] = &user_pubkey[..];
        let rows = self.query_location_rows(
            "SELECT id, timestamp, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, is_envelope FROM location_updates WHERE user_pubkey = ? ORDER BY timestamp DESC LIMIT 1;",
            &[&user],
        )?;
        match rows.into_iter().next() {
            Some(raw) => self.reconstruct_location(user_pubkey, &raw),
            None => Ok(None),
        }
    }

    /// `location_store_get_history`, newest first.
    pub fn location_store_get_history(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<LocationData>> {
        let user: &[u8] = &user_pubkey[..];
        let limit_val = limit as i64;
        let offset_val = offset as i64;
        let rows = self.query_location_rows(
            "SELECT id, timestamp, payload_nonce, ephemeral_pubkey, encrypted_payload, signature, is_envelope FROM location_updates WHERE user_pubkey = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
            &[&user, &limit_val, &offset_val],
        )?;
        let mut out = Vec::new();
        for raw in &rows {
            if let Some(d) = self.reconstruct_location(user_pubkey, raw)? {
                out.push(d);
            }
        }
        Ok(out)
    }
    // -- gossip_peers.c ------------------------------------------------

    /// `gossip_peers_init` (C `ensure_initialized`): create the table
    /// and indexes, adding `api_port` to pre-existing tables. The
    /// duplicate-column error from the `ALTER TABLE` is ignored,
    /// exactly as in C. Every peer operation calls this first, as
    /// the C `ensure_initialized` does.
    pub fn gossip_peers_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_GOSSIP_PEERS)?;
        match self.conn.execute_batch(ADD_PEERS_API_PORT) {
            Ok(()) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        self.conn.execute_batch(CREATE_IDX_PEERS_LAST_SEEN)?;
        self.conn.execute_batch(CREATE_IDX_PEERS_PUBKEY)?;
        self.node_trust_init()
    }

    /// Create the `node_trust` table and migrate any legacy
    /// `gossip_peers.node_pubkey` values into it (DESIGN.md §10).
    /// The migration is one-way and idempotent: rows already in
    /// `node_trust` win, and the legacy column is left in place
    /// (nothing reads or writes it from now on). Every trust
    /// operation calls this first, like the C
    /// `ensure_initialized`.
    pub fn node_trust_init(&self) -> Result<()> {
        // The migration reads gossip_peers, so make sure it
        // exists even when a trust call comes first.
        self.conn.execute_batch(CREATE_GOSSIP_PEERS)?;
        self.conn.execute_batch(CREATE_NODE_TRUST)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO node_trust (node_pubkey, hostname, trusted_at, source) SELECT node_pubkey, hostname, first_seen, 'migrated' FROM gossip_peers WHERE node_pubkey IS NOT NULL AND length(node_pubkey) = ?",
            params![PUBKEY_SIZE as i64],
        )?;
        Ok(())
    }

    /// `gossip_peers_add_or_update`: address-book write ONLY.
    /// On hostname conflict the ports, `last_seen` and tags are
    /// replaced; `first_seen` is preserved. This never touches
    /// trust (`node_trust`) or the legacy `node_pubkey` column,
    /// so discovery/bootstrap persistence can never erase a
    /// trusted key (DESIGN.md §10). Empty tags bind as NULL.
    pub fn gossip_peers_add_or_update(
        &self,
        hostname: &str,
        gossip_port: u16,
        api_port: u16,
        tags: Option<&str>,
    ) -> Result<()> {
        if hostname.is_empty() {
            return Err(invalid("hostname is empty"));
        }
        self.gossip_peers_init()?;
        let now = now_epoch() as i64;
        let tags: Option<&str> = tags.filter(|t| !t.is_empty());
        self.conn.execute(
            "INSERT INTO gossip_peers (hostname, gossip_port, api_port, first_seen, last_seen, tags) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(hostname) DO UPDATE SET gossip_port=excluded.gossip_port, api_port=excluded.api_port, last_seen=excluded.last_seen, tags=excluded.tags",
            params![
                hostname,
                gossip_port as i64,
                api_port as i64,
                now,
                now,
                tags,
            ],
        )?;
        Ok(())
    }

    /// `gossip_peers_touch`: bump `last_seen`; insert a placeholder
    /// row with zero ports when the hostname is unknown.
    pub fn gossip_peers_touch(&self, hostname: &str) -> Result<()> {
        if hostname.is_empty() {
            return Err(invalid("hostname is empty"));
        }
        self.gossip_peers_init()?;
        let changed = self.conn.execute(
            "UPDATE gossip_peers SET last_seen = ? WHERE hostname = ?",
            params![now_epoch() as i64, hostname],
        )?;
        if changed == 0 {
            self.gossip_peers_add_or_update(hostname, 0, 0, None)?;
        }
        Ok(())
    }

    /// `gossip_peers_fetch_all`, ordered by hostname. The
    /// `node_pubkey` of each row is display-only: it is the
    /// trusted key recorded for that hostname in `node_trust`
    /// (falling back to the legacy column for rows migrated
    /// data has not covered), or all-zero when the peer is not
    /// trusted.
    pub fn gossip_peers_fetch_all(&self) -> Result<Vec<GossipPeerInfo>> {
        self.gossip_peers_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT hostname, gossip_port, api_port, COALESCE((SELECT node_pubkey FROM node_trust WHERE node_trust.hostname = gossip_peers.hostname ORDER BY trusted_at ASC LIMIT 1), node_pubkey), first_seen, last_seen, COALESCE(tags, '') FROM gossip_peers ORDER BY hostname",
        )?;
        let rows = stmt.query_map(params![], peer_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Grant trust to a node/member public key (the ingest
    /// whitelist). This is the ONLY write path for trust:
    /// enrollment and explicit seeding call it; discovery and
    /// other address-book writes never do (DESIGN.md §10).
    /// Re-granting an already-trusted key refreshes its
    /// hostname hint and source but keeps the original
    /// `trusted_at`.
    pub fn node_trust_add(
        &self,
        node_pubkey: &[u8; PUBKEY_SIZE],
        hostname: Option<&str>,
        source: &str,
    ) -> Result<()> {
        self.node_trust_init()?;
        let hostname: Option<&str> = hostname.filter(|h| !h.is_empty());
        self.conn.execute(
            "INSERT INTO node_trust (node_pubkey, hostname, trusted_at, source) VALUES (?, ?, ?, ?) ON CONFLICT(node_pubkey) DO UPDATE SET hostname=COALESCE(excluded.hostname, node_trust.hostname), source=excluded.source",
            params![&node_pubkey[..], hostname, now_epoch() as i64, source],
        )?;
        Ok(())
    }

    /// Whether `node_pubkey` is currently trusted.
    pub fn node_trust_is_trusted(&self, node_pubkey: &[u8; PUBKEY_SIZE]) -> Result<bool> {
        self.node_trust_init()?;
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM node_trust WHERE node_pubkey = ?")?;
        let mut rows = stmt.query(params![&node_pubkey[..]])?;
        Ok(rows.next()?.is_some())
    }

    /// The trust entry for `node_pubkey`, `Ok(None)` when the
    /// key is not trusted.
    pub fn node_trust_get(
        &self,
        node_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Option<NodeTrustEntry>> {
        self.node_trust_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT node_pubkey, COALESCE(hostname, ''), trusted_at, source FROM node_trust WHERE node_pubkey = ?",
        )?;
        let mut rows = stmt.query(params![&node_pubkey[..]])?;
        match rows.next()? {
            Some(row) => Ok(Some(trust_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Revoke trust for `node_pubkey`; returns whether an entry
    /// was removed.
    pub fn node_trust_remove(&self, node_pubkey: &[u8; PUBKEY_SIZE]) -> Result<bool> {
        self.node_trust_init()?;
        let changed = self.conn.execute(
            "DELETE FROM node_trust WHERE node_pubkey = ?",
            params![&node_pubkey[..]],
        )?;
        Ok(changed > 0)
    }

    /// All trust entries, oldest grant first.
    pub fn node_trust_list(&self) -> Result<Vec<NodeTrustEntry>> {
        self.node_trust_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT node_pubkey, COALESCE(hostname, ''), trusted_at, source FROM node_trust ORDER BY trusted_at ASC, node_pubkey ASC",
        )?;
        let rows = stmt.query_map(params![], trust_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -- devices (DESIGN.md §3.1) ------------------------------------

    /// Create the `devices` table. Every device operation calls
    /// this first, like the C `ensure_initialized`.
    pub fn devices_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_DEVICES)?;
        Ok(())
    }

    /// Record a member's device certificate (enrollment's write
    /// path). The certificate is verified first — signature and
    /// expiry at `now` — and an invalid one is rejected (the
    /// `identity` module logs the reason) and never stored.
    ///
    /// Re-adding a certificate for an already-known
    /// (member, device) pair replaces the stored certificate
    /// and returns the device to `active`: a fresh vouch from
    /// the member key is exactly what re-issuance means. The
    /// original `created_at` is kept.
    pub fn device_add(&self, cert: &DeviceCertificate, now: u64) -> Result<()> {
        self.devices_init()?;
        crate::identity::verify_device_certificate(cert, now).map_err(|e| {
            invalid(&format!("device certificate rejected: {e}"))
        })?;
        // Verification has established both pubkeys are 32 bytes.
        let cert_bytes = cert.encode_to_vec();
        let cert_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
        insert_device_row(&self.conn, cert, &cert_bytes, &cert_hash, now)
    }

    /// The recorded device for (member, device), `Ok(None)` when
    /// the pair was never enrolled.
    pub fn device_get(
        &self,
        member_pubkey: &[u8; PUBKEY_SIZE],
        device_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Option<DeviceEntry>> {
        self.devices_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT member_pubkey, device_pubkey, label, cert, cert_hash, status, issued_at, expires_at, revoked_at, created_at, updated_at FROM devices WHERE member_pubkey = ? AND device_pubkey = ?",
        )?;
        let mut rows = stmt.query(params![&member_pubkey[..], &device_pubkey[..]])?;
        match rows.next()? {
            Some(row) => Ok(Some(device_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// All devices recorded for a member, oldest certificate
    /// first, including revoked ones (the audit trail).
    pub fn device_list(&self, member_pubkey: &[u8; PUBKEY_SIZE]) -> Result<Vec<DeviceEntry>> {
        self.devices_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT member_pubkey, device_pubkey, label, cert, cert_hash, status, issued_at, expires_at, revoked_at, created_at, updated_at FROM devices WHERE member_pubkey = ? ORDER BY issued_at ASC, device_pubkey ASC",
        )?;
        let rows = stmt.query_map(params![&member_pubkey[..]], device_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Revoke a device: a status flip to `revoked`, never a
    /// delete, so the enrollment record stays auditable.
    /// Returns whether an active device was actually revoked
    /// (unknown pairs and already-revoked devices report
    /// `false`).
    pub fn device_revoke(
        &self,
        member_pubkey: &[u8; PUBKEY_SIZE],
        device_pubkey: &[u8; PUBKEY_SIZE],
        revoked_at: u64,
    ) -> Result<bool> {
        self.devices_init()?;
        let changed = self.conn.execute(
            "UPDATE devices SET status='revoked', revoked_at=?, updated_at=? WHERE member_pubkey=? AND device_pubkey=? AND status='active'",
            params![
                revoked_at as i64,
                revoked_at as i64,
                &member_pubkey[..],
                &device_pubkey[..]
            ],
        )?;
        Ok(changed > 0)
    }

    /// Apply a signed device revocation (the gossiped record):
    /// the member-key signature is verified first (rejections
    /// are logged by the `identity` module), then the device is
    /// revoked at the revocation's `revoked_at`. Returns
    /// whether an active device was revoked.
    pub fn device_apply_revocation(&self, revocation: &DeviceRevocation) -> Result<bool> {
        crate::identity::verify_device_revocation(revocation).map_err(|e| {
            invalid(&format!("device revocation rejected: {e}"))
        })?;
        // Verification has established both pubkeys are 32 bytes.
        let member_pubkey: [u8; PUBKEY_SIZE] = revocation
            .member_pubkey
            .as_slice()
            .try_into()
            .expect("verified length");
        let device_pubkey: [u8; PUBKEY_SIZE] = revocation
            .device_pubkey
            .as_slice()
            .try_into()
            .expect("verified length");
        self.device_revoke(&member_pubkey, &device_pubkey, revocation.revoked_at)
    }

    /// Is this device currently trusted for this member? True
    /// only when a device row exists, is `active`, and its
    /// stored certificate still verifies at `now` — signature
    /// and expiry are re-checked on every call, so a tampered
    /// row or a lapsed certificate stops trusting (and the
    /// failed verification is logged by the `identity`
    /// module). This is the helper ingest/API paths ask before
    /// treating a device key as its member.
    pub fn device_is_trusted(
        &self,
        member_pubkey: &[u8; PUBKEY_SIZE],
        device_pubkey: &[u8; PUBKEY_SIZE],
        now: u64,
    ) -> Result<bool> {
        let Some(entry) = self.device_get(member_pubkey, device_pubkey)? else {
            return Ok(false);
        };
        if entry.status != DeviceStatus::Active {
            return Ok(false);
        }
        let cert = match DeviceCertificate::decode(entry.cert.as_slice()) {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!(
                    "identity: stored device certificate member={} device={} does not decode: {e}",
                    hex_encode_pubkey(member_pubkey),
                    hex_encode_pubkey(device_pubkey)
                );
                return Ok(false);
            }
        };
        // The stored certificate must be for exactly this pair;
        // a row whose certificate names other keys is corrupt.
        if cert.member_pubkey != member_pubkey[..] || cert.device_pubkey != device_pubkey[..] {
            eprintln!(
                "identity: stored device certificate member={} device={} names different keys",
                hex_encode_pubkey(member_pubkey),
                hex_encode_pubkey(device_pubkey)
            );
            return Ok(false);
        }
        Ok(crate::identity::verify_device_certificate(&cert, now).is_ok())
    }

    // -- enrollment (Phase B3, DESIGN.md §3.2) --------------------

    /// Create the `pairing_codes` table if needed (lazy, like
    /// [`Store::devices_init`]).
    pub fn pairings_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_PAIRING_CODES)?;
        Ok(())
    }

    /// Create the `enrollments` table if needed.
    pub fn enrollments_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_ENROLLMENTS)?;
        Ok(())
    }

    /// Create the `recovery_approvers` table if needed.
    pub fn recovery_approvers_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_RECOVERY_APPROVERS)?;
        Ok(())
    }

    /// Open a pending pairing for a joining device (the store
    /// half of `/enroll/begin`). The certificate is verified
    /// first — signature and expiry at `now` — and an invalid
    /// one is rejected (the `identity` module logs the reason)
    /// and never stored. `code_hash` is the SHA-256 of the code
    /// the joining device displays; the code itself is never
    /// stored. Opening a new pairing for a (member, device)
    /// pair retires any earlier still-pending pairing for the
    /// same pair, so only the freshest code can complete.
    pub fn pairing_create(
        &self,
        code_hash: &[u8; 32],
        cert: &DeviceCertificate,
        display_name: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<()> {
        self.pairings_init()?;
        crate::identity::verify_device_certificate(cert, now).map_err(|e| {
            invalid(&format!("device certificate rejected: {e}"))
        })?;
        // Verification has established both pubkeys are 32 bytes.
        let cert_bytes = cert.encode_to_vec();
        let cert_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
        self.conn.execute(
            "UPDATE pairing_codes SET status='expired' WHERE member_pubkey = ? AND device_pubkey = ? AND status = 'pending'",
            params![&cert.member_pubkey[..], &cert.device_pubkey[..]],
        )?;
        self.conn.execute(
            "INSERT INTO pairing_codes (code_hash, member_pubkey, device_pubkey, display_name, cert, cert_hash, status, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL)",
            params![
                &code_hash[..],
                &cert.member_pubkey[..],
                &cert.device_pubkey[..],
                display_name,
                cert_bytes,
                &cert_hash[..],
                now as i64,
                expires_at as i64,
            ],
        )?;
        Ok(())
    }

    /// The pairing recorded for a code hash, `Ok(None)` when the
    /// code is unknown.
    pub fn pairing_get(&self, code_hash: &[u8; 32]) -> Result<Option<PairingRecord>> {
        self.pairings_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT code_hash, member_pubkey, device_pubkey, display_name, cert, cert_hash, status, created_at, expires_at, used_at FROM pairing_codes WHERE code_hash = ?",
        )?;
        let mut rows = stmt.query(params![&code_hash[..]])?;
        match rows.next()? {
            Some(row) => Ok(Some(pairing_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Mark a still-pending pairing expired. Returns whether a
    /// row changed.
    pub fn pairing_mark_expired(&self, code_hash: &[u8; 32]) -> Result<bool> {
        self.pairings_init()?;
        let changed = self.conn.execute(
            "UPDATE pairing_codes SET status='expired' WHERE code_hash = ? AND status = 'pending'",
            params![&code_hash[..]],
        )?;
        Ok(changed > 0)
    }

    /// Complete a pairing atomically (the store half of
    /// `/enroll/approve`, after the API layer has verified the
    /// approval signature and the approver's standing): in one
    /// transaction, register the member (a no-op when the member
    /// already exists — an existing member is adding a device),
    /// record the device certificate, write the enrollment
    /// audit record, and mark the pairing used. The certificate
    /// is re-verified at completion time, so a certificate that
    /// lapsed between begin and approve completes nothing.
    pub fn pairing_complete(
        &self,
        code_hash: &[u8; 32],
        approval: &PairingApproval,
        now: u64,
    ) -> Result<PairingCompleteOutcome> {
        self.pairings_init()?;
        self.enrollments_init()?;
        self.devices_init()?;
        let Some(record) = self.pairing_get(code_hash)? else {
            return Ok(PairingCompleteOutcome::UnknownCode);
        };
        match record.status.as_str() {
            "used" => return Ok(PairingCompleteOutcome::AlreadyUsed),
            "expired" => return Ok(PairingCompleteOutcome::Expired),
            _ => {}
        }
        if now >= record.expires_at {
            let _ = self.pairing_mark_expired(code_hash);
            return Ok(PairingCompleteOutcome::Expired);
        }
        let cert = DeviceCertificate::decode(record.cert.as_slice())
            .map_err(|e| invalid(&format!("stored pairing certificate does not decode: {e}")))?;
        crate::identity::verify_device_certificate(&cert, now).map_err(|e| {
            invalid(&format!("device certificate rejected at completion: {e}"))
        })?;
        if cert.member_pubkey != record.member_pubkey[..]
            || cert.device_pubkey != record.device_pubkey[..]
        {
            return Err(invalid(
                "stored pairing certificate names different keys than the pairing",
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO users (pubkey, username, is_active) VALUES (?, ?, 1) ON CONFLICT(pubkey) DO NOTHING",
            params![hex_encode_pubkey(&record.member_pubkey), record.display_name],
        )?;
        insert_device_row(&tx, &cert, &record.cert, &record.cert_hash, now)?;
        insert_enrollment_row(
            &tx,
            &EnrollmentRecord {
                id: 0,
                member_pubkey: record.member_pubkey,
                device_pubkey: record.device_pubkey,
                cert_hash: record.cert_hash,
                approver_kind: approval.approver_kind.clone(),
                approver_member_pubkey: approval.approver_member_pubkey,
                approver_device_pubkey: approval.approver_device_pubkey,
                recovery_pubkey: approval.recovery_pubkey,
                approval_signature: approval.approval_signature.clone(),
                approval_timestamp: approval.approval_timestamp,
                created_at: now,
            },
        )?;
        let changed = tx.execute(
            "UPDATE pairing_codes SET status='used', used_at = ? WHERE code_hash = ? AND status = 'pending'",
            params![now as i64, &code_hash[..]],
        )?;
        if changed == 0 {
            // Another completion won the race between the check
            // above and this transaction; dropping `tx` rolls
            // the whole enrollment back.
            return Ok(PairingCompleteOutcome::AlreadyUsed);
        }
        tx.commit()?;
        Ok(PairingCompleteOutcome::Completed)
    }

    /// Write an enrollment audit record outside a pairing
    /// completion — the founding bootstrap's path (its
    /// enrollments have no pairing and no approver). Returns
    /// the new row id.
    pub fn enrollment_insert(&self, record: &EnrollmentRecord) -> Result<i64> {
        self.enrollments_init()?;
        insert_enrollment_row(&self.conn, record)
    }

    /// All enrollment records for a member, oldest first (the
    /// audit trail of how each of their devices joined).
    pub fn enrollments_for_member(
        &self,
        member_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Vec<EnrollmentRecord>> {
        self.enrollments_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, member_pubkey, device_pubkey, cert_hash, approver_kind, approver_member_pubkey, approver_device_pubkey, recovery_pubkey, approval_signature, approval_timestamp, created_at FROM enrollments WHERE member_pubkey = ? ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![&member_pubkey[..]], enrollment_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Register a household recovery key (the printed backup
    /// card's public half) as an enrollment approver. Called by
    /// the founding bootstrap; the matching secret never touches
    /// the node.
    pub fn recovery_approver_add(
        &self,
        recovery_pubkey: &[u8; PUBKEY_SIZE],
        label: &str,
        now: u64,
    ) -> Result<()> {
        self.recovery_approvers_init()?;
        self.conn.execute(
            "INSERT INTO recovery_approvers (recovery_pubkey, label, created_at) VALUES (?, ?, ?) ON CONFLICT(recovery_pubkey) DO NOTHING",
            params![&recovery_pubkey[..], label, now as i64],
        )?;
        Ok(())
    }

    /// Is this key a registered household recovery approver?
    pub fn recovery_approver_is_registered(
        &self,
        recovery_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<bool> {
        self.recovery_approvers_init()?;
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM recovery_approvers WHERE recovery_pubkey = ?")?;
        let mut rows = stmt.query(params![&recovery_pubkey[..]])?;
        Ok(rows.next()?.is_some())
    }

    // -- sender sessions, shares, visibility (Phase B4, DESIGN.md §9) --

    /// Create the `message_sessions` table (lazy, like
    /// [`Store::devices_init`]); also part of `MESSAGE_SCHEMA`.
    pub fn message_sessions_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_MESSAGE_SESSIONS)?;
        Ok(())
    }

    /// Create the Phase B4 tables: sessions, skipped keys,
    /// share audit, parent links, visibility settings and
    /// conversation members. Every B4 operation calls this
    /// first, like the C `ensure_initialized`.
    pub fn sessions_init(&self) -> Result<()> {
        self.conn.execute_batch(CREATE_SESSIONS)?;
        self.conn.execute_batch(CREATE_SESSION_SKIPPED_KEYS)?;
        self.conn.execute_batch(CREATE_GROUP_KEY_SHARES)?;
        self.conn.execute_batch(CREATE_PARENT_LINKS)?;
        self.conn.execute_batch(CREATE_VISIBILITY_SETTINGS)?;
        self.conn.execute_batch(CREATE_CONVERSATION_MEMBERS)?;
        Ok(())
    }

    /// Insert or replace one device's ratchet state for a
    /// session. Saving is how a session is created (with
    /// `next_index` 0 and the root key as `chain_key`) and how
    /// every advance is persisted.
    #[allow(clippy::too_many_arguments)]
    pub fn session_save(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
        group_id: &[u8],
        sender_member_pubkey: &[u8; PUBKEY_SIZE],
        sender_device_pubkey: &[u8; PUBKEY_SIZE],
        direction: &str,
        chain_key: &[u8],
        next_index: u64,
        now: u64,
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT INTO sessions (session_id, owner_device_pubkey, group_id, sender_member_pubkey, sender_device_pubkey, direction, chain_key, next_index, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(session_id, owner_device_pubkey) DO UPDATE SET chain_key = excluded.chain_key, next_index = excluded.next_index, updated_at = excluded.updated_at",
            params![
                session_id,
                &owner_device_pubkey[..],
                group_id,
                &sender_member_pubkey[..],
                &sender_device_pubkey[..],
                direction,
                chain_key,
                next_index as i64,
                now as i64,
                now as i64
            ],
        )?;
        Ok(())
    }

    /// One device's ratchet state for a session, `Ok(None)`
    /// when this device holds no state for it (it never
    /// received a share, or the session is not its own).
    pub fn session_get(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Option<SessionRecord>> {
        self.sessions_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT session_id, owner_device_pubkey, group_id, sender_member_pubkey, sender_device_pubkey, direction, chain_key, next_index, created_at, updated_at FROM sessions WHERE session_id = ? AND owner_device_pubkey = ?",
        )?;
        let mut rows = stmt.query(params![session_id, &owner_device_pubkey[..]])?;
        match rows.next()? {
            Some(row) => Ok(Some(session_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Advance a stored session's ratchet state after a
    /// message was encrypted or decrypted under it. Returns
    /// whether a row was updated.
    pub fn session_update_state(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
        chain_key: &[u8],
        next_index: u64,
        now: u64,
    ) -> Result<bool> {
        self.sessions_init()?;
        let changed = self.conn.execute(
            "UPDATE sessions SET chain_key = ?, next_index = ?, updated_at = ? WHERE session_id = ? AND owner_device_pubkey = ?",
            params![
                chain_key,
                next_index as i64,
                now as i64,
                session_id,
                &owner_device_pubkey[..]
            ],
        )?;
        Ok(changed > 0)
    }

    /// Cache the derived message key for an index the
    /// receiver ratchet skipped over, so the message can
    /// still be decrypted when it arrives out of order.
    pub fn session_skipped_key_put(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
        message_index: u64,
        message_key: &[u8],
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT OR REPLACE INTO session_skipped_keys (session_id, owner_device_pubkey, message_index, message_key) VALUES (?, ?, ?, ?)",
            params![
                session_id,
                &owner_device_pubkey[..],
                message_index as i64,
                message_key
            ],
        )?;
        Ok(())
    }

    /// A cached skipped message key, `Ok(None)` when the
    /// index was never skipped (or was already consumed).
    pub fn session_skipped_key_get(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
        message_index: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.sessions_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT message_key FROM session_skipped_keys WHERE session_id = ? AND owner_device_pubkey = ? AND message_index = ?",
        )?;
        let mut rows = stmt.query(params![
            session_id,
            &owner_device_pubkey[..],
            message_index as i64
        ])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Drop a cached skipped key (after it was used, so a
    /// replayed message cannot be decrypted twice).
    pub fn session_skipped_key_remove(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
        message_index: u64,
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "DELETE FROM session_skipped_keys WHERE session_id = ? AND owner_device_pubkey = ? AND message_index = ?",
            params![
                session_id,
                &owner_device_pubkey[..],
                message_index as i64
            ],
        )?;
        Ok(())
    }

    /// How many skipped keys are cached for one device's
    /// session state.
    pub fn session_skipped_key_count(
        &self,
        session_id: &[u8],
        owner_device_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<u64> {
        self.sessions_init()?;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM session_skipped_keys WHERE session_id = ? AND owner_device_pubkey = ?",
            params![session_id, &owner_device_pubkey[..]],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Record a group key share envelope in the audit table
    /// (who shared which session to which device, and the
    /// exact envelope bytes). Called when a share is built
    /// (sender side) and when one is accepted (recipient
    /// side).
    #[allow(clippy::too_many_arguments)]
    pub fn share_record_insert(
        &self,
        session_id: &[u8],
        group_id: &[u8],
        sender_member_pubkey: &[u8; PUBKEY_SIZE],
        sender_device_pubkey: &[u8; PUBKEY_SIZE],
        recipient_member_pubkey: &[u8; PUBKEY_SIZE],
        recipient_device_pubkey: &[u8; PUBKEY_SIZE],
        envelope_bytes: &[u8],
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT INTO group_key_shares (session_id, group_id, sender_member_pubkey, sender_device_pubkey, recipient_member_pubkey, recipient_device_pubkey, envelope) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                group_id,
                &sender_member_pubkey[..],
                &sender_device_pubkey[..],
                &recipient_member_pubkey[..],
                &recipient_device_pubkey[..],
                envelope_bytes
            ],
        )?;
        Ok(())
    }

    /// All recorded share envelopes for one session, oldest
    /// first, as serialized `Envelope` bytes.
    pub fn shares_for_session(&self, session_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.sessions_init()?;
        let mut stmt = self
            .conn
            .prepare("SELECT envelope FROM group_key_shares WHERE session_id = ? ORDER BY id ASC")?;
        let rows = stmt.query_map(params![session_id], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Record that `parent` is a parent of `child` (the
    /// parent-of link the visibility rule consults).
    pub fn parent_link_add(
        &self,
        parent_member_pubkey: &[u8; PUBKEY_SIZE],
        child_member_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT INTO parent_links (parent_member_pubkey, child_member_pubkey) VALUES (?, ?) ON CONFLICT(parent_member_pubkey, child_member_pubkey) DO NOTHING",
            params![&parent_member_pubkey[..], &child_member_pubkey[..]],
        )?;
        Ok(())
    }

    /// All recorded parents of a child member.
    pub fn parents_of(
        &self,
        child_member_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Vec<[u8; PUBKEY_SIZE]>> {
        self.sessions_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT parent_member_pubkey FROM parent_links WHERE child_member_pubkey = ? ORDER BY parent_member_pubkey ASC",
        )?;
        let rows = stmt.query_map(params![&child_member_pubkey[..]], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut out = Vec::new();
        for r in rows {
            let v = r?;
            if v.len() == PUBKEY_SIZE {
                let mut key = [0u8; PUBKEY_SIZE];
                key.copy_from_slice(&v);
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Set a child's parental-visibility level. `set_by`
    /// records which parent set it (the caller checks the
    /// parent-of link; this layer stores the audit fact).
    pub fn visibility_set(
        &self,
        child_member_pubkey: &[u8; PUBKEY_SIZE],
        level: VisibilityLevel,
        set_by: &[u8; PUBKEY_SIZE],
        now: u64,
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT INTO visibility_settings (child_member_pubkey, level, set_by, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(child_member_pubkey) DO UPDATE SET level = excluded.level, set_by = excluded.set_by, updated_at = excluded.updated_at",
            params![
                &child_member_pubkey[..],
                level.as_str(),
                &set_by[..],
                now as i64
            ],
        )?;
        Ok(())
    }

    /// A child's parental-visibility level. Children with no
    /// recorded setting are [`VisibilityLevel::None`]: no
    /// visibility until a parent grants some.
    pub fn visibility_get(
        &self,
        child_member_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<VisibilityLevel> {
        self.sessions_init()?;
        let mut stmt = self
            .conn
            .prepare("SELECT level FROM visibility_settings WHERE child_member_pubkey = ?")?;
        let mut rows = stmt.query(params![&child_member_pubkey[..]])?;
        match rows.next()? {
            Some(row) => Ok(VisibilityLevel::from_db(&row.get::<_, String>(0)?)),
            None => Ok(VisibilityLevel::None),
        }
    }

    /// Add a member to a conversation's member list (the
    /// membership the share distribution helper consults).
    pub fn conversation_member_add(
        &self,
        group_id: &[u8],
        member_pubkey: &[u8; PUBKEY_SIZE],
        now: u64,
    ) -> Result<()> {
        self.sessions_init()?;
        self.conn.execute(
            "INSERT INTO conversation_members (group_id, member_pubkey, joined_at) VALUES (?, ?, ?) ON CONFLICT(group_id, member_pubkey) DO NOTHING",
            params![group_id, &member_pubkey[..], now as i64],
        )?;
        Ok(())
    }

    /// Remove a member from a conversation. Returns whether
    /// a row was removed.
    pub fn conversation_member_remove(
        &self,
        group_id: &[u8],
        member_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<bool> {
        self.sessions_init()?;
        let changed = self.conn.execute(
            "DELETE FROM conversation_members WHERE group_id = ? AND member_pubkey = ?",
            params![group_id, &member_pubkey[..]],
        )?;
        Ok(changed > 0)
    }

    /// A conversation's members, in join order.
    pub fn conversation_members(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<[u8; PUBKEY_SIZE]>> {
        self.sessions_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT member_pubkey FROM conversation_members WHERE group_id = ? ORDER BY joined_at ASC, member_pubkey ASC",
        )?;
        let rows = stmt.query_map(params![group_id], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for r in rows {
            let v = r?;
            if v.len() == PUBKEY_SIZE {
                let mut key = [0u8; PUBKEY_SIZE];
                key.copy_from_slice(&v);
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Register a user directly (founding bootstrap and tests):
    /// an active `users` row for `user_pubkey` under `username`.
    /// A no-op when the pubkey is already registered.
    pub fn user_register(&self, user_pubkey: &[u8; PUBKEY_SIZE], username: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO users (pubkey, username, is_active) VALUES (?, ?, 1) ON CONFLICT(pubkey) DO NOTHING",
            params![hex_encode_pubkey(user_pubkey), username],
        )?;
        Ok(())
    }

    /// How many users are registered (any active state). The
    /// founding bootstrap refuses to run unless this is 0.
    pub fn user_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Delete a peer by hostname; returns whether a row was removed.
    /// The C package has no remove operation (its header lists only
    /// add/touch/list/get); this is provided because the porting
    /// task asks for add/list/remove coverage. It is a plain
    /// `DELETE FROM gossip_peers WHERE hostname = ?`.
    pub fn gossip_peers_remove(&self, hostname: &str) -> Result<bool> {
        self.gossip_peers_init()?;
        let changed = self.conn.execute(
            "DELETE FROM gossip_peers WHERE hostname = ?",
            params![hostname],
        )?;
        Ok(changed > 0)
    }
    // -- permissions.c --------------------------------------------------

    fn user_id_by_pubkey(&self, user_pubkey: &[u8; PUBKEY_SIZE]) -> Result<Option<i64>> {
        let hex = hex_encode_pubkey(user_pubkey);
        let mut stmt = self.conn.prepare(SQL_SELECT_USER_BY_PUBKEY)?;
        let mut rows = stmt.query(params![hex])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, i64>(0)?)),
            None => Ok(None),
        }
    }

    /// `user_exists`: registered and `is_active = 1`. Like the C
    /// `bool` function, any failure reads as `false`.
    pub fn user_exists(&self, user_pubkey: &[u8; PUBKEY_SIZE]) -> bool {
        let hex = hex_encode_pubkey(user_pubkey);
        let run = (|| -> Result<bool> {
            let mut stmt = self.conn.prepare(SQL_SELECT_USER_BY_PUBKEY)?;
            let mut rows = stmt.query(params![hex])?;
            match rows.next()? {
                // Column 6 is is_active in SQL_SELECT_USER_BY_PUBKEY.
                Some(row) => Ok(row.get::<_, i64>(6)? == 1),
                None => Ok(false),
            }
        })();
        run.unwrap_or(false)
    }

    /// `load_role_permission_sets`: permission rows of a role,
    /// grouped by (scope, conditions, time window) with permission
    /// flags OR-ed together, in first-seen group order, as in C.
    pub fn load_role_permission_sets(&self, role_id: i64) -> Result<Vec<PermissionSet>> {
        let mut stmt = self.conn.prepare(SQL_SELECT_ROLE_PERMISSIONS)?;
        let mut rows = stmt.query(params![role_id])?;
        // (scope_flags, condition_flags, time_start, time_end, combined)
        let mut groups: Vec<(u32, u64, u64, u64, u64)> = Vec::new();
        while let Some(row) = rows.next()? {
            // Column indexes follow SQL_SELECT_ROLE_PERMISSIONS.
            let scope_flags = row.get::<_, i64>(5)? as u32;
            let condition_flags = row.get::<_, i64>(6)? as u64;
            let time_start = row.get::<_, Option<i64>>(7)?.unwrap_or(0) as u64;
            let time_end = row.get::<_, Option<i64>>(8)?.unwrap_or(0) as u64;
            let permission_flags = row.get::<_, i64>(10)? as u64;
            match groups.iter_mut().find(|g| {
                g.0 == scope_flags
                    && g.1 == condition_flags
                    && g.2 == time_start
                    && g.3 == time_end
            }) {
                Some(g) => g.4 |= permission_flags,
                None => {
                    if groups.len() >= 32 {
                        return Err(Error::TooManyPermissionGroups);
                    }
                    groups.push((
                        scope_flags,
                        condition_flags,
                        time_start,
                        time_end,
                        permission_flags,
                    ));
                }
            }
        }
        drop(rows);
        drop(stmt);
        Ok(groups
            .into_iter()
            .map(|(scopes, conditions, time_start, time_end, permissions)| PermissionSet {
                permissions,
                scopes,
                conditions,
                time_start,
                time_end,
            })
            .collect())
    }

    /// `load_user_roles`: empty vector for an unknown user (C returns
    /// success with count 0). At most 32 roles, as in C. The C code
    /// keeps `role_name` pointers into the finalized statement
    /// (use-after-finalize); here names are owned copies.
    pub fn load_user_roles(&self, user_pubkey: &[u8; PUBKEY_SIZE]) -> Result<Vec<Role>> {
        let user_id = match self.user_id_by_pubkey(user_pubkey)? {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };
        let mut stmt = self.conn.prepare(SQL_SELECT_USER_ROLES)?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok((row.get::<_, i64>(2)?, row.get::<_, String>(5)?))
        })?;
        let mut role_refs: Vec<(i64, String)> = Vec::new();
        for r in rows {
            role_refs.push(r?);
            if role_refs.len() >= 32 {
                break;
            }
        }
        drop(stmt);
        let mut roles = Vec::new();
        for (role_id, role_name) in role_refs {
            let sets = self.load_role_permission_sets(role_id)?;
            roles.push(Role {
                role_name,
                permission_sets: sets,
                created_timestamp: 0,
                modified_timestamp: 0,
            });
        }
        Ok(roles)
    }

    /// `check_user_permission`: true when any permission set of any
    /// of the user's roles grants `permission` in `scope` and is
    /// active now. Like the C `bool` function, errors read as false.
    pub fn check_user_permission(
        &self,
        user_pubkey: &[u8; PUBKEY_SIZE],
        permission: u64,
        scope: PermissionScope,
    ) -> bool {
        let roles = match self.load_user_roles(user_pubkey) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let now = now_epoch();
        roles
            .iter()
            .any(|r| has_permission_in_scope(&r.permission_sets, permission, scope, now))
    }
}

fn trust_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeTrustEntry> {
    let pubkey_blob: Vec<u8> = row.get(0)?;
    let mut node_pubkey = [0u8; PUBKEY_SIZE];
    if pubkey_blob.len() == PUBKEY_SIZE {
        node_pubkey.copy_from_slice(&pubkey_blob);
    }
    Ok(NodeTrustEntry {
        node_pubkey,
        hostname: row.get(1)?,
        trusted_at: row.get::<_, i64>(2)? as u64,
        source: row.get(3)?,
    })
}

/// Copy a blob into a fixed-size array when its length matches
/// exactly; a wrong-length blob reads as zeroes (the
/// `device_from_row` idiom, factored out for the enrollment
/// row mappers).
fn blob_to_array<const N: usize>(blob: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    if blob.len() == N {
        out.copy_from_slice(blob);
    }
    out
}

/// [`blob_to_array`] for nullable pubkey columns: NULL (or a
/// wrong-length blob) reads as `None`.
fn blob_to_opt_pubkey(blob: Option<Vec<u8>>) -> Option<[u8; PUBKEY_SIZE]> {
    let blob = blob?;
    if blob.len() == PUBKEY_SIZE {
        Some(blob_to_array(&blob))
    } else {
        None
    }
}

/// Insert (or refresh) a device row from an already-verified
/// certificate: the write half of [`Store::device_add`], shared
/// with the enrollment completion transaction so both paths
/// store exactly the same row.
fn insert_device_row(
    conn: &Connection,
    cert: &DeviceCertificate,
    cert_bytes: &[u8],
    cert_hash: &[u8; 32],
    now: u64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO devices (member_pubkey, device_pubkey, label, cert, cert_hash, status, issued_at, expires_at, revoked_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, ?, ?) ON CONFLICT(member_pubkey, device_pubkey) DO UPDATE SET label=excluded.label, cert=excluded.cert, cert_hash=excluded.cert_hash, status='active', issued_at=excluded.issued_at, expires_at=excluded.expires_at, revoked_at=NULL, updated_at=excluded.updated_at",
        params![
            &cert.member_pubkey[..],
            &cert.device_pubkey[..],
            cert.label,
            cert_bytes,
            &cert_hash[..],
            cert.issued_at as i64,
            cert.expires_at as i64,
            now as i64,
            now as i64,
        ],
    )?;
    Ok(())
}

/// Insert one enrollment audit row; returns its row id. Shared
/// by [`Store::pairing_complete`] (inside its transaction) and
/// [`Store::enrollment_insert`] (the founding bootstrap).
fn insert_enrollment_row(conn: &Connection, record: &EnrollmentRecord) -> Result<i64> {
    conn.execute(
        "INSERT INTO enrollments (member_pubkey, device_pubkey, cert_hash, approver_kind, approver_member_pubkey, approver_device_pubkey, recovery_pubkey, approval_signature, approval_timestamp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            &record.member_pubkey[..],
            &record.device_pubkey[..],
            &record.cert_hash[..],
            record.approver_kind,
            record.approver_member_pubkey.as_ref().map(|k| &k[..]),
            record.approver_device_pubkey.as_ref().map(|k| &k[..]),
            record.recovery_pubkey.as_ref().map(|k| &k[..]),
            record.approval_signature,
            record.approval_timestamp as i64,
            record.created_at as i64,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn pairing_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PairingRecord> {
    let code_blob: Vec<u8> = row.get(0)?;
    let member_blob: Vec<u8> = row.get(1)?;
    let device_blob: Vec<u8> = row.get(2)?;
    let hash_blob: Vec<u8> = row.get(5)?;
    Ok(PairingRecord {
        code_hash: blob_to_array(&code_blob),
        member_pubkey: blob_to_array(&member_blob),
        device_pubkey: blob_to_array(&device_blob),
        display_name: row.get(3)?,
        cert: row.get(4)?,
        cert_hash: blob_to_array(&hash_blob),
        status: row.get(6)?,
        created_at: row.get::<_, i64>(7)? as u64,
        expires_at: row.get::<_, i64>(8)? as u64,
        used_at: row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
    })
}

fn enrollment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EnrollmentRecord> {
    let member_blob: Vec<u8> = row.get(1)?;
    let device_blob: Vec<u8> = row.get(2)?;
    let hash_blob: Vec<u8> = row.get(3)?;
    Ok(EnrollmentRecord {
        id: row.get(0)?,
        member_pubkey: blob_to_array(&member_blob),
        device_pubkey: blob_to_array(&device_blob),
        cert_hash: blob_to_array(&hash_blob),
        approver_kind: row.get(4)?,
        approver_member_pubkey: blob_to_opt_pubkey(row.get(5)?),
        approver_device_pubkey: blob_to_opt_pubkey(row.get(6)?),
        recovery_pubkey: blob_to_opt_pubkey(row.get(7)?),
        approval_signature: row.get(8)?,
        approval_timestamp: row.get::<_, i64>(9)? as u64,
        created_at: row.get::<_, i64>(10)? as u64,
    })
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceEntry> {
    let member_blob: Vec<u8> = row.get(0)?;
    let device_blob: Vec<u8> = row.get(1)?;
    let hash_blob: Vec<u8> = row.get(4)?;
    let mut member_pubkey = [0u8; PUBKEY_SIZE];
    if member_blob.len() == PUBKEY_SIZE {
        member_pubkey.copy_from_slice(&member_blob);
    }
    let mut device_pubkey = [0u8; PUBKEY_SIZE];
    if device_blob.len() == PUBKEY_SIZE {
        device_pubkey.copy_from_slice(&device_blob);
    }
    let mut cert_hash = [0u8; 32];
    if hash_blob.len() == 32 {
        cert_hash.copy_from_slice(&hash_blob);
    }
    let status_text: String = row.get(5)?;
    Ok(DeviceEntry {
        member_pubkey,
        device_pubkey,
        label: row.get(2)?,
        cert: row.get(3)?,
        cert_hash,
        status: DeviceStatus::from_db(&status_text),
        issued_at: row.get::<_, i64>(6)? as u64,
        expires_at: row.get::<_, i64>(7)? as u64,
        revoked_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        created_at: row.get::<_, i64>(9)? as u64,
        updated_at: row.get::<_, i64>(10)? as u64,
    })
}

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    fn key32(blob: Vec<u8>) -> [u8; PUBKEY_SIZE] {
        let mut key = [0u8; PUBKEY_SIZE];
        if blob.len() == PUBKEY_SIZE {
            key.copy_from_slice(&blob);
        }
        key
    }
    Ok(SessionRecord {
        session_id: row.get(0)?,
        owner_device_pubkey: key32(row.get(1)?),
        group_id: row.get(2)?,
        sender_member_pubkey: key32(row.get(3)?),
        sender_device_pubkey: key32(row.get(4)?),
        direction: row.get(5)?,
        chain_key: row.get(6)?,
        next_index: row.get::<_, i64>(7)? as u64,
        created_at: row.get::<_, i64>(8)? as u64,
        updated_at: row.get::<_, i64>(9)? as u64,
    })
}

fn peer_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GossipPeerInfo> {
    let pubkey_blob: Option<Vec<u8>> = row.get(3)?;
    let mut node_pubkey = [0u8; PUBKEY_SIZE];
    if let Some(blob) = pubkey_blob {
        if blob.len() == PUBKEY_SIZE {
            node_pubkey.copy_from_slice(&blob);
        }
    }
    Ok(GossipPeerInfo {
        hostname: row.get(0)?,
        gossip_port: row.get::<_, i64>(1)? as u16,
        api_port: row.get::<_, i64>(2)? as u16,
        node_pubkey,
        first_seen: row.get::<_, i64>(4)? as u64,
        last_seen: row.get::<_, i64>(5)? as u64,
        tags: row.get(6)?,
    })
}

#[allow(dead_code)]
struct RawMessageRow {
    id: i64,
    version: u32,
    timestamp: u64,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    group_id: Option<Vec<u8>>,
    payload_nonce: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    encrypted_payload: Vec<u8>,
    signature: Vec<u8>,
}

struct RawLocationRow {
    id: i64,
    timestamp: u64,
    payload_nonce: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    encrypted_payload: Vec<u8>,
    signature: Vec<u8>,
    is_envelope: bool,
}
#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Store {
        let store = Store::open_in_memory().expect("open in-memory");
        store.init_schema().expect("init schema");
        store
    }

    fn make_message(sender: &[u8; 32], recipient: &[u8; 32], timestamp: u64) -> Message {
        Message {
            header: Some(MessageHeader {
                version: 1,
                timestamp,
                sender_pubkey: sender.to_vec(),
                recipients_pubkey: vec![recipient.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![0x01; 24],
            ephemeral_pubkey: vec![0x02; 32],
            payload_ciphertext: vec![0x03; 16],
            keywraps: vec![MessageRecipientKeyWrap {
                recipient_pubkey: recipient.to_vec(),
                key_nonce: vec![0x04; 24],
                wrapped_key: vec![0x05; 32],
            }],
            signature: vec![0x06; 64],
            session_id: Vec::new(),
            message_index: 0,
        }
    }

    fn make_envelope(sender: &[u8; 32], recipient: &[u8; 32], timestamp: u64) -> Envelope {
        Envelope {
            header: Some(EnvelopeHeader {
                version: 1,
                content_type: 100,
                schema_version: 1,
                timestamp,
                sender_pubkey: sender.to_vec(),
                recipients_pubkey: vec![recipient.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![0x01; 24],
            ephemeral_pubkey: vec![0x02; 32],
            payload_ciphertext: vec![0x03; 16],
            keywraps: vec![RecipientKeyWrap {
                recipient_pubkey: recipient.to_vec(),
                key_nonce: vec![0x04; 24],
                wrapped_key: vec![0x05; 32],
            }],
            signature: vec![0x06; 64],
        }
    }

    fn make_client_request(sender: &[u8; 32], recipient: &[u8; 32], timestamp: u64) -> ClientRequest {
        ClientRequest {
            header: Some(ClientRequestHeader {
                version: 1,
                content_type: CONTENT_LOCATION_UPDATE,
                schema_version: 1,
                timestamp,
                sender_pubkey: sender.to_vec(),
                recipients_pubkey: vec![recipient.to_vec()],
                group_id: Vec::new(),
            }),
            payload_nonce: vec![0x01; 24],
            ephemeral_pubkey: vec![0x02; 32],
            payload_ciphertext: vec![0x03; 16],
            keywraps: vec![ClientRequestKeyWrap {
                recipient_pubkey: recipient.to_vec(),
                key_nonce: vec![0x04; 24],
                wrapped_key: vec![0x05; 32],
            }],
            signature: vec![0x06; 64],
        }
    }

    fn table_exists(store: &Store, name: &str) -> bool {
        let mut stmt = store
            .connection()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
            .unwrap();
        let mut rows = stmt.query(params![name]).unwrap();
        rows.next().unwrap().is_some()
    }

    #[test]
    fn sha256_known_vectors() {
        // FIPS 180-4 examples.
        assert_eq!(
            hex_encode_for_test(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode_for_test(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn hex_encode_for_test(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn schema_creation_idempotent_and_migration() {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        // Running schema creation twice must succeed (IF NOT EXISTS).
        store.init_schema().unwrap();
        for table in [
            "gossip_messages",
            "gossip_envelopes",
            "gossip_envelope_recipients",
            "users",
            "roles",
            "permissions",
            "user_roles",
            "role_permissions",
            "transaction_permissions",
            "gossip_seen",
            "nodes",
            "user_messages",
            "message_recipients",
            "location_updates",
            "location_keywraps",
            "gossip_peers",
            "node_trust",
        ] {
            assert!(table_exists(&store, table), "missing table {table}");
        }
        // Schema versioning: starts at 0, set/check round-trips.
        assert_eq!(store.schema_check_version().unwrap(), 0);
        store.schema_set_version(CURRENT_SCHEMA_VERSION).unwrap();
        assert_eq!(store.schema_check_version().unwrap(), 2);

        // Migration path on a fresh database: 0 -> 1, then 1 -> 2.
        let fresh = Store::open_in_memory().unwrap();
        fresh.schema_migrate(0, 1).unwrap();
        assert_eq!(fresh.schema_check_version().unwrap(), 1);
        assert!(table_exists(&fresh, "gossip_envelopes"));
        fresh.schema_migrate(1, 2).unwrap();
        assert_eq!(fresh.schema_check_version().unwrap(), 2);
        assert!(table_exists(&fresh, "nodes"));
        assert!(fresh.schema_migrate(2, 3).is_err());
    }

    #[test]
    fn nodes_insert_and_get() {
        let store = test_store();
        let node = NodeRecord {
            node_id: "node1".to_string(),
            node_name: "Node One".to_string(),
            hostname: "host1".to_string(),
            gossip_port: 9000,
            api_port: 8000,
            discovery_mode: "static".to_string(),
            hostname_prefix: String::new(),
            dns_domain: String::new(),
        };
        store.nodes_insert_or_update(&node).unwrap();
        let got = store.nodes_get_by_id("node1").unwrap().expect("node found");
        assert_eq!(got, node);
        assert!(store.nodes_get_by_id("missing").unwrap().is_none());
        let mut updated = node.clone();
        updated.api_port = 8001;
        store.nodes_insert_or_update(&updated).unwrap();
        assert_eq!(
            store.nodes_get_by_id("node1").unwrap().unwrap().api_port,
            8001
        );
    }
    #[test]
    fn message_insert_recent_and_conversation() {
        let mut store = test_store();
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let carol = [0x33u8; 32];
        store
            .message_store_save(&make_message(&alice, &bob, 100), 9_999_999_999)
            .unwrap();
        store
            .message_store_save(&make_message(&bob, &alice, 200), 9_999_999_999)
            .unwrap();
        store
            .message_store_save(&make_message(&alice, &carol, 300), 9_999_999_999)
            .unwrap();

        // Recent for bob: the two alice<->bob messages, newest first.
        let recent = store.message_store_fetch_recent(&bob, 10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].header.as_ref().unwrap().timestamp, 200);
        assert_eq!(recent[1].header.as_ref().unwrap().timestamp, 100);
        assert_eq!(
            recent[1].header.as_ref().unwrap().sender_pubkey,
            alice.to_vec()
        );
        assert_eq!(
            recent[1].header.as_ref().unwrap().recipients_pubkey,
            vec![bob.to_vec()]
        );
        assert_eq!(recent[1].keywraps.len(), 1);

        // Conversation alice<->bob excludes the carol message.
        let conv = store
            .message_store_fetch_conversation(&alice, &bob, 10)
            .unwrap();
        assert_eq!(conv.len(), 2);
        // Limit is honored.
        assert_eq!(
            store
                .message_store_fetch_conversation(&alice, &bob, 1)
                .unwrap()
                .len(),
            1
        );

        // Conversation partner list for alice: bob and carol.
        let list = store.message_store_fetch_conversations(&alice, 10).unwrap();
        assert_eq!(list.total_count, 2);
        assert_eq!(list.conversations.len(), 2);
        assert_eq!(list.conversations[0].partner_pubkey, carol.to_vec());
        assert_eq!(list.conversations[0].last_message_timestamp, 300);

        // Invalid messages are rejected (bad nonce length, no header).
        let mut bad = make_message(&alice, &bob, 400);
        bad.payload_nonce = vec![0u8; 10];
        assert!(store.message_store_save(&bad, 9_999_999_999).is_err());
        let mut no_header = make_message(&alice, &bob, 400);
        no_header.header = None;
        assert!(store.message_store_save(&no_header, 9_999_999_999).is_err());
        // Failed saves stored nothing new.
        assert_eq!(store.message_store_fetch_recent(&bob, 10).unwrap().len(), 2);
    }

    #[test]
    fn seen_digest_deduplication() {
        let store = test_store();
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let msg = make_message(&alice, &bob, 100);
        let digest = message_store_compute_digest(&msg);
        // Deterministic, and distinct for a distinct message.
        assert_eq!(digest, message_store_compute_digest(&msg));
        assert_ne!(
            digest,
            message_store_compute_digest(&make_message(&alice, &bob, 101))
        );
        assert!(!store.message_store_has_seen(&digest).unwrap());
        store.message_store_mark_seen(&digest, 9_999_999_999).unwrap();
        assert!(store.message_store_has_seen(&digest).unwrap());
        // The gossip/location views share the same table, as in C.
        assert!(store.gossip_store_has_seen(&digest).unwrap());
        assert!(store.location_store_has_seen(&digest).unwrap());
    }

    #[test]
    fn envelope_save_and_fetch() {
        let store = test_store();
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        let env = make_envelope(&alice, &bob, 500);
        store.gossip_store_save_envelope(&env, 9_999_999_999).unwrap();

        let recent = store.gossip_store_fetch_recent_envelopes(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].version, 1);
        assert_eq!(recent[0].content_type, 100);
        assert_eq!(recent[0].timestamp, 500);
        assert_eq!(recent[0].sender, alice.to_vec());
        // C quirk: plain fetch returns only the encrypted payload.
        assert_eq!(recent[0].envelope, vec![0x03u8; 16]);

        // For-user fetch (recipient side) returns a serialized envelope.
        let for_bob = store
            .gossip_store_fetch_recent_envelopes_for_user(&bob, 10)
            .unwrap();
        assert_eq!(for_bob.len(), 1);
        let decoded = Envelope::decode(&for_bob[0].envelope[..]).unwrap();
        assert_eq!(decoded.header.as_ref().unwrap().sender_pubkey, alice.to_vec());
        assert_eq!(
            decoded.header.as_ref().unwrap().recipients_pubkey,
            vec![bob.to_vec()]
        );
        assert_eq!(decoded.payload_ciphertext, vec![0x03u8; 16]);
        assert_eq!(decoded.keywraps.len(), 1);
        // Sender side matches too; strangers see nothing.
        assert_eq!(
            store
                .gossip_store_fetch_recent_envelopes_for_user(&alice, 10)
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .gossip_store_fetch_recent_envelopes_for_user(&[0x99u8; 32], 10)
                .unwrap()
                .is_empty()
        );
        // Invalid envelope (missing header) is rejected.
        let mut bad = make_envelope(&alice, &bob, 600);
        bad.header = None;
        assert!(store.gossip_store_save_envelope(&bad, 9_999_999_999).is_err());
    }

    #[test]
    fn location_update_latest_and_history() {
        let mut store = test_store();
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        store
            .location_store_save(&make_client_request(&alice, &bob, 100), 9_999_999_999)
            .unwrap();
        store
            .location_store_save(&make_client_request(&alice, &bob, 200), 9_999_999_999)
            .unwrap();
        store
            .location_store_save_envelope(&make_envelope(&alice, &bob, 300), 9_999_999_999)
            .unwrap();

        // Latest is the envelope update at t=300.
        let latest = store.location_store_get_latest(&alice).unwrap().unwrap();
        assert!(latest.is_envelope);
        let env = Envelope::decode(&latest.data[..]).unwrap();
        assert_eq!(env.header.as_ref().unwrap().timestamp, 300);
        assert_eq!(
            env.header.as_ref().unwrap().content_type,
            CONTENT_LOCATION_UPDATE
        );

        // History is newest-first with per-row envelope flags.
        let history = store.location_store_get_history(&alice, 10, 0).unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[0].is_envelope);
        assert!(!history[1].is_envelope);
        let req = ClientRequest::decode(&history[1].data[..]).unwrap();
        assert_eq!(req.header.as_ref().unwrap().timestamp, 200);
        assert_eq!(
            req.header.as_ref().unwrap().recipients_pubkey,
            vec![bob.to_vec()]
        );
        // Limit/offset page through history.
        let page = store.location_store_get_history(&alice, 1, 2).unwrap();
        assert_eq!(page.len(), 1);
        let oldest = ClientRequest::decode(&page[0].data[..]).unwrap();
        assert_eq!(oldest.header.as_ref().unwrap().timestamp, 100);
        // Unknown user: no latest, empty history.
        assert!(store.location_store_get_latest(&bob).unwrap().is_none());
    }

    #[test]
    fn ttl_cleanup_removes_expired_keeps_fresh() {
        let mut store = test_store();
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        // Expiring exactly at the cleanup instant is removed (<=).
        store
            .gossip_store_save_envelope(&make_envelope(&alice, &bob, 100), 1_000)
            .unwrap();
        store
            .gossip_store_save_envelope(&make_envelope(&alice, &bob, 200), 9_999_999_999)
            .unwrap();
        store
            .message_store_save(&make_message(&alice, &bob, 100), 500)
            .unwrap();
        store
            .message_store_save(&make_message(&alice, &bob, 200), 9_999_999_999)
            .unwrap();
        let expired_digest = [0x01u8; 32];
        let fresh_digest = [0x02u8; 32];
        store.gossip_store_mark_seen(&expired_digest, 999).unwrap();
        store.gossip_store_mark_seen(&fresh_digest, 9_999_999_999).unwrap();

        store.gossip_store_cleanup(1_000).unwrap();

        let envelopes = store.gossip_store_fetch_recent_envelopes(10).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].timestamp, 200);
        let messages = store.message_store_fetch_recent(&bob, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.as_ref().unwrap().timestamp, 200);
        assert!(!store.gossip_store_has_seen(&expired_digest).unwrap());
        assert!(store.gossip_store_has_seen(&fresh_digest).unwrap());
        // Default-TTL helper: 30 days, as configured in config.c.
        assert_eq!(DEFAULT_TTL_SECS, 2_592_000);
        assert_eq!(default_expires_at(1_000), 1_000 + 2_592_000);
    }
    #[test]
    fn gossip_peer_add_list_remove() {
        let store = test_store();
        store
            .gossip_peers_add_or_update("host-b", 9000, 8000, Some("beta"))
            .unwrap();
        store
            .gossip_peers_add_or_update("host-a", 9001, 8001, None)
            .unwrap();

        // Ordered by hostname. Address rows carry no key on
        // their own: node_pubkey is zero until trust is granted
        // for that hostname.
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].hostname, "host-a");
        assert_eq!(peers[0].gossip_port, 9001);
        assert_eq!(peers[0].node_pubkey, [0u8; 32]);
        assert_eq!(peers[0].tags, "");
        assert_eq!(peers[1].tags, "beta");
        assert!(peers[0].first_seen > 0);

        // Update keeps first_seen, replaces ports/tags.
        let first_seen = peers[0].first_seen;
        store
            .gossip_peers_add_or_update("host-a", 9100, 8100, Some("alpha"))
            .unwrap();
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers[0].gossip_port, 9100);
        assert_eq!(peers[0].tags, "alpha");
        assert_eq!(peers[0].first_seen, first_seen);

        // Touch on an unknown host inserts a zero-port placeholder.
        store.gossip_peers_touch("host-c").unwrap();
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[2].hostname, "host-c");
        assert_eq!(peers[2].gossip_port, 0);

        // Remove: first removal reports true, second false.
        assert!(store.gossip_peers_remove("host-c").unwrap());
        assert!(!store.gossip_peers_remove("host-c").unwrap());
        assert_eq!(store.gossip_peers_fetch_all().unwrap().len(), 2);

        // Empty hostname is rejected, as in C.
        assert!(store.gossip_peers_add_or_update("", 1, 1, None).is_err());
    }

    #[test]
    fn node_trust_add_get_list_remove() {
        let store = test_store();
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        assert!(!store.node_trust_is_trusted(&key1).unwrap());
        assert!(store.node_trust_get(&key1).unwrap().is_none());

        store
            .node_trust_add(&key1, Some("host-a"), "seed")
            .unwrap();
        store.node_trust_add(&key2, None, "enrollment").unwrap();
        assert!(store.node_trust_is_trusted(&key1).unwrap());
        assert!(store.node_trust_is_trusted(&key2).unwrap());

        let entry = store.node_trust_get(&key1).unwrap().unwrap();
        assert_eq!(entry.hostname, "host-a");
        assert_eq!(entry.source, "seed");
        assert!(entry.trusted_at > 0);
        // A grant without an address records an empty hint.
        assert_eq!(store.node_trust_get(&key2).unwrap().unwrap().hostname, "");

        // The peer list surfaces the trusted key for its hostname.
        store
            .gossip_peers_add_or_update("host-a", 9000, 8000, None)
            .unwrap();
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers[0].node_pubkey, key1);

        let list = store.node_trust_list().unwrap();
        assert_eq!(list.len(), 2);

        // Re-grant refreshes the source but keeps trusted_at.
        let before = store.node_trust_get(&key1).unwrap().unwrap();
        store
            .node_trust_add(&key1, Some("host-a2"), "enrollment")
            .unwrap();
        let after = store.node_trust_get(&key1).unwrap().unwrap();
        assert_eq!(after.trusted_at, before.trusted_at);
        assert_eq!(after.hostname, "host-a2");
        assert_eq!(after.source, "enrollment");

        // Revocation: first remove reports true, second false.
        assert!(store.node_trust_remove(&key1).unwrap());
        assert!(!store.node_trust_is_trusted(&key1).unwrap());
        assert!(!store.node_trust_remove(&key1).unwrap());
    }

    /// Regression test for DESIGN.md §10: discovery/bootstrap
    /// persistence (the exact `gossip_peers_add_or_update` call
    /// the peer sink performs, plus touch) must never erase a
    /// trusted key.
    #[test]
    fn node_trust_survives_discovery_upserts() {
        let store = test_store();
        let key = [0x42u8; 32];
        store.node_trust_add(&key, Some("host-a"), "seed").unwrap();

        // Address-book writes of every flavour discovery makes.
        store
            .gossip_peers_add_or_update("host-a", 9000, 8000, None)
            .unwrap();
        store
            .gossip_peers_add_or_update("host-a", 9000, 0, None)
            .unwrap();
        store.gossip_peers_touch("host-a").unwrap();

        assert!(store.node_trust_is_trusted(&key).unwrap());
        let entry = store.node_trust_get(&key).unwrap().unwrap();
        assert_eq!(entry.hostname, "host-a");
        // ... and the address row still displays the trusted key.
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_pubkey, key);
    }

    /// A database written by the pre-fix code (pubkey in the
    /// peers table) keeps its trust after the split: the first
    /// trust/peer operation migrates the legacy values.
    #[test]
    fn node_trust_migrates_legacy_peer_pubkeys() {
        let store = test_store();
        let key = [0x24u8; 32];
        store
            .connection()
            .execute(
                "INSERT INTO gossip_peers (hostname, gossip_port, api_port, node_pubkey, first_seen, last_seen, tags) VALUES ('legacy', 9000, 8000, ?1, 100, 100, NULL)",
                params![&key[..]],
            )
            .unwrap();
        assert!(store.node_trust_is_trusted(&key).unwrap());
        let entry = store.node_trust_get(&key).unwrap().unwrap();
        assert_eq!(entry.source, "migrated");
        assert_eq!(entry.hostname, "legacy");
        assert_eq!(entry.trusted_at, 100);
    }

    /// The Wave 2 smoke scenario at store level (DESIGN.md
    /// §10): trust is applied, the store is reopened (node
    /// restart), startup bootstrap persists the peer's address
    /// again — and the key must still be trusted.
    #[test]
    fn node_trust_survives_reopen_and_bootstrap() {
        let path = std::env::temp_dir().join(format!(
            "tinyweb_store_trust_test_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let key = [0x33u8; 32];
        {
            let store = Store::open(&path).unwrap();
            store.init_schema().unwrap();
            store
                .node_trust_add(&key, Some("peer-node"), "seed")
                .unwrap();
            store
                .gossip_peers_add_or_update("peer-node", 9000, 8000, None)
                .unwrap();
        }
        // "Restart": reopen, re-init, re-run bootstrap's
        // address persistence for the already-known peer.
        let store = Store::open(&path).unwrap();
        store.init_schema().unwrap();
        store
            .gossip_peers_add_or_update("peer-node", 9000, 0, None)
            .unwrap();
        assert!(store.node_trust_is_trusted(&key).unwrap());
        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A member keystore with a member key and one device key
    /// labelled `label`, plus the certificate issued for that
    /// device at `issued_at` with no expiry.
    fn member_with_cert(
        label: &str,
        issued_at: u64,
    ) -> (
        crate::keystore::MemberKeystore,
        DeviceCertificate,
        [u8; PUBKEY_SIZE],
        [u8; PUBKEY_SIZE],
    ) {
        let mut member = crate::keystore::MemberKeystore::new();
        member.generate_member_key().unwrap();
        let device_pubkey = member.add_device_key(label).unwrap();
        let cert = crate::identity::issue_device_certificate(&member, label, issued_at, 0).unwrap();
        let member_pubkey = member.member_public_key().unwrap();
        (member, cert, member_pubkey, device_pubkey)
    }

    #[test]
    fn device_add_get_list_and_trust() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);

        // Unknown pairs are not trusted and not found.
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW).unwrap());
        assert!(store.device_get(&member_pk, &device_pk).unwrap().is_none());
        assert!(store.device_list(&member_pk).unwrap().is_empty());

        store.device_add(&cert, NOW).unwrap();
        assert!(store.device_is_trusted(&member_pk, &device_pk, NOW).unwrap());
        // No-expiry certificates stay trusted.
        assert!(store
            .device_is_trusted(&member_pk, &device_pk, NOW + 10_000_000)
            .unwrap());
        // ... but only for the member who vouched for the device.
        assert!(!store
            .device_is_trusted(&[0xEE; 32], &device_pk, NOW)
            .unwrap());

        let entry = store.device_get(&member_pk, &device_pk).unwrap().unwrap();
        assert_eq!(entry.label, "phone");
        assert_eq!(entry.status, DeviceStatus::Active);
        assert_eq!(entry.issued_at, NOW);
        assert_eq!(entry.expires_at, 0);
        assert_eq!(entry.revoked_at, None);
        let cert_bytes = cert.encode_to_vec();
        assert_eq!(entry.cert, cert_bytes);
        let expected_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
        assert_eq!(entry.cert_hash, expected_hash);

        let list = store.device_list(&member_pk).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], entry);
    }

    #[test]
    fn device_add_rejects_tampered_and_expired_certificates() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);

        // A certificate whose label was changed after signing
        // does not verify and is never stored.
        let mut tampered = cert.clone();
        tampered.label = "forged".to_string();
        assert!(store.device_add(&tampered, NOW).is_err());
        assert!(store.device_get(&member_pk, &device_pk).unwrap().is_none());

        // An already-expired certificate is rejected at add
        // time, not stored to fail later.
        let expired = crate::identity::create_device_certificate(
            member.member_keystore(),
            &device_pk,
            "phone",
            NOW - 100,
            NOW - 50,
        )
        .unwrap();
        assert!(store.device_add(&expired, NOW).is_err());
        assert!(store.device_get(&member_pk, &device_pk).unwrap().is_none());
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW).unwrap());
    }

    #[test]
    fn device_revoke_flips_status_and_keeps_the_row() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        store.device_add(&cert, NOW).unwrap();

        assert!(store.device_revoke(&member_pk, &device_pk, NOW + 5).unwrap());
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW + 6).unwrap());
        // The row remains as an audit trail.
        let entry = store.device_get(&member_pk, &device_pk).unwrap().unwrap();
        assert_eq!(entry.status, DeviceStatus::Revoked);
        assert_eq!(entry.revoked_at, Some(NOW + 5));
        assert_eq!(store.device_list(&member_pk).unwrap().len(), 1);
        // Revoking again (or an unknown pair) changes nothing.
        assert!(!store.device_revoke(&member_pk, &device_pk, NOW + 7).unwrap());
        assert!(!store.device_revoke(&member_pk, &[0x99; 32], NOW + 7).unwrap());

        // A fresh certificate from the member re-activates the
        // device (re-issuance).
        store.device_add(&cert, NOW + 10).unwrap();
        let entry = store.device_get(&member_pk, &device_pk).unwrap().unwrap();
        assert_eq!(entry.status, DeviceStatus::Active);
        assert_eq!(entry.revoked_at, None);
        assert!(store.device_is_trusted(&member_pk, &device_pk, NOW + 10).unwrap());
    }

    #[test]
    fn device_apply_revocation_verifies_the_signature() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        store.device_add(&cert, NOW).unwrap();

        let revocation = crate::identity::create_device_revocation(
            member.member_keystore(),
            &device_pk,
            NOW + 5,
            "lost",
        )
        .unwrap();
        // A revocation whose reason was altered after signing
        // is rejected and changes nothing.
        let mut forged = revocation.clone();
        forged.reason = "forged".to_string();
        assert!(store.device_apply_revocation(&forged).is_err());
        assert!(store.device_is_trusted(&member_pk, &device_pk, NOW + 6).unwrap());

        assert!(store.device_apply_revocation(&revocation).unwrap());
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW + 6).unwrap());
        let entry = store.device_get(&member_pk, &device_pk).unwrap().unwrap();
        assert_eq!(entry.status, DeviceStatus::Revoked);
        assert_eq!(entry.revoked_at, Some(NOW + 5));
    }

    #[test]
    fn member_with_two_devices_has_independent_trust() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let mut member = crate::keystore::MemberKeystore::new();
        member.generate_member_key().unwrap();
        let member_pk = member.member_public_key().unwrap();
        let phone = member.add_device_key("phone").unwrap();
        let laptop = member.add_device_key("laptop").unwrap();
        for label in ["phone", "laptop"] {
            let cert =
                crate::identity::issue_device_certificate(&member, label, NOW, 0).unwrap();
            store.device_add(&cert, NOW).unwrap();
        }
        assert!(store.device_is_trusted(&member_pk, &phone, NOW).unwrap());
        assert!(store.device_is_trusted(&member_pk, &laptop, NOW).unwrap());
        assert_eq!(store.device_list(&member_pk).unwrap().len(), 2);

        // Revoking one device leaves the other trusted.
        assert!(store.device_revoke(&member_pk, &phone, NOW + 1).unwrap());
        assert!(!store.device_is_trusted(&member_pk, &phone, NOW + 1).unwrap());
        assert!(store.device_is_trusted(&member_pk, &laptop, NOW + 1).unwrap());
        let list = store.device_list(&member_pk).unwrap();
        assert_eq!(list.len(), 2);
        let statuses: Vec<DeviceStatus> = list.iter().map(|d| d.status).collect();
        assert!(statuses.contains(&DeviceStatus::Revoked));
        assert!(statuses.contains(&DeviceStatus::Active));
    }

    #[test]
    fn devices_survive_reopen() {
        const NOW: u64 = 1_700_000_000;
        let path = std::env::temp_dir().join(format!(
            "tinyweb_store_devices_test_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        {
            let store = Store::open(&path).unwrap();
            store.init_schema().unwrap();
            store.device_add(&cert, NOW).unwrap();
            assert!(store.device_revoke(&member_pk, &device_pk, NOW + 5).unwrap());
        }
        // "Restart": the enrollment record, including the
        // revocation, is still there and still decisive.
        let store = Store::open(&path).unwrap();
        store.init_schema().unwrap();
        let entry = store.device_get(&member_pk, &device_pk).unwrap().unwrap();
        assert_eq!(entry.status, DeviceStatus::Revoked);
        assert_eq!(entry.revoked_at, Some(NOW + 5));
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW + 6).unwrap());
        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn permission_checks() {
        let store = test_store();
        let alice = [0xABu8; 32];
        let alice_hex = hex_encode_pubkey(&alice);
        let conn = store.connection();
        conn.execute(
            "INSERT INTO users (pubkey, username, is_active) VALUES (?1, 'alice', 1)",
            params![alice_hex],
        )
        .unwrap();
        let user_id = conn.last_insert_rowid();
        conn.execute("INSERT INTO roles (name) VALUES ('member')", params![])
            .unwrap();
        let role_id = conn.last_insert_rowid();
        // Two permission rows sharing one scope/conditions group are
        // OR-ed into a single set by load_role_permission_sets.
        conn.execute(
            "INSERT INTO permissions (name, permission_flags, scope_flags, condition_flags, category) VALUES ('send', ?1, 0, 0, 0)",
            params![PERMISSION_SEND_MESSAGE as i64],
        )
        .unwrap();
        let send_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO permissions (name, permission_flags, scope_flags, condition_flags, category) VALUES ('fwd', ?1, 0, 0, 0)",
            params![PERMISSION_FORWARD_MESSAGE as i64],
        )
        .unwrap();
        let fwd_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            params![user_id, role_id],
        )
        .unwrap();
        let direct = PermissionScope::Direct.bit() as i64;
        conn.execute(
            "INSERT INTO role_permissions (role_id, permission_id, scope_flags, condition_flags) VALUES (?1, ?2, ?3, ?4)",
            params![role_id, send_id, direct, CONDITION_ALWAYS as i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO role_permissions (role_id, permission_id, scope_flags, condition_flags) VALUES (?1, ?2, ?3, ?4)",
            params![role_id, fwd_id, direct, CONDITION_ALWAYS as i64],
        )
        .unwrap();
        // An expired time-restricted grant must not take effect.
        conn.execute(
            "INSERT INTO permissions (name, permission_flags, scope_flags, condition_flags, category) VALUES ('read', ?1, 0, 0, 0)",
            params![PERMISSION_READ_MESSAGE as i64],
        )
        .unwrap();
        let read_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO role_permissions (role_id, permission_id, scope_flags, condition_flags, time_start, time_end) VALUES (?1, ?2, ?3, ?4, 0, 1)",
            params![role_id, read_id, direct, CONDITION_TIME_RESTRICTED as i64],
        )
        .unwrap();

        assert!(store.user_exists(&alice));
        assert!(!store.user_exists(&[0xCDu8; 32]));

        let roles = store.load_user_roles(&alice).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].role_name, "member");
        assert_eq!(roles[0].permission_sets.len(), 2);
        let grouped = roles[0]
            .permission_sets
            .iter()
            .find(|s| s.conditions == CONDITION_ALWAYS)
            .unwrap();
        assert_eq!(
            grouped.permissions,
            PERMISSION_SEND_MESSAGE | PERMISSION_FORWARD_MESSAGE
        );
        assert!(store.load_user_roles(&[0xCDu8; 32]).unwrap().is_empty());

        assert!(store.check_user_permission(
            &alice,
            PERMISSION_SEND_MESSAGE,
            PermissionScope::Direct
        ));
        assert!(!store.check_user_permission(
            &alice,
            PERMISSION_SEND_MESSAGE,
            PermissionScope::Community
        ));
        assert!(!store.check_user_permission(
            &alice,
            PERMISSION_READ_MESSAGE,
            PermissionScope::Direct
        ));
        assert!(!store.check_user_permission(
            &[0xCDu8; 32],
            PERMISSION_SEND_MESSAGE,
            PermissionScope::Direct
        ));

        // Inactive users do not exist, as in C.
        let mallory = [0xEFu8; 32];
        conn.execute(
            "INSERT INTO users (pubkey, username, is_active) VALUES (?1, 'mallory', 0)",
            params![hex_encode_pubkey(&mallory)],
        )
        .unwrap();
        assert!(!store.user_exists(&mallory));
    }

    #[test]
    fn file_backed_store_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "tinyweb_store_test_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        {
            let mut store = Store::open(&path).unwrap();
            store.init_schema().unwrap();
            store
                .message_store_save(&make_message(&alice, &bob, 42), 9_999_999_999)
                .unwrap();
        }
        // Reopening the same file sees the row (WAL file database).
        let store = Store::open(&path).unwrap();
        store.init_schema().unwrap();
        assert_eq!(store.message_store_fetch_recent(&bob, 10).unwrap().len(), 1);
        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn parent_approval() -> PairingApproval {
        PairingApproval {
            approver_kind: "parent".to_string(),
            approver_member_pubkey: Some([0xAA; 32]),
            approver_device_pubkey: Some([0xBB; 32]),
            recovery_pubkey: None,
            approval_signature: vec![0x0A; 64],
            approval_timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn pairing_create_get_and_fresh_begin_retires_prior_code() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        let hash_a = [0xA1; 32];
        let hash_b = [0xB2; 32];

        assert!(store.pairing_get(&hash_a).unwrap().is_none());
        store
            .pairing_create(&hash_a, &cert, "New Member", NOW, NOW + 600)
            .unwrap();
        let record = store.pairing_get(&hash_a).unwrap().unwrap();
        assert_eq!(record.member_pubkey, member_pk);
        assert_eq!(record.device_pubkey, device_pk);
        assert_eq!(record.display_name, "New Member");
        assert_eq!(record.status, "pending");
        assert_eq!(record.expires_at, NOW + 600);
        assert_eq!(record.used_at, None);
        let cert_bytes = cert.encode_to_vec();
        assert_eq!(record.cert, cert_bytes);
        let expected_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
        assert_eq!(record.cert_hash, expected_hash);

        // A fresh begin for the same (member, device) retires
        // the earlier pending code: only the newest can complete.
        store
            .pairing_create(&hash_b, &cert, "New Member", NOW + 1, NOW + 601)
            .unwrap();
        assert_eq!(
            store.pairing_get(&hash_a).unwrap().unwrap().status,
            "expired"
        );
        assert_eq!(
            store.pairing_complete(&hash_a, &parent_approval(), NOW + 2)
                .unwrap(),
            PairingCompleteOutcome::Expired
        );
        assert_eq!(
            store.pairing_get(&hash_b).unwrap().unwrap().status,
            "pending"
        );

        // A tampered certificate is rejected at create and
        // never stored.
        let mut forged = cert.clone();
        forged.label = "forged".to_string();
        assert!(store
            .pairing_create(&[0xC3; 32], &forged, "Forged", NOW, NOW + 600)
            .is_err());
        assert!(store.pairing_get(&[0xC3; 32]).unwrap().is_none());
    }

    #[test]
    fn pairing_complete_enrolls_atomically_and_only_once() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        let code_hash = [0xD4; 32];
        store
            .pairing_create(&code_hash, &cert, "New Member", NOW, NOW + 600)
            .unwrap();

        // Unknown codes complete nothing.
        assert_eq!(
            store
                .pairing_complete(&[0xFF; 32], &parent_approval(), NOW + 1)
                .unwrap(),
            PairingCompleteOutcome::UnknownCode
        );
        assert!(!store.user_exists(&member_pk));

        assert_eq!(
            store
                .pairing_complete(&code_hash, &parent_approval(), NOW + 1)
                .unwrap(),
            PairingCompleteOutcome::Completed
        );
        // Everything landed together: user row, trusted device,
        // audit record, pairing marked used.
        assert!(store.user_exists(&member_pk));
        assert!(store.device_is_trusted(&member_pk, &device_pk, NOW + 1).unwrap());
        let record = store.pairing_get(&code_hash).unwrap().unwrap();
        assert_eq!(record.status, "used");
        assert_eq!(record.used_at, Some(NOW + 1));
        let enrollments = store.enrollments_for_member(&member_pk).unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].approver_kind, "parent");
        assert_eq!(
            enrollments[0].approver_member_pubkey,
            Some([0xAA; 32])
        );
        assert_eq!(
            enrollments[0].approver_device_pubkey,
            Some([0xBB; 32])
        );
        assert_eq!(enrollments[0].recovery_pubkey, None);
        assert_eq!(enrollments[0].cert_hash, record.cert_hash);

        // The same code never completes twice.
        assert_eq!(
            store
                .pairing_complete(&code_hash, &parent_approval(), NOW + 2)
                .unwrap(),
            PairingCompleteOutcome::AlreadyUsed
        );
        assert_eq!(store.enrollments_for_member(&member_pk).unwrap().len(), 1);
    }

    #[test]
    fn pairing_complete_after_expiry_enrolls_nothing() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let (_member, cert, member_pk, device_pk) = member_with_cert("phone", NOW);
        let code_hash = [0xE5; 32];
        store
            .pairing_create(&code_hash, &cert, "Late Member", NOW, NOW + 600)
            .unwrap();
        assert_eq!(
            store
                .pairing_complete(&code_hash, &parent_approval(), NOW + 600)
                .unwrap(),
            PairingCompleteOutcome::Expired
        );
        assert!(!store.user_exists(&member_pk));
        assert!(!store.device_is_trusted(&member_pk, &device_pk, NOW).unwrap());
        assert!(store.enrollments_for_member(&member_pk).unwrap().is_empty());
        assert_eq!(
            store.pairing_get(&code_hash).unwrap().unwrap().status,
            "expired"
        );
    }

    #[test]
    fn recovery_approver_registration() {
        let store = test_store();
        let key = [0x42; 32];
        assert!(!store.recovery_approver_is_registered(&key).unwrap());
        store.recovery_approver_add(&key, "backup card", 1_700_000_000).unwrap();
        assert!(store.recovery_approver_is_registered(&key).unwrap());
        assert!(!store.recovery_approver_is_registered(&[0x43; 32]).unwrap());
        // Re-adding is a no-op, not an error.
        store.recovery_approver_add(&key, "backup card", 1_700_000_100).unwrap();
        assert!(store.recovery_approver_is_registered(&key).unwrap());
    }

    // -- Phase B4: sessions, visibility, membership -----------------

    #[test]
    fn session_state_round_trip_and_skipped_keys() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let session_id = vec![0x51; 16];
        let group_id = vec![0x61; 16];
        let owner = [0x01; 32];
        let member = [0x02; 32];
        let device = [0x03; 32];

        assert!(store.session_get(&session_id, &owner).unwrap().is_none());
        store
            .session_save(
                &session_id,
                &owner,
                &group_id,
                &member,
                &device,
                "received",
                &[0xAA; 32],
                0,
                NOW,
            )
            .unwrap();
        let rec = store.session_get(&session_id, &owner).unwrap().unwrap();
        assert_eq!(rec.group_id, group_id);
        assert_eq!(rec.sender_member_pubkey, member);
        assert_eq!(rec.sender_device_pubkey, device);
        assert_eq!(rec.direction, "received");
        assert_eq!(rec.chain_key, vec![0xAA; 32]);
        assert_eq!(rec.next_index, 0);
        // Another device holds no state for this session.
        assert!(store.session_get(&session_id, &[0x09; 32]).unwrap().is_none());

        // Advancing replaces the chain state, never the identity.
        assert!(store
            .session_update_state(&session_id, &owner, &[0xBB; 32], 3, NOW + 5)
            .unwrap());
        let rec = store.session_get(&session_id, &owner).unwrap().unwrap();
        assert_eq!(rec.chain_key, vec![0xBB; 32]);
        assert_eq!(rec.next_index, 3);
        assert!(!store
            .session_update_state(&session_id, &[0x09; 32], &[0xBB; 32], 3, NOW)
            .unwrap());

        // Skipped keys: put, get, count, consume.
        assert_eq!(store.session_skipped_key_count(&session_id, &owner).unwrap(), 0);
        store
            .session_skipped_key_put(&session_id, &owner, 1, &[0xCC; 32])
            .unwrap();
        store
            .session_skipped_key_put(&session_id, &owner, 2, &[0xDD; 32])
            .unwrap();
        assert_eq!(store.session_skipped_key_count(&session_id, &owner).unwrap(), 2);
        assert_eq!(
            store.session_skipped_key_get(&session_id, &owner, 1).unwrap(),
            Some(vec![0xCC; 32])
        );
        store.session_skipped_key_remove(&session_id, &owner, 1).unwrap();
        assert_eq!(
            store.session_skipped_key_get(&session_id, &owner, 1).unwrap(),
            None
        );
        assert_eq!(store.session_skipped_key_count(&session_id, &owner).unwrap(), 1);
    }

    #[test]
    fn session_state_survives_reopen() {
        const NOW: u64 = 1_700_000_000;
        let dir = std::env::temp_dir().join(format!(
            "tinyweb-b4-store-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.db");
        let session_id = vec![0x52; 16];
        let owner = [0x01; 32];
        {
            let store = Store::open(&path).unwrap();
            store.init_schema().unwrap();
            store
                .session_save(
                    &session_id,
                    &owner,
                    &[0x62; 16],
                    &[0x02; 32],
                    &[0x03; 32],
                    "own",
                    &[0xAA; 32],
                    7,
                    NOW,
                )
                .unwrap();
            store
                .session_skipped_key_put(&session_id, &owner, 4, &[0xCC; 32])
                .unwrap();
        }
        {
            let store = Store::open(&path).unwrap();
            store.init_schema().unwrap();
            let rec = store.session_get(&session_id, &owner).unwrap().unwrap();
            assert_eq!(rec.direction, "own");
            assert_eq!(rec.next_index, 7);
            assert_eq!(
                store.session_skipped_key_get(&session_id, &owner, 4).unwrap(),
                Some(vec![0xCC; 32])
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_links_visibility_and_conversation_members() {
        const NOW: u64 = 1_700_000_000;
        let store = test_store();
        let parent = [0x0A; 32];
        let other_parent = [0x0B; 32];
        let child = [0x0C; 32];
        let group_id = vec![0x63; 16];

        // No link, no setting: no parents, visibility none.
        assert!(store.parents_of(&child).unwrap().is_empty());
        assert_eq!(store.visibility_get(&child).unwrap(), VisibilityLevel::None);

        store.parent_link_add(&parent, &child).unwrap();
        store.parent_link_add(&other_parent, &child).unwrap();
        store.parent_link_add(&parent, &child).unwrap(); // idempotent
        assert_eq!(store.parents_of(&child).unwrap(), vec![parent, other_parent]);

        store
            .visibility_set(&child, VisibilityLevel::RecipientsAndTimes, &parent, NOW)
            .unwrap();
        assert_eq!(
            store.visibility_get(&child).unwrap(),
            VisibilityLevel::RecipientsAndTimes
        );
        store
            .visibility_set(&child, VisibilityLevel::Full, &other_parent, NOW + 1)
            .unwrap();
        assert_eq!(store.visibility_get(&child).unwrap(), VisibilityLevel::Full);

        // Membership: join order preserved, removal works.
        assert!(store.conversation_members(&group_id).unwrap().is_empty());
        store.conversation_member_add(&group_id, &child, NOW).unwrap();
        store.conversation_member_add(&group_id, &parent, NOW + 1).unwrap();
        store.conversation_member_add(&group_id, &child, NOW + 2).unwrap(); // no dup
        assert_eq!(
            store.conversation_members(&group_id).unwrap(),
            vec![child, parent]
        );
        assert!(store.conversation_member_remove(&group_id, &child).unwrap());
        assert!(!store.conversation_member_remove(&group_id, &child).unwrap());
        assert_eq!(store.conversation_members(&group_id).unwrap(), vec![parent]);
    }

    #[test]
    fn message_session_fields_round_trip() {
        let store = test_store();
        let sender = [0x21; 32];
        let recipient = [0x22; 32];
        let mut store = store;

        // A legacy message stores and reads back with no
        // session fields.
        let legacy = make_message(&sender, &recipient, 1_700_000_000);
        store.message_store_save(&legacy, 1_700_100_000).unwrap();

        // A session message keeps its session id + index.
        let mut session_msg = make_message(&sender, &recipient, 1_700_000_100);
        session_msg.session_id = vec![0x53; 16];
        session_msg.message_index = 42;
        store.message_store_save(&session_msg, 1_700_100_000).unwrap();

        let recent = store
            .message_store_fetch_recent(&recipient, 10)
            .unwrap();
        assert_eq!(recent.len(), 2);
        let by_ts: std::collections::HashMap<u64, &Message> = recent
            .iter()
            .map(|m| (m.header.as_ref().unwrap().timestamp, m))
            .collect();
        let legacy_back = by_ts[&1_700_000_000];
        assert!(legacy_back.session_id.is_empty());
        assert_eq!(legacy_back.message_index, 0);
        let session_back = by_ts[&1_700_000_100];
        assert_eq!(session_back.session_id, vec![0x53; 16]);
        assert_eq!(session_back.message_index, 42);
    }
}










