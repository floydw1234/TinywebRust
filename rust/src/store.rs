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

use crate::proto::{
    ClientRequest, ClientRequestHeader, ClientRequestKeyWrap, ConversationList,
    ConversationSummary, Envelope, EnvelopeHeader, Message, MessageHeader,
    MessageRecipientKeyWrap, RecipientKeyWrap, StoredEnvelope,
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

/// C `GossipPeerInfo` (`gossip_peers.h`).
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
        Ok(())
    }

    /// `gossip_peers_add_or_update`. On hostname conflict the ports,
    /// pubkey, `last_seen` and tags are replaced; `first_seen` is
    /// preserved. Empty tags bind as NULL.
    pub fn gossip_peers_add_or_update(
        &self,
        hostname: &str,
        gossip_port: u16,
        api_port: u16,
        node_pubkey: Option<&[u8; PUBKEY_SIZE]>,
        tags: Option<&str>,
    ) -> Result<()> {
        if hostname.is_empty() {
            return Err(invalid("hostname is empty"));
        }
        self.gossip_peers_init()?;
        let now = now_epoch() as i64;
        let pubkey: Option<&[u8]> = node_pubkey.map(|k| &k[..]);
        let tags: Option<&str> = tags.filter(|t| !t.is_empty());
        self.conn.execute(
            "INSERT INTO gossip_peers (hostname, gossip_port, api_port, node_pubkey, first_seen, last_seen, tags) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(hostname) DO UPDATE SET gossip_port=excluded.gossip_port, api_port=excluded.api_port, node_pubkey=excluded.node_pubkey, last_seen=excluded.last_seen, tags=excluded.tags",
            params![
                hostname,
                gossip_port as i64,
                api_port as i64,
                pubkey,
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
            self.gossip_peers_add_or_update(hostname, 0, 0, None, None)?;
        }
        Ok(())
    }

    /// `gossip_peers_fetch_all`, ordered by hostname.
    pub fn gossip_peers_fetch_all(&self) -> Result<Vec<GossipPeerInfo>> {
        self.gossip_peers_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT hostname, gossip_port, api_port, node_pubkey, first_seen, last_seen, COALESCE(tags, '') FROM gossip_peers ORDER BY hostname",
        )?;
        let rows = stmt.query_map(params![], peer_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// `gossip_peers_get_by_pubkey`: `Ok(None)` when not found
    /// (C returns -1 there).
    pub fn gossip_peers_get_by_pubkey(
        &self,
        node_pubkey: &[u8; PUBKEY_SIZE],
    ) -> Result<Option<GossipPeerInfo>> {
        self.gossip_peers_init()?;
        let mut stmt = self.conn.prepare(
            "SELECT hostname, gossip_port, api_port, node_pubkey, first_seen, last_seen, COALESCE(tags, '') FROM gossip_peers WHERE node_pubkey = ? LIMIT 1",
        )?;
        let mut rows = stmt.query(params![&node_pubkey[..]])?;
        match rows.next()? {
            Some(row) => Ok(Some(peer_from_row(row)?)),
            None => Ok(None),
        }
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
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        store
            .gossip_peers_add_or_update("host-b", 9000, 8000, Some(&key2), Some("beta"))
            .unwrap();
        store
            .gossip_peers_add_or_update("host-a", 9001, 8001, Some(&key1), None)
            .unwrap();

        // Ordered by hostname.
        let peers = store.gossip_peers_fetch_all().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].hostname, "host-a");
        assert_eq!(peers[0].gossip_port, 9001);
        assert_eq!(peers[0].node_pubkey, key1);
        assert_eq!(peers[0].tags, "");
        assert_eq!(peers[1].tags, "beta");
        assert!(peers[0].first_seen > 0);

        // Update keeps first_seen, replaces ports/tags.
        let first_seen = peers[0].first_seen;
        store
            .gossip_peers_add_or_update("host-a", 9100, 8100, Some(&key1), Some("alpha"))
            .unwrap();
        let by_key = store.gossip_peers_get_by_pubkey(&key1).unwrap().unwrap();
        assert_eq!(by_key.gossip_port, 9100);
        assert_eq!(by_key.tags, "alpha");
        assert_eq!(by_key.first_seen, first_seen);
        assert!(store.gossip_peers_get_by_pubkey(&[0x77u8; 32]).unwrap().is_none());

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
        assert!(store
            .gossip_peers_add_or_update("", 1, 1, None, None)
            .is_err());
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
}










