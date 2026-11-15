//! Sender sessions for group conversations (DESIGN.md §9,
//! Phase B4).
//!
//! The decided scheme is Megolm-style **sender sessions**: for
//! each group conversation, each sending device holds one
//! shared **session root key**. The root key is handed out
//! **once** to every other member's enrolled device as a
//! signed share (a [`GroupKeyShare`] record in an envelope,
//! the key itself wrapped per recipient device with the
//! existing `crypto_box` wrap machinery). After the handout,
//! group messages are encrypted **once** under per-message
//! keys stepped forward from the root key by a one-way hash
//! ratchet — no per-message recipient wrap list rides along.
//!
//! Crypto choices (DESIGN.md §9): XChaCha20-Poly1305 with the
//! full 16-byte tag (the extended-nonce member of the
//! ChaCha20-Poly1305 family; the 24-byte nonce also matches
//! the frozen `Message` field shape). Megolm v1's AES-CBC +
//! truncated HMAC is deliberately NOT copied. Ratchet:
//! `message_key(i) = SHA256("TWMESSAGEKEY\0" || chain(i))`,
//! `chain(i+1) = SHA256("TWCHAINKEY\0" || chain(i))`, chain(0)
//! = root key. The per-message nonce is derived from the
//! message key, which is used exactly once, so nonce reuse is
//! impossible. The AEAD associated data binds group id,
//! session id, message index and sender member key, so a
//! ciphertext cannot be transplanted into another
//! conversation, session or position. (The frozen `Message`
//! signing digest predates the session fields, so the
//! member-key signature covers header + ciphertext hash and
//! the session id / index are authenticated by the AEAD
//! associated data instead.)
//!
//! Receiver window: a message up to [`MAX_MESSAGE_GAP`]
//! indices ahead of the next expected index is accepted, with
//! the skipped message keys cached in the store (bounded by
//! the gap) so out-of-order delivery still decrypts. Anything
//! further ahead is rejected, as is an already-consumed index
//! (replay). Every rejection is logged with its reason —
//! nothing fails silently.
//!
//! Rotation happens on membership change only: when a member
//! joins or a device is revoked, the sender starts a fresh
//! session ([`start_session`] again) and shares it with the
//! then-current device set. A new member reads from their
//! join point forward (they never receive the old session);
//! a revoked device receives no share of the new session.
//! There is deliberately no lost-phone re-keying beyond
//! this — William accepted that risk on Nov 14, 2026
//! (iMessage keys never rotate either).
//!
//! Parental visibility (William's decision, Nov 14, 2026):
//! for a child in a group conversation, a parent who is NOT
//! a member is governed by a per-child setting — `none`
//! (receives nothing), `recipients_and_times` (receives a
//! content-free [`ConversationMetadata`] record per message,
//! never a key), or `full` (their devices receive shares
//! like a member's). A parent who IS a member is an ordinary
//! member and the setting does not apply. [`compute_distribution`]
//! is where the rule is applied.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encryption::{
    self, wrap_key_for_recipient, SYMMETRIC_KEY_SIZE,
};
use crate::keystore::{self, fill_random, Keystore, MemberKeystore};
use crate::proto::{
    ConversationMetadata, Envelope, EnvelopeHeader, GroupKeyShare, Message, MessageHeader,
};
use crate::store::{Store, VisibilityLevel, PUBKEY_SIZE};
use crate::validation;

/// `CONTENT_GROUP_KEY_SHARE` (`envelope.proto`).
pub const CONTENT_GROUP_KEY_SHARE: u32 = 25;
/// `CONTENT_CONVERSATION_METADATA` (`envelope.proto`).
pub const CONTENT_CONVERSATION_METADATA: u32 = 35;

/// Conversation (group) id size in bytes.
pub const GROUP_ID_SIZE: usize = 16;
/// Session id size in bytes.
pub const SESSION_ID_SIZE: usize = 16;
/// Maximum number of message indices a receiver will skip
/// ahead in one session. A message further ahead than this
/// is rejected ([`Error::TooFarAhead`]); the bound also caps
/// the skipped-key cache at `MAX_MESSAGE_GAP` entries.
pub const MAX_MESSAGE_GAP: u64 = 1000;

/// Domain separator for the chain-step hash.
const CHAIN_STEP_DOMAIN: &[u8] = b"TWCHAINKEY\0";
/// Domain separator for the message-key hash.
const MESSAGE_KEY_DOMAIN: &[u8] = b"TWMESSAGEKEY\0";
/// Domain separator for the message-nonce hash.
const MESSAGE_NONCE_DOMAIN: &[u8] = b"TWMSGNONCE\0";
/// Domain separator for the AEAD associated data.
const MESSAGE_AAD_DOMAIN: &[u8] = b"TWGROUPMSG\0";
/// Domain separator for the group key share signing digest.
pub const GROUP_SHARE_DOMAIN: &[u8] = b"TWGROUPSHARE\0";

/// Error type for sender-session operations.
#[derive(Debug)]
pub enum Error {
    /// Keystore failure (not loaded, I/O, crypto).
    Keystore(keystore::Error),
    /// Store failure.
    Store(crate::store::Error),
    /// Structurally invalid input (wrong field sizes, missing
    /// header, not a session message, ...).
    Malformed(String),
    /// A signature (share signature or envelope signature)
    /// does not verify.
    BadSignature,
    /// The share (or wrap) names a different recipient than
    /// the device trying to open it.
    NotRecipient,
    /// The sending device is not an enrolled, currently
    /// trusted device of its member.
    SenderNotEnrolled(String),
    /// The recipient device is not enrolled, or is revoked /
    /// otherwise not currently trusted.
    RecipientNotEnrolled(String),
    /// This device holds no state for the session (it never
    /// received — or no longer holds — a share).
    UnknownSession,
    /// The message index was already consumed: a replay.
    Replay { index: u64 },
    /// The message index is beyond the skip window.
    TooFarAhead { index: u64, next_index: u64 },
    /// AEAD or box failure (tampered ciphertext/wrap, wrong
    /// keys).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Keystore(e) => write!(f, "keystore error: {e}"),
            Error::Store(e) => write!(f, "store error: {e}"),
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::BadSignature => write!(f, "signature does not verify"),
            Error::NotRecipient => write!(f, "not addressed to this device"),
            Error::SenderNotEnrolled(m) => write!(f, "sender device not enrolled/trusted: {m}"),
            Error::RecipientNotEnrolled(m) => {
                write!(f, "recipient device not enrolled/trusted: {m}")
            }
            Error::UnknownSession => write!(f, "no session state held for this session"),
            Error::Replay { index } => write!(f, "message index {index} already consumed"),
            Error::TooFarAhead { index, next_index } => {
                write!(f, "message index {index} too far ahead of next expected {next_index}")
            }
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Keystore(e) => Some(e),
            Error::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::Keystore(e)
    }
}

impl From<crate::store::Error> for Error {
    fn from(e: crate::store::Error) -> Self {
        Error::Store(e)
    }
}

impl From<encryption::Error> for Error {
    fn from(e: encryption::Error) -> Self {
        match e {
            encryption::Error::NotRecipient => Error::NotRecipient,
            encryption::Error::NotInitialized => {
                Error::Keystore(keystore::Error::NotLoaded)
            }
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Session result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn malformed(msg: &str) -> Error {
    Error::Malformed(msg.to_string())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_arg<'a>(field: &'a [u8], name: &str) -> Result<&'a [u8; PUBKEY_SIZE]> {
    <&[u8; PUBKEY_SIZE]>::try_from(field)
        .map_err(|_| malformed(&format!("{name} is not {PUBKEY_SIZE} bytes")))
}

fn sign_digest(keystore: &Keystore, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let secret = keystore.get_private_key()?;
    let signing = SigningKey::from_keypair_bytes(&secret)
        .map_err(|e| malformed(&format!("secret key is not a valid keypair: {e}")))?;
    Ok(signing.sign(digest).to_bytes().to_vec())
}

fn verify_digest_signature(
    pubkey: &[u8; PUBKEY_SIZE],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let signature = <&[u8; 64]>::try_from(signature)
        .map_err(|_| malformed("signature is not 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| malformed(&format!("signer public key is invalid: {e}")))?;
    verifying_key
        .verify(digest, &Signature::from_bytes(signature))
        .map_err(|_| Error::BadSignature)
}

// ---------------------------------------------------------------------------
// Hash ratchet (per-message keys)
// ---------------------------------------------------------------------------

/// The message key for the message sent under `chain_key`:
/// `SHA256("TWMESSAGEKEY\0" || chain_key)`. One-way: holding
/// a message key reveals nothing about the chain.
pub fn derive_message_key(chain_key: &[u8; SYMMETRIC_KEY_SIZE]) -> [u8; SYMMETRIC_KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_KEY_DOMAIN);
    hasher.update(chain_key);
    hasher.finalize().into()
}

/// Step the chain forward: `SHA256("TWCHAINKEY\0" ||
/// chain_key)`. One-way: an old message key (or an old chain
/// key) cannot produce a later message key.
pub fn advance_chain_key(chain_key: &[u8; SYMMETRIC_KEY_SIZE]) -> [u8; SYMMETRIC_KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_STEP_DOMAIN);
    hasher.update(chain_key);
    hasher.finalize().into()
}

/// The 24-byte XChaCha nonce for a message key:
/// `SHA256("TWMSGNONCE\0" || message_key)[..24]`. Message
/// keys are used exactly once, so the derived nonce is
/// unique per key.
fn message_nonce(message_key: &[u8; SYMMETRIC_KEY_SIZE]) -> [u8; 24] {
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(MESSAGE_NONCE_DOMAIN);
        hasher.update(message_key);
        hasher.finalize()
    };
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

/// AEAD associated data binding a session ciphertext to its
/// conversation, session, position and sender.
fn message_aad(
    group_id: &[u8],
    session_id: &[u8],
    message_index: u64,
    sender_member_pubkey: &[u8; PUBKEY_SIZE],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MESSAGE_AAD_DOMAIN.len() + 16 + 16 + 8 + 32);
    aad.extend_from_slice(MESSAGE_AAD_DOMAIN);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&message_index.to_le_bytes());
    aad.extend_from_slice(sender_member_pubkey);
    aad
}

fn seal_message(
    message_key: &[u8; SYMMETRIC_KEY_SIZE],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(message_key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("session message encryption failed".to_string()))
}

fn open_message(
    message_key: &[u8; SYMMETRIC_KEY_SIZE],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(message_key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("session message decryption failed".to_string()))
}

// ---------------------------------------------------------------------------
// Group key shares
// ---------------------------------------------------------------------------

/// Signing digest for a group key share:
/// `SHA256("TWGROUPSHARE\0" || group_id || session_id ||
/// sender_member || sender_device || recipient_member ||
/// recipient_device || created_at (LE u64) ||
/// wrapped_key_hash)`. The wrapped-key hash binds the actual
/// key material in the envelope's wrap to this recipient, so
/// a relay cannot swap or retarget wraps.
pub fn group_share_digest(
    group_id: &[u8],
    session_id: &[u8],
    sender_member_pubkey: &[u8; PUBKEY_SIZE],
    sender_device_pubkey: &[u8; PUBKEY_SIZE],
    recipient_member_pubkey: &[u8; PUBKEY_SIZE],
    recipient_device_pubkey: &[u8; PUBKEY_SIZE],
    created_at: u64,
    wrapped_key_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GROUP_SHARE_DOMAIN);
    hasher.update(group_id);
    hasher.update(session_id);
    hasher.update(sender_member_pubkey);
    hasher.update(sender_device_pubkey);
    hasher.update(recipient_member_pubkey);
    hasher.update(recipient_device_pubkey);
    hasher.update(created_at.to_le_bytes());
    hasher.update(wrapped_key_hash);
    hasher.finalize().into()
}

/// Build one signed share envelope handing `root_key` of
/// session `session_id` in conversation `group_id` from the
/// sender's device `device_label` (in `sender`) to one
/// recipient device. The share record rides in the clear as
/// the envelope payload (it holds no key material); the root
/// key itself is the envelope's single key wrap. The
/// envelope's `payload_nonce` is zero-filled: there is no
/// payload cipher for a share.
pub fn build_share_envelope(
    sender: &MemberKeystore,
    device_label: &str,
    recipient_member_pubkey: &[u8; PUBKEY_SIZE],
    recipient_device_pubkey: &[u8; PUBKEY_SIZE],
    group_id: &[u8; GROUP_ID_SIZE],
    session_id: &[u8; SESSION_ID_SIZE],
    root_key: &[u8; SYMMETRIC_KEY_SIZE],
    created_at: u64,
) -> Result<Envelope> {
    let sender_member_pubkey = sender.member_public_key()?;
    let device_keystore = sender
        .device_keystore(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;
    let sender_device_pubkey = device_keystore.get_public_key()?;

    let (ephemeral_pubkey, wrap) = wrap_key_for_recipient(recipient_device_pubkey, root_key)?;
    let wrapped_key_hash = sha256(&wrap.wrapped_key);
    let digest = group_share_digest(
        group_id,
        session_id,
        &sender_member_pubkey,
        &sender_device_pubkey,
        recipient_member_pubkey,
        recipient_device_pubkey,
        created_at,
        &wrapped_key_hash,
    );
    let signature = sign_digest(device_keystore, &digest)?;

    let share = GroupKeyShare {
        group_id: group_id.to_vec(),
        session_id: session_id.to_vec(),
        sender_member_pubkey: sender_member_pubkey.to_vec(),
        sender_device_pubkey: sender_device_pubkey.to_vec(),
        recipient_member_pubkey: recipient_member_pubkey.to_vec(),
        recipient_device_pubkey: recipient_device_pubkey.to_vec(),
        created_at,
        wrapped_key_hash: wrapped_key_hash.to_vec(),
        signature,
    };

    let mut envelope = Envelope {
        header: Some(EnvelopeHeader {
            version: 1,
            content_type: CONTENT_GROUP_KEY_SHARE,
            schema_version: 1,
            timestamp: created_at,
            sender_pubkey: sender_device_pubkey.to_vec(),
            recipients_pubkey: vec![recipient_device_pubkey.to_vec()],
            group_id: group_id.to_vec(),
        }),
        payload_nonce: vec![0u8; 24],
        ephemeral_pubkey,
        payload_ciphertext: share.encode_to_vec(),
        keywraps: vec![wrap],
        signature: Vec::new(),
    };
    let envelope_digest = validation::compute_envelope_signing_digest(&envelope)
        .ok_or_else(|| malformed("share envelope signing digest cannot be computed"))?;
    envelope.signature = sign_digest(device_keystore, &envelope_digest)?;
    Ok(envelope)
}

/// Verify a share envelope for ingest (node side) or
/// acceptance (recipient side): structure, header/payload
/// agreement, the wrap binding, the envelope signature, the
/// share signature, and — against `store` — that the sending
/// device and the recipient device are both enrolled and
/// currently trusted (not revoked, certificate valid) at
/// `now`. Every rejection is logged with its reason before
/// the error is returned. Returns the parsed share record.
pub fn verify_share_envelope(
    store: &Store,
    envelope: &Envelope,
    now: u64,
) -> Result<GroupKeyShare> {
    match verify_share_envelope_inner(store, envelope, now) {
        Ok(share) => Ok(share),
        Err(e) => {
            let sender = envelope
                .header
                .as_ref()
                .map(|h| hex(&h.sender_pubkey))
                .unwrap_or_else(|| "none".to_string());
            eprintln!("sessions: rejected group key share sender={sender}: {e}");
            Err(e)
        }
    }
}

fn verify_share_envelope_inner(
    store: &Store,
    envelope: &Envelope,
    now: u64,
) -> Result<GroupKeyShare> {
    let header = envelope
        .header
        .as_ref()
        .ok_or_else(|| malformed("share envelope has no header"))?;
    if header.content_type != CONTENT_GROUP_KEY_SHARE {
        return Err(malformed(&format!(
            "content type {} is not a group key share",
            header.content_type
        )));
    }
    let share = GroupKeyShare::decode(envelope.payload_ciphertext.as_slice())
        .map_err(|e| malformed(&format!("share payload does not decode: {e}")))?;
    if share.group_id.len() != GROUP_ID_SIZE {
        return Err(malformed("share group_id is not 16 bytes"));
    }
    if share.session_id.len() != SESSION_ID_SIZE {
        return Err(malformed("share session_id is not 16 bytes"));
    }
    let sender_member = key_arg(&share.sender_member_pubkey, "sender_member_pubkey")?;
    let sender_device = key_arg(&share.sender_device_pubkey, "sender_device_pubkey")?;
    let recipient_member = key_arg(&share.recipient_member_pubkey, "recipient_member_pubkey")?;
    let recipient_device = key_arg(&share.recipient_device_pubkey, "recipient_device_pubkey")?;
    if share.wrapped_key_hash.len() != 32 {
        return Err(malformed("share wrapped_key_hash is not 32 bytes"));
    }

    // Header and payload must agree about who this share is
    // from, who it is for, and which conversation it keys.
    if header.sender_pubkey != share.sender_device_pubkey {
        return Err(malformed("header sender is not the share's sender device"));
    }
    if header.recipients_pubkey != vec![share.recipient_device_pubkey.clone()] {
        return Err(malformed("header recipients are not the share's recipient device"));
    }
    if header.group_id != share.group_id {
        return Err(malformed("header group_id is not the share's group_id"));
    }

    // Exactly one wrap, naming the recipient device, and the
    // share must bind that exact wrap.
    if envelope.keywraps.len() != 1 {
        return Err(malformed("share envelope must carry exactly one key wrap"));
    }
    let wrap = &envelope.keywraps[0];
    if wrap.recipient_pubkey != share.recipient_device_pubkey {
        return Err(malformed("key wrap does not name the share's recipient device"));
    }
    if sha256(&wrap.wrapped_key) != share.wrapped_key_hash.as_slice() {
        return Err(malformed("key wrap does not match the share's wrapped_key_hash"));
    }

    // The envelope signature (sender device, over the frozen
    // envelope digest) and the share signature (sender device,
    // over the share digest) must both verify.
    if !validation::verify_envelope_signature(envelope) {
        return Err(Error::BadSignature);
    }
    let mut wrapped_key_hash = [0u8; 32];
    wrapped_key_hash.copy_from_slice(&share.wrapped_key_hash);
    let digest = group_share_digest(
        &share.group_id,
        &share.session_id,
        sender_member,
        sender_device,
        recipient_member,
        recipient_device,
        share.created_at,
        &wrapped_key_hash,
    );
    verify_digest_signature(sender_device, &digest, &share.signature)?;

    // Enrollment: shares move only between enrolled, verified
    // devices (DESIGN.md §9 hard rule).
    if !store.device_is_trusted(sender_member, sender_device, now)? {
        return Err(Error::SenderNotEnrolled(format!(
            "member={} device={}",
            hex(sender_member),
            hex(sender_device)
        )));
    }
    if !store.device_is_trusted(recipient_member, recipient_device, now)? {
        return Err(Error::RecipientNotEnrolled(format!(
            "member={} device={}",
            hex(recipient_member),
            hex(recipient_device)
        )));
    }
    Ok(share)
}

/// Accept a share envelope as the recipient device: verify
/// it (including the ingest enrollment checks), unwrap the
/// session root key with our device key, and store our
/// `received` ratchet state plus the share audit record.
/// Returns the session id.
pub fn accept_share(
    store: &Store,
    envelope: &Envelope,
    member: &MemberKeystore,
    device_label: &str,
    now: u64,
) -> Result<[u8; SESSION_ID_SIZE]> {
    let share = verify_share_envelope(store, envelope, now)?;
    let our_member = member.member_public_key()?;
    let device_keystore = member
        .device_keystore(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;
    let our_device = device_keystore.get_public_key()?;
    if share.recipient_member_pubkey != our_member.as_slice()
        || share.recipient_device_pubkey != our_device.as_slice()
    {
        return Err(Error::NotRecipient);
    }
    let root_key = crate::encryption::unwrap_wrapped_key(
        &envelope.ephemeral_pubkey,
        &envelope.keywraps[0],
        device_keystore,
    )?;
    let sender_member = key_arg(&share.sender_member_pubkey, "sender_member_pubkey")?;
    let sender_device = key_arg(&share.sender_device_pubkey, "sender_device_pubkey")?;
    store.session_save(
        &share.session_id,
        &our_device,
        &share.group_id,
        sender_member,
        sender_device,
        "received",
        &root_key,
        0,
        now,
    )?;
    store.share_record_insert(
        &share.session_id,
        &share.group_id,
        sender_member,
        sender_device,
        &our_member,
        &our_device,
        &envelope.encode_to_vec(),
    )?;
    let mut session_id = [0u8; SESSION_ID_SIZE];
    session_id.copy_from_slice(&share.session_id);
    Ok(session_id)
}

// ---------------------------------------------------------------------------
// Distribution (membership + revocation + visibility)
// ---------------------------------------------------------------------------

/// The result of computing who receives what for one sender
/// session in one conversation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareDistribution {
    /// (member, device) pairs that receive a session share:
    /// every trusted device of every conversation member
    /// (except the sending device itself), plus the devices
    /// of non-member parents whose visibility level for a
    /// child in the conversation is `full`.
    pub devices: Vec<([u8; PUBKEY_SIZE], [u8; PUBKEY_SIZE])>,
    /// Non-member parents at the `recipients_and_times`
    /// level for a child in the conversation: they receive
    /// content-free metadata records, never a key.
    pub metadata_parents: Vec<[u8; PUBKEY_SIZE]>,
    /// The subset of parents included in `devices` via the
    /// `full` visibility level (informational; their devices
    /// are already in `devices`).
    pub full_parents: Vec<[u8; PUBKEY_SIZE]>,
}

/// Append (member, device) to a distribution's device list
/// if not already present.
fn push_device(
    dist: &mut ShareDistribution,
    member: [u8; PUBKEY_SIZE],
    device: [u8; PUBKEY_SIZE],
) {
    if !dist.devices.contains(&(member, device)) {
        dist.devices.push((member, device));
    }
}

/// Compute the share distribution for a session sent by
/// (`sender_member`, `sender_device`) in `group_id`, at
/// `now`: conversation membership from the store, only
/// enrolled + currently trusted devices, and the parental
/// visibility rule for children in the conversation whose
/// parents are not themselves members.
pub fn compute_distribution(
    store: &Store,
    group_id: &[u8],
    sender_member: &[u8; PUBKEY_SIZE],
    sender_device: &[u8; PUBKEY_SIZE],
    now: u64,
) -> Result<ShareDistribution> {
    let mut members = store.conversation_members(group_id)?;
    if !members.contains(sender_member) {
        members.push(*sender_member);
    }
    let member_set: std::collections::BTreeSet<[u8; PUBKEY_SIZE]> =
        members.iter().copied().collect();

    let mut distribution = ShareDistribution::default();

    // Members' trusted devices (the sending device already
    // holds the key by definition).
    for member in &members {
        for entry in store.device_list(member)? {
            if store.device_is_trusted(member, &entry.device_pubkey, now)?
                && !(*member == *sender_member && entry.device_pubkey == *sender_device)
            {
                push_device(&mut distribution, *member, entry.device_pubkey);
            }
        }
    }

    // Parental visibility for children in the conversation.
    for child in &members {
        for parent in store.parents_of(child)? {
            if member_set.contains(&parent) {
                continue; // a member parent is an ordinary member
            }
            match store.visibility_get(child)? {
                VisibilityLevel::Full => {
                    if !distribution.full_parents.contains(&parent) {
                        distribution.full_parents.push(parent);
                    }
                    for entry in store.device_list(&parent)? {
                        if store.device_is_trusted(&parent, &entry.device_pubkey, now)? {
                            push_device(&mut distribution, parent, entry.device_pubkey);
                        }
                    }
                }
                VisibilityLevel::RecipientsAndTimes => {
                    if !distribution.metadata_parents.contains(&parent) {
                        distribution.metadata_parents.push(parent);
                    }
                }
                VisibilityLevel::None => {}
            }
        }
    }

    // A parent who receives the key at `full` for any child
    // needs no metadata records.
    distribution
        .metadata_parents
        .retain(|p| !distribution.full_parents.contains(p));
    Ok(distribution)
}

/// Set a child's visibility level, on behalf of `set_by`.
/// Only a recorded parent of the child may set it — anyone
/// else is refused (and the refusal is the caller's to log;
/// this returns the error).
pub fn set_child_visibility(
    store: &Store,
    set_by: &[u8; PUBKEY_SIZE],
    child: &[u8; PUBKEY_SIZE],
    level: VisibilityLevel,
    now: u64,
) -> Result<()> {
    if !store.parents_of(child)?.contains(set_by) {
        eprintln!(
            "sessions: rejected visibility change for child={} by non-parent={}",
            hex(child),
            hex(set_by)
        );
        return Err(malformed("only a parent of the child may set their visibility level"));
    }
    store.visibility_set(child, level, set_by, now)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// A freshly started sender session: its id, the share
/// envelopes to distribute (one per recipient device), and
/// the distribution they were computed from (so the caller
/// can address metadata records for later messages).
#[derive(Debug)]
pub struct StartedSession {
    /// The new session's id.
    pub session_id: [u8; SESSION_ID_SIZE],
    /// One share envelope per recipient device.
    pub shares: Vec<Envelope>,
    /// The distribution the shares were computed from.
    pub distribution: ShareDistribution,
}

/// Start a sender session for `group_id` from the sender's
/// device `device_label`: generate a fresh root key, store
/// our `own` ratchet state, and build one signed share
/// envelope per device in the current distribution. This is
/// both the initial session creation and the rotation
/// operation — after a membership change (a member joined,
/// a device was revoked), starting a fresh session and
/// sharing it with the then-current device set is exactly
/// the rotation the design calls for; old sessions are left
/// untouched so history stays readable by those who held it.
pub fn start_session(
    store: &Store,
    sender: &MemberKeystore,
    device_label: &str,
    group_id: &[u8; GROUP_ID_SIZE],
    now: u64,
) -> Result<StartedSession> {
    let sender_member = sender.member_public_key()?;
    let sender_device = sender
        .device_public_key(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;

    let mut session_id = [0u8; SESSION_ID_SIZE];
    fill_random(&mut session_id)?;
    let mut root_key = Zeroizing::new([0u8; SYMMETRIC_KEY_SIZE]);
    fill_random(&mut *root_key)?;

    store.session_save(
        &session_id,
        &sender_device,
        group_id,
        &sender_member,
        &sender_device,
        "own",
        &*root_key,
        0,
        now,
    )?;

    let distribution = compute_distribution(store, group_id, &sender_member, &sender_device, now)?;
    let mut shares = Vec::with_capacity(distribution.devices.len());
    for (member, device) in &distribution.devices {
        let envelope = build_share_envelope(
            sender,
            device_label,
            member,
            device,
            group_id,
            &session_id,
            &root_key,
            now,
        )?;
        store.share_record_insert(
            &session_id,
            group_id,
            &sender_member,
            &sender_device,
            member,
            device,
            &envelope.encode_to_vec(),
        )?;
        shares.push(envelope);
    }
    Ok(StartedSession {
        session_id,
        shares,
        distribution,
    })
}

/// Rotate a conversation's sender session after a membership
/// change: a fresh session shared with the current device
/// set. Identical to [`start_session`] by design — the name
/// exists so call sites read as the operation the design
/// describes.
pub fn rotate_session(
    store: &Store,
    sender: &MemberKeystore,
    device_label: &str,
    group_id: &[u8; GROUP_ID_SIZE],
    now: u64,
) -> Result<StartedSession> {
    start_session(store, sender, device_label, group_id, now)
}

// ---------------------------------------------------------------------------
// Session messages
// ---------------------------------------------------------------------------

/// Encrypt one group message under our `own` session
/// `session_id`: derive the message key at the current
/// index, step and persist the ratchet BEFORE sealing (an
/// index is never reused, even on failure), and return the
/// wire `Message` — legacy header/signature shape, session
/// fields set, no key wraps. The plaintext is the serialized
/// payload (a `GroupMessage` proto for chat). Signing is by
/// the member key, as the message path expects.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_session_message(
    store: &Store,
    session_id: &[u8; SESSION_ID_SIZE],
    sender: &MemberKeystore,
    device_label: &str,
    recipient_members: &[[u8; PUBKEY_SIZE]],
    plaintext: &[u8],
    timestamp: u64,
    now: u64,
) -> Result<Message> {
    let sender_member = sender.member_public_key()?;
    let sender_device = sender
        .device_public_key(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;
    let row = store
        .session_get(session_id, &sender_device)?
        .ok_or(Error::UnknownSession)?;
    if row.direction != "own" {
        return Err(malformed("session is not an own (sending) session"));
    }
    let chain_key: [u8; SYMMETRIC_KEY_SIZE] = row
        .chain_key
        .as_slice()
        .try_into()
        .map_err(|_| malformed("stored chain key is not 32 bytes"))?;
    let index = row.next_index;
    let message_key = Zeroizing::new(derive_message_key(&chain_key));
    let next_chain = advance_chain_key(&chain_key);
    store.session_update_state(session_id, &sender_device, &next_chain, index + 1, now)?;

    let nonce = message_nonce(&message_key);
    let aad = message_aad(&row.group_id, session_id, index, &sender_member);
    let ciphertext = seal_message(&*message_key, &nonce, &aad, plaintext)?;

    let mut message = Message {
        header: Some(MessageHeader {
            version: 1,
            timestamp,
            sender_pubkey: sender_member.to_vec(),
            recipients_pubkey: recipient_members.iter().map(|k| k.to_vec()).collect(),
            group_id: row.group_id.clone(),
        }),
        payload_nonce: nonce.to_vec(),
        ephemeral_pubkey: sender_device.to_vec(),
        payload_ciphertext: ciphertext,
        keywraps: Vec::new(),
        signature: Vec::new(),
        session_id: session_id.to_vec(),
        message_index: index,
    };
    let digest = validation::compute_message_signing_digest(&message)
        .ok_or_else(|| malformed("session message signing digest cannot be computed"))?;
    message.signature = sign_digest(sender.member_keystore(), &digest)?;
    Ok(message)
}

/// Decrypt one session `Message` with this device's stored
/// ratchet state (`owner_device` is our device key). Handles
/// out-of-order delivery within [`MAX_MESSAGE_GAP`] via the
/// skipped-key cache; replays and far-future indices are
/// rejected and logged. State advances are persisted before
/// the plaintext is returned.
pub fn decrypt_session_message(
    store: &Store,
    owner_device: &[u8; PUBKEY_SIZE],
    message: &Message,
    now: u64,
) -> Result<Vec<u8>> {
    match decrypt_session_message_inner(store, owner_device, message, now) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => {
            eprintln!(
                "sessions: rejected session message session={} index={} for device={}: {e}",
                hex(&message.session_id),
                message.message_index,
                hex(owner_device)
            );
            Err(e)
        }
    }
}

fn decrypt_session_message_inner(
    store: &Store,
    owner_device: &[u8; PUBKEY_SIZE],
    message: &Message,
    now: u64,
) -> Result<Vec<u8>> {
    let header = message
        .header
        .as_ref()
        .ok_or_else(|| malformed("session message has no header"))?;
    if message.session_id.len() != SESSION_ID_SIZE {
        return Err(malformed("message carries no session id (not a session message)"));
    }
    let sender_member = key_arg(&header.sender_pubkey, "sender_pubkey")?;
    let session_id = message.session_id.as_slice();
    let index = message.message_index;
    let nonce: [u8; 24] = message
        .payload_nonce
        .as_slice()
        .try_into()
        .map_err(|_| malformed("session message payload_nonce is not 24 bytes"))?;
    let aad = message_aad(&header.group_id, session_id, index, sender_member);

    // A cached skipped key means this index was jumped over
    // earlier; it is consumed exactly once.
    if let Some(cached) = store.session_skipped_key_get(session_id, owner_device, index)? {
        let message_key: [u8; SYMMETRIC_KEY_SIZE] = cached
            .as_slice()
            .try_into()
            .map_err(|_| malformed("cached skipped key is not 32 bytes"))?;
        let plaintext = open_message(&message_key, &nonce, &aad, &message.payload_ciphertext)?;
        store.session_skipped_key_remove(session_id, owner_device, index)?;
        return Ok(plaintext);
    }

    let row = store
        .session_get(session_id, owner_device)?
        .ok_or(Error::UnknownSession)?;
    if index < row.next_index {
        return Err(Error::Replay { index });
    }
    if index > row.next_index.saturating_add(MAX_MESSAGE_GAP) {
        return Err(Error::TooFarAhead {
            index,
            next_index: row.next_index,
        });
    }

    // Ratchet forward to the message's index, caching the
    // message keys of the indices we skip.
    let mut chain_key: [u8; SYMMETRIC_KEY_SIZE] = row
        .chain_key
        .as_slice()
        .try_into()
        .map_err(|_| malformed("stored chain key is not 32 bytes"))?;
    let mut cur = row.next_index;
    let message_key = loop {
        let mk = derive_message_key(&chain_key);
        if cur == index {
            break mk;
        }
        store.session_skipped_key_put(session_id, owner_device, cur, &mk)?;
        chain_key = advance_chain_key(&chain_key);
        cur += 1;
    };
    let next_chain = advance_chain_key(&chain_key);
    store.session_update_state(session_id, owner_device, &next_chain, index + 1, now)?;
    open_message(&message_key, &nonce, &aad, &message.payload_ciphertext)
}

// ---------------------------------------------------------------------------
// Conversation metadata (recipients-and-times visibility)
// ---------------------------------------------------------------------------

/// Build the content-free metadata envelope addressed to
/// `parent_member` for one session message: conversation id,
/// sender, the conversation's member list, the message
/// timestamp, and the session/index correlator — no text, no
/// key material. The payload is encrypted with the standard
/// envelope mechanism wrapped to the parent's member key, and
/// the envelope is signed by the sender's member key.
#[allow(clippy::too_many_arguments)]
pub fn build_metadata_envelope(
    store: &Store,
    sender: &MemberKeystore,
    group_id: &[u8],
    session_id: &[u8; SESSION_ID_SIZE],
    message_index: u64,
    message_timestamp: u64,
    parent_member: &[u8; PUBKEY_SIZE],
) -> Result<Envelope> {
    let sender_member = sender.member_public_key()?;
    let members = store.conversation_members(group_id)?;
    let metadata = ConversationMetadata {
        group_id: group_id.to_vec(),
        sender_member_pubkey: sender_member.to_vec(),
        recipient_member_pubkeys: members.iter().map(|m| m.to_vec()).collect(),
        message_timestamp,
        session_id: session_id.to_vec(),
        message_index,
    };
    let mut envelope = Envelope {
        header: Some(EnvelopeHeader {
            version: 1,
            content_type: CONTENT_CONVERSATION_METADATA,
            schema_version: 1,
            timestamp: message_timestamp,
            sender_pubkey: sender_member.to_vec(),
            recipients_pubkey: vec![parent_member.to_vec()],
            group_id: group_id.to_vec(),
        }),
        payload_nonce: Vec::new(),
        ephemeral_pubkey: Vec::new(),
        payload_ciphertext: Vec::new(),
        keywraps: Vec::new(),
        signature: Vec::new(),
    };
    crate::encryption::encrypt_envelope_payload(
        &metadata.encode_to_vec(),
        &[*parent_member],
        &mut envelope,
        sender.member_keystore(),
    )?;
    let digest = validation::compute_envelope_signing_digest(&envelope)
        .ok_or_else(|| malformed("metadata envelope signing digest cannot be computed"))?;
    envelope.signature = sign_digest(sender.member_keystore(), &digest)?;
    Ok(envelope)
}

/// Collected per-session skipped-key state, for tests and
/// diagnostics: how many skipped keys a device holds.
pub fn skipped_key_count(
    store: &Store,
    session_id: &[u8],
    owner_device: &[u8; PUBKEY_SIZE],
) -> Result<u64> {
    Ok(store.session_skipped_key_count(session_id, owner_device)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector for the ratchet + seal construction,
    /// pinned so the client implementations (the test page's
    /// TypeScript mirror in webui/src/utils/groupSession.ts) can
    /// prove byte-compatibility against the node's own code.
    /// If these values ever change, the wire format has changed.
    #[test]
    fn ratchet_known_answer_vector() {
        let root = [0x11u8; 32];
        let mk0 = derive_message_key(&root);
        assert_eq!(
            hex(&mk0),
            "d00408aa711fd302fe2e80959c56642654223ca7058c36901a867afe92381787"
        );
        let chain1 = advance_chain_key(&root);
        assert_eq!(
            hex(&chain1),
            "3878f4eac1458397a520067d0087ba0967bd15e06d3b86b7312ef5d222fe2b31"
        );
        let mk1 = derive_message_key(&chain1);
        assert_eq!(
            hex(&mk1),
            "5f0db29d692d81264311840d4d68e37e2ebf6eee053ad432270396d996207a2a"
        );
        let nonce0 = message_nonce(&mk0);
        assert_eq!(hex(&nonce0), "3c72c3cd2c2374b4aaf2d53c4c6f654c052753766220d39f");
        let group = [0x22u8; 16];
        let session = [0x33u8; 16];
        let sender = [0x44u8; 32];
        let aad = message_aad(&group, &session, 0, &sender);
        let ct = seal_message(&mk0, &nonce0, &aad, b"tinyweb group kat").unwrap();
        assert_eq!(
            hex(&ct),
            "79689d035c8fdd061ea5f28fe42da76ff9606b049e1f7bd0c8bc2f47bab56e845e"
        );
        let wrapped_hash = sha256(b"kat wrapped key");
        let digest = group_share_digest(
            &group,
            &session,
            &sender,
            &[0x55u8; 32],
            &[0x66u8; 32],
            &[0x77u8; 32],
            1_700_000_000,
            &wrapped_hash,
        );
        assert_eq!(
            hex(&digest),
            "ebca0a43923dd18692564345fcc5f2fc8c6439e3842b7f0dca484ab36fe72340"
        );
    }
    use crate::proto::GroupMessage;

    const NOW: u64 = 1_700_000_000;
    const GROUP: [u8; GROUP_ID_SIZE] = [0x6A; GROUP_ID_SIZE];

    struct TestMember {
        ks: MemberKeystore,
        member_pk: [u8; PUBKEY_SIZE],
        device_pk: [u8; PUBKEY_SIZE],
    }

    /// A member with one device ("phone"), enrolled in the
    /// household store (certificate recorded).
    fn make_member(store: &Store, name: &str) -> TestMember {
        let mut ks = MemberKeystore::new();
        ks.generate_member_key().unwrap();
        let device_pk = ks.add_device_key("phone").unwrap();
        let cert = crate::identity::issue_device_certificate(&ks, "phone", NOW, 0).unwrap();
        store.device_add(&cert, NOW).unwrap();
        let member_pk = ks.member_public_key().unwrap();
        store.user_register(&member_pk, name).unwrap();
        TestMember {
            ks,
            member_pk,
            device_pk,
        }
    }

    fn join(store: &Store, member: &TestMember) {
        store
            .conversation_member_add(&GROUP, &member.member_pk, NOW)
            .unwrap();
    }

    fn group_plaintext(text: &str) -> Vec<u8> {
        GroupMessage {
            text: text.to_string(),
            group_id: GROUP.to_vec(),
            media_ref: Vec::new(),
            reply_to_timestamp: 0,
        }
        .encode_to_vec()
    }

    fn share_for(started: &StartedSession, member: &TestMember) -> Envelope {
        started
            .shares
            .iter()
            .find(|e| {
                e.header.as_ref().unwrap().recipients_pubkey
                    == vec![member.device_pk.to_vec()]
            })
            .unwrap_or_else(|| panic!("no share for device {}", hex(&member.device_pk)))
            .clone()
    }

    /// Sender A plus members B and C in one conversation;
    /// A has started a session and B and C have accepted
    /// their shares.
    fn trio_with_session() -> (Store, TestMember, TestMember, TestMember, StartedSession) {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let a = make_member(&store, "A");
        let b = make_member(&store, "B");
        let c = make_member(&store, "C");
        join(&store, &a);
        join(&store, &b);
        join(&store, &c);
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        assert_eq!(started.shares.len(), 2, "shares for B and C only");
        accept_share(&store, &share_for(&started, &b), &b.ks, "phone", NOW).unwrap();
        accept_share(&store, &share_for(&started, &c), &c.ks, "phone", NOW).unwrap();
        (store, a, b, c, started)
    }

    #[test]
    fn ratchet_keys_differ_per_index_and_are_one_way() {
        let root = [0x42; SYMMETRIC_KEY_SIZE];
        let chain1 = advance_chain_key(&root);
        let chain2 = advance_chain_key(&chain1);
        let mk0 = derive_message_key(&root);
        let mk1 = derive_message_key(&chain1);
        let mk2 = derive_message_key(&chain2);
        assert_ne!(mk0, mk1);
        assert_ne!(mk1, mk2);
        assert_ne!(mk0, mk2);
        assert_ne!(message_nonce(&mk0), message_nonce(&mk1));

        // An old message key cannot decrypt a later message:
        // seal under mk1, opening with mk0 fails the AEAD tag.
        let aad = message_aad(&GROUP, &[0x01; 16], 1, &[0x02; 32]);
        let sealed = seal_message(&mk1, &message_nonce(&mk1), &aad, b"later message").unwrap();
        assert!(open_message(&mk0, &message_nonce(&mk0), &aad, &sealed).is_err());
        assert_eq!(
            open_message(&mk1, &message_nonce(&mk1), &aad, &sealed).unwrap(),
            b"later message".to_vec()
        );
    }

    #[test]
    fn group_message_round_trip_three_members() {
        let (store, a, b, c, started) = trio_with_session();
        let recipients = [a.member_pk, b.member_pk, c.member_pk];

        let msg = encrypt_session_message(
            &store,
            &started.session_id,
            &a.ks,
            "phone",
            &recipients,
            &group_plaintext("hello group"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();
        assert_eq!(msg.session_id, started.session_id.to_vec());
        assert_eq!(msg.message_index, 0);
        assert!(msg.keywraps.is_empty(), "session messages carry no wraps");
        // The wire message passes the legacy validation shape.
        crate::validation::message_validate_at(&msg, NOW + 10).unwrap();

        for member in [&b, &c] {
            let pt = decrypt_session_message(&store, &member.device_pk, &msg, NOW + 10).unwrap();
            let decoded = GroupMessage::decode(pt.as_slice()).unwrap();
            assert_eq!(decoded.text, "hello group");
        }

        // A second message (index 1) decrypts for both as well.
        let msg2 = encrypt_session_message(
            &store,
            &started.session_id,
            &a.ks,
            "phone",
            &recipients,
            &group_plaintext("second"),
            NOW + 20,
            NOW + 20,
        )
        .unwrap();
        assert_eq!(msg2.message_index, 1);
        for member in [&b, &c] {
            let pt = decrypt_session_message(&store, &member.device_pk, &msg2, NOW + 20).unwrap();
            assert_eq!(GroupMessage::decode(pt.as_slice()).unwrap().text, "second");
        }
    }

    #[test]
    fn non_member_device_cannot_decrypt() {
        let (store, a, b, _c, started) = trio_with_session();
        let outsider = make_member(&store, "D"); // enrolled, not in the conversation
        assert!(!started
            .distribution
            .devices
            .contains(&(outsider.member_pk, outsider.device_pk)));

        let msg = encrypt_session_message(
            &store,
            &started.session_id,
            &a.ks,
            "phone",
            &[a.member_pk, b.member_pk],
            &group_plaintext("members only"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();
        // No session state: decryption is impossible.
        assert!(matches!(
            decrypt_session_message(&store, &outsider.device_pk, &msg, NOW + 10),
            Err(Error::UnknownSession)
        ));
        // And B's share envelope is not openable by D.
        assert!(matches!(
            accept_share(&store, &share_for(&started, &b), &outsider.ks, "phone", NOW),
            Err(Error::NotRecipient)
        ));
    }

    #[test]
    fn unsigned_share_is_rejected() {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let a = make_member(&store, "A");
        let b = make_member(&store, "B");
        join(&store, &a);
        join(&store, &b);
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        let envelope = share_for(&started, &b);
        verify_share_envelope(&store, &envelope, NOW).unwrap();

        // Strip the share signature, then re-sign the ENVELOPE
        // with the sender device key so only the share
        // signature is wrong.
        let mut share = GroupKeyShare::decode(envelope.payload_ciphertext.as_slice()).unwrap();
        share.signature = vec![0u8; 64];
        let mut tampered = envelope.clone();
        tampered.payload_ciphertext = share.encode_to_vec();
        let digest = validation::compute_envelope_signing_digest(&tampered).unwrap();
        tampered.signature =
            sign_digest(a.ks.device_keystore("phone").unwrap(), &digest).unwrap();
        assert!(matches!(
            verify_share_envelope(&store, &tampered, NOW),
            Err(Error::BadSignature)
        ));

        // An entirely unsigned share (empty signature) too.
        share.signature = Vec::new();
        let mut unsigned = envelope;
        unsigned.payload_ciphertext = share.encode_to_vec();
        let digest = validation::compute_envelope_signing_digest(&unsigned).unwrap();
        unsigned.signature =
            sign_digest(a.ks.device_keystore("phone").unwrap(), &digest).unwrap();
        assert!(verify_share_envelope(&store, &unsigned, NOW).is_err());
    }

    #[test]
    fn share_to_revoked_device_refused_at_distribution_and_ingest() {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let a = make_member(&store, "A");
        let b = make_member(&store, "B");
        join(&store, &a);
        join(&store, &b);

        // While B's device is active it is in the distribution
        // and a share to it verifies.
        let dist = compute_distribution(&store, &GROUP, &a.member_pk, &a.device_pk, NOW).unwrap();
        assert!(dist.devices.contains(&(b.member_pk, b.device_pk)));
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        let envelope = share_for(&started, &b);
        verify_share_envelope(&store, &envelope, NOW).unwrap();

        // Revoke B's device: distribution drops it, and the
        // already-built share is refused at ingest.
        store.device_revoke(&b.member_pk, &b.device_pk, NOW + 1).unwrap();
        let dist = compute_distribution(&store, &GROUP, &a.member_pk, &a.device_pk, NOW + 1).unwrap();
        assert!(!dist.devices.contains(&(b.member_pk, b.device_pk)));
        assert!(matches!(
            verify_share_envelope(&store, &envelope, NOW + 1),
            Err(Error::RecipientNotEnrolled(_))
        ));
    }

    #[test]
    fn rotation_on_join_new_member_reads_forward_only() {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let a = make_member(&store, "A");
        let b = make_member(&store, "B");
        let c = make_member(&store, "C");
        join(&store, &a);
        join(&store, &b);
        let s1 = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        accept_share(&store, &share_for(&s1, &b), &b.ks, "phone", NOW).unwrap();
        let msg1 = encrypt_session_message(
            &store,
            &s1.session_id,
            &a.ks,
            "phone",
            &[a.member_pk, b.member_pk],
            &group_plaintext("before C joined"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();
        decrypt_session_message(&store, &b.device_pk, &msg1, NOW + 10).unwrap();

        // C joins; A rotates. C is in the new distribution.
        join(&store, &c);
        let s2 = rotate_session(&store, &a.ks, "phone", &GROUP, NOW + 20).unwrap();
        assert_ne!(s1.session_id, s2.session_id);
        assert!(s2.distribution.devices.contains(&(c.member_pk, c.device_pk)));
        accept_share(&store, &share_for(&s2, &c), &c.ks, "phone", NOW + 20).unwrap();
        accept_share(&store, &share_for(&s2, &b), &b.ks, "phone", NOW + 20).unwrap();

        let msg2 = encrypt_session_message(
            &store,
            &s2.session_id,
            &a.ks,
            "phone",
            &[a.member_pk, b.member_pk, c.member_pk],
            &group_plaintext("after C joined"),
            NOW + 30,
            NOW + 30,
        )
        .unwrap();
        // C reads from its join point forward...
        let pt = decrypt_session_message(&store, &c.device_pk, &msg2, NOW + 30).unwrap();
        assert_eq!(
            GroupMessage::decode(pt.as_slice()).unwrap().text,
            "after C joined"
        );
        decrypt_session_message(&store, &b.device_pk, &msg2, NOW + 30).unwrap();
        // ...but not the pre-join history.
        assert!(matches!(
            decrypt_session_message(&store, &c.device_pk, &msg1, NOW + 30),
            Err(Error::UnknownSession)
        ));
    }

    #[test]
    fn rotation_on_revoke_revoked_device_reads_nothing_new() {
        let (store, a, b, c, s1) = trio_with_session();
        let recipients = [a.member_pk, b.member_pk, c.member_pk];
        let msg1 = encrypt_session_message(
            &store,
            &s1.session_id,
            &a.ks,
            "phone",
            &recipients,
            &group_plaintext("before revoke"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();
        decrypt_session_message(&store, &c.device_pk, &msg1, NOW + 10).unwrap();

        // C's device is revoked; A rotates. The new
        // distribution excludes the revoked device.
        store.device_revoke(&c.member_pk, &c.device_pk, NOW + 20).unwrap();
        let s2 = rotate_session(&store, &a.ks, "phone", &GROUP, NOW + 20).unwrap();
        assert!(!s2.distribution.devices.contains(&(c.member_pk, c.device_pk)));
        assert!(s2.shares.iter().all(|e| {
            e.header.as_ref().unwrap().recipients_pubkey != vec![c.device_pk.to_vec()]
        }));
        accept_share(&store, &share_for(&s2, &b), &b.ks, "phone", NOW + 20).unwrap();

        let msg2 = encrypt_session_message(
            &store,
            &s2.session_id,
            &a.ks,
            "phone",
            &recipients,
            &group_plaintext("after revoke"),
            NOW + 30,
            NOW + 30,
        )
        .unwrap();
        decrypt_session_message(&store, &b.device_pk, &msg2, NOW + 30).unwrap();
        assert!(matches!(
            decrypt_session_message(&store, &c.device_pk, &msg2, NOW + 30),
            Err(Error::UnknownSession)
        ));
    }

    /// A conversation of sender A, member B, and child K;
    /// P is K's parent and NOT a member.
    fn family_setup() -> (Store, TestMember, TestMember, TestMember, TestMember) {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let a = make_member(&store, "A");
        let b = make_member(&store, "B");
        let kid = make_member(&store, "K");
        let parent = make_member(&store, "P");
        join(&store, &a);
        join(&store, &b);
        join(&store, &kid);
        store.parent_link_add(&parent.member_pk, &kid.member_pk).unwrap();
        (store, a, b, kid, parent)
    }

    #[test]
    fn visibility_full_parent_decrypts_childs_group_message() {
        let (store, a, b, _kid, parent) = family_setup();
        set_child_visibility(
            &store,
            &parent.member_pk,
            &_kid.member_pk,
            VisibilityLevel::Full,
            NOW,
        )
        .unwrap();
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        assert!(started.distribution.full_parents.contains(&parent.member_pk));
        assert!(started
            .distribution
            .devices
            .contains(&(parent.member_pk, parent.device_pk)));

        accept_share(&store, &share_for(&started, &parent), &parent.ks, "phone", NOW).unwrap();
        let msg = encrypt_session_message(
            &store,
            &started.session_id,
            &a.ks,
            "phone",
            &[a.member_pk, b.member_pk, _kid.member_pk],
            &group_plaintext("kid group chat"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();
        let pt = decrypt_session_message(&store, &parent.device_pk, &msg, NOW + 10).unwrap();
        assert_eq!(
            GroupMessage::decode(pt.as_slice()).unwrap().text,
            "kid group chat"
        );
    }

    #[test]
    fn visibility_recipients_and_times_parent_gets_metadata_not_key() {
        let (store, a, b, kid, parent) = family_setup();
        set_child_visibility(
            &store,
            &parent.member_pk,
            &kid.member_pk,
            VisibilityLevel::RecipientsAndTimes,
            NOW,
        )
        .unwrap();
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        assert!(!started
            .distribution
            .devices
            .contains(&(parent.member_pk, parent.device_pk)));
        assert!(started.distribution.metadata_parents.contains(&parent.member_pk));
        accept_share(&store, &share_for(&started, &b), &b.ks, "phone", NOW).unwrap();

        let msg = encrypt_session_message(
            &store,
            &started.session_id,
            &a.ks,
            "phone",
            &[a.member_pk, b.member_pk, kid.member_pk],
            &group_plaintext("secret words"),
            NOW + 10,
            NOW + 10,
        )
        .unwrap();

        // The metadata record opens for the parent and shows
        // who/when — and there is no content to find in it.
        let envelope = build_metadata_envelope(
            &store,
            &a.ks,
            &GROUP,
            &started.session_id,
            msg.message_index,
            NOW + 10,
            &parent.member_pk,
        )
        .unwrap();
        assert_eq!(
            envelope.header.as_ref().unwrap().content_type,
            CONTENT_CONVERSATION_METADATA
        );
        let payload =
            crate::encryption::decrypt_envelope_payload(&envelope, parent.ks.member_keystore())
                .unwrap();
        let metadata = ConversationMetadata::decode(payload.as_slice()).unwrap();
        assert_eq!(metadata.group_id, GROUP.to_vec());
        assert_eq!(metadata.sender_member_pubkey, a.member_pk.to_vec());
        assert_eq!(metadata.message_timestamp, NOW + 10);
        assert_eq!(metadata.session_id, started.session_id.to_vec());
        assert_eq!(metadata.message_index, 0);
        assert_eq!(metadata.recipient_member_pubkeys.len(), 3);

        // But the parent holds no key: the message itself
        // does not decrypt.
        assert!(matches!(
            decrypt_session_message(&store, &parent.device_pk, &msg, NOW + 10),
            Err(Error::UnknownSession)
        ));
    }

    #[test]
    fn visibility_none_parent_gets_nothing() {
        let (store, a, _b, _kid, parent) = family_setup();
        // Default is none; also set it explicitly.
        let started = start_session(&store, &a.ks, "phone", &GROUP, NOW).unwrap();
        assert!(!started
            .distribution
            .devices
            .contains(&(parent.member_pk, parent.device_pk)));
        assert!(!started.distribution.metadata_parents.contains(&parent.member_pk));
        assert!(!started.distribution.full_parents.contains(&parent.member_pk));

        set_child_visibility(
            &store,
            &parent.member_pk,
            &_kid.member_pk,
            VisibilityLevel::None,
            NOW,
        )
        .unwrap();
        let dist = compute_distribution(&store, &GROUP, &a.member_pk, &a.device_pk, NOW).unwrap();
        assert!(!dist.devices.contains(&(parent.member_pk, parent.device_pk)));
        assert!(!dist.metadata_parents.contains(&parent.member_pk));
    }

    #[test]
    fn visibility_change_requires_a_parent() {
        let (store, _a, _b, kid, parent) = family_setup();
        let stranger = make_member(&store, "S");
        assert!(set_child_visibility(
            &store,
            &stranger.member_pk,
            &kid.member_pk,
            VisibilityLevel::Full,
            NOW,
        )
        .is_err());
        assert_eq!(store.visibility_get(&kid.member_pk).unwrap(), VisibilityLevel::None);
        set_child_visibility(
            &store,
            &parent.member_pk,
            &kid.member_pk,
            VisibilityLevel::Full,
            NOW,
        )
        .unwrap();
        assert_eq!(
            store.visibility_get(&kid.member_pk).unwrap(),
            VisibilityLevel::Full
        );
    }

    #[test]
    fn out_of_order_delivery_and_replay_protection() {
        let (store, a, b, _c, started) = trio_with_session();
        let recipients = [a.member_pk, b.member_pk, _c.member_pk];
        let mut msgs = Vec::new();
        for i in 0..3 {
            msgs.push(
                encrypt_session_message(
                    &store,
                    &started.session_id,
                    &a.ks,
                    "phone",
                    &recipients,
                    &group_plaintext(&format!("m{i}")),
                    NOW + 10 + i,
                    NOW + 10 + i,
                )
                .unwrap(),
            );
        }
        // Deliver 2 first: 0 and 1 are cached as skipped keys.
        let pt = decrypt_session_message(&store, &b.device_pk, &msgs[2], NOW + 20).unwrap();
        assert_eq!(GroupMessage::decode(pt.as_slice()).unwrap().text, "m2");
        assert_eq!(
            skipped_key_count(&store, &started.session_id, &b.device_pk).unwrap(),
            2
        );
        // Then 0 and 1 decrypt from the cache, consuming it.
        let pt = decrypt_session_message(&store, &b.device_pk, &msgs[0], NOW + 21).unwrap();
        assert_eq!(GroupMessage::decode(pt.as_slice()).unwrap().text, "m0");
        let pt = decrypt_session_message(&store, &b.device_pk, &msgs[1], NOW + 22).unwrap();
        assert_eq!(GroupMessage::decode(pt.as_slice()).unwrap().text, "m1");
        assert_eq!(
            skipped_key_count(&store, &started.session_id, &b.device_pk).unwrap(),
            0
        );
        // A replay of an already-consumed index is rejected.
        assert!(matches!(
            decrypt_session_message(&store, &b.device_pk, &msgs[0], NOW + 23),
            Err(Error::Replay { index: 0 })
        ));
        // A far-future index is rejected, not ratcheted to.
        let mut future = msgs[2].clone();
        future.message_index = 3 + MAX_MESSAGE_GAP + 1;
        assert!(matches!(
            decrypt_session_message(&store, &b.device_pk, &future, NOW + 24),
            Err(Error::TooFarAhead { .. })
        ));
    }
}
