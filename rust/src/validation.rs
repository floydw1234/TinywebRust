//! Message and request validation.
//!
//! Rust counterpart of the C validation package
//! `src/packages/validation/` (`gossip_validation.c`,
//! `message_validation.c`, `client_request_validation.c`):
//! cryptographic signature verification, timestamp/expiry checks,
//! and structural validation of envelopes, messages, and client
//! requests before they are stored or rebroadcast.
//!
//! Behaviour is a faithful port of the C code: the same
//! accept/reject conditions, the same timestamp/expiry windows,
//! the same structural checks, in the same order where order
//! affects the outcome. Cryptographic operations are byte
//! compatible with the C node's libsodium/OpenSSL output:
//! Ed25519 detached signatures (`crypto_sign_verify_detached`)
//! are verified with `ed25519-dalek`, and SHA-256 digests
//! (OpenSSL `SHA256`) are computed with `sha2`, so signatures
//! and digests are identical for identical inputs.
//!
//! Only the primitives validation itself needs are implemented
//! here: the signing, encryption, keystore, and transactions
//! packages are separate modules and are not ported wholesale.
//! In particular this module never decrypts payloads, so no
//! `crypto_box`/`crypto_secretbox` equivalent is required; the
//! envelope signature check inlines the digest + verify logic
//! of C `tw_envelope_verify` (`envelope.c`) without porting the
//! rest of that package. Integers in signing digests are hashed
//! little-endian, matching the C code, which hashes the native
//! in-memory representation on the (little-endian) platforms
//! TinyWebC targets.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::proto::{ClientRequest, Envelope, Message};

// ---------------------------------------------------------------------------
// Shared constants (C: message_validation.c / client_request_validation.c)
// ---------------------------------------------------------------------------

/// Maximum payload ciphertext size for messages and client
/// requests: 1 MiB (`MAX_MESSAGE_SIZE` / `MAX_CLIENT_REQUEST_SIZE`).
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Replay-protection clock-skew window for messages and client
/// requests: 60 seconds (`CLOCK_SKEW_WINDOW`).
pub const CLOCK_SKEW_WINDOW_SECONDS: u64 = 60;

/// Default message TTL: 7 days (`MESSAGE_TTL`).
pub const MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Default client-request TTL: 7 days (`CLIENT_REQUEST_TTL`).
pub const CLIENT_REQUEST_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Maximum `group_id` length accepted by the message and
/// client-request signing digests (C sanity check; the envelope
/// digest has no such cap).
pub const MAX_GROUP_ID_BYTES: usize = 64;

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify an Ed25519 detached signature, byte-compatible with
/// libsodium `crypto_sign_verify_detached` as wrapped by C
/// `verify_signature` (`packages/signing/signing.c`).
///
/// Returns `false` for malformed public keys or signatures as
/// well as for signatures that do not verify; the C wrapper
/// collapses all of these to a non-zero return.
pub fn verify_signature(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    verifying_key
        .verify(message, &Signature::from_bytes(&signature))
        .is_ok()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Signing digests
//
// All three digests share the C shape
//   SHA256(domain || raw header fields || SHA256(ciphertext))
// with a NUL-terminated domain separator and little-endian
// integers, exactly as in `compute_envelope_digest`
// (transactions/envelope.c), `compute_message_signing_digest`
// (validation/message_validation.c), and
// `compute_client_request_signing_digest`
// (validation/client_request_validation.c). Each returns `None`
// where the C helper returns -1.
// ---------------------------------------------------------------------------

/// Signing digest for an [`Envelope`] (C `compute_envelope_digest`).
///
/// Unlike the message/client-request digests, the envelope
/// digest imposes no length cap on `group_id`, matching the C
/// code. An empty `payload_ciphertext` is hashed as empty input;
/// the C helper rejects a NULL ciphertext pointer, which has no
/// Rust analogue (a `Vec` is never null).
pub fn compute_envelope_signing_digest(envelope: &Envelope) -> Option<[u8; 32]> {
    let header = envelope.header.as_ref()?;
    let payload_hash = sha256(&envelope.payload_ciphertext);

    let mut hasher = Sha256::new();
    hasher.update(b"TWENVELOPE\0");
    hasher.update(header.version.to_le_bytes());
    hasher.update(header.content_type.to_le_bytes());
    hasher.update(header.schema_version.to_le_bytes());
    hasher.update(header.timestamp.to_le_bytes());
    if header.sender_pubkey.len() != 32 {
        return None;
    }
    hasher.update(&header.sender_pubkey);
    hasher.update((header.recipients_pubkey.len() as u32).to_le_bytes());
    for recipient in &header.recipients_pubkey {
        if recipient.len() != 32 {
            return None;
        }
        hasher.update(recipient);
    }
    hasher.update((header.group_id.len() as u32).to_le_bytes());
    hasher.update(&header.group_id);
    hasher.update(payload_hash);
    Some(hasher.finalize().into())
}

/// Signing digest for a [`Message`] (C
/// `compute_message_signing_digest`). Returns `None` where the C
/// helper returns -1: sender/recipient keys not 32 bytes, or
/// `group_id` longer than 64 bytes.
pub fn compute_message_signing_digest(message: &Message) -> Option<[u8; 32]> {
    let header = message.header.as_ref()?;
    let payload_hash = sha256(&message.payload_ciphertext);

    let mut hasher = Sha256::new();
    hasher.update(b"TWMESSAGE\0");
    hasher.update(header.version.to_le_bytes());
    hasher.update(header.timestamp.to_le_bytes());
    if header.sender_pubkey.len() != 32 {
        return None;
    }
    hasher.update(&header.sender_pubkey);
    hasher.update((header.recipients_pubkey.len() as u32).to_le_bytes());
    for recipient in &header.recipients_pubkey {
        if recipient.len() != 32 {
            return None;
        }
        hasher.update(recipient);
    }
    if header.group_id.len() > MAX_GROUP_ID_BYTES {
        return None;
    }
    hasher.update((header.group_id.len() as u32).to_le_bytes());
    hasher.update(&header.group_id);
    hasher.update(payload_hash);
    Some(hasher.finalize().into())
}

/// Signing digest for a [`ClientRequest`] (C
/// `compute_client_request_signing_digest`). Returns `None`
/// under the same conditions as
/// [`compute_message_signing_digest`].
pub fn compute_client_request_signing_digest(request: &ClientRequest) -> Option<[u8; 32]> {
    let header = request.header.as_ref()?;
    let payload_hash = sha256(&request.payload_ciphertext);

    let mut hasher = Sha256::new();
    hasher.update(b"TWCLIENTREQ\0");
    hasher.update(header.version.to_le_bytes());
    hasher.update(header.content_type.to_le_bytes());
    hasher.update(header.schema_version.to_le_bytes());
    hasher.update(header.timestamp.to_le_bytes());
    if header.sender_pubkey.len() != 32 {
        return None;
    }
    hasher.update(&header.sender_pubkey);
    hasher.update((header.recipients_pubkey.len() as u32).to_le_bytes());
    for recipient in &header.recipients_pubkey {
        if recipient.len() != 32 {
            return None;
        }
        hasher.update(recipient);
    }
    if header.group_id.len() > MAX_GROUP_ID_BYTES {
        return None;
    }
    hasher.update((header.group_id.len() as u32).to_le_bytes());
    hasher.update(&header.group_id);
    hasher.update(payload_hash);
    Some(hasher.finalize().into())
}

/// Verify an envelope's Ed25519 signature over its signing
/// digest (C `tw_envelope_verify`, inlined; the rest of the
/// transactions package is not ported here).
pub fn verify_envelope_signature(envelope: &Envelope) -> bool {
    let Some(header) = envelope.header.as_ref() else {
        return false;
    };
    let Some(digest) = compute_envelope_signing_digest(envelope) else {
        return false;
    };
    verify_signature(&envelope.signature, &digest, &header.sender_pubkey)
}

// ---------------------------------------------------------------------------
// Gossip envelope validation (C: gossip_validation.c/.h)
// ---------------------------------------------------------------------------

/// Validation limits for gossip envelopes (C
/// `GossipValidationConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipValidationConfig {
    /// Maximum future clock skew, in seconds.
    pub max_clock_skew_seconds: u64,
    /// Maximum message age beyond the skew window, in seconds.
    pub message_ttl_seconds: u64,
    /// Maximum payload ciphertext size, in bytes.
    pub max_payload_bytes: usize,
}

/// Gossip validation failures (C `GossipValidationResult`
/// without the `OK` case, which is `Ok(())` here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipValidationError {
    /// Envelope (or its header) or config missing (C
    /// `GOSSIP_VALIDATION_ERROR_NULL`). Rust callers pass values
    /// rather than pointers, so this covers only a missing
    /// header; a missing envelope/config is unrepresentable.
    Null,
    /// Unsupported content type (C
    /// `GOSSIP_VALIDATION_ERROR_TYPE`). Defined by the C header
    /// but never returned by the C implementation, which performs
    /// no content-type check; kept for parity and likewise never
    /// produced here.
    Type,
    /// Signature verification failed (C
    /// `GOSSIP_VALIDATION_ERROR_SIGNATURE`), including signing
    /// digests that cannot be computed, which C funnels through
    /// `tw_envelope_verify` into this result.
    Signature,
    /// Timestamp outside the allowed window (C
    /// `GOSSIP_VALIDATION_ERROR_TIMESTAMP`).
    Timestamp,
    /// Payload exceeds the configured limit (C
    /// `GOSSIP_VALIDATION_ERROR_PAYLOAD`).
    Payload,
}

/// Result of [`gossip_validate_envelope`]: `Ok(())` is C
/// `GOSSIP_VALIDATION_OK`.
pub type GossipValidationResult = Result<(), GossipValidationError>;

impl fmt::Display for GossipValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(gossip_validation_error_string(&Err(*self)))
    }
}

impl std::error::Error for GossipValidationError {}

/// Validate a gossip envelope against `config` at time
/// `now_epoch` (C `gossip_validate_envelope`).
///
/// Check order matches the C code, which affects the outcome
/// when several checks would fail: payload size first, then the
/// timestamp window, then the Ed25519 signature. The timestamp
/// window accepts a future skew of up to
/// `config.max_clock_skew_seconds` and a past age of up to
/// `config.message_ttl_seconds + config.max_clock_skew_seconds`;
/// both boundaries are inclusive (C uses strict `>`).
pub fn gossip_validate_envelope(
    envelope: &Envelope,
    config: &GossipValidationConfig,
    now_epoch: u64,
) -> GossipValidationResult {
    let Some(header) = envelope.header.as_ref() else {
        return Err(GossipValidationError::Null);
    };

    if envelope.payload_ciphertext.len() > config.max_payload_bytes {
        return Err(GossipValidationError::Payload);
    }

    let timestamp = header.timestamp;
    if now_epoch < timestamp {
        if timestamp - now_epoch > config.max_clock_skew_seconds {
            return Err(GossipValidationError::Timestamp);
        }
    } else if now_epoch - timestamp
        > config
            .message_ttl_seconds
            .saturating_add(config.max_clock_skew_seconds)
    {
        return Err(GossipValidationError::Timestamp);
    }

    if !verify_envelope_signature(envelope) {
        return Err(GossipValidationError::Signature);
    }

    Ok(())
}

/// Expiration epoch for storage/deduplication (C
/// `gossip_validation_expiration`): header timestamp plus the
/// configured TTL, or 0 when the envelope has no header. The
/// addition wraps on overflow, as the C `uint64_t` addition does.
pub fn gossip_validation_expiration(
    envelope: &Envelope,
    config: &GossipValidationConfig,
) -> u64 {
    let Some(header) = envelope.header.as_ref() else {
        return 0;
    };
    header.timestamp.wrapping_add(config.message_ttl_seconds)
}

/// Human-readable string for a gossip validation result (C
/// `gossip_validation_error_string`); `Ok(())` maps to `"ok"`.
pub fn gossip_validation_error_string(result: &GossipValidationResult) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(GossipValidationError::Null) => "null envelope or config",
        Err(GossipValidationError::Type) => "unsupported content type",
        Err(GossipValidationError::Signature) => "invalid signature",
        Err(GossipValidationError::Timestamp) => "timestamp outside allowed range",
        Err(GossipValidationError::Payload) => "payload exceeds limit",
    }
}

// ---------------------------------------------------------------------------
// Message validation (C: message_validation.c/.h)
// ---------------------------------------------------------------------------

/// Message validation failures (C `MessageValidationResult`
/// without the `OK` case, which is `Ok(())` here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageValidationError {
    /// Signature malformed or does not verify (C
    /// `MESSAGE_VALIDATION_INVALID_SIGNATURE`).
    InvalidSignature,
    /// Timestamp older than the 60 s window (C
    /// `MESSAGE_VALIDATION_EXPIRED`).
    Expired,
    /// Timestamp more than 60 s in the future (C
    /// `MESSAGE_VALIDATION_FUTURE_TIMESTAMP`).
    FutureTimestamp,
    /// Payload ciphertext over 1 MiB (C
    /// `MESSAGE_VALIDATION_TOO_LARGE`).
    TooLarge,
    /// Message or header missing (C
    /// `MESSAGE_VALIDATION_INVALID_FORMAT`).
    InvalidFormat,
    /// Signing digest could not be computed (C
    /// `MESSAGE_VALIDATION_ERROR`).
    Error,
}

/// Result of [`message_validate`]: `Ok(())` is C
/// `MESSAGE_VALIDATION_OK`.
pub type MessageValidationResult = Result<(), MessageValidationError>;

impl fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(message_validation_result_to_string(&Err(*self)))
    }
}

impl std::error::Error for MessageValidationError {}

/// Validate a message at the current wall-clock time (C
/// `message_validate`, which reads `time(NULL)` internally).
pub fn message_validate(message: &Message) -> MessageValidationResult {
    message_validate_at(message, now_epoch_seconds())
}

/// Validate a message as of `now_epoch` seconds. This is the
/// deterministic core of [`message_validate`]; the C function
/// cannot be given a time, so boundary behaviour is only
/// testable through this entry point.
///
/// Check order matches the C code: missing header, then the
/// timestamp window (future before expired, both boundaries
/// inclusive), then payload size, then the signing digest, then
/// signature length, then Ed25519 verification.
pub fn message_validate_at(message: &Message, now_epoch: u64) -> MessageValidationResult {
    let Some(header) = message.header.as_ref() else {
        return Err(MessageValidationError::InvalidFormat);
    };

    let msg_ts = header.timestamp;
    if msg_ts > now_epoch.saturating_add(CLOCK_SKEW_WINDOW_SECONDS) {
        return Err(MessageValidationError::FutureTimestamp);
    }
    if msg_ts.saturating_add(CLOCK_SKEW_WINDOW_SECONDS) < now_epoch {
        return Err(MessageValidationError::Expired);
    }

    if message.payload_ciphertext.len() > MAX_PAYLOAD_BYTES {
        return Err(MessageValidationError::TooLarge);
    }

    let Some(digest) = compute_message_signing_digest(message) else {
        return Err(MessageValidationError::Error);
    };

    if message.signature.len() != 64 {
        return Err(MessageValidationError::InvalidSignature);
    }

    if !verify_signature(&message.signature, &digest, &header.sender_pubkey) {
        return Err(MessageValidationError::InvalidSignature);
    }

    Ok(())
}

/// Expiration epoch for storage/deduplication (C
/// `message_validation_get_expiration`): header timestamp plus
/// the 7-day TTL, or 0 when the message has no header. The
/// addition wraps on overflow, as in C.
pub fn message_validation_get_expiration(message: &Message) -> u64 {
    let Some(header) = message.header.as_ref() else {
        return 0;
    };
    header.timestamp.wrapping_add(MESSAGE_TTL_SECONDS)
}

/// Human-readable string for a message validation result (C
/// `message_validation_result_to_string`); `Ok(())` maps to
/// `"OK"`, and the generic `Error` falls through to the C
/// default arm.
pub fn message_validation_result_to_string(result: &MessageValidationResult) -> &'static str {
    match result {
        Ok(()) => "OK",
        Err(MessageValidationError::InvalidSignature) => "Invalid signature",
        Err(MessageValidationError::Expired) => "Message expired (outside 60s window)",
        Err(MessageValidationError::FutureTimestamp) => "Message from the future",
        Err(MessageValidationError::TooLarge) => "Message too large",
        Err(MessageValidationError::InvalidFormat) => "Invalid message format",
        Err(MessageValidationError::Error) => "Unknown validation error",
    }
}

// ---------------------------------------------------------------------------
// Client-request validation (C: client_request_validation.c/.h)
// ---------------------------------------------------------------------------

/// Client-request validation failures (C
/// `ClientRequestValidationResult` without the `OK` case, which
/// is `Ok(())` here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequestValidationError {
    /// Signature malformed or does not verify (C
    /// `CLIENT_REQUEST_VALIDATION_INVALID_SIGNATURE`).
    InvalidSignature,
    /// Timestamp older than the 60 s window (C
    /// `CLIENT_REQUEST_VALIDATION_EXPIRED`).
    Expired,
    /// Timestamp more than 60 s in the future (C
    /// `CLIENT_REQUEST_VALIDATION_FUTURE_TIMESTAMP`).
    FutureTimestamp,
    /// Payload ciphertext over 1 MiB (C
    /// `CLIENT_REQUEST_VALIDATION_TOO_LARGE`).
    TooLarge,
    /// Request or header missing (C
    /// `CLIENT_REQUEST_VALIDATION_INVALID_FORMAT`).
    InvalidFormat,
    /// Header recipients lack matching keywraps (C
    /// `CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS`).
    InvalidRecipients,
    /// Signing digest could not be computed (C
    /// `CLIENT_REQUEST_VALIDATION_ERROR`).
    Error,
}

/// Result of [`client_request_validate`]: `Ok(())` is C
/// `CLIENT_REQUEST_VALIDATION_OK`.
pub type ClientRequestValidationResult = Result<(), ClientRequestValidationError>;

impl fmt::Display for ClientRequestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(client_request_validation_result_to_string(&Err(*self)))
    }
}

impl std::error::Error for ClientRequestValidationError {}

/// Validate a client request at the current wall-clock time (C
/// `client_request_validate`, which reads `time(NULL)`
/// internally).
pub fn client_request_validate(request: &ClientRequest) -> ClientRequestValidationResult {
    client_request_validate_at(request, now_epoch_seconds())
}

/// Validate a client request as of `now_epoch` seconds; the
/// deterministic core of [`client_request_validate`]. Check
/// order matches the C code, as documented for
/// [`message_validate_at`].
pub fn client_request_validate_at(
    request: &ClientRequest,
    now_epoch: u64,
) -> ClientRequestValidationResult {
    let Some(header) = request.header.as_ref() else {
        return Err(ClientRequestValidationError::InvalidFormat);
    };

    let req_ts = header.timestamp;
    if req_ts > now_epoch.saturating_add(CLOCK_SKEW_WINDOW_SECONDS) {
        return Err(ClientRequestValidationError::FutureTimestamp);
    }
    if req_ts.saturating_add(CLOCK_SKEW_WINDOW_SECONDS) < now_epoch {
        return Err(ClientRequestValidationError::Expired);
    }

    if request.payload_ciphertext.len() > MAX_PAYLOAD_BYTES {
        return Err(ClientRequestValidationError::TooLarge);
    }

    let Some(digest) = compute_client_request_signing_digest(request) else {
        return Err(ClientRequestValidationError::Error);
    };

    if request.signature.len() != 64 {
        return Err(ClientRequestValidationError::InvalidSignature);
    }

    if !verify_signature(&request.signature, &digest, &header.sender_pubkey) {
        return Err(ClientRequestValidationError::InvalidSignature);
    }

    Ok(())
}

/// Validate that every header recipient has a matching keywrap
/// (C `client_request_validate_recipients`): at least one
/// recipient, exactly one keywrap slot per recipient, and each
/// recipient public key present among the keywraps (keywrap keys
/// must be 32 bytes; a header key of any other length can never
/// match, as in the C `memcmp` over 32 bytes).
pub fn client_request_validate_recipients(
    request: &ClientRequest,
) -> ClientRequestValidationResult {
    let Some(header) = request.header.as_ref() else {
        return Err(ClientRequestValidationError::InvalidFormat);
    };

    if header.recipients_pubkey.is_empty() {
        return Err(ClientRequestValidationError::InvalidRecipients);
    }

    if request.keywraps.len() != header.recipients_pubkey.len() {
        return Err(ClientRequestValidationError::InvalidRecipients);
    }

    for recipient in &header.recipients_pubkey {
        let found = request
            .keywraps
            .iter()
            .any(|wrap| wrap.recipient_pubkey.len() == 32 && wrap.recipient_pubkey == *recipient);
        if !found {
            return Err(ClientRequestValidationError::InvalidRecipients);
        }
    }

    Ok(())
}

/// Expiration epoch for storage/deduplication (C
/// `client_request_get_expiration`): header timestamp plus the
/// 7-day TTL, or 0 when the request has no header. The addition
/// wraps on overflow, as in C.
pub fn client_request_get_expiration(request: &ClientRequest) -> u64 {
    let Some(header) = request.header.as_ref() else {
        return 0;
    };
    header.timestamp.wrapping_add(CLIENT_REQUEST_TTL_SECONDS)
}

/// Human-readable string for a client-request validation result
/// (C `client_request_validation_result_to_string`); `Ok(())`
/// maps to `"OK"`, and the generic `Error` falls through to the
/// C default arm.
pub fn client_request_validation_result_to_string(
    result: &ClientRequestValidationResult,
) -> &'static str {
    match result {
        Ok(()) => "OK",
        Err(ClientRequestValidationError::InvalidSignature) => "Invalid signature",
        Err(ClientRequestValidationError::Expired) => "Request expired (outside 60s window)",
        Err(ClientRequestValidationError::FutureTimestamp) => "Request from the future",
        Err(ClientRequestValidationError::TooLarge) => "Request too large",
        Err(ClientRequestValidationError::InvalidFormat) => "Invalid request format",
        Err(ClientRequestValidationError::InvalidRecipients) => {
            "Invalid recipients (missing keywraps)"
        }
        Err(ClientRequestValidationError::Error) => "Unknown validation error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        ClientRequestHeader, ClientRequestKeyWrap, EnvelopeHeader, MessageHeader,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_700_000_000;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn test_pubkey() -> Vec<u8> {
        test_signing_key().verifying_key().to_bytes().to_vec()
    }

    fn sign_digest(digest: &[u8; 32]) -> Vec<u8> {
        test_signing_key().sign(digest).to_bytes().to_vec()
    }

    fn signed_message(timestamp: u64) -> Message {
        let pubkey = test_pubkey();
        let mut message = Message {
            header: Some(MessageHeader {
                version: 1,
                timestamp,
                sender_pubkey: pubkey.clone(),
                recipients_pubkey: vec![pubkey],
                group_id: Vec::new(),
            }),
            payload_ciphertext: vec![0xAB; 16],
            ..Default::default()
        };
        let digest = compute_message_signing_digest(&message).expect("digest");
        message.signature = sign_digest(&digest);
        message
    }

    fn signed_client_request(timestamp: u64) -> ClientRequest {
        let pubkey = test_pubkey();
        let mut request = ClientRequest {
            header: Some(ClientRequestHeader {
                version: 1,
                content_type: 33,
                schema_version: 1,
                timestamp,
                sender_pubkey: pubkey.clone(),
                recipients_pubkey: vec![pubkey],
                group_id: Vec::new(),
            }),
            payload_ciphertext: vec![0xCD; 16],
            ..Default::default()
        };
        let digest = compute_client_request_signing_digest(&request).expect("digest");
        request.signature = sign_digest(&digest);
        request
    }

    fn signed_envelope(timestamp: u64, payload_len: usize) -> Envelope {
        let pubkey = test_pubkey();
        let mut envelope = Envelope {
            header: Some(EnvelopeHeader {
                version: 1,
                content_type: 33,
                schema_version: 1,
                timestamp,
                sender_pubkey: pubkey.clone(),
                recipients_pubkey: vec![pubkey],
                group_id: Vec::new(),
            }),
            payload_ciphertext: vec![0xEF; payload_len],
            ..Default::default()
        };
        let digest = compute_envelope_signing_digest(&envelope).expect("digest");
        envelope.signature = sign_digest(&digest);
        envelope
    }

    fn gossip_config() -> GossipValidationConfig {
        GossipValidationConfig {
            max_clock_skew_seconds: 300,
            message_ttl_seconds: 86_400,
            max_payload_bytes: 1024 * 1024,
        }
    }

    // -- Primitive byte compatibility -------------------------------------

    #[test]
    fn sha256_matches_openssl_known_vector() {
        // SHA256("abc") as produced by OpenSSL.
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn ed25519_verify_matches_libsodium_rfc8032_vector() {
        // RFC 8032 test vector (empty message); libsodium
        // crypto_sign_verify_detached accepts this signature.
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        assert!(verify_signature(&signature, b"", &pubkey));
        let mut tampered = signature;
        tampered[0] ^= 0xFF;
        assert!(!verify_signature(&tampered, b"", &pubkey));
        assert!(!verify_signature(&signature, b"x", &pubkey));
        assert!(!verify_signature(&signature[..63], b"", &pubkey));
        assert!(!verify_signature(&signature, b"", &pubkey[..31]));
    }

    // -- Messages -----------------------------------------------------------

    #[test]
    fn message_valid_signature_accepted_and_tamper_rejected() {
        let message = signed_message(NOW);
        assert_eq!(message_validate_at(&message, NOW), Ok(()));

        let mut tampered_sig = message.clone();
        tampered_sig.signature[0] ^= 0xFF;
        assert_eq!(
            message_validate_at(&tampered_sig, NOW),
            Err(MessageValidationError::InvalidSignature)
        );

        let mut tampered_payload = message.clone();
        tampered_payload.payload_ciphertext[0] ^= 0xFF;
        assert_eq!(
            message_validate_at(&tampered_payload, NOW),
            Err(MessageValidationError::InvalidSignature)
        );

        // Wall-clock entry point accepts a freshly signed message.
        let fresh = signed_message(now_epoch_seconds());
        assert_eq!(message_validate(&fresh), Ok(()));
    }

    #[test]
    fn message_timestamp_window_boundaries() {
        // Exactly at either edge of the 60 s window: accepted.
        assert_eq!(message_validate_at(&signed_message(NOW + 60), NOW), Ok(()));
        assert_eq!(message_validate_at(&signed_message(NOW - 60), NOW), Ok(()));
        // One second beyond either edge: rejected.
        assert_eq!(
            message_validate_at(&signed_message(NOW + 61), NOW),
            Err(MessageValidationError::FutureTimestamp)
        );
        assert_eq!(
            message_validate_at(&signed_message(NOW - 61), NOW),
            Err(MessageValidationError::Expired)
        );
    }

    #[test]
    fn message_structural_checks_and_ordering() {
        // Missing header.
        assert_eq!(
            message_validate_at(&Message::default(), NOW),
            Err(MessageValidationError::InvalidFormat)
        );

        // Expired beats oversized (timestamp is checked first).
        let mut expired_big = signed_message(NOW - 61);
        expired_big.payload_ciphertext = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            message_validate_at(&expired_big, NOW),
            Err(MessageValidationError::Expired)
        );

        // Oversized with a fresh timestamp.
        let mut big = signed_message(NOW);
        big.payload_ciphertext = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            message_validate_at(&big, NOW),
            Err(MessageValidationError::TooLarge)
        );

        // Exactly 1 MiB passes the size check (fails only on the
        // now-stale signature, proving size was accepted).
        let mut at_limit = signed_message(NOW);
        at_limit.payload_ciphertext = vec![0; MAX_PAYLOAD_BYTES];
        assert_eq!(
            message_validate_at(&at_limit, NOW),
            Err(MessageValidationError::InvalidSignature)
        );

        // Bad sender key length fails digest computation -> Error.
        let mut bad_sender = signed_message(NOW);
        bad_sender.header.as_mut().expect("header").sender_pubkey = vec![0; 31];
        assert_eq!(
            message_validate_at(&bad_sender, NOW),
            Err(MessageValidationError::Error)
        );

        // Bad recipient key length -> Error.
        let mut bad_recipient = signed_message(NOW);
        bad_recipient
            .header
            .as_mut()
            .expect("header")
            .recipients_pubkey = vec![vec![0; 31]];
        assert_eq!(
            message_validate_at(&bad_recipient, NOW),
            Err(MessageValidationError::Error)
        );

        // group_id over the 64-byte cap -> Error, even with a
        // signature that would otherwise be checked afterwards.
        let mut bad_group = signed_message(NOW);
        bad_group.header.as_mut().expect("header").group_id = vec![0; 65];
        bad_group.signature = vec![0; 63];
        assert_eq!(
            message_validate_at(&bad_group, NOW),
            Err(MessageValidationError::Error)
        );

        // Short signature (with a computable digest) -> InvalidSignature.
        let mut short_sig = signed_message(NOW);
        short_sig.signature = vec![0; 63];
        assert_eq!(
            message_validate_at(&short_sig, NOW),
            Err(MessageValidationError::InvalidSignature)
        );
    }

    #[test]
    fn message_expiration_and_strings() {
        assert_eq!(message_validation_get_expiration(&Message::default()), 0);
        let message = signed_message(NOW);
        assert_eq!(
            message_validation_get_expiration(&message),
            NOW + MESSAGE_TTL_SECONDS
        );
        assert_eq!(message_validation_result_to_string(&Ok(())), "OK");
        assert_eq!(
            message_validation_result_to_string(&Err(MessageValidationError::Expired)),
            "Message expired (outside 60s window)"
        );
        assert_eq!(
            message_validation_result_to_string(&Err(MessageValidationError::Error)),
            "Unknown validation error"
        );
    }

    // -- Client requests ----------------------------------------------------

    #[test]
    fn client_request_valid_signature_accepted_and_tamper_rejected() {
        let request = signed_client_request(NOW);
        assert_eq!(client_request_validate_at(&request, NOW), Ok(()));

        let mut tampered = request.clone();
        tampered.signature[0] ^= 0xFF;
        assert_eq!(
            client_request_validate_at(&tampered, NOW),
            Err(ClientRequestValidationError::InvalidSignature)
        );

        let fresh = signed_client_request(now_epoch_seconds());
        assert_eq!(client_request_validate(&fresh), Ok(()));
    }

    #[test]
    fn client_request_timestamp_and_structural_boundaries() {
        assert_eq!(
            client_request_validate_at(&signed_client_request(NOW + 60), NOW),
            Ok(())
        );
        assert_eq!(
            client_request_validate_at(&signed_client_request(NOW - 60), NOW),
            Ok(())
        );
        assert_eq!(
            client_request_validate_at(&signed_client_request(NOW + 61), NOW),
            Err(ClientRequestValidationError::FutureTimestamp)
        );
        assert_eq!(
            client_request_validate_at(&signed_client_request(NOW - 61), NOW),
            Err(ClientRequestValidationError::Expired)
        );
        assert_eq!(
            client_request_validate_at(&ClientRequest::default(), NOW),
            Err(ClientRequestValidationError::InvalidFormat)
        );

        let mut big = signed_client_request(NOW);
        big.payload_ciphertext = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            client_request_validate_at(&big, NOW),
            Err(ClientRequestValidationError::TooLarge)
        );

        let mut bad_group = signed_client_request(NOW);
        bad_group.header.as_mut().expect("header").group_id = vec![0; 65];
        assert_eq!(
            client_request_validate_at(&bad_group, NOW),
            Err(ClientRequestValidationError::Error)
        );

        assert_eq!(client_request_get_expiration(&ClientRequest::default()), 0);
        assert_eq!(
            client_request_get_expiration(&signed_client_request(NOW)),
            NOW + CLIENT_REQUEST_TTL_SECONDS
        );
    }

    #[test]
    fn client_request_recipient_keywrap_checks() {
        let pubkey = test_pubkey();
        let other = vec![9u8; 32];
        let wrap = |key: &Vec<u8>| ClientRequestKeyWrap {
            recipient_pubkey: key.clone(),
            ..Default::default()
        };

        // Missing header.
        assert_eq!(
            client_request_validate_recipients(&ClientRequest::default()),
            Err(ClientRequestValidationError::InvalidFormat)
        );

        // No recipients.
        let mut request = signed_client_request(NOW);
        request.header.as_mut().expect("header").recipients_pubkey = Vec::new();
        assert_eq!(
            client_request_validate_recipients(&request),
            Err(ClientRequestValidationError::InvalidRecipients)
        );

        // Keywrap count mismatch.
        let mut request = signed_client_request(NOW);
        request.keywraps = Vec::new();
        assert_eq!(
            client_request_validate_recipients(&request),
            Err(ClientRequestValidationError::InvalidRecipients)
        );

        // Matching keywrap accepted; wrong or short keys rejected.
        let mut request = signed_client_request(NOW);
        request.keywraps = vec![wrap(&pubkey)];
        assert_eq!(client_request_validate_recipients(&request), Ok(()));

        request.keywraps = vec![wrap(&other)];
        assert_eq!(
            client_request_validate_recipients(&request),
            Err(ClientRequestValidationError::InvalidRecipients)
        );

        request.keywraps = vec![wrap(&vec![1u8; 31])];
        assert_eq!(
            client_request_validate_recipients(&request),
            Err(ClientRequestValidationError::InvalidRecipients)
        );
    }

    // -- Gossip envelopes ---------------------------------------------------

    #[test]
    fn gossip_valid_envelope_accepted_and_tamper_rejected() {
        let config = gossip_config();
        let envelope = signed_envelope(NOW, 100);
        assert_eq!(gossip_validate_envelope(&envelope, &config, NOW), Ok(()));

        let mut tampered = envelope.clone();
        tampered.signature[0] ^= 0xFF;
        assert_eq!(
            gossip_validate_envelope(&tampered, &config, NOW),
            Err(GossipValidationError::Signature)
        );

        // Missing header maps to the C NULL result.
        assert_eq!(
            gossip_validate_envelope(&Envelope::default(), &config, NOW),
            Err(GossipValidationError::Null)
        );
    }

    #[test]
    fn gossip_timestamp_window_boundaries() {
        let config = gossip_config();
        // Future boundary: exactly max skew passes, one more fails.
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW + 300, 10), &config, NOW),
            Ok(())
        );
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW + 301, 10), &config, NOW),
            Err(GossipValidationError::Timestamp)
        );
        // Past boundary: exactly TTL + skew passes, one more fails.
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW - (86_400 + 300), 10), &config, NOW),
            Ok(())
        );
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW - (86_400 + 301), 10), &config, NOW),
            Err(GossipValidationError::Timestamp)
        );
    }

    #[test]
    fn gossip_payload_limit_and_check_ordering() {
        let mut config = gossip_config();
        config.max_payload_bytes = 1024;

        // Over the limit, even with an expired timestamp: payload
        // is checked first in the C code.
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW - 90_000, 2000), &config, NOW),
            Err(GossipValidationError::Payload)
        );
        // Exactly at the limit passes the size check.
        assert_eq!(
            gossip_validate_envelope(&signed_envelope(NOW, 1024), &config, NOW),
            Ok(())
        );

        // Expiration is timestamp + TTL; headerless gives 0.
        let envelope = signed_envelope(5000, 10);
        let ttl_config = GossipValidationConfig {
            message_ttl_seconds: 1000,
            ..config
        };
        assert_eq!(gossip_validation_expiration(&envelope, &ttl_config), 6000);
        assert_eq!(gossip_validation_expiration(&Envelope::default(), &config), 0);
        assert_eq!(gossip_validation_error_string(&Ok(())), "ok");
        assert_eq!(
            gossip_validation_error_string(&Err(GossipValidationError::Payload)),
            "payload exceeds limit"
        );
    }

    #[test]
    fn digests_are_domain_separated() {
        // Identical fields under different domains must digest
        // differently, as the C domain separators require.
        let message_digest =
            compute_message_signing_digest(&signed_message(NOW)).expect("message digest");
        let request_digest = compute_client_request_signing_digest(&signed_client_request(NOW))
            .expect("request digest");
        let envelope_digest =
            compute_envelope_signing_digest(&signed_envelope(NOW, 16)).expect("envelope digest");
        assert_ne!(message_digest, request_digest);
        assert_ne!(message_digest, envelope_digest);
        assert_ne!(request_digest, envelope_digest);
    }
}



