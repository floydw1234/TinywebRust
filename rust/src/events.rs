//! Calendar events (DESIGN.md §2.3/§5, Phase C3).
//!
//! An event is a first-class content type: one versioned
//! [`CalendarEvent`] record per event, carried in the clear as
//! the payload of a `CONTENT_CALENDAR_EVENT` envelope and
//! signed by the acting member's device key. Create, update and
//! delete are the same record re-issued with a later
//! `updated_at`; the store projection (`Store::events_list_range`
//! and friends) keeps the newest version per event id, and a
//! version with `deleted = true` is the tombstone — so every
//! box that holds the envelopes converges on the same calendar
//! (DESIGN.md §4.2: the envelope store is the source of truth,
//! the events table is a rebuildable projection of it).
//!
//! The model is iCalendar-shaped (stable id, start/end
//! instants + IANA timezone, RRULE string, all-day flag) so a
//! future calendar-sync bridge maps onto it 1:1. Events are
//! app-only until then — no external calendar sync in this
//! phase (William's settled decision).
//!
//! Payload encryption: deliberately NONE in this phase. Events
//! sit in the identity/control class — like device certificates,
//! the record is signed but readable by the family box that
//! hosts the calendar (the stopgap stack's CalDAV server has
//! exactly the same property). This is a reversible choice:
//! wrapping event payloads under group sessions later changes
//! the transport, not this record.
//!
//! Authorization: the actor issuing a version must be the
//! event's creator, or — for update/delete of an existing
//! event — a recorded parent of the creator (the same
//! `parent_links` relation the session machinery uses). A
//! first version must be issued by the creator themselves.
//! Every rejection is logged with its reason, here and at the
//! API layer — nothing fails silently.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message as _;
use sha2::{Digest, Sha256};

use crate::keystore::{self, MemberKeystore};
use crate::proto::{CalendarEvent, Envelope, EnvelopeHeader};
use crate::store::{Store, PUBKEY_SIZE};
use crate::validation;

/// `CONTENT_CALENDAR_EVENT` (`envelope.proto`, Phase C3). The
/// legacy `CONTENT_EVENT_CREATE` (155) is the C sketch's
/// one-shot event message — no timezone, recurrence or
/// versioning — and is not used.
pub const CONTENT_CALENDAR_EVENT: u32 = 162;

/// Event id size in bytes (a UUID-shaped stable id).
pub const EVENT_ID_SIZE: usize = 16;

/// Domain separator for the calendar event signing digest.
pub const EVENT_DOMAIN: &[u8] = b"TWEVENT\0";

/// Retention grace past the later of an event version's end
/// and its `updated_at` (DESIGN.md §4.3: events are retained
/// until end time + a grace period, not on the chat TTL).
pub const EVENT_RETENTION_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Error type for calendar event operations.
#[derive(Debug)]
pub enum Error {
    /// Keystore failure (not loaded, I/O, crypto).
    Keystore(keystore::Error),
    /// Store failure.
    Store(crate::store::Error),
    /// Structurally invalid input (wrong field sizes, missing
    /// header, incoherent times, ...).
    Malformed(String),
    /// A signature (record signature or envelope signature)
    /// does not verify.
    BadSignature,
    /// The acting device is not an enrolled, currently
    /// trusted device of the acting member.
    ActorNotEnrolled(String),
    /// The acting member may not issue this version (not the
    /// creator, and not a recorded parent of the creator for
    /// an update/delete).
    NotAuthorized(String),
    /// A newer (or conflicting same-clock) version of this
    /// event is already held; this one changes nothing.
    StaleVersion(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Keystore(e) => write!(f, "keystore error: {e}"),
            Error::Store(e) => write!(f, "store error: {e}"),
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::BadSignature => write!(f, "signature does not verify"),
            Error::ActorNotEnrolled(m) => {
                write!(f, "acting device not enrolled/trusted: {m}")
            }
            Error::NotAuthorized(m) => write!(f, "actor not authorized: {m}"),
            Error::StaleVersion(m) => write!(f, "stale event version: {m}"),
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

/// Event result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn malformed(msg: &str) -> Error {
    Error::Malformed(msg.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_arg<'a>(field: &'a [u8], name: &str) -> Result<&'a [u8; PUBKEY_SIZE]> {
    <&[u8; PUBKEY_SIZE]>::try_from(field)
        .map_err(|_| malformed(&format!("{name} is not {PUBKEY_SIZE} bytes")))
}

fn sign_digest_with(signing: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    signing.sign(digest).to_bytes().to_vec()
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

/// The signing digest of a [`CalendarEvent`] record:
/// `SHA256("TWEVENT\0" || fields 1-15 in order)`. Fixed-size
/// fields are hashed raw; variable-length strings are hashed
/// with a little-endian u32 length prefix so field boundaries
/// can never blur. The signature field itself is excluded.
pub fn calendar_event_digest(event: &CalendarEvent) -> [u8; 32] {
    fn put_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(&event.event_id);
    put_len_prefixed(&mut hasher, event.title.as_bytes());
    put_len_prefixed(&mut hasher, event.notes.as_bytes());
    put_len_prefixed(&mut hasher, event.location.as_bytes());
    hasher.update(event.start_unix.to_le_bytes());
    hasher.update(event.end_unix.to_le_bytes());
    put_len_prefixed(&mut hasher, event.timezone.as_bytes());
    hasher.update([event.all_day as u8]);
    put_len_prefixed(&mut hasher, event.rrule.as_bytes());
    hasher.update(&event.created_by);
    hasher.update(&event.actor_member_pubkey);
    hasher.update(&event.actor_device_pubkey);
    hasher.update(event.created_at.to_le_bytes());
    hasher.update(event.updated_at.to_le_bytes());
    hasher.update([event.deleted as u8]);
    hasher.finalize().into()
}

/// Build one signed event envelope issuing `event` as a new
/// version, signed by the device key `device_label` of member
/// `actor`. The record's `created_by`, `actor_member_pubkey`
/// and `actor_device_pubkey` fields are filled in from the
/// keystore (any values the caller put there are replaced) and
/// the record signature is computed here. The record rides in
/// the clear as the envelope payload — no key wraps, a
/// zero-filled payload nonce (there is no payload cipher), and
/// the device key as the ephemeral key, exactly like a group
/// key share envelope. The envelope's header timestamp is the
/// record's `updated_at` (its version clock).
pub fn build_event_envelope(
    actor: &MemberKeystore,
    device_label: &str,
    event: &CalendarEvent,
) -> Result<Envelope> {
    let actor_member_pubkey = actor.member_public_key()?;
    let device_keystore = actor
        .device_keystore(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;
    let secret = device_keystore.get_private_key()?;
    let device_signing = SigningKey::from_keypair_bytes(&secret)
        .map_err(|e| malformed(&format!("device secret is not a valid keypair: {e}")))?;
    build_event_envelope_with_keys(&actor_member_pubkey, &device_signing, event)
}

/// [`build_event_envelope`] with the acting member's pubkey
/// and device signing key given directly (the founding
/// parent's backup-card keys are the case this exists for:
/// the card holds raw seeds, not a [`MemberKeystore`]).
pub fn build_event_envelope_with_keys(
    actor_member_pubkey: &[u8; PUBKEY_SIZE],
    device_signing: &SigningKey,
    event: &CalendarEvent,
) -> Result<Envelope> {
    let actor_device_pubkey = device_signing.verifying_key().to_bytes();

    let mut record = event.clone();
    record.created_by = if record.created_by.is_empty() {
        actor_member_pubkey.to_vec()
    } else {
        record.created_by.clone()
    };
    record.actor_member_pubkey = actor_member_pubkey.to_vec();
    record.actor_device_pubkey = actor_device_pubkey.to_vec();
    let digest = calendar_event_digest(&record);
    record.signature = sign_digest_with(device_signing, &digest);

    let mut envelope = Envelope {
        header: Some(EnvelopeHeader {
            version: 1,
            content_type: CONTENT_CALENDAR_EVENT,
            schema_version: 1,
            timestamp: record.updated_at,
            sender_pubkey: actor_device_pubkey.to_vec(),
            recipients_pubkey: Vec::new(),
            group_id: Vec::new(),
        }),
        payload_nonce: vec![0u8; 24],
        ephemeral_pubkey: actor_device_pubkey.to_vec(),
        payload_ciphertext: record.encode_to_vec(),
        keywraps: Vec::new(),
        signature: Vec::new(),
    };
    let envelope_digest = validation::compute_envelope_signing_digest(&envelope)
        .ok_or_else(|| malformed("event envelope signing digest cannot be computed"))?;
    envelope.signature = sign_digest_with(device_signing, &envelope_digest);
    Ok(envelope)
}

/// How long an event envelope is retained: the gossip default
/// (header timestamp + the configured TTL) or the event's own
/// horizon — its end plus the retention grace — whichever is
/// later (DESIGN.md §4.3).
pub fn event_expires_at(event: &CalendarEvent, default_expires_at: u64) -> u64 {
    let end = if event.end_unix > 0 {
        event.end_unix as u64
    } else {
        0
    };
    let horizon = end
        .max(event.updated_at)
        .saturating_add(EVENT_RETENTION_GRACE_SECONDS);
    default_expires_at.max(horizon)
}

/// Verify an event envelope for ingest (gossip) or submission
/// (API): structure, header/payload agreement, the envelope
/// signature, the record signature, the acting device's
/// enrollment, the actor authorization rule, and the version
/// rule against what the store already holds. Every rejection
/// is logged with its reason before the error is returned.
/// Returns the parsed record on success.
pub fn verify_event_envelope(
    store: &Store,
    envelope: &Envelope,
    now: u64,
) -> Result<CalendarEvent> {
    match verify_event_envelope_inner(store, envelope, now) {
        Ok(event) => Ok(event),
        Err(e) => {
            let sender = envelope
                .header
                .as_ref()
                .map(|h| hex(&h.sender_pubkey))
                .unwrap_or_else(|| "none".to_string());
            eprintln!("events: rejected calendar event sender={sender}: {e}");
            Err(e)
        }
    }
}

fn verify_event_envelope_inner(
    store: &Store,
    envelope: &Envelope,
    now: u64,
) -> Result<CalendarEvent> {
    let header = envelope
        .header
        .as_ref()
        .ok_or_else(|| malformed("event envelope has no header"))?;
    if header.content_type != CONTENT_CALENDAR_EVENT {
        return Err(malformed(&format!(
            "content type {} is not a calendar event",
            header.content_type
        )));
    }
    let event = CalendarEvent::decode(envelope.payload_ciphertext.as_slice())
        .map_err(|e| malformed(&format!("event payload does not decode: {e}")))?;
    if event.event_id.len() != EVENT_ID_SIZE {
        return Err(malformed("event_id is not 16 bytes"));
    }
    let created_by = key_arg(&event.created_by, "created_by")?;
    let actor_member = key_arg(&event.actor_member_pubkey, "actor_member_pubkey")?;
    let actor_device = key_arg(&event.actor_device_pubkey, "actor_device_pubkey")?;
    if event.signature.len() != 64 {
        return Err(malformed("event signature is not 64 bytes"));
    }
    if event.title.is_empty() {
        return Err(malformed("event title is empty"));
    }
    if event.end_unix < event.start_unix {
        return Err(malformed("event end is before its start"));
    }
    if event.updated_at < event.created_at {
        return Err(malformed("event updated_at is before its created_at"));
    }

    // Header and payload must agree about who issued this
    // version, and an event envelope carries no wraps and no
    // recipients — it is household content, addressed to the
    // node, not to a key.
    if header.sender_pubkey != event.actor_device_pubkey {
        return Err(malformed("header sender is not the event's actor device"));
    }
    if !header.recipients_pubkey.is_empty() {
        return Err(malformed("event envelope must not name recipients"));
    }
    if !header.group_id.is_empty() {
        return Err(malformed("event envelope must not name a group"));
    }
    if !envelope.keywraps.is_empty() {
        return Err(malformed("event envelope must not carry key wraps"));
    }
    if header.timestamp != event.updated_at {
        return Err(malformed(
            "header timestamp is not the event's updated_at (its version clock)",
        ));
    }

    // Both signatures must verify: the envelope signature
    // (actor device, over the frozen envelope digest) and the
    // record signature (actor device, over the TWEVENT digest).
    if !validation::verify_envelope_signature(envelope) {
        return Err(Error::BadSignature);
    }
    let digest = calendar_event_digest(&event);
    verify_digest_signature(actor_device, &digest, &event.signature)?;

    // The creator must be a registered member and the acting
    // device must be an enrolled, currently trusted device of
    // the acting member.
    if !store.user_exists(created_by) {
        return Err(Error::ActorNotEnrolled(format!(
            "creator member={} is not registered",
            hex(created_by)
        )));
    }
    if !store.device_is_trusted(actor_member, actor_device, now)? {
        return Err(Error::ActorNotEnrolled(format!(
            "member={} device={}",
            hex(actor_member),
            hex(actor_device)
        )));
    }

    // Authorization + version rule, against the projection of
    // what this node already holds (brought current first —
    // the projection is derived from the envelope store).
    store.events_project_pending()?;
    let existing = store.event_get(&event.event_id)?;
    match &existing {
        None => {
            // A first version may only be issued by the
            // creator themselves.
            if actor_member != created_by {
                return Err(Error::NotAuthorized(format!(
                    "first version of event {} issued by member={} but created_by is member={}",
                    hex(&event.event_id),
                    hex(actor_member),
                    hex(created_by)
                )));
            }
        }
        Some(current) => {
            // The stored creator is immutable: a version that
            // names a different creator is not this event.
            if current.created_by != *created_by {
                return Err(Error::NotAuthorized(format!(
                    "version of event {} names creator member={} but the event's creator is member={}",
                    hex(&event.event_id),
                    hex(created_by),
                    hex(&current.created_by)
                )));
            }
            // Update/delete: the creator, or a recorded parent
            // of the creator.
            if actor_member != created_by {
                let parents = store.parents_of(created_by)?;
                if !parents.contains(actor_member) {
                    return Err(Error::NotAuthorized(format!(
                        "member={} is neither the creator of event {} nor a recorded parent of member={}",
                        hex(actor_member),
                        hex(&event.event_id),
                        hex(created_by)
                    )));
                }
            }
            // Version rule: strictly newer wins. The same clock
            // value is accepted only for the identical payload
            // (a re-arrival — the caller's dedup turns it into
            // a duplicate); a different payload at the same
            // clock is a conflict and is refused, so what a
            // node holds can never silently flap.
            if event.updated_at < current.updated_at {
                return Err(Error::StaleVersion(format!(
                    "event {} version at {} is older than the held version at {}",
                    hex(&event.event_id),
                    event.updated_at,
                    current.updated_at
                )));
            }
            if event.updated_at == current.updated_at
                && event.encode_to_vec() != current.payload
            {
                return Err(Error::StaleVersion(format!(
                    "event {} already has a different version at {}",
                    hex(&event.event_id),
                    event.updated_at
                )));
            }
        }
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemberKeystore;

    /// An enrolled test member: member keystore + "phone"
    /// device, registered in the store with its certificate
    /// (the store-level mirror of the API tests' helper).
    fn make_member(store: &Store, name: &str) -> MemberKeystore {
        let mut ks = MemberKeystore::new();
        ks.generate_member_key().unwrap();
        ks.add_device_key("phone").unwrap();
        let member_pk = ks.member_public_key().unwrap();
        let now = 1_700_000_000;
        let cert = crate::identity::issue_device_certificate(&ks, "phone", now, 0).unwrap();
        store.user_register(&member_pk, name).unwrap();
        store.device_add(&cert, now).unwrap();
        ks
    }

    fn base_event(id_byte: u8, title: &str, updated_at: u64) -> CalendarEvent {
        CalendarEvent {
            event_id: vec![id_byte; EVENT_ID_SIZE],
            title: title.to_string(),
            notes: String::new(),
            location: String::new(),
            start_unix: 1_800_000_000,
            end_unix: 1_800_003_600,
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

    fn test_store() -> Store {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        store
    }

    /// The fixed record the page's known-answer check
    /// (webui/scripts/events-kat.check.mjs) also builds: the
    /// TWEVENT digest and the serialized record must match
    /// byte-for-byte across the Rust and TypeScript
    /// implementations, or the node will reject every event
    /// the page signs.
    fn kat_record() -> CalendarEvent {
        CalendarEvent {
            event_id: vec![0x11; EVENT_ID_SIZE],
            title: "KAT event".to_string(),
            notes: "known answer".to_string(),
            location: "Test Range".to_string(),
            start_unix: 1_795_388_400,
            end_unix: 1_795_393_800,
            timezone: "America/Denver".to_string(),
            all_day: false,
            rrule: "FREQ=WEEKLY".to_string(),
            created_by: vec![0x22; PUBKEY_SIZE],
            actor_member_pubkey: vec![0x22; PUBKEY_SIZE],
            actor_device_pubkey: vec![0x33; PUBKEY_SIZE],
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            deleted: false,
            signature: vec![0xAA; 64],
        }
    }

    #[test]
    fn event_known_answer_vector() {
        // Pinned from the Rust implementation; the page's
        // check (webui/scripts/events-kat.check.mjs) asserts
        // its TypeScript digest + serialization match these
        // exact bytes.
        let record = kat_record();
        let digest = calendar_event_digest(&record);
        assert_eq!(
            hex(&digest),
            "932677988c074eee5803d8769949ab7e687c219732e5f93f9a6614b57786966d"
        );
        assert_eq!(
            hex(&record.encode_to_vec()),
            "0a101111111111111111111111111111111112094b4154206576656e741a0c6b6e6f776e20616e73776572220a546573742052616e676528f0e78dd8063088928ed8063a0e416d65726963612f44656e7665724a0b465245513d5745454b4c59522022222222222222222222222222222222222222222222222222222222222222225a202222222222222222222222222222222222222222222222222222222222222222622033333333333333333333333333333333333333333333333333333333333333336880e2cfaa0670e4e2cfaa06820140aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn build_and_verify_round_trip() {        let store = test_store();
        let alice = make_member(&store, "Alice");
        let event = base_event(0xE1, "Dentist", 1_700_000_100);
        let envelope = build_event_envelope(&alice, "phone", &event).unwrap();
        let verified = verify_event_envelope(&store, &envelope, 1_700_000_200).unwrap();
        assert_eq!(verified.title, "Dentist");
        assert_eq!(verified.created_by, alice.member_public_key().unwrap().to_vec());
        // After the envelope is stored and projected, the same
        // version re-verifies (a re-arrival, not a conflict).
        store
            .gossip_store_save_envelope(&envelope, event_expires_at(&verified, u64::MAX / 2))
            .unwrap();
        let again = verify_event_envelope(&store, &envelope, 1_700_000_300).unwrap();
        assert_eq!(again, verified);
    }

    #[test]
    fn tampered_record_signature_is_rejected() {
        let store = test_store();
        let alice = make_member(&store, "Alice");
        let event = base_event(0xE2, "Dentist", 1_700_000_100);
        let mut envelope = build_event_envelope(&alice, "phone", &event).unwrap();
        // Corrupt the record signature but re-sign the envelope
        // so only the record-level check can catch it.
        let mut record = CalendarEvent::decode(envelope.payload_ciphertext.as_slice()).unwrap();
        record.signature[0] ^= 0xFF;
        envelope.payload_ciphertext = record.encode_to_vec();
        envelope.signature = Vec::new();
        let device_secret = alice
            .device_keystore("phone")
            .unwrap()
            .get_private_key()
            .unwrap();
        let device_signing = SigningKey::from_keypair_bytes(&device_secret).unwrap();
        let digest = validation::compute_envelope_signing_digest(&envelope).unwrap();
        envelope.signature = device_signing.sign(&digest).to_bytes().to_vec();
        let err = verify_event_envelope(&store, &envelope, 1_700_000_200).unwrap_err();
        assert!(matches!(err, Error::BadSignature), "got {err}");
    }

    #[test]
    fn stranger_cannot_update_and_parent_can() {
        let store = test_store();
        let child = make_member(&store, "Child");
        let parent = make_member(&store, "Parent");
        let stranger = make_member(&store, "Stranger");
        let child_pk = child.member_public_key().unwrap();
        let parent_pk = parent.member_public_key().unwrap();
        store.parent_link_add(&parent_pk, &child_pk).unwrap();

        let created = base_event(0xE3, "Soccer", 1_700_000_100);
        let create_env = build_event_envelope(&child, "phone", &created).unwrap();
        verify_event_envelope(&store, &create_env, 1_700_000_200).unwrap();
        store.gossip_store_save_envelope(&create_env, u64::MAX / 2).unwrap();

        // A stranger's update is refused.
        let mut update = base_event(0xE3, "Soccer (moved)", 1_700_000_500);
        update.created_by = child_pk.to_vec();
        update.created_at = 1_700_000_100;
        let stranger_env = build_event_envelope(&stranger, "phone", &update).unwrap();
        let err = verify_event_envelope(&store, &stranger_env, 1_700_000_600).unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)), "got {err}");

        // A stale version from the creator is refused.
        let mut stale = base_event(0xE3, "Soccer (old)", 1_700_000_050);
        stale.created_by = child_pk.to_vec();
        stale.created_at = 1_700_000_100;
        // (updated_at < created_at would be malformed; use a
        // coherent stale pair instead.)
        stale.created_at = 1_700_000_040;
        let stale_env = build_event_envelope(&child, "phone", &stale).unwrap();
        let err = verify_event_envelope(&store, &stale_env, 1_700_000_600).unwrap_err();
        assert!(matches!(err, Error::StaleVersion(_)), "got {err}");

        // The recorded parent's update verifies.
        let parent_env = build_event_envelope(&parent, "phone", &update).unwrap();
        let verified = verify_event_envelope(&store, &parent_env, 1_700_000_600).unwrap();
        assert_eq!(verified.title, "Soccer (moved)");
        assert_eq!(verified.actor_member_pubkey, parent_pk.to_vec());
    }
}
