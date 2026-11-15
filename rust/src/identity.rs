//! Device identity: member-signed device certificates and
//! revocations (DESIGN.md §3).
//!
//! The design has three kinds of keys (DESIGN.md §3.1): the node
//! key identifies the home box, the member key identifies a person,
//! and a device key identifies one phone/laptop of one member. A
//! device key is trusted because a member vouches for it with a
//! **device certificate**: the member key signs the statement
//! "device key D belongs to member M". This module creates and
//! verifies those certificates, plus the matching signed
//! **device revocations** ("member M no longer vouches for D").
//!
//! Both records are the `DeviceCertificate` / `DeviceRevocation`
//! protobuf messages from `content.proto` (content types
//! `CONTENT_DEVICE_CERTIFICATE` / `CONTENT_DEVICE_REVOCATION`), so
//! they can travel as ordinary envelope content and be stored by
//! the `devices` table in the store module. The signature covers
//! a domain-separated SHA-256 digest of the statement fields —
//! the same shape as the envelope/message digests in the
//! validation module (`SHA256(domain || fields)`, NUL-terminated
//! domain, little-endian integers) — which makes each record
//! self-verifying wherever it turns up.
//!
//! Standing rule (project-wide): rejections are never silent.
//! Every failed verification logs one `eprintln!` line with the
//! reason before returning the error, mirroring the gossip
//! ingest rejection logs.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::keystore::{Keystore, MemberKeystore, SIGN_PUBKEY_SIZE};
use crate::proto::{DeviceCertificate, DeviceRevocation};

/// Domain separator for the device-certificate signing digest.
pub const DEVICE_CERT_DOMAIN: &[u8] = b"TWDEVCERT\0";
/// Domain separator for the device-revocation signing digest.
pub const DEVICE_REVOCATION_DOMAIN: &[u8] = b"TWDEVREVOKE\0";
/// Ed25519 signature size.
pub const SIGNATURE_SIZE: usize = 64;

/// Error type for certificate/revocation operations.
#[derive(Debug)]
pub enum Error {
    /// Keystore failure while reaching for the member key
    /// (not loaded, I/O, crypto).
    Keystore(crate::keystore::Error),
    /// The record is structurally invalid: a pubkey that is not
    /// 32 bytes, a signature that is not 64 bytes, and so on.
    Malformed(String),
    /// The member-key signature does not verify.
    BadSignature,
    /// The certificate's `expires_at` is set and is not in the
    /// future at the verification time.
    Expired { expires_at: u64, now: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Keystore(e) => write!(f, "keystore error: {e}"),
            Error::Malformed(m) => write!(f, "malformed record: {m}"),
            Error::BadSignature => write!(f, "signature does not verify"),
            Error::Expired { expires_at, now } => {
                write!(f, "certificate expired at {expires_at} (now {now})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Keystore(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::keystore::Error> for Error {
    fn from(e: crate::keystore::Error) -> Self {
        Error::Keystore(e)
    }
}

/// Identity result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn malformed(msg: &str) -> Error {
    Error::Malformed(msg.to_string())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn pubkey_arg<'a>(field: &'a [u8], name: &str) -> Result<&'a [u8; SIGN_PUBKEY_SIZE]> {
    <&[u8; SIGN_PUBKEY_SIZE]>::try_from(field)
        .map_err(|_| malformed(&format!("{name} is not {SIGN_PUBKEY_SIZE} bytes")))
}

// ---------------------------------------------------------------------------
// Signing digests
// ---------------------------------------------------------------------------

/// Signing digest for a device certificate:
/// `SHA256("TWDEVCERT\0" || member_pubkey || device_pubkey ||
/// issued_at (LE u64) || expires_at (LE u64) || SHA256(label))`.
/// The label is hashed so the digest layout stays fixed-size
/// regardless of label length, as with the ciphertext hash in
/// the envelope digest.
pub fn device_certificate_digest(
    member_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    device_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    label: &str,
    issued_at: u64,
    expires_at: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_CERT_DOMAIN);
    hasher.update(member_pubkey);
    hasher.update(device_pubkey);
    hasher.update(issued_at.to_le_bytes());
    hasher.update(expires_at.to_le_bytes());
    hasher.update(sha256(label.as_bytes()));
    hasher.finalize().into()
}

/// Signing digest for a device revocation:
/// `SHA256("TWDEVREVOKE\0" || member_pubkey || device_pubkey ||
/// revoked_at (LE u64) || SHA256(reason))`.
pub fn device_revocation_digest(
    member_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    device_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    revoked_at: u64,
    reason: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_REVOCATION_DOMAIN);
    hasher.update(member_pubkey);
    hasher.update(device_pubkey);
    hasher.update(revoked_at.to_le_bytes());
    hasher.update(sha256(reason.as_bytes()));
    hasher.finalize().into()
}

fn signing_key_of(keystore: &Keystore) -> Result<SigningKey> {
    let secret = keystore.get_private_key()?;
    SigningKey::from_keypair_bytes(&secret)
        .map_err(|e| malformed(&format!("member secret key is not a valid keypair: {e}")))
}

fn verify_signature(
    pubkey: &[u8; SIGN_PUBKEY_SIZE],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let signature = <&[u8; SIGNATURE_SIZE]>::try_from(signature)
        .map_err(|_| malformed(&format!("signature is not {SIGNATURE_SIZE} bytes")))?;
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| malformed(&format!("signer public key is invalid: {e}")))?;
    verifying_key
        .verify(digest, &Signature::from_bytes(signature))
        .map_err(|_| Error::BadSignature)
}

// ---------------------------------------------------------------------------
// Device certificates
// ---------------------------------------------------------------------------

/// Create a device certificate: `member` (a keystore holding the
/// member key) vouches that `device_pubkey` is a device of that
/// member. `expires_at` of 0 means the certificate never expires.
/// The returned record is fully signed and self-verifying.
pub fn create_device_certificate(
    member: &Keystore,
    device_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    label: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<DeviceCertificate> {
    let member_pubkey = member.get_public_key()?;
    let digest = device_certificate_digest(&member_pubkey, device_pubkey, label, issued_at, expires_at);
    let signature = signing_key_of(member)?.sign(&digest);
    Ok(DeviceCertificate {
        member_pubkey: member_pubkey.to_vec(),
        device_pubkey: device_pubkey.to_vec(),
        label: label.to_string(),
        issued_at,
        expires_at,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Issue a certificate for one of the devices in a
/// [`MemberKeystore`], looked up by label. This is the operation
/// enrollment performs after a member adds a device key.
pub fn issue_device_certificate(
    member: &MemberKeystore,
    device_label: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<DeviceCertificate> {
    let device_pubkey = member
        .device_public_key(device_label)
        .ok_or_else(|| malformed(&format!("no device key labelled {device_label:?}")))?;
    create_device_certificate(member.member_keystore(), &device_pubkey, device_label, issued_at, expires_at)
}

/// Verify a device certificate at time `now`: field shapes, the
/// member-key signature over the certificate digest, and expiry
/// (`expires_at` of 0 never expires; otherwise the certificate
/// is valid strictly before `expires_at`). Every rejection is
/// logged with its reason before the error is returned.
pub fn verify_device_certificate(cert: &DeviceCertificate, now: u64) -> Result<()> {
    match verify_device_certificate_inner(cert, now) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!(
                "identity: rejected device certificate member={} device={}: {e}",
                hex(&cert.member_pubkey),
                hex(&cert.device_pubkey)
            );
            Err(e)
        }
    }
}

fn verify_device_certificate_inner(cert: &DeviceCertificate, now: u64) -> Result<()> {
    let member_pubkey = pubkey_arg(&cert.member_pubkey, "member_pubkey")?;
    let device_pubkey = pubkey_arg(&cert.device_pubkey, "device_pubkey")?;
    let digest = device_certificate_digest(
        member_pubkey,
        device_pubkey,
        &cert.label,
        cert.issued_at,
        cert.expires_at,
    );
    verify_signature(member_pubkey, &digest, &cert.signature)?;
    if cert.expires_at != 0 && now >= cert.expires_at {
        return Err(Error::Expired {
            expires_at: cert.expires_at,
            now,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Device revocations
// ---------------------------------------------------------------------------

/// Create a device revocation: `member` withdraws its vouch for
/// `device_pubkey` at `revoked_at`. `reason` is free-form
/// ("lost", "replaced", ...) and may be empty.
pub fn create_device_revocation(
    member: &Keystore,
    device_pubkey: &[u8; SIGN_PUBKEY_SIZE],
    revoked_at: u64,
    reason: &str,
) -> Result<DeviceRevocation> {
    let member_pubkey = member.get_public_key()?;
    let digest = device_revocation_digest(&member_pubkey, device_pubkey, revoked_at, reason);
    let signature = signing_key_of(member)?.sign(&digest);
    Ok(DeviceRevocation {
        member_pubkey: member_pubkey.to_vec(),
        device_pubkey: device_pubkey.to_vec(),
        revoked_at,
        reason: reason.to_string(),
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify a device revocation: field shapes and the member-key
/// signature over the revocation digest. Every rejection is
/// logged with its reason before the error is returned.
pub fn verify_device_revocation(rev: &DeviceRevocation) -> Result<()> {
    match verify_device_revocation_inner(rev) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!(
                "identity: rejected device revocation member={} device={}: {e}",
                hex(&rev.member_pubkey),
                hex(&rev.device_pubkey)
            );
            Err(e)
        }
    }
}

fn verify_device_revocation_inner(rev: &DeviceRevocation) -> Result<()> {
    let member_pubkey = pubkey_arg(&rev.member_pubkey, "member_pubkey")?;
    let device_pubkey = pubkey_arg(&rev.device_pubkey, "device_pubkey")?;
    let digest = device_revocation_digest(member_pubkey, device_pubkey, rev.revoked_at, &rev.reason);
    verify_signature(member_pubkey, &digest, &rev.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Keystore;

    const NOW: u64 = 1_700_000_000;

    fn member_with_device() -> (MemberKeystore, [u8; SIGN_PUBKEY_SIZE]) {
        let mut member = MemberKeystore::new();
        member.generate_member_key().expect("member key");
        let device_pubkey = member.add_device_key("phone").expect("device key");
        (member, device_pubkey)
    }

    #[test]
    fn certificate_create_verify_round_trip() {
        let (member, device_pubkey) = member_with_device();
        let cert = issue_device_certificate(&member, "phone", NOW, 0).expect("issue");
        assert_eq!(
            cert.member_pubkey,
            member.member_public_key().expect("member pk").to_vec()
        );
        assert_eq!(cert.device_pubkey, device_pubkey.to_vec());
        assert_eq!(cert.label, "phone");
        assert_eq!(cert.signature.len(), SIGNATURE_SIZE);
        verify_device_certificate(&cert, NOW).expect("verify at issue time");
        // A no-expiry certificate stays valid arbitrarily far out.
        verify_device_certificate(&cert, NOW + 100 * 365 * 24 * 60 * 60).expect("verify later");
    }

    #[test]
    fn certificate_digests_are_domain_separated() {
        let member_pk = [7u8; SIGN_PUBKEY_SIZE];
        let device_pk = [9u8; SIGN_PUBKEY_SIZE];
        let cert_digest = device_certificate_digest(&member_pk, &device_pk, "phone", NOW, 0);
        let rev_digest = device_revocation_digest(&member_pk, &device_pk, NOW, "phone");
        assert_ne!(cert_digest, rev_digest);
        // Every signed field feeds the digest.
        assert_ne!(
            cert_digest,
            device_certificate_digest(&member_pk, &device_pk, "tablet", NOW, 0)
        );
        assert_ne!(
            cert_digest,
            device_certificate_digest(&member_pk, &device_pk, "phone", NOW, 1)
        );
        assert_ne!(
            cert_digest,
            device_certificate_digest(&member_pk, &[8u8; 32], "phone", NOW, 0)
        );
    }

    #[test]
    fn tampered_certificate_is_rejected() {
        let (member, _) = member_with_device();
        let cert = issue_device_certificate(&member, "phone", NOW, 0).expect("issue");

        // Relabelling after signing breaks the signature.
        let mut relabelled = cert.clone();
        relabelled.label = "attacker laptop".to_string();
        assert!(matches!(
            verify_device_certificate(&relabelled, NOW),
            Err(Error::BadSignature)
        ));

        // Swapping in a different device key breaks it too.
        let mut swapped = cert.clone();
        swapped.device_pubkey = [42u8; SIGN_PUBKEY_SIZE].to_vec();
        assert!(matches!(
            verify_device_certificate(&swapped, NOW),
            Err(Error::BadSignature)
        ));

        // A certificate signed by a different member does not
        // verify against the claimed member key.
        let mut other = MemberKeystore::new();
        other.generate_member_key().expect("other member");
        let device_pk = other.add_device_key("phone").expect("other device");
        let foreign = create_device_certificate(other.member_keystore(), &device_pk, "phone", NOW, 0)
            .expect("foreign cert");
        let mut forged = foreign.clone();
        forged.member_pubkey = cert.member_pubkey.clone();
        assert!(matches!(
            verify_device_certificate(&forged, NOW),
            Err(Error::BadSignature)
        ));

        // Truncated fields are malformed, not a panic.
        let mut short = cert.clone();
        short.member_pubkey = vec![1u8; 16];
        assert!(matches!(
            verify_device_certificate(&short, NOW),
            Err(Error::Malformed(_))
        ));
        let mut no_sig = cert;
        no_sig.signature = Vec::new();
        assert!(matches!(
            verify_device_certificate(&no_sig, NOW),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let (member, device_pubkey) = member_with_device();
        let expires_at = NOW + 3600;
        let cert = create_device_certificate(
            member.member_keystore(),
            &device_pubkey,
            "phone",
            NOW,
            expires_at,
        )
        .expect("issue expiring cert");
        verify_device_certificate(&cert, NOW).expect("valid at issue");
        verify_device_certificate(&cert, expires_at - 1).expect("valid just before expiry");
        assert!(matches!(
            verify_device_certificate(&cert, expires_at),
            Err(Error::Expired { .. })
        ));
        assert!(matches!(
            verify_device_certificate(&cert, expires_at + 1),
            Err(Error::Expired { .. })
        ));
    }

    #[test]
    fn revocation_create_verify_round_trip_and_tamper() {
        let (member, device_pubkey) = member_with_device();
        let rev = create_device_revocation(member.member_keystore(), &device_pubkey, NOW, "lost")
            .expect("create revocation");
        assert_eq!(rev.signature.len(), SIGNATURE_SIZE);
        verify_device_revocation(&rev).expect("verify revocation");

        // Changing the reason after signing breaks the signature.
        let mut tampered = rev.clone();
        tampered.reason = "replaced".to_string();
        assert!(matches!(
            verify_device_revocation(&tampered),
            Err(Error::BadSignature)
        ));

        // A revocation from an unloaded keystore cannot be made.
        let empty = Keystore::new();
        assert!(create_device_revocation(&empty, &device_pubkey, NOW, "").is_err());
    }

    #[test]
    fn issue_for_unknown_device_label_fails() {
        let (member, _) = member_with_device();
        assert!(matches!(
            issue_device_certificate(&member, "no-such-device", NOW, 0),
            Err(Error::Malformed(_))
        ));
    }
}
