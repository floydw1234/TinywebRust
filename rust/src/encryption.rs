//! Envelope and message payload encryption.
//!
//! Rust counterpart of the C encryption package
//! (`src/packages/encryption/`, `encryption.h`/`encryption.c`):
//! libsodium-based payload encryption for `Envelope`/`Message`
//! protobufs. A random 32-byte symmetric key encrypts the payload
//! once with `crypto_secretbox_easy` (XSalsa20-Poly1305, random
//! 24-byte payload nonce); a fresh ephemeral X25519 keypair wraps
//! that key for each recipient with `crypto_box_easy` (random
//! 24-byte nonce per wrap), after converting each recipient's
//! Ed25519 public key to Curve25519. Decryption finds the caller's
//! wrap, opens it with the caller's converted X25519 secret and the
//! envelope's ephemeral public key, then opens the payload.
//! Wire behaviour is identical to the C build (see the
//! known-answer tests at the bottom of this module).
//!
//! Location payloads need no location-specific code in this
//! package: in the C build a location update travels as a
//! `ClientRequest` (`content.proto` `LocationUpdate`, content type
//! `CONTENT_LOCATION_UPDATE`) whose payload fields
//! (`payload_nonce`, `ephemeral_pubkey`, `payload_ciphertext`,
//! `keywraps`) have exactly the `Envelope` layout, and
//! `client_request_to_envelope`
//! (`src/packages/comm/client_request_converter.c`) copies those
//! fields verbatim into an `Envelope`. The store layer persists
//! them in `location_updates` and the per-location wraps in the
//! `location_keywraps` table (`src/packages/sql/location_store.c`,
//! already ported in `store.rs`), the API layer returns the bytes
//! still encrypted (`src/packages/comm/locationApi.c`), and actual
//! decryption is the envelope decryption below
//! (`envelope_dispatcher.c` calls `decrypt_envelope_payload` for
//! every content type, location included). So location code simply
//! reuses [`encrypt_envelope_payload`]/[`decrypt_envelope_payload`]
//! (via the `ClientRequest` -> `Envelope` conversion), and there is
//! deliberately no `encrypt_location_*` function here or in C.
//!
//! One C defect is deliberately not reproduced: the C decryptors
//! fetch the caller's key with `keystore_get_encryption_public_key`,
//! which returns the *X25519-converted* public key, and compare it
//! against `RecipientKeyWrap.recipient_pubkey`, which the
//! encryptors fill with the recipient's *Ed25519* key. The two
//! encodings never agree, so the C decryptors can only report
//! "not a recipient". The port compares against the caller's
//! Ed25519 public key (C `keystore_get_public_key`) — the key the
//! wraps actually name — while still opening the wrap with the
//! converted X25519 secret, exactly as the C code does next.
//!
//! The C functions take the recipient list as a flat
//! `num_recipients * 32` byte buffer plus a count; the port takes
//! `&[[u8; 32]]`, so the count is the slice length. The C code also
//! requires a loaded keypair for encryption (it checks
//! `keystore_is_keypair_loaded` even though sealing only uses the
//! ephemeral keypair); the port keeps that check, with the
//! [`Keystore`] passed explicitly instead of read from the C
//! global. `*_global` wrappers using the module-level keystore
//! singleton are provided for call sites shaped like the C code.

use std::fmt;

use crypto_box::{
    aead::Aead, PublicKey, SalsaBox, SecretKey,
};
use zeroize::Zeroizing;

use crate::keystore::{
    self, ed25519_pk_to_curve25519, fill_random, secretbox_easy, secretbox_open_easy, Keystore,
};
use crate::proto::{Envelope, Message, MessageRecipientKeyWrap, RecipientKeyWrap};

/// X25519/Ed25519 public key size (`PUBKEY_SIZE` in `encryption.h`).
pub const PUBKEY_SIZE: usize = 32;
/// X25519 secret key size (`SECRET_SIZE` in `encryption.h`).
pub const SECRET_SIZE: usize = 32;
/// Box/secretbox nonce size (`NONCE_SIZE` in `encryption.h`).
pub const NONCE_SIZE: usize = 24;
/// Poly1305 MAC size (`MAC_SIZE` in `encryption.h`).
pub const MAC_SIZE: usize = 16;
/// Symmetric payload key size (`crypto_secretbox_KEYBYTES`).
pub const SYMMETRIC_KEY_SIZE: usize = 32;
/// Maximum plaintext size (`MAX_PLAINTEXT_SIZE`): 2 KiB.
pub const MAX_PLAINTEXT_SIZE: usize = 2048;
/// Maximum ciphertext size (`MAX_CIPHERTEXT_SIZE`): plaintext + MAC.
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_PLAINTEXT_SIZE + MAC_SIZE;
/// Maximum number of recipients (`MAX_RECIPIENTS`).
pub const MAX_RECIPIENTS: usize = 50;
/// Size of each wrapped symmetric key (`ENCRYPTED_KEY_SIZE`): key + MAC.
pub const ENCRYPTED_KEY_SIZE: usize = SYMMETRIC_KEY_SIZE + MAC_SIZE;

/// Error type for all encryption operations.
#[derive(Debug)]
pub enum Error {
    /// Caller supplied invalid arguments (C `TW_ERROR_INVALID_ARGUMENT`):
    /// no recipients, too many recipients, or oversized plaintext on
    /// encrypt; structurally invalid fields on decrypt.
    InvalidArgument(String),
    /// No keypair loaded in the keystore (C `TW_ERROR_NOT_INITIALIZED`).
    NotInitialized,
    /// The loaded keypair is not a recipient of this payload: no
    /// keywrap names its Ed25519 public key.
    NotRecipient,
    /// Cryptographic failure (C `TW_ERROR_CRYPTO_ERROR`): a key
    /// conversion failed, or decryption failed authentication
    /// (tampered ciphertext/wrap or wrong keys).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::NotInitialized => write!(f, "keypair not loaded"),
            Error::NotRecipient => write!(f, "not a recipient of this payload"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        match e {
            keystore::Error::NotLoaded => Error::NotInitialized,
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Encryption result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn invalid(msg: &str) -> Error {
    Error::InvalidArgument(msg.to_string())
}

fn crypto(msg: &str) -> Error {
    Error::Crypto(msg.to_string())
}

// ---------------------------------------------------------------------------
// libsodium primitives (`crypto_box_easy` / `crypto_box_open_easy`;
// the payload secretbox itself lives in `keystore`)
// ---------------------------------------------------------------------------

/// libsodium `crypto_box_easy` with the `salsa20` (XSalsa20-Poly1305)
/// construction: X25519 agreement between `ephemeral_secret` and
/// `recipient_pubkey`, HSalsa20 key derivation, then secretbox.
/// Output is MAC || ciphertext, `plaintext.len() + 16` bytes.
fn box_easy(
    recipient_pubkey: &[u8; PUBKEY_SIZE],
    ephemeral_secret: &[u8; SECRET_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let salsabox = SalsaBox::new(
        &PublicKey::from_bytes(*recipient_pubkey),
        &SecretKey::from_bytes(*ephemeral_secret),
    );
    salsabox
        .encrypt(crypto_box::Nonce::from_slice(nonce), plaintext)
        .map_err(|_| crypto("crypto_box_easy failed"))
}

/// libsodium `crypto_box_open_easy`, the inverse of [`box_easy`]:
/// opens `ciphertext` (MAC || ciphertext) sent by the holder of the
/// secret matching `ephemeral_pubkey` to the holder of `our_secret`.
fn box_open_easy(
    ephemeral_pubkey: &[u8; PUBKEY_SIZE],
    our_secret: &[u8; SECRET_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let salsabox = SalsaBox::new(
        &PublicKey::from_bytes(*ephemeral_pubkey),
        &SecretKey::from_bytes(*our_secret),
    );
    salsabox
        .decrypt(crypto_box::Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| crypto("crypto_box_open_easy failed"))
}

// ---------------------------------------------------------------------------
// Shared encrypt/decrypt cores (the C envelope and message functions
// are byte-for-byte copies of each other apart from the wrap type)
// ---------------------------------------------------------------------------

/// One recipient's wrap, as raw fields shared by `RecipientKeyWrap`
/// and `MessageRecipientKeyWrap`.
struct WrapFields {
    recipient_pubkey: Vec<u8>,
    key_nonce: Vec<u8>,
    wrapped_key: Vec<u8>,
}

/// The encrypted payload plus wraps, before they are mapped onto a
/// specific protobuf type.
struct SealedPayload {
    payload_nonce: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    payload_ciphertext: Vec<u8>,
    keywraps: Vec<WrapFields>,
}

/// The body of C `encrypt_envelope_payload`/`encrypt_message_payload`,
/// which are identical apart from the target struct.
fn seal_payload(
    plaintext: &[u8],
    recipient_pubkeys: &[[u8; PUBKEY_SIZE]],
    keystore: &Keystore,
) -> Result<SealedPayload> {
    if recipient_pubkeys.is_empty() {
        return Err(invalid("no recipients"));
    }
    if !keystore.is_keypair_loaded() {
        return Err(Error::NotInitialized);
    }
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(invalid(&format!(
            "plaintext size ({} bytes) exceeds maximum allowed size ({MAX_PLAINTEXT_SIZE} bytes)",
            plaintext.len()
        )));
    }
    if recipient_pubkeys.len() > MAX_RECIPIENTS {
        return Err(invalid(&format!(
            "number of recipients ({}) exceeds maximum allowed ({MAX_RECIPIENTS})",
            recipient_pubkeys.len()
        )));
    }

    // Ephemeral X25519 keypair (C `crypto_box_keypair`).
    let mut ephemeral_secret = Zeroizing::new([0u8; SECRET_SIZE]);
    fill_random(&mut *ephemeral_secret)?;
    let ephemeral_key = SecretKey::from_bytes(*ephemeral_secret);
    let ephemeral_pubkey = ephemeral_key.public_key().to_bytes();

    // Random symmetric key, used once for the payload.
    let mut symmetric_key = Zeroizing::new([0u8; SYMMETRIC_KEY_SIZE]);
    fill_random(&mut *symmetric_key)?;

    let mut payload_nonce = [0u8; NONCE_SIZE];
    fill_random(&mut payload_nonce)?;
    let payload_ciphertext = secretbox_easy(&symmetric_key, &payload_nonce, plaintext)?;

    // Wrap the symmetric key for each recipient.
    let mut keywraps = Vec::with_capacity(recipient_pubkeys.len());
    for recipient in recipient_pubkeys {
        let curve_pubkey = ed25519_pk_to_curve25519(recipient)?;
        let mut key_nonce = [0u8; NONCE_SIZE];
        fill_random(&mut key_nonce)?;
        let wrapped_key = box_easy(
            &curve_pubkey,
            &ephemeral_secret,
            &key_nonce,
            &*symmetric_key,
        )?;
        keywraps.push(WrapFields {
            recipient_pubkey: recipient.to_vec(),
            key_nonce: key_nonce.to_vec(),
            wrapped_key,
        });
    }

    Ok(SealedPayload {
        payload_nonce: payload_nonce.to_vec(),
        ephemeral_pubkey: ephemeral_pubkey.to_vec(),
        payload_ciphertext,
        keywraps,
    })
}

/// The body of C `decrypt_envelope_payload`/`decrypt_message_payload`.
/// `wraps` yields `(recipient_pubkey, key_nonce, wrapped_key)` triples.
fn open_payload<'a>(
    payload_nonce: &[u8],
    ephemeral_pubkey: &[u8],
    payload_ciphertext: &[u8],
    wraps: impl Iterator<Item = (&'a [u8], &'a [u8], &'a [u8])>,
    keystore: &Keystore,
) -> Result<Vec<u8>> {
    if !keystore.is_keypair_loaded() {
        return Err(Error::NotInitialized);
    }
    // Our Ed25519 public key names our wrap (see the module-level
    // note on the C comparison against the converted key); our
    // converted X25519 secret opens it.
    let our_pubkey = keystore.get_public_key()?;
    let our_secret = keystore.get_encryption_private_key()?;

    let mut our_wrap: Option<(&[u8], &[u8])> = None;
    for (recipient_pubkey, key_nonce, wrapped_key) in wraps {
        if recipient_pubkey == our_pubkey.as_slice() {
            our_wrap = Some((key_nonce, wrapped_key));
            break;
        }
    }
    let Some((key_nonce, wrapped_key)) = our_wrap else {
        return Err(Error::NotRecipient);
    };

    let ephemeral_pubkey: &[u8; PUBKEY_SIZE] = ephemeral_pubkey
        .try_into()
        .map_err(|_| invalid("ephemeral_pubkey is not 32 bytes"))?;
    let key_nonce: &[u8; NONCE_SIZE] = key_nonce
        .try_into()
        .map_err(|_| invalid("key_nonce is not 24 bytes"))?;
    if wrapped_key.len() != ENCRYPTED_KEY_SIZE {
        return Err(invalid("wrapped_key is not 48 bytes"));
    }
    let symmetric_key = box_open_easy(ephemeral_pubkey, &our_secret, key_nonce, wrapped_key)?;
    let symmetric_key: &[u8; SYMMETRIC_KEY_SIZE] = symmetric_key
        .as_slice()
        .try_into()
        .map_err(|_| crypto("decrypted symmetric key is not 32 bytes"))?;

    // The C code checks the ciphertext size after unwrapping the key.
    if payload_ciphertext.len() < MAC_SIZE || payload_ciphertext.len() > MAX_CIPHERTEXT_SIZE {
        return Err(invalid(&format!(
            "invalid ciphertext size {}",
            payload_ciphertext.len()
        )));
    }
    let payload_nonce: &[u8; NONCE_SIZE] = payload_nonce
        .try_into()
        .map_err(|_| invalid("payload_nonce is not 24 bytes"))?;
    secretbox_open_easy(symmetric_key, payload_nonce, payload_ciphertext)
        .map_err(|_| crypto("payload decryption failed"))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` for `recipient_pubkeys` (Ed25519 keys) and
/// populate `envelope`'s `payload_nonce`, `ephemeral_pubkey`,
/// `payload_ciphertext` and `keywraps` (C `encrypt_envelope_payload`).
/// Header and signature are left untouched, as in C. On error the
/// envelope is not modified.
pub fn encrypt_envelope_payload(
    plaintext: &[u8],
    recipient_pubkeys: &[[u8; PUBKEY_SIZE]],
    envelope: &mut Envelope,
    keystore: &Keystore,
) -> Result<()> {
    let sealed = seal_payload(plaintext, recipient_pubkeys, keystore)?;
    envelope.payload_nonce = sealed.payload_nonce;
    envelope.ephemeral_pubkey = sealed.ephemeral_pubkey;
    envelope.payload_ciphertext = sealed.payload_ciphertext;
    envelope.keywraps = sealed
        .keywraps
        .into_iter()
        .map(|w| RecipientKeyWrap {
            recipient_pubkey: w.recipient_pubkey,
            key_nonce: w.key_nonce,
            wrapped_key: w.wrapped_key,
        })
        .collect();
    Ok(())
}

/// Decrypt an envelope's payload for the keypair in `keystore`
/// (C `decrypt_envelope_payload`). Returns the plaintext; the C
/// caller-owned buffer becomes an owned `Vec` here.
pub fn decrypt_envelope_payload(envelope: &Envelope, keystore: &Keystore) -> Result<Vec<u8>> {
    open_payload(
        &envelope.payload_nonce,
        &envelope.ephemeral_pubkey,
        &envelope.payload_ciphertext,
        envelope
            .keywraps
            .iter()
            .map(|w| (w.recipient_pubkey.as_slice(), w.key_nonce.as_slice(), w.wrapped_key.as_slice())),
        keystore,
    )
}

/// Encrypt `plaintext` for `recipient_pubkeys` (Ed25519 keys) and
/// populate `message`'s payload fields (C `encrypt_message_payload`).
/// Identical wire behaviour to [`encrypt_envelope_payload`].
pub fn encrypt_message_payload(
    plaintext: &[u8],
    recipient_pubkeys: &[[u8; PUBKEY_SIZE]],
    message: &mut Message,
    keystore: &Keystore,
) -> Result<()> {
    let sealed = seal_payload(plaintext, recipient_pubkeys, keystore)?;
    message.payload_nonce = sealed.payload_nonce;
    message.ephemeral_pubkey = sealed.ephemeral_pubkey;
    message.payload_ciphertext = sealed.payload_ciphertext;
    message.keywraps = sealed
        .keywraps
        .into_iter()
        .map(|w| MessageRecipientKeyWrap {
            recipient_pubkey: w.recipient_pubkey,
            key_nonce: w.key_nonce,
            wrapped_key: w.wrapped_key,
        })
        .collect();
    Ok(())
}

/// Decrypt a message's payload for the keypair in `keystore`
/// (C `decrypt_message_payload`).
pub fn decrypt_message_payload(message: &Message, keystore: &Keystore) -> Result<Vec<u8>> {
    open_payload(
        &message.payload_nonce,
        &message.ephemeral_pubkey,
        &message.payload_ciphertext,
        message
            .keywraps
            .iter()
            .map(|w| (w.recipient_pubkey.as_slice(), w.key_nonce.as_slice(), w.wrapped_key.as_slice())),
        keystore,
    )
}

/// [`encrypt_envelope_payload`] using the module-level keystore
/// singleton, for call sites shaped like the C code.
pub fn encrypt_envelope_payload_global(
    plaintext: &[u8],
    recipient_pubkeys: &[[u8; PUBKEY_SIZE]],
    envelope: &mut Envelope,
) -> Result<()> {
    let ks = keystore::global_keystore_lock();
    encrypt_envelope_payload(plaintext, recipient_pubkeys, envelope, &ks)
}

/// [`decrypt_envelope_payload`] using the module-level keystore singleton.
pub fn decrypt_envelope_payload_global(envelope: &Envelope) -> Result<Vec<u8>> {
    let ks = keystore::global_keystore_lock();
    decrypt_envelope_payload(envelope, &ks)
}

/// [`encrypt_message_payload`] using the module-level keystore singleton.
pub fn encrypt_message_payload_global(
    plaintext: &[u8],
    recipient_pubkeys: &[[u8; PUBKEY_SIZE]],
    message: &mut Message,
) -> Result<()> {
    let ks = keystore::global_keystore_lock();
    encrypt_message_payload(plaintext, recipient_pubkeys, message, &ks)
}

/// [`decrypt_message_payload`] using the module-level keystore singleton.
pub fn decrypt_message_payload_global(message: &Message) -> Result<Vec<u8>> {
    let ks = keystore::global_keystore_lock();
    decrypt_message_payload(message, &ks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{secretbox_easy, secretbox_open_easy};

    fn hex_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let v = hex_bytes(hex);
        <[u8; N]>::try_from(v.as_slice()).expect("vector length")
    }

    fn loaded_keystore() -> (Keystore, [u8; PUBKEY_SIZE]) {
        let mut ks = Keystore::new();
        ks.generate_keypair().expect("generate");
        let pk = ks.get_public_key().expect("public key");
        (ks, pk)
    }

    #[test]
    fn secretbox_kat() {
        // libsodium crypto_secretbox_easy(key, nonce, "hello tinyweb
        // secretbox") with key 00..1f and nonce 00..17.
        let key: [u8; 32] = hex_array(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let nonce: [u8; 24] = hex_array("000102030405060708090a0b0c0d0e0f1011121314151617");
        let ciphertext = secretbox_easy(&key, &nonce, b"hello tinyweb secretbox").expect("seal");
        assert_eq!(
            ciphertext,
            hex_bytes("bc734d0457112b2f4611f33e392f31e6369a5423a8ead679d545f85b0aaf39f231d723abee4a47")
        );
        assert_eq!(
            secretbox_open_easy(&key, &nonce, &ciphertext).expect("open"),
            b"hello tinyweb secretbox".to_vec()
        );
        let mut tampered = ciphertext.clone();
        tampered[20] ^= 1;
        assert!(secretbox_open_easy(&key, &nonce, &tampered).is_err());
    }

    #[test]
    fn box_kat() {
        // libsodium crypto_box_seed_keypair keys (seed 00..1f and
        // seed a5 * 32) and crypto_box_easy under nonce 07 * 24.
        let pk1: [u8; 32] =
            hex_array("4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01");
        let sk1: [u8; 32] =
            hex_array("3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f");
        let pk2: [u8; 32] =
            hex_array("38150ac87589d52473c215b4e3aa905065f1630f06e3eab93fa3384e0fdb7844");
        let sk2: [u8; 32] =
            hex_array("774b67b3a64977e9a42e46217f17a6e85402a50a1ec8b75eb53fcdd5d4eb4b54");
        let nonce = [7u8; 24];
        let ciphertext = box_easy(&pk2, &sk1, &nonce, b"wrap the symmetric key 1234").expect("box");
        assert_eq!(
            ciphertext,
            hex_bytes("4b862effea35b1c85882072b93149b639303953535d8b8af5f98664decb284104a5c62d9b797f182389ec2")
        );
        assert_eq!(
            box_open_easy(&pk1, &sk2, &nonce, &ciphertext).expect("open"),
            b"wrap the symmetric key 1234".to_vec()
        );
    }

    #[test]
    fn envelope_encrypt_decrypt_round_trip() {
        let (sender, _sender_pk) = loaded_keystore();
        let (recipient, recipient_pk) = loaded_keystore();
        let plaintext = b"Hello, World! This is a test message.";

        let mut envelope = Envelope::default();
        envelope.signature = vec![9u8; 64];
        encrypt_envelope_payload(plaintext, &[recipient_pk], &mut envelope, &sender)
            .expect("encrypt");
        // Field shapes exactly as the C code populates them.
        assert_eq!(envelope.payload_nonce.len(), NONCE_SIZE);
        assert_eq!(envelope.ephemeral_pubkey.len(), PUBKEY_SIZE);
        assert_eq!(envelope.payload_ciphertext.len(), plaintext.len() + MAC_SIZE);
        assert_eq!(envelope.keywraps.len(), 1);
        assert_eq!(envelope.keywraps[0].recipient_pubkey, recipient_pk.to_vec());
        assert_eq!(envelope.keywraps[0].key_nonce.len(), NONCE_SIZE);
        assert_eq!(envelope.keywraps[0].wrapped_key.len(), ENCRYPTED_KEY_SIZE);
        // Header/signature are not the encryption layer's business.
        assert_eq!(envelope.signature, vec![9u8; 64]);

        assert_eq!(
            decrypt_envelope_payload(&envelope, &recipient).expect("decrypt"),
            plaintext.to_vec()
        );
        // The sender is not a recipient unless listed.
        assert!(matches!(
            decrypt_envelope_payload(&envelope, &sender),
            Err(Error::NotRecipient)
        ));

        // Fresh randomness per call: ephemeral key, nonces, ciphertext.
        let mut again = Envelope::default();
        encrypt_envelope_payload(plaintext, &[recipient_pk], &mut again, &sender)
            .expect("encrypt again");
        assert_ne!(again.ephemeral_pubkey, envelope.ephemeral_pubkey);
        assert_ne!(again.payload_nonce, envelope.payload_nonce);
        assert_ne!(again.payload_ciphertext, envelope.payload_ciphertext);
    }

    #[test]
    fn message_encrypt_decrypt_round_trip() {
        let (sender, _sender_pk) = loaded_keystore();
        let (recipient, recipient_pk) = loaded_keystore();
        let plaintext = b"direct message payload";

        let mut message = Message::default();
        encrypt_message_payload(plaintext, &[recipient_pk], &mut message, &sender)
            .expect("encrypt");
        assert_eq!(message.payload_nonce.len(), NONCE_SIZE);
        assert_eq!(message.ephemeral_pubkey.len(), PUBKEY_SIZE);
        assert_eq!(message.payload_ciphertext.len(), plaintext.len() + MAC_SIZE);
        assert_eq!(message.keywraps.len(), 1);
        assert_eq!(
            message.keywraps[0].recipient_pubkey,
            recipient_pk.to_vec()
        );
        assert_eq!(
            decrypt_message_payload(&message, &recipient).expect("decrypt"),
            plaintext.to_vec()
        );
        assert!(matches!(
            decrypt_message_payload(&message, &sender),
            Err(Error::NotRecipient)
        ));
    }

    #[test]
    fn multi_recipient_second_recipient_decrypts() {
        let (sender, _sender_pk) = loaded_keystore();
        let (first, first_pk) = loaded_keystore();
        let (second, second_pk) = loaded_keystore();
        let (third, third_pk) = loaded_keystore();
        let (outsider, _outsider_pk) = loaded_keystore();
        let plaintext = b"group payload for three recipients";

        let mut envelope = Envelope::default();
        encrypt_envelope_payload(
            plaintext,
            &[first_pk, second_pk, third_pk],
            &mut envelope,
            &sender,
        )
        .expect("encrypt");
        assert_eq!(envelope.keywraps.len(), 3);

        // Every listed recipient — in particular the second — opens it.
        for ks in [&first, &second, &third] {
            assert_eq!(
                decrypt_envelope_payload(&envelope, ks).expect("decrypt"),
                plaintext.to_vec()
            );
        }
        assert!(matches!(
            decrypt_envelope_payload(&envelope, &outsider),
            Err(Error::NotRecipient)
        ));

        // Same for messages.
        let mut message = Message::default();
        encrypt_message_payload(
            plaintext,
            &[first_pk, second_pk, third_pk],
            &mut message,
            &sender,
        )
        .expect("encrypt message");
        assert_eq!(
            decrypt_message_payload(&message, &second).expect("decrypt message"),
            plaintext.to_vec()
        );
    }

    #[test]
    fn limits_and_unloaded_keystore() {
        let (sender, _sender_pk) = loaded_keystore();
        let (recipient, recipient_pk) = loaded_keystore();
        let unloaded = Keystore::new();

        // No keypair loaded (C TW_ERROR_NOT_INITIALIZED), either direction.
        let mut envelope = Envelope::default();
        assert!(matches!(
            encrypt_envelope_payload(b"x", &[recipient_pk], &mut envelope, &unloaded),
            Err(Error::NotInitialized)
        ));
        assert!(matches!(
            decrypt_envelope_payload(&envelope, &unloaded),
            Err(Error::NotInitialized)
        ));

        // Zero recipients, oversized plaintext, too many recipients.
        assert!(matches!(
            encrypt_envelope_payload(b"x", &[], &mut envelope, &sender),
            Err(Error::InvalidArgument(_))
        ));
        let oversized = vec![b'A'; MAX_PLAINTEXT_SIZE + 1];
        assert!(matches!(
            encrypt_envelope_payload(&oversized, &[recipient_pk], &mut envelope, &sender),
            Err(Error::InvalidArgument(_))
        ));
        let too_many = vec![recipient_pk; MAX_RECIPIENTS + 1];
        assert!(matches!(
            encrypt_envelope_payload(b"x", &too_many, &mut envelope, &sender),
            Err(Error::InvalidArgument(_))
        ));
        // Exactly at both limits is accepted.
        let max_plaintext = vec![b'B'; MAX_PLAINTEXT_SIZE];
        let max_recipients = vec![recipient_pk; MAX_RECIPIENTS];
        encrypt_envelope_payload(&max_plaintext, &max_recipients, &mut envelope, &sender)
            .expect("encrypt at limits");
        assert_eq!(
            decrypt_envelope_payload(&envelope, &recipient).expect("decrypt at limits"),
            max_plaintext
        );

        // Empty plaintext round-trips (ciphertext is just the MAC).
        let mut envelope = Envelope::default();
        encrypt_envelope_payload(b"", &[recipient_pk], &mut envelope, &sender)
            .expect("encrypt empty");
        assert_eq!(envelope.payload_ciphertext.len(), MAC_SIZE);
        assert_eq!(
            decrypt_envelope_payload(&envelope, &recipient).expect("decrypt empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn tampered_and_malformed_payloads_fail() {
        let (sender, _sender_pk) = loaded_keystore();
        let (recipient, recipient_pk) = loaded_keystore();
        let mut envelope = Envelope::default();
        encrypt_envelope_payload(b"authenticated payload", &[recipient_pk], &mut envelope, &sender)
            .expect("encrypt");

        let mut tampered = envelope.clone();
        tampered.payload_ciphertext[0] ^= 1;
        assert!(decrypt_envelope_payload(&tampered, &recipient).is_err());

        let mut tampered = envelope.clone();
        tampered.keywraps[0].wrapped_key[0] ^= 1;
        assert!(decrypt_envelope_payload(&tampered, &recipient).is_err());

        // Malformed field lengths error instead of panicking (the C
        // code would read out of bounds on these).
        let mut malformed = envelope.clone();
        malformed.ephemeral_pubkey.truncate(10);
        assert!(decrypt_envelope_payload(&malformed, &recipient).is_err());
        let mut malformed = envelope.clone();
        malformed.keywraps[0].wrapped_key.truncate(10);
        assert!(decrypt_envelope_payload(&malformed, &recipient).is_err());
        let mut malformed = envelope.clone();
        malformed.payload_nonce.clear();
        assert!(decrypt_envelope_payload(&malformed, &recipient).is_err());
        let mut malformed = envelope;
        malformed.payload_ciphertext.truncate(8);
        assert!(decrypt_envelope_payload(&malformed, &recipient).is_err());
    }

    #[test]
    fn global_keystore_round_trip() {
        // The only test using the module-level singleton: it mirrors
        // the C call shape (no explicit keystore handle).
        keystore::keystore_cleanup();
        let sk: [u8; 64] = hex_array(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        );
        keystore::keystore_load_raw_ed25519_keypair(&sk).expect("load global");
        assert!(keystore::keystore_is_keypair_loaded());
        let pk = keystore::keystore_get_public_key().expect("global pk");

        let mut envelope = Envelope::default();
        encrypt_envelope_payload_global(b"global round trip", &[pk], &mut envelope)
            .expect("encrypt global");
        assert_eq!(
            decrypt_envelope_payload_global(&envelope).expect("decrypt global"),
            b"global round trip".to_vec()
        );
        keystore::keystore_cleanup();
        assert!(!keystore::keystore_is_keypair_loaded());
    }
}
