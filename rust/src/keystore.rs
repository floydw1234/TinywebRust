//! Node key storage.
//!
//! Rust counterpart of the C keystore package
//! (`src/packages/keystore/`, `keystore.h`/`keystore.c`): holds the
//! node Ed25519 identity keypair (with the X25519 encryption keypair
//! converted from it), generates keypairs, and saves/loads the
//! private key to/from a passphrase-encrypted file.
//!
//! The C package keeps one global keypair behind a mutex
//! (`sign_public_key`/`sign_secret_key`/`keypair_loaded` in
//! `keystore.c`); the Rust port replaces that global with an owned
//! [`Keystore`], and additionally keeps a module-level singleton
//! ([`GLOBAL_KEYSTORE`] plus the free `keystore_*` functions at the
//! bottom of this module) so other modules can use it the way C
//! code does. Every public function mirrors the C function named in
//! its doc comment, with `Result<T, Error>` in place of `int` error
//! codes and owned arrays in place of out-params.
//!
//! Byte compatibility with the C/libsodium build is the hard
//! requirement, and every primitive here is chosen for it:
//! Ed25519 keypairs are libsodium `crypto_sign` keypairs (64-byte
//! secret = 32-byte seed || 32-byte public key), the
//! Ed25519 -> X25519 conversions are libsodium
//! `crypto_sign_ed25519_pk_to_curve25519` /
//! `crypto_sign_ed25519_sk_to_curve25519`, the passphrase KDF is
//! libsodium `crypto_pwhash` (Argon2id, interactive limits), and
//! the file encryption is libsodium `crypto_secretbox_easy`
//! (XSalsa20-Poly1305). Known-answer tests at the bottom of this
//! module pin each of those against libsodium test vectors.
//!
//! Two locking defects in the C code are deliberately not
//! reproduced: `keystore_load_private_key` returns success without
//! unlocking `g_keystore_mutex`, and `keystore_load_user_key`
//! unlocks a mutex it never locked (and `keystore_cleanup`
//! destroys the mutex, making the keystore unusable afterwards).
//! The Rust port has no equivalent failure mode: [`Keystore`] is a
//! plain value, and cleanup only zeroizes the key material.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use argon2::{Algorithm, Argon2, Params, Version};
use crypto_secretbox::{
    aead::{Aead, KeyInit},
    XSalsa20Poly1305,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Ed25519 public key size (`SIGN_PUBKEY_SIZE`: `crypto_sign_PUBLICKEYBYTES`).
pub const SIGN_PUBKEY_SIZE: usize = 32;
/// Ed25519 secret key size (`SIGN_SECRET_SIZE`: `crypto_sign_SECRETKEYBYTES`).
/// The 64 bytes are the 32-byte seed followed by the 32-byte public key.
pub const SIGN_SECRET_SIZE: usize = 64;
/// X25519 public key size (`PUBKEY_SIZE`: `crypto_box_PUBLICKEYBYTES`).
pub const PUBKEY_SIZE: usize = 32;
/// X25519 secret key size (`SECRET_SIZE`: `crypto_box_SECRETKEYBYTES`).
pub const SECRET_SIZE: usize = 32;
/// Symmetric key size for `crypto_secretbox` (`crypto_secretbox_KEYBYTES`).
pub const SECRETBOX_KEY_SIZE: usize = 32;
/// Nonce size for `crypto_secretbox`/`crypto_box` (24 bytes; the C
/// keystore sizes its file nonce with `crypto_box_NONCEBYTES`, which
/// is the same 24).
pub const SECRETBOX_NONCE_SIZE: usize = 24;
/// Poly1305 MAC size (`crypto_secretbox_MACBYTES`).
pub const SECRETBOX_MAC_SIZE: usize = 16;
/// `crypto_pwhash_SALTBYTES`.
pub const PWHASH_SALT_SIZE: usize = 16;
/// `crypto_pwhash_OPSLIMIT_INTERACTIVE`.
pub const PWHASH_OPSLIMIT_INTERACTIVE: u32 = 2;
/// `crypto_pwhash_MEMLIMIT_INTERACTIVE` (64 MiB, in bytes as libsodium
/// expresses it; the `argon2` crate takes the same quantity in KiB).
pub const PWHASH_MEMLIMIT_INTERACTIVE: usize = 67_108_864;
/// Total size of a key file written by `keystore_save_private_key`:
/// 16-byte salt || 24-byte nonce || 80-byte secretbox ciphertext
/// (64-byte secret key + 16-byte MAC).
pub const KEY_FILE_SIZE: usize =
    PWHASH_SALT_SIZE + SECRETBOX_NONCE_SIZE + SIGN_SECRET_SIZE + SECRETBOX_MAC_SIZE;

/// Error type for all keystore operations.
#[derive(Debug)]
pub enum Error {
    /// No keypair is loaded (C returns `-1` with
    /// `TW_ERROR_INVALID_STATE` in this case).
    NotLoaded,
    /// Caller supplied an invalid argument (C `TW_ERROR_INVALID_ARGUMENT`
    /// / `TW_ERROR_NULL_POINTER`).
    InvalidArgument(String),
    /// Underlying filesystem failure (C `TW_ERROR_IO_ERROR`).
    Io(std::io::Error),
    /// Cryptographic failure (C `TW_ERROR_CRYPTO_ERROR`): key
    /// derivation failed, or the file could not be decrypted (wrong
    /// passphrase or corrupted file), or a key conversion failed.
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotLoaded => write!(f, "no keypair loaded"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Keystore result alias.
pub type Result<T> = std::result::Result<T, Error>;

fn invalid(msg: &str) -> Error {
    Error::InvalidArgument(msg.to_string())
}

fn crypto(msg: &str) -> Error {
    Error::Crypto(msg.to_string())
}

/// Fill `buf` with cryptographically secure random bytes
/// (libsodium `randombytes_buf`).
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| crypto(&format!("randombytes_buf failed: {e}")))
}

// ---------------------------------------------------------------------------
// Ed25519 -> Curve25519 conversion (libsodium
// `crypto_sign_ed25519_pk_to_curve25519` /
// `crypto_sign_ed25519_sk_to_curve25519`)
// ---------------------------------------------------------------------------

/// Convert an Ed25519 public key to an X25519 public key, exactly
/// libsodium `crypto_sign_ed25519_pk_to_curve25519`: the Edwards
/// point `(x, y)` maps to the Montgomery `u = (1 + y) / (1 - y)`.
///
/// Returns [`Error::Crypto`] for bytes that are not a valid Edwards
/// point encoding (libsodium returns `-1`), including the identity
/// encoding `y = 1`, where `1 - y` has no inverse.
pub fn ed25519_pk_to_curve25519(
    ed25519_pubkey: &[u8; SIGN_PUBKEY_SIZE],
) -> Result<[u8; PUBKEY_SIZE]> {
    let point = CompressedEdwardsY(*ed25519_pubkey)
        .decompress()
        .ok_or_else(|| crypto("invalid Ed25519 public key encoding"))?;
    // libsodium rejects small-order points (the identity, y = 1, has
    // no Montgomery image at all, since 1 - y is not invertible).
    if point.is_small_order() {
        return Err(crypto("Ed25519 public key has small order"));
    }
    Ok(point.to_montgomery().to_bytes())
}

/// Convert an Ed25519 secret key to an X25519 secret key, exactly
/// libsodium `crypto_sign_ed25519_sk_to_curve25519`: SHA-512 of the
/// first 32 bytes (the seed) of the 64-byte secret, first 32 bytes
/// of the digest, clamped (`h[0] &= 248; h[31] &= 127; h[31] |= 64`).
///
/// This operation cannot fail for a well-formed 64-byte secret, as
/// in libsodium.
pub fn ed25519_sk_to_curve25519(ed25519_secret: &[u8; SIGN_SECRET_SIZE]) -> [u8; SECRET_SIZE] {
    let digest = Sha512::digest(&ed25519_secret[..32]);
    let mut out = [0u8; SECRET_SIZE];
    out.copy_from_slice(&digest[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// The Ed25519 public key embedded in a 64-byte secret key
/// (libsodium `crypto_sign_ed25519_sk_to_pk`, which copies bytes
/// 32..64 of the secret).
fn ed25519_sk_to_pk(ed25519_secret: &[u8; SIGN_SECRET_SIZE]) -> [u8; SIGN_PUBKEY_SIZE] {
    let mut pk = [0u8; SIGN_PUBKEY_SIZE];
    pk.copy_from_slice(&ed25519_secret[32..]);
    pk
}

// ---------------------------------------------------------------------------
// libsodium-compatible primitives shared with the encryption module
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `passphrase` and `salt`, exactly
/// libsodium `crypto_pwhash` with `crypto_pwhash_ALG_DEFAULT`
/// (Argon2id v1.3), `OPSLIMIT_INTERACTIVE` (2) and
/// `MEMLIMIT_INTERACTIVE` (64 MiB, i.e. 65536 KiB in `argon2` units),
/// one lane — the parameter set the C keystore derives file keys with.
pub(crate) fn crypto_pwhash_interactive(
    passphrase: &[u8],
    salt: &[u8; PWHASH_SALT_SIZE],
) -> Result<[u8; SECRETBOX_KEY_SIZE]> {
    let params = Params::new(
        (PWHASH_MEMLIMIT_INTERACTIVE / 1024) as u32,
        PWHASH_OPSLIMIT_INTERACTIVE,
        1,
        Some(SECRETBOX_KEY_SIZE),
    )
    .map_err(|e| crypto(&format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; SECRETBOX_KEY_SIZE];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| crypto(&format!("crypto_pwhash failed: {e}")))?;
    Ok(out)
}

/// Encrypt with libsodium `crypto_secretbox_easy` (XSalsa20-Poly1305):
/// the output is the 16-byte Poly1305 MAC followed by the ciphertext,
/// `plaintext.len() + 16` bytes in total. Byte-identical to libsodium;
/// pinned by a known-answer test in the encryption module.
pub(crate) fn secretbox_easy(
    key: &[u8; SECRETBOX_KEY_SIZE],
    nonce: &[u8; SECRETBOX_NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(key));
    cipher
        .encrypt(crypto_secretbox::Nonce::from_slice(nonce), plaintext)
        .map_err(|_| crypto("crypto_secretbox_easy failed"))
}

/// Decrypt with libsodium `crypto_secretbox_open_easy`; `ciphertext`
/// is the MAC-prefixed output of [`secretbox_easy`]. A wrong key or
/// tampered ciphertext yields [`Error::Crypto`], as libsodium's `-1`.
pub(crate) fn secretbox_open_easy(
    key: &[u8; SECRETBOX_KEY_SIZE],
    nonce: &[u8; SECRETBOX_NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(key));
    cipher
        .decrypt(crypto_secretbox::Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| crypto("crypto_secretbox_open_easy failed"))
}

// ---------------------------------------------------------------------------
// Keystore (C: the global keypair in `keystore.c`)
// ---------------------------------------------------------------------------

/// The node keypair: the Rust replacement for the C keystore's
/// global `sign_public_key`/`sign_secret_key`/`keypair_loaded`.
///
/// Key material is zeroized on [`Keystore::cleanup`] and on drop
/// (the C code zeroizes only in `keystore_cleanup`).
#[derive(Clone)]
pub struct Keystore {
    sign_public_key: [u8; SIGN_PUBKEY_SIZE],
    sign_secret_key: [u8; SIGN_SECRET_SIZE],
    keypair_loaded: bool,
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.sign_secret_key.zeroize();
        self.sign_public_key.zeroize();
    }
}

impl fmt::Debug for Keystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("Keystore")
            .field("keypair_loaded", &self.keypair_loaded)
            .finish_non_exhaustive()
    }
}

impl Keystore {
    /// A keystore with no keypair loaded.
    pub fn new() -> Self {
        Keystore {
            sign_public_key: [0u8; SIGN_PUBKEY_SIZE],
            sign_secret_key: [0u8; SIGN_SECRET_SIZE],
            keypair_loaded: false,
        }
    }

    /// Generate a new Ed25519 keypair (C `keystore_generate_keypair`,
    /// i.e. libsodium `crypto_sign_keypair`), replacing any loaded one.
    pub fn generate_keypair(&mut self) -> Result<()> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        self.sign_secret_key = signing_key.to_keypair_bytes();
        self.sign_public_key = signing_key.verifying_key().to_bytes();
        self.keypair_loaded = true;
        Ok(())
    }

    /// Save the Ed25519 private key to `filename`, encrypted with
    /// `passphrase` (C `keystore_save_private_key`).
    ///
    /// File format, byte-identical to the C build so key files are
    /// interchangeable: 16-byte random salt || 24-byte random nonce
    /// || `crypto_secretbox_easy` ciphertext of the 64-byte secret
    /// key under a key derived with `crypto_pwhash` (Argon2id,
    /// interactive limits) — 120 bytes in total.
    pub fn save_private_key(&self, filename: impl AsRef<Path>, passphrase: &str) -> Result<()> {
        if !self.keypair_loaded {
            return Err(Error::NotLoaded);
        }
        let mut salt = [0u8; PWHASH_SALT_SIZE];
        let mut nonce = [0u8; SECRETBOX_NONCE_SIZE];
        fill_random(&mut salt)?;
        fill_random(&mut nonce)?;
        let mut key = crypto_pwhash_interactive(passphrase.as_bytes(), &salt)?;
        let ciphertext = secretbox_easy(&key, &nonce, &self.sign_secret_key);
        key.zeroize();
        let ciphertext = ciphertext?;

        let mut file_bytes = Vec::with_capacity(KEY_FILE_SIZE);
        file_bytes.extend_from_slice(&salt);
        file_bytes.extend_from_slice(&nonce);
        file_bytes.extend_from_slice(&ciphertext);
        debug_assert_eq!(file_bytes.len(), KEY_FILE_SIZE);
        std::fs::write(filename.as_ref(), &file_bytes)?;
        Ok(())
    }

    /// Load an Ed25519 private key from `filename`, decrypting it
    /// with `passphrase` (C `keystore_load_private_key`); see
    /// [`Keystore::save_private_key`] for the file format.
    ///
    /// Like the C code, only the first 120 bytes of the file are
    /// read; trailing bytes are ignored. On failure the previously
    /// loaded keypair (if any) is left in place — the C code
    /// decrypts directly into its global buffer, the port decrypts
    /// into a temporary and only commits on success.
    pub fn load_private_key(&mut self, filename: impl AsRef<Path>, passphrase: &str) -> Result<()> {
        let file_bytes = std::fs::read(filename.as_ref())?;
        if file_bytes.len() < KEY_FILE_SIZE {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "key file too short",
            )));
        }
        let mut salt = [0u8; PWHASH_SALT_SIZE];
        salt.copy_from_slice(&file_bytes[..PWHASH_SALT_SIZE]);
        let mut nonce = [0u8; SECRETBOX_NONCE_SIZE];
        nonce.copy_from_slice(
            &file_bytes[PWHASH_SALT_SIZE..PWHASH_SALT_SIZE + SECRETBOX_NONCE_SIZE],
        );
        let ciphertext = &file_bytes[PWHASH_SALT_SIZE + SECRETBOX_NONCE_SIZE..KEY_FILE_SIZE];

        let mut key = crypto_pwhash_interactive(passphrase.as_bytes(), &salt)?;
        let plaintext = secretbox_open_easy(&key, &nonce, ciphertext);
        key.zeroize();
        let plaintext = plaintext.map_err(|_| {
            crypto("failed to decrypt private key (wrong passphrase or corrupted file)")
        })?;

        let mut secret = [0u8; SIGN_SECRET_SIZE];
        secret.copy_from_slice(&plaintext);
        self.sign_public_key = ed25519_sk_to_pk(&secret);
        self.sign_secret_key = secret;
        self.keypair_loaded = true;
        Ok(())
    }

    /// Load a raw 64-byte Ed25519 secret key (C
    /// `keystore_load_raw_ed25519_keypair`); the public key is the
    /// upper 32 bytes of the secret, as with libsodium
    /// `crypto_sign_ed25519_sk_to_pk`.
    pub fn load_raw_ed25519_keypair(&mut self, private_key: &[u8; SIGN_SECRET_SIZE]) -> Result<()> {
        self.sign_secret_key = *private_key;
        self.sign_public_key = ed25519_sk_to_pk(private_key);
        self.keypair_loaded = true;
        Ok(())
    }

    /// Load a raw 64-byte Ed25519 secret key from
    /// `{base_keys_path}/users/{user_id}/key.bin` (C
    /// `keystore_load_user_key`). Unlike the passphrase-protected
    /// format of [`Keystore::load_private_key`], that file holds the
    /// bare 64-byte secret.
    pub fn load_user_key(&mut self, base_keys_path: impl AsRef<Path>, user_id: &str) -> Result<()> {
        if user_id.is_empty() {
            return Err(invalid("user_id is empty"));
        }
        let key_path: PathBuf = base_keys_path
            .as_ref()
            .join("users")
            .join(user_id)
            .join("key.bin");
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() < SIGN_SECRET_SIZE {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "user key file too short",
            )));
        }
        let mut secret = [0u8; SIGN_SECRET_SIZE];
        secret.copy_from_slice(&bytes[..SIGN_SECRET_SIZE]);
        self.load_raw_ed25519_keypair(&secret)
    }

    /// The Ed25519 public key (C `keystore_get_public_key`).
    pub fn get_public_key(&self) -> Result<[u8; SIGN_PUBKEY_SIZE]> {
        if !self.keypair_loaded {
            return Err(Error::NotLoaded);
        }
        Ok(self.sign_public_key)
    }

    /// The X25519 public key converted from the Ed25519 public key
    /// (C `keystore_get_encryption_public_key`).
    ///
    /// Note the C name is a misnomer in one caller: the encryption
    /// package compares `RecipientKeyWrap.recipient_pubkey` (an
    /// Ed25519 key) against this converted key. See the decryption
    /// note in the encryption module.
    pub fn get_encryption_public_key(&self) -> Result<[u8; PUBKEY_SIZE]> {
        if !self.keypair_loaded {
            return Err(Error::NotLoaded);
        }
        ed25519_pk_to_curve25519(&self.sign_public_key)
    }

    /// The raw 64-byte Ed25519 secret key (C `_keystore_get_private_key`;
    /// internal use by the signing/encryption modules).
    pub fn get_private_key(&self) -> Result<[u8; SIGN_SECRET_SIZE]> {
        if !self.keypair_loaded {
            return Err(Error::NotLoaded);
        }
        Ok(self.sign_secret_key)
    }

    /// The X25519 secret key converted from the Ed25519 secret key
    /// (C `_keystore_get_encryption_private_key`).
    pub fn get_encryption_private_key(&self) -> Result<[u8; SECRET_SIZE]> {
        if !self.keypair_loaded {
            return Err(Error::NotLoaded);
        }
        Ok(ed25519_sk_to_curve25519(&self.sign_secret_key))
    }

    /// Whether a keypair is loaded (C `keystore_is_keypair_loaded`).
    pub fn is_keypair_loaded(&self) -> bool {
        self.keypair_loaded
    }

    /// Zeroize the key material and mark the keypair unloaded
    /// (C `keystore_cleanup`, minus its mutex destruction: the
    /// keystore remains usable afterwards).
    pub fn cleanup(&mut self) {
        self.sign_secret_key.zeroize();
        self.sign_public_key.zeroize();
        self.keypair_loaded = false;
    }
}

// ---------------------------------------------------------------------------
// Module-level singleton (the C global keystore)
// ---------------------------------------------------------------------------

/// The module-level keystore singleton, replacing the C globals in
/// `keystore.c`. Prefer an owned [`Keystore`] in new code; this
/// exists so call sites shaped like the C code (which has no
/// keystore handle) keep working.
pub static GLOBAL_KEYSTORE: OnceLock<Mutex<Keystore>> = OnceLock::new();

fn global_keystore() -> &'static Mutex<Keystore> {
    GLOBAL_KEYSTORE.get_or_init(|| Mutex::new(Keystore::new()))
}

/// Lock the module-level keystore (see [`GLOBAL_KEYSTORE`]).
pub fn global_keystore_lock() -> MutexGuard<'static, Keystore> {
    global_keystore()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initialize the keystore (C `keystore_init`, which calls
/// `sodium_init`). The pure-Rust primitives need no global
/// initialization, so this succeeds unconditionally; it exists for
/// call-site parity with the C code.
pub fn keystore_init() -> Result<()> {
    let _ = global_keystore();
    Ok(())
}

/// C `keystore_generate_keypair`, on the module-level keystore.
pub fn keystore_generate_keypair() -> Result<()> {
    global_keystore_lock().generate_keypair()
}

/// C `keystore_save_private_key`, on the module-level keystore.
pub fn keystore_save_private_key(filename: impl AsRef<Path>, passphrase: &str) -> Result<()> {
    global_keystore_lock().save_private_key(filename, passphrase)
}

/// C `keystore_load_private_key`, on the module-level keystore.
pub fn keystore_load_private_key(filename: impl AsRef<Path>, passphrase: &str) -> Result<()> {
    global_keystore_lock().load_private_key(filename, passphrase)
}

/// C `keystore_load_raw_ed25519_keypair`, on the module-level keystore.
pub fn keystore_load_raw_ed25519_keypair(private_key: &[u8; SIGN_SECRET_SIZE]) -> Result<()> {
    global_keystore_lock().load_raw_ed25519_keypair(private_key)
}

/// C `keystore_load_user_key`, on the module-level keystore.
pub fn keystore_load_user_key(base_keys_path: impl AsRef<Path>, user_id: &str) -> Result<()> {
    global_keystore_lock().load_user_key(base_keys_path, user_id)
}

/// C `keystore_get_public_key`, on the module-level keystore.
pub fn keystore_get_public_key() -> Result<[u8; SIGN_PUBKEY_SIZE]> {
    global_keystore_lock().get_public_key()
}

/// C `keystore_get_encryption_public_key`, on the module-level keystore.
pub fn keystore_get_encryption_public_key() -> Result<[u8; PUBKEY_SIZE]> {
    global_keystore_lock().get_encryption_public_key()
}

/// C `_keystore_get_private_key`, on the module-level keystore.
pub fn keystore_get_private_key() -> Result<[u8; SIGN_SECRET_SIZE]> {
    global_keystore_lock().get_private_key()
}

/// C `_keystore_get_encryption_private_key`, on the module-level keystore.
pub fn keystore_get_encryption_private_key() -> Result<[u8; SECRET_SIZE]> {
    global_keystore_lock().get_encryption_private_key()
}

/// C `keystore_is_keypair_loaded`, on the module-level keystore.
pub fn keystore_is_keypair_loaded() -> bool {
    global_keystore_lock().is_keypair_loaded()
}

/// C `keystore_cleanup`, on the module-level keystore.
pub fn keystore_cleanup() {
    global_keystore_lock().cleanup()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::MontgomeryPoint;

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

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tinyweb-keystore-test-{}-{tag}.bin",
            std::process::id()
        ))
    }

    /// libsodium `crypto_sign_seed_keypair` with seed `00 01 .. 1f`.
    const SIGN1_PK: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const SIGN1_SK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    /// libsodium `crypto_sign_seed_keypair` with seed `42` repeated.
    const SIGN2_PK: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
    const SIGN2_SK: &str = "42424242424242424242424242424242424242424242424242424242424242422152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

    #[test]
    fn ed25519_to_curve25519_conversion_kats() {
        // libsodium crypto_sign_ed25519_pk_to_curve25519 /
        // crypto_sign_ed25519_sk_to_curve25519 outputs.
        let pk1: [u8; 32] = hex_array(SIGN1_PK);
        let sk1: [u8; 64] = hex_array(SIGN1_SK);
        assert_eq!(
            ed25519_pk_to_curve25519(&pk1).expect("pk conversion"),
            hex_array::<32>("4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01")
        );
        assert_eq!(
            ed25519_sk_to_curve25519(&sk1),
            hex_array::<32>("3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f")
        );

        let pk2: [u8; 32] = hex_array(SIGN2_PK);
        let sk2: [u8; 64] = hex_array(SIGN2_SK);
        assert_eq!(
            ed25519_pk_to_curve25519(&pk2).expect("pk conversion"),
            hex_array::<32>("cc4f2cdb695dd766f34118eb67b98652fed1d8bc49c330b119bbfa8a64989378")
        );
        assert_eq!(
            ed25519_sk_to_curve25519(&sk2),
            hex_array::<32>("90e7595fc89e52fdfddce9c6a43d74dbf6047025ee0462d2d172e8b6a2841d6e")
        );

        // The converted pair must agree as an X25519 keypair.
        for (pk, sk) in [(pk1, sk1), (pk2, sk2)] {
            let curve_pk = ed25519_pk_to_curve25519(&pk).expect("pk conversion");
            let curve_sk = ed25519_sk_to_curve25519(&sk);
            assert_eq!(
                MontgomeryPoint::mul_base_clamped(curve_sk).to_bytes(),
                curve_pk
            );
        }

        // The identity encoding has no Montgomery image.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(ed25519_pk_to_curve25519(&identity).is_err());
    }

    #[test]
    fn crypto_pwhash_interactive_kat() {
        // libsodium crypto_pwhash(32, pw, salt, OPSLIMIT_INTERACTIVE,
        // MEMLIMIT_INTERACTIVE, ALG_ARGON2ID13) outputs.
        let salt: [u8; 16] = hex_array("000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            crypto_pwhash_interactive(b"correct horse battery staple", &salt)
                .expect("pwhash"),
            hex_array::<32>("c05ce4c4dd7e0e45ee6011cc59d068ade47df1b01fc0cf9cd4678bdf68a5b7b0")
        );
        assert_eq!(
            crypto_pwhash_interactive(b"hunter2", &[0xFFu8; 16]).expect("pwhash"),
            hex_array::<32>("adb24cc7f10145d7148b022f5bfdbc27cb413c35c3f3cbb549f74ad0042e545f")
        );
    }

    #[test]
    fn generate_accessors_and_cleanup() {
        let mut ks = Keystore::new();
        assert!(!ks.is_keypair_loaded());
        assert!(matches!(ks.get_public_key(), Err(Error::NotLoaded)));
        assert!(matches!(
            ks.get_encryption_private_key(),
            Err(Error::NotLoaded)
        ));

        ks.generate_keypair().expect("generate");
        assert!(ks.is_keypair_loaded());
        let pk = ks.get_public_key().expect("public key");
        let secret = ks.get_private_key().expect("private key");
        // libsodium secret layout: seed || public key.
        assert_eq!(&secret[32..], &pk[..]);
        assert_eq!(
            ks.get_encryption_public_key().expect("encryption pk"),
            ed25519_pk_to_curve25519(&pk).expect("conversion")
        );
        let enc_sk = ks.get_encryption_private_key().expect("encryption sk");
        assert_eq!(enc_sk, ed25519_sk_to_curve25519(&secret));
        assert_eq!(
            MontgomeryPoint::mul_base_clamped(enc_sk).to_bytes(),
            ks.get_encryption_public_key().expect("encryption pk")
        );

        // A second generation replaces the keypair.
        ks.generate_keypair().expect("regenerate");
        assert!(ks.is_keypair_loaded());

        ks.cleanup();
        assert!(!ks.is_keypair_loaded());
        assert!(matches!(ks.get_public_key(), Err(Error::NotLoaded)));
        // Cleanup leaves the keystore reusable (unlike the C mutex).
        ks.generate_keypair().expect("generate after cleanup");
        assert!(ks.is_keypair_loaded());
    }

    #[test]
    fn load_raw_ed25519_keypair_kat() {
        let mut ks = Keystore::new();
        let sk: [u8; 64] = hex_array(SIGN2_SK);
        ks.load_raw_ed25519_keypair(&sk).expect("load raw");
        assert!(ks.is_keypair_loaded());
        assert_eq!(ks.get_public_key().expect("pk"), hex_array::<32>(SIGN2_PK));
        assert_eq!(ks.get_private_key().expect("sk"), sk);
        assert_eq!(
            ks.get_encryption_public_key().expect("enc pk"),
            hex_array::<32>("cc4f2cdb695dd766f34118eb67b98652fed1d8bc49c330b119bbfa8a64989378")
        );
        assert_eq!(
            ks.get_encryption_private_key().expect("enc sk"),
            hex_array::<32>("90e7595fc89e52fdfddce9c6a43d74dbf6047025ee0462d2d172e8b6a2841d6e")
        );
    }

    #[test]
    fn save_load_round_trip_and_wrong_passphrase() {
        let path = temp_path("roundtrip");
        let mut ks = Keystore::new();
        // Saving with nothing loaded fails, as in C.
        assert!(matches!(
            ks.save_private_key(&path, "pw"),
            Err(Error::NotLoaded)
        ));
        ks.generate_keypair().expect("generate");
        let pk = ks.get_public_key().expect("pk");
        let secret = ks.get_private_key().expect("sk");
        ks.save_private_key(&path, "s3cret passphrase")
            .expect("save");

        let file_bytes = std::fs::read(&path).expect("read key file");
        assert_eq!(file_bytes.len(), KEY_FILE_SIZE);
        assert_eq!(KEY_FILE_SIZE, 120);
        // The layout is salt || nonce || ciphertext: decrypting the
        // tail with the interactive-KDF key (both primitives are
        // KAT-anchored) must recover the secret, which pins the
        // offsets a C reader would use.
        let mut salt = [0u8; PWHASH_SALT_SIZE];
        salt.copy_from_slice(&file_bytes[..16]);
        let mut nonce = [0u8; SECRETBOX_NONCE_SIZE];
        nonce.copy_from_slice(&file_bytes[16..40]);
        let key = crypto_pwhash_interactive(b"s3cret passphrase", &salt).expect("kdf");
        let opened = secretbox_open_easy(&key, &nonce, &file_bytes[40..]).expect("open");
        assert_eq!(opened, secret.to_vec());

        let mut loaded = Keystore::new();
        // Wrong passphrase fails and loads nothing.
        assert!(loaded
            .load_private_key(&path, "wrong passphrase")
            .is_err());
        assert!(!loaded.is_keypair_loaded());
        loaded
            .load_private_key(&path, "s3cret passphrase")
            .expect("load");
        assert_eq!(loaded.get_public_key().expect("pk"), pk);
        assert_eq!(loaded.get_private_key().expect("sk"), secret);

        // A failed load keeps the previously loaded keypair.
        assert!(loaded.load_private_key(&path, "wrong again").is_err());
        assert_eq!(loaded.get_public_key().expect("pk"), pk);

        // Missing and short files fail.
        assert!(Keystore::new()
            .load_private_key(temp_path("does-not-exist"), "pw")
            .is_err());
        let short_path = temp_path("short");
        std::fs::write(&short_path, [0u8; 42]).expect("write short");
        assert!(Keystore::new().load_private_key(&short_path, "pw").is_err());
        let _ = std::fs::remove_file(&short_path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn c_format_key_file_fixture_loads() {
        // A 120-byte key file produced byte-for-byte by libsodium
        // (salt 00..0f, nonce 00..17, crypto_pwhash interactive
        // Argon2id key for "fixture-passphrase", crypto_secretbox_easy
        // of the SIGN1 secret key above).
        let fixture = hex_bytes(
            "000102030405060708090a0b0c0d0e0f\
             000102030405060708090a0b0c0d0e0f1011121314151617\
             2cf0808253d0943d2dc76dd426231a56216dbff37e20be4936f3a3d5203520bc\
             2b2ac1deb4187d9d4b8560ea513d29cb9351b030953b86e1551a1588c21cd85e\
             556d768177f6bd790e93b0072efc04a4",
        );
        assert_eq!(fixture.len(), KEY_FILE_SIZE);
        let path = temp_path("c-fixture");
        std::fs::write(&path, &fixture).expect("write fixture");

        let mut ks = Keystore::new();
        ks.load_private_key(&path, "fixture-passphrase")
            .expect("load C fixture");
        assert_eq!(ks.get_public_key().expect("pk"), hex_array::<32>(SIGN1_PK));
        assert_eq!(ks.get_private_key().expect("sk"), hex_array::<64>(SIGN1_SK));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_user_key_reads_raw_secret_file() {
        let base = std::env::temp_dir().join(format!(
            "tinyweb-keystore-test-{}-userkey",
            std::process::id()
        ));
        let dir = base.join("users").join("alice");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("key.bin"), hex_array::<64>(SIGN2_SK)).expect("write");

        let mut ks = Keystore::new();
        ks.load_user_key(&base, "alice").expect("load user key");
        assert_eq!(ks.get_public_key().expect("pk"), hex_array::<32>(SIGN2_PK));
        assert!(Keystore::new().load_user_key(&base, "mallory").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
