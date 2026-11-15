import sodium from 'libsodium-wrappers'

/**
 * Browser keystore — ported from the C web-ui (client/web-ui/src/utils/keystore.js).
 * Manages the Ed25519 identity keypair used for request signing and derives
 * the X25519 keys used for payload encryption, exactly like the node does.
 *
 * Storage format is identical to the C web-ui: localStorage key
 * `tinyweb_keypair` holding { salt, nonce, ciphertext, publicKey } (hex),
 * where ciphertext is the secret key sealed with a key derived from the
 * passphrase (BLAKE2b generichash of salt || passphrase). The test UI uses
 * an empty passphrase so the identity auto-loads, same as the C web-ui.
 */

const STORAGE_KEY = 'tinyweb_keypair'

// Salt length for the sealed-key blob: 16 bytes, the value of libsodium's
// crypto_pwhash_SALTBYTES. The standard libsodium-wrappers build does not
// export the crypto_pwhash constants (they exist only in the -sumo build),
// and the seal below never calls crypto_pwhash itself — it derives the
// secretbox key with BLAKE2b generichash over salt || passphrase — so the
// length is spelled out here. Referencing sodium.crypto_pwhash_SALTBYTES
// yielded undefined and made randombytes_buf throw, which silently broke
// identity generation. The stored format is unchanged.
const SALT_BYTES = 16

export class KeyStore {
  private storageKey: string
  private initialized = false
  private loadError: string | null = null
  private signPublicKey: Uint8Array | null = null
  private signSecretKey: Uint8Array | null = null

  /**
   * Each instance seals its keypair under its own localStorage key.
   * The default singleton uses the legacy `tinyweb_keypair` key;
   * enrollment keeps its member/device keys under their own keys
   * (see utils/enrollment.ts) so joining never disturbs the active
   * identity until the member is actually enrolled.
   */
  constructor(storageKey: string = STORAGE_KEY) {
    this.storageKey = storageKey
  }

  async init(): Promise<boolean> {
    if (this.initialized) {
      if (!this.isKeypairLoaded()) await this.tryAutoLoad()
      return true
    }
    await sodium.ready
    this.initialized = true
    await this.tryAutoLoad()
    return true
  }

  private async tryAutoLoad(): Promise<void> {
    try {
      if (localStorage.getItem(this.storageKey) && !this.isKeypairLoaded()) {
        await this.loadKeypair('')
      }
    } catch (e) {
      // Keys may be sealed with a non-empty passphrase; leave unloaded, but
      // never fail silently — record it so the UI can show what happened.
      this.loadError = e instanceof Error ? e.message : String(e)
      console.error('KeyStore: failed to auto-load stored keypair:', e)
    }
  }

  /** The last auto-load failure, if any, so the UI can surface it. */
  getLoadError(): string | null {
    return this.loadError
  }

  async generateKeypair(): Promise<void> {
    if (!this.initialized) await this.init()
    const kp = sodium.crypto_sign_keypair()
    this.signPublicKey = kp.publicKey
    this.signSecretKey = kp.privateKey
  }

  async saveKeypair(passphrase: string): Promise<void> {
    if (!this.signSecretKey || !this.signPublicKey) throw new Error('No keypair loaded')
    await sodium.ready
    const actualPassphrase = passphrase || ''

    const salt = sodium.randombytes_buf(SALT_BYTES)
    const keyMaterial = new Uint8Array(salt.length + actualPassphrase.length)
    keyMaterial.set(salt, 0)
    keyMaterial.set(new TextEncoder().encode(actualPassphrase), salt.length)
    const key = sodium.crypto_generichash(sodium.crypto_secretbox_KEYBYTES, keyMaterial, null)

    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const ciphertext = sodium.crypto_secretbox_easy(this.signSecretKey, nonce, key)

    const keyData = {
      salt: sodium.to_hex(salt),
      nonce: sodium.to_hex(nonce),
      ciphertext: sodium.to_hex(ciphertext),
      publicKey: sodium.to_hex(this.signPublicKey),
    }
    localStorage.setItem(this.storageKey, JSON.stringify(keyData))
  }

  async loadKeypair(passphrase: string): Promise<void> {
    const stored = localStorage.getItem(this.storageKey)
    if (!stored) throw new Error('No keypair found in storage')
    const keyData = JSON.parse(stored)

    const salt = sodium.from_hex(keyData.salt)
    const nonce = sodium.from_hex(keyData.nonce)
    const ciphertext = sodium.from_hex(keyData.ciphertext)
    const actualPassphrase = passphrase || ''

    const keyMaterial = new Uint8Array(salt.length + actualPassphrase.length)
    keyMaterial.set(salt, 0)
    keyMaterial.set(new TextEncoder().encode(actualPassphrase), salt.length)
    const key = sodium.crypto_generichash(sodium.crypto_secretbox_KEYBYTES, keyMaterial, null)

    try {
      this.signSecretKey = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key)
    } catch {
      throw new Error('Failed to decrypt keypair - wrong passphrase?')
    }
    if (keyData.publicKey) {
      this.signPublicKey = sodium.from_hex(keyData.publicKey)
    } else if (this.signSecretKey.length === 64) {
      this.signPublicKey = this.signSecretKey.slice(32, 64)
    }
    this.loadError = null
  }

  /**
   * Import a raw Ed25519 key. Accepts either a 64-byte secret key (hex,
   * as produced by libsodium crypto_sign_keypair) or a 32-byte seed (hex).
   */
  async importKey(secretHex: string): Promise<void> {
    if (!this.initialized) await this.init()
    const bytes = sodium.from_hex(secretHex.trim())
    if (bytes.length === 64) {
      this.signSecretKey = bytes
      this.signPublicKey = bytes.slice(32, 64)
    } else if (bytes.length === 32) {
      const kp = sodium.crypto_sign_seed_keypair(bytes)
      this.signPublicKey = kp.publicKey
      this.signSecretKey = kp.privateKey
    } else {
      throw new Error(`Expected 64-byte secret key or 32-byte seed, got ${bytes.length} bytes`)
    }
  }

  getPublicKey(): Uint8Array {
    if (!this.signPublicKey) throw new Error('No keypair loaded')
    return this.signPublicKey
  }

  getPublicKeyHex(): string {
    return sodium.to_hex(this.getPublicKey())
  }

  /** X25519 public key converted from the Ed25519 identity key. */
  getEncryptionPublicKey(): Uint8Array {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(this.getPublicKey())
  }

  _getPrivateKey(): Uint8Array {
    if (!this.signSecretKey) throw new Error('No keypair loaded')
    return this.signSecretKey
  }

  /** X25519 private key converted from the Ed25519 secret key. */
  _getEncryptionPrivateKey(): Uint8Array {
    if (!this.signSecretKey) throw new Error('No keypair loaded')
    return sodium.crypto_sign_ed25519_sk_to_curve25519(this.signSecretKey)
  }

  isKeypairLoaded(): boolean {
    return this.signPublicKey !== null && this.signSecretKey !== null
  }

  hasStoredKeypair(): boolean {
    return localStorage.getItem(this.storageKey) !== null
  }

  deleteStoredKeypair(): void {
    localStorage.removeItem(this.storageKey)
    this.loadError = null
  }

  cleanup(): void {
    if (this.signPublicKey) sodium.memzero(this.signPublicKey)
    if (this.signSecretKey) sodium.memzero(this.signSecretKey)
    this.signPublicKey = null
    this.signSecretKey = null
  }
}

const keyStore = new KeyStore()
export default keyStore
