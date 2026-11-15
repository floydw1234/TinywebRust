import sodium from 'libsodium-wrappers'
import keyStore from './keystore'

/**
 * Payload encryption — ported from the C web-ui
 * (client/web-ui/src/utils/encryption.js), mirroring the node backend
 * (src/packages/encryption/encryption.c).
 *
 * Hybrid scheme: a random symmetric key encrypts the payload with
 * crypto_secretbox (XSalsa20-Poly1305); the symmetric key is wrapped for
 * each recipient with crypto_box (X25519 + XSalsa20-Poly1305) under an
 * ephemeral keypair, so each recipient can unwrap with their X25519
 * private key (converted from their Ed25519 identity key).
 */

export const MAX_PLAINTEXT_SIZE = 2048
export const MAX_RECIPIENTS = 50
export const ENCRYPTED_KEY_SIZE = 48 // 32-byte key + 16-byte MAC

export interface EncryptedPayload {
  ciphertext: Uint8Array
  nonce: Uint8Array // 24-byte secretbox nonce
  encryptedKeys: Uint8Array[] // one wrapped symmetric key per recipient
  keyNonces: Uint8Array[] // one box nonce per recipient
  ephemeralPubkey: Uint8Array // X25519 ephemeral public key
  numRecipients: number
}

export function emptyPayload(): EncryptedPayload {
  return {
    ciphertext: new Uint8Array(0),
    nonce: new Uint8Array(0),
    encryptedKeys: [],
    keyNonces: [],
    ephemeralPubkey: new Uint8Array(0),
    numRecipients: 0,
  }
}

/**
 * Encrypt plaintext for multiple recipients.
 * @param recipientPubkeys X25519 public keys (converted from Ed25519).
 */
export async function encryptPayloadMulti(
  plaintext: Uint8Array,
  recipientPubkeys: Uint8Array[],
): Promise<EncryptedPayload> {
  await sodium.ready

  if (!plaintext || plaintext.length === 0) throw new Error('Plaintext cannot be empty')
  if (plaintext.length > MAX_PLAINTEXT_SIZE) {
    throw new Error(`Plaintext too large: ${plaintext.length} > ${MAX_PLAINTEXT_SIZE}`)
  }
  if (!recipientPubkeys || recipientPubkeys.length === 0) {
    throw new Error('Must specify at least one recipient')
  }
  if (recipientPubkeys.length > MAX_RECIPIENTS) {
    throw new Error(`Too many recipients: ${recipientPubkeys.length} > ${MAX_RECIPIENTS}`)
  }

  const ephemeralKeypair = sodium.crypto_box_keypair()
  const symmetricKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
  const messageNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)

  const ciphertext = sodium.crypto_secretbox_easy(plaintext, messageNonce, symmetricKey)

  const encryptedKeys: Uint8Array[] = []
  const keyNonces: Uint8Array[] = []
  for (const recipientPubkey of recipientPubkeys) {
    const keyNonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
    const encryptedKey = sodium.crypto_box_easy(
      symmetricKey,
      keyNonce,
      recipientPubkey,
      ephemeralKeypair.privateKey,
    )
    encryptedKeys.push(encryptedKey)
    keyNonces.push(keyNonce)
  }

  const payload: EncryptedPayload = {
    ciphertext,
    nonce: messageNonce,
    encryptedKeys,
    keyNonces,
    ephemeralPubkey: ephemeralKeypair.publicKey,
    numRecipients: recipientPubkeys.length,
  }

  sodium.memzero(symmetricKey)
  sodium.memzero(ephemeralKeypair.privateKey)
  return payload
}

/**
 * Decrypt a payload addressed to the loaded identity.
 * @param recipientPubkeys X25519 public keys in the same order as the
 *        payload's wrapped keys (i.e. converted header recipients).
 */
export async function decryptPayload(
  encrypted: EncryptedPayload,
  recipientPubkeys: Uint8Array[],
): Promise<Uint8Array> {
  await sodium.ready

  if (!encrypted || !recipientPubkeys || recipientPubkeys.length === 0) {
    throw new Error('Invalid parameters')
  }
  const MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 16
  if (encrypted.ciphertext.length > MAX_CIPHERTEXT_SIZE) {
    throw new Error('Ciphertext size exceeds maximum allowed size')
  }

  const ourPublicKey = keyStore.getEncryptionPublicKey()
  const ourPrivateKey = keyStore._getEncryptionPrivateKey()

  let recipientIndex = -1
  for (let i = 0; i < recipientPubkeys.length; i++) {
    if (sodium.memcmp(ourPublicKey, recipientPubkeys[i])) {
      recipientIndex = i
      break
    }
  }
  if (recipientIndex === -1) {
    throw new Error('Our key is not in the recipient list for this payload')
  }
  if (recipientIndex >= encrypted.encryptedKeys.length) {
    throw new Error(`Recipient index ${recipientIndex} out of bounds`)
  }

  let symmetricKey: Uint8Array
  try {
    symmetricKey = sodium.crypto_box_open_easy(
      encrypted.encryptedKeys[recipientIndex],
      encrypted.keyNonces[recipientIndex],
      encrypted.ephemeralPubkey,
      ourPrivateKey,
    )
  } catch {
    throw new Error('Failed to decrypt symmetric key')
  }

  try {
    const plaintext = sodium.crypto_secretbox_open_easy(
      encrypted.ciphertext,
      encrypted.nonce,
      symmetricKey,
    )
    sodium.memzero(symmetricKey)
    return plaintext
  } catch {
    sodium.memzero(symmetricKey)
    throw new Error('Failed to decrypt message')
  }
}
