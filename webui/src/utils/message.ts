import sodium from 'libsodium-wrappers'
// SHA-256 comes from @noble/hashes: the standard libsodium-wrappers build
// does not export crypto_hash_sha256 (it exists only in the -sumo build).
import { sha256 } from '@noble/hashes/sha2.js'
import keyStore from './keystore'
import { encryptPayloadMulti } from './encryption'
import type { MessageHeaderData, TinyMessage } from './protobuf'

/**
 * Message construction + signing — ported from the C web-ui
 * (client/web-ui/src/utils/message.js), matching the node backend
 * (src/packages/validation/message_validation.c).
 *
 * Digest = SHA256( "TWMESSAGE\0" || header fields (little-endian) ||
 *                  SHA256(ciphertext) )
 * Plaintext is the raw UTF-8 message text, as in the C web-ui.
 */

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v, true)
  return b
}

function u64le(v: number): Uint8Array {
  const b = new Uint8Array(8)
  const view = new DataView(b.buffer)
  view.setUint32(0, v & 0xffffffff, true)
  view.setUint32(4, Math.floor(v / 0x100000000), true)
  return b
}

export function computeMessageDigest(header: MessageHeaderData, ciphertext: Uint8Array): Uint8Array {
  const domain = new Uint8Array([84, 87, 77, 69, 83, 83, 65, 71, 69, 0]) // "TWMESSAGE\0"
  const parts: Uint8Array[] = [domain]
  parts.push(u32le(header.version))
  parts.push(u64le(header.timestamp))
  if (header.senderPubkey.length !== 32) throw new Error('Invalid sender_pubkey length')
  parts.push(header.senderPubkey)
  parts.push(u32le(header.recipientsPubkey.length))
  for (const pk of header.recipientsPubkey) {
    if (pk.length !== 32) throw new Error('Invalid recipient_pubkey length')
    parts.push(pk)
  }
  const groupId = header.groupId || new Uint8Array(0)
  parts.push(u32le(groupId.length))
  if (groupId.length > 0) parts.push(groupId)
  parts.push(sha256(ciphertext))

  const total = parts.reduce((n, p) => n + p.length, 0)
  const combined = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    combined.set(p, offset)
    offset += p.length
  }
  return sha256(combined)
}

export async function createSignedMessage(
  header: MessageHeaderData,
  plaintext: Uint8Array,
): Promise<TinyMessage> {
  await sodium.ready
  if (!header.senderPubkey || header.senderPubkey.length === 0) {
    header.senderPubkey = keyStore.getPublicKey()
  }

  // Sender is always a recipient (appended last) so they can read their own messages.
  const senderInList = header.recipientsPubkey.some((pk) =>
    sodium.memcmp(header.senderPubkey, pk),
  )
  if (!senderInList) {
    header.recipientsPubkey = [...header.recipientsPubkey, header.senderPubkey]
  }

  const encryptionPubkeys = header.recipientsPubkey.map((pk) =>
    sodium.crypto_sign_ed25519_pk_to_curve25519(pk),
  )
  const encrypted = await encryptPayloadMulti(plaintext, encryptionPubkeys)

  const message: TinyMessage = {
    header: { ...header },
    encryptedPayload: encrypted,
    signature: new Uint8Array(0),
    sessionId: new Uint8Array(0),
    messageIndex: 0,
  }
  const digest = computeMessageDigest(message.header, encrypted.ciphertext)
  message.signature = sodium.crypto_sign_detached(digest, keyStore._getPrivateKey())
  return message
}

export async function createDirectMessage(
  recipientPubkey: Uint8Array,
  messageText: string,
): Promise<TinyMessage> {
  const header: MessageHeaderData = {
    version: 1,
    timestamp: Math.floor(Date.now() / 1000),
    senderPubkey: keyStore.getPublicKey(),
    recipientsPubkey: [recipientPubkey],
    groupId: null,
  }
  return createSignedMessage(header, new TextEncoder().encode(messageText))
}
