import sodium from 'libsodium-wrappers'
// SHA-256 comes from @noble/hashes: the standard libsodium-wrappers build
// does not export crypto_hash_sha256 (it exists only in the -sumo build).
import { sha256 } from '@noble/hashes/sha2.js'
import keyStore from './keystore'
import { encryptPayloadMulti } from './encryption'
import {
  CONTENT_LOCATION_UPDATE,
  encodeLocationUpdate,
  type ClientRequestHeaderData,
  type LocationUpdateData,
  type TinyClientRequest,
} from './protobuf'

/**
 * ClientRequest construction + signing — ported from the C web-ui
 * (client/web-ui/src/utils/clientRequestHelper.js), matching the node
 * backend (src/packages/validation/client_request_validation.c).
 *
 * Digest = SHA256( "TWCLIENTREQ\0" || header fields (little-endian) ||
 *                  SHA256(ciphertext) )
 *
 * Note: the content type used here is 33 (CONTENT_LOCATION_UPDATE in
 * envelope.proto), which is what the node's envelope dispatcher routes
 * to the location handler. The old C web-ui used 1 here, which is
 * CONTENT_USER_REGISTRATION — that looks like a bug in the old UI.
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

export function computeClientRequestDigest(
  header: ClientRequestHeaderData,
  ciphertext: Uint8Array,
): Uint8Array {
  const domain = new Uint8Array([84, 87, 67, 76, 73, 69, 78, 84, 82, 69, 81, 0]) // "TWCLIENTREQ\0"
  const parts: Uint8Array[] = [domain]
  parts.push(u32le(header.version))
  parts.push(u32le(header.contentType))
  parts.push(u32le(header.schemaVersion))
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

/**
 * Build a signed ClientRequest carrying a LocationUpdate, encrypted to
 * the given Ed25519 recipient pubkeys.
 */
export async function createSignedLocationRequest(
  location: LocationUpdateData,
  recipientPubkeys: Uint8Array[],
): Promise<TinyClientRequest> {
  await sodium.ready
  await keyStore.init()
  if (!keyStore.isKeypairLoaded()) {
    throw new Error('No keypair loaded. Generate or import an identity first.')
  }

  const locationBytes = encodeLocationUpdate(location)
  const encryptionPubkeys = recipientPubkeys.map((pk) =>
    sodium.crypto_sign_ed25519_pk_to_curve25519(pk),
  )
  const encryptedPayload = await encryptPayloadMulti(locationBytes, encryptionPubkeys)

  const header: ClientRequestHeaderData = {
    version: 1,
    contentType: CONTENT_LOCATION_UPDATE,
    schemaVersion: 1,
    timestamp: Math.floor(Date.now() / 1000),
    senderPubkey: keyStore.getPublicKey(),
    recipientsPubkey: recipientPubkeys,
    groupId: null,
  }

  const digest = computeClientRequestDigest(header, encryptedPayload.ciphertext)
  const signature = sodium.crypto_sign_detached(digest, keyStore._getPrivateKey())

  return { header, encryptedPayload, signature }
}
