import sodium from 'libsodium-wrappers'
import { sha256 } from '@noble/hashes/sha2.js'
import keyStore from './keystore'

/**
 * Request authentication — ported from the C web-ui
 * (client/web-ui/src/utils/requestAuth.js), matching the node backend
 * (src/packages/comm/request_auth.c::compute_request_digest).
 *
 * Digest = SHA256( "TWREQUEST\0" || method || uri || query? || timestamp || pubkey )
 * signed with the identity Ed25519 key. Sent as headers:
 *   X-User-Pubkey, X-Signature, X-Timestamp
 *
 * Note: SHA-256 comes from @noble/hashes, not WebCrypto, because this
 * page may be served over plain HTTP on a Tailscale IP, which is not a
 * "secure context" — crypto.subtle would be unavailable there. (The
 * standard libsodium-wrappers build does not export crypto_hash_sha256;
 * that function exists only in the -sumo build.) The digest bytes are
 * identical either way.
 */

function computeRequestDigest(
  method: string,
  uri: string,
  query: string,
  timestamp: string,
  pubkey: Uint8Array,
): Uint8Array {
  const domain = new Uint8Array([84, 87, 82, 69, 81, 85, 69, 83, 84, 0]) // "TWREQUEST\0"
  const parts: Uint8Array[] = [domain]
  parts.push(new TextEncoder().encode(method))
  parts.push(new TextEncoder().encode(uri))
  // Backend only hashes the query when it is non-empty.
  if (query && query.length > 0) {
    parts.push(new TextEncoder().encode(query))
  }
  parts.push(new TextEncoder().encode(timestamp))
  parts.push(pubkey)

  const total = parts.reduce((n, p) => n + p.length, 0)
  const combined = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    combined.set(p, offset)
    offset += p.length
  }
  return sha256(combined)
}

export interface AuthHeaders {
  'X-User-Pubkey': string
  'X-Signature': string
  'X-Timestamp': string
}

/**
 * Sign a request to the node.
 * @param method HTTP method, e.g. "GET"
 * @param uri    Path the node sees, e.g. "/messages/recent" (no proxy prefix)
 * @param query  Query string without the leading "?", e.g. "user=ab12&limit=50"
 */
export async function signRequest(method: string, uri: string, query = ''): Promise<AuthHeaders> {
  await sodium.ready
  await keyStore.init()
  if (!keyStore.isKeypairLoaded()) {
    throw new Error('No keypair loaded. Generate or import an identity first.')
  }
  const pubkey = keyStore.getPublicKey()
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const digest = computeRequestDigest(method, uri, query, timestamp, pubkey)
  const signature = sodium.crypto_sign_detached(digest, keyStore._getPrivateKey())
  return {
    'X-User-Pubkey': sodium.to_hex(pubkey),
    'X-Signature': sodium.to_hex(signature),
    'X-Timestamp': timestamp,
  }
}
