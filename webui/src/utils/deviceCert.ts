import sodium from 'libsodium-wrappers'
import { sha256 } from '@noble/hashes/sha2.js'
import { serializeDeviceCertificate, type DeviceCertificateData } from './protobuf'

/**
 * Device certificate construction — the page-side mirror of the
 * node's identity rules (rust/src/identity.rs, Phase B2/B3).
 *
 * A joining device makes two Ed25519 keypairs locally — a member
 * key (the person) and a device key (this browser) — and the member
 * key vouches for the device key with a certificate:
 *
 *   digest    = SHA256( "TWDEVCERT\0" || member_pubkey || device_pubkey
 *                       || issued_at (LE u64) || expires_at (LE u64)
 *                       || SHA256(label) )
 *   signature = Ed25519_sign(member_secret, digest)
 *
 * The signature travels inside the DeviceCertificate protobuf; the
 * serialized cert is what POST /enroll/begin carries (hex). The node
 * re-verifies the signature before it stores the pairing, and an
 * approver's signature later binds the hash of the serialized cert.
 *
 * SHA-256 comes from @noble/hashes for the same reason as in
 * requestAuth.ts: the standard libsodium-wrappers build does not
 * export crypto_hash_sha256.
 */

const DOMAIN = new Uint8Array([84, 87, 68, 69, 86, 67, 69, 82, 84, 0]) // "TWDEVCERT\0"

function u64le(v: number): Uint8Array {
  const b = new Uint8Array(8)
  const view = new DataView(b.buffer)
  view.setUint32(0, v & 0xffffffff, true)
  view.setUint32(4, Math.floor(v / 0x100000000), true)
  return b
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export function deviceCertificateDigest(
  memberPubkey: Uint8Array,
  devicePubkey: Uint8Array,
  label: string,
  issuedAt: number,
  expiresAt: number,
): Uint8Array {
  if (memberPubkey.length !== 32) throw new Error('Invalid member_pubkey length')
  if (devicePubkey.length !== 32) throw new Error('Invalid device_pubkey length')
  return sha256(
    concat([
      DOMAIN,
      memberPubkey,
      devicePubkey,
      u64le(issuedAt),
      u64le(expiresAt),
      sha256(new TextEncoder().encode(label)),
    ]),
  )
}

export interface BuiltDeviceCertificate {
  cert: DeviceCertificateData
  /** Serialized DeviceCertificate protobuf — the bytes /enroll/begin carries as hex. */
  bytes: Uint8Array
  /** The digest the member key signed (kept for display/debugging). */
  digest: Uint8Array
}

/**
 * Build a member-signed device certificate. `memberSecretKey` is the
 * 64-byte libsodium secret key of the member keypair. An
 * `expiresAt` of 0 means the certificate never expires (the node's
 * convention).
 */
export function buildDeviceCertificate(
  memberSecretKey: Uint8Array,
  memberPubkey: Uint8Array,
  devicePubkey: Uint8Array,
  label: string,
  issuedAt: number,
  expiresAt = 0,
): BuiltDeviceCertificate {
  const digest = deviceCertificateDigest(memberPubkey, devicePubkey, label, issuedAt, expiresAt)
  const signature = sodium.crypto_sign_detached(digest, memberSecretKey)
  const cert: DeviceCertificateData = {
    memberPubkey,
    devicePubkey,
    label,
    issuedAt,
    expiresAt,
    signature,
  }
  return { cert, bytes: serializeDeviceCertificate(cert), digest }
}
