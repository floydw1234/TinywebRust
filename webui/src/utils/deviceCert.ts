import sodium from 'libsodium-wrappers'
import { sha256 } from '@noble/hashes/sha2.js'
import { serializeDeviceCertificate, type DeviceCertificateData } from './protobuf'
import { toHex } from './hex'

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

const REVOKE_DOMAIN = new Uint8Array([84, 87, 68, 69, 86, 82, 69, 86, 79, 75, 69, 0]) // "TWDEVREVOKE\0"

/**
 * Signing digest for a device revocation — the page-side mirror
 * of the node's `device_revocation_digest` (rust/src/identity.rs):
 *
 *   digest = SHA256( "TWDEVREVOKE\0" || member_pubkey || device_pubkey
 *                    || revoked_at (LE u64) || SHA256(reason) )
 *
 * In the parent authorization for POST /devices/revoke,
 * `revoked_at` is the body's `timestamp` field, and the body's
 * `reason` must be the exact string hashed here.
 */
export function deviceRevocationDigest(
  memberPubkey: Uint8Array,
  devicePubkey: Uint8Array,
  revokedAt: number,
  reason: string,
): Uint8Array {
  if (memberPubkey.length !== 32) throw new Error('Invalid member_pubkey length')
  if (devicePubkey.length !== 32) throw new Error('Invalid device_pubkey length')
  return sha256(
    concat([
      REVOKE_DOMAIN,
      memberPubkey,
      devicePubkey,
      u64le(revokedAt),
      sha256(new TextEncoder().encode(reason)),
    ]),
  )
}

export interface DeviceRevocationAuth {
  parent_member_pubkey: string // hex
  parent_device_pubkey: string // hex
  timestamp: number
  signature: string // hex
}

/**
 * Build the parent authorization for POST /devices/revoke: the
 * recorded parent's *device* key signs the revocation digest for
 * the child's device. `parentDeviceSecretKey` is the 64-byte
 * libsodium secret key of the parent's device keypair.
 */
export function buildDeviceRevocationAuth(
  parentDeviceSecretKey: Uint8Array,
  parentMemberPubkey: Uint8Array,
  parentDevicePubkey: Uint8Array,
  memberPubkey: Uint8Array,
  devicePubkey: Uint8Array,
  reason: string,
  timestamp: number,
): DeviceRevocationAuth {
  const digest = deviceRevocationDigest(memberPubkey, devicePubkey, timestamp, reason)
  const signature = sodium.crypto_sign_detached(digest, parentDeviceSecretKey)
  return {
    parent_member_pubkey: toHex(parentMemberPubkey),
    parent_device_pubkey: toHex(parentDevicePubkey),
    timestamp,
    signature: toHex(signature),
  }
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
