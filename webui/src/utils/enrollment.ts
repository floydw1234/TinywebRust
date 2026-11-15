import sodium from 'libsodium-wrappers'
import keyStore, { KeyStore } from './keystore'
import { buildDeviceCertificate } from './deviceCert'
import { enrollBegin, enrollStatus, type EnrollBeginResult } from '../api'
import { toHex } from './hex'

/**
 * Enrollment state for the test page (Phase B5) — the client half
 * of the node's pairing flow (rust/src/api.rs, Phase B3):
 *
 *   1. This browser generates a member keypair + a device keypair,
 *      sealed in localStorage under their own keys (the active
 *      identity in `tinyweb_keypair` is NOT touched yet).
 *   2. The member key signs a device certificate for the device key
 *      (utils/deviceCert.ts) and POST /enroll/begin opens a pairing:
 *      the node returns a single-use code, good for ~10 minutes.
 *   3. The page polls GET /enroll/status. When an approver (a parent
 *      on their own device, or the backup-card recovery key) signs,
 *      the node enrolls the member + device atomically.
 *   4. Only then does the enrolled member key become the page's
 *      active identity, so Messages/Location sign as the member —
 *      one join lights up every feature.
 *
 * Non-secret bookkeeping (names, pubkeys, phase, the live code)
 * lives in localStorage `tinyweb_enrollment` so a page reload keeps
 * the flow resumable. Every failure throws with the node's reason;
 * callers surface it in the UI — nothing is swallowed here.
 */

const META_KEY = 'tinyweb_enrollment'
const MEMBER_STORAGE_KEY = 'tinyweb_member_keypair'
const DEVICE_STORAGE_KEY = 'tinyweb_device_keypair'

export type EnrollmentPhase = 'keys' | 'pending' | 'enrolled'

export interface EnrollmentMeta {
  displayName: string
  deviceLabel: string
  memberPubkey: string // hex
  devicePubkey: string // hex
  phase: EnrollmentPhase
  code?: string
  expiresAt?: number // unix seconds, from the node's begin reply
  enrolledAt?: number // unix seconds
}

const memberStore = new KeyStore(MEMBER_STORAGE_KEY)
const deviceStore = new KeyStore(DEVICE_STORAGE_KEY)

export function getEnrollmentMeta(): EnrollmentMeta | null {
  try {
    const raw = localStorage.getItem(META_KEY)
    return raw ? (JSON.parse(raw) as EnrollmentMeta) : null
  } catch {
    return null
  }
}

function saveMeta(meta: EnrollmentMeta): void {
  localStorage.setItem(META_KEY, JSON.stringify(meta))
}

export async function initEnrollmentStores(): Promise<void> {
  await memberStore.init()
  await deviceStore.init()
}

export function enrollmentKeysLoaded(): boolean {
  return memberStore.isKeypairLoaded() && deviceStore.isKeypairLoaded()
}

/** The store holding the enrollment member key (advanced/test use). */
export function getMemberStore(): KeyStore {
  return memberStore
}

/** The store holding the enrollment device key (advanced/test use). */
export function getDeviceStore(): KeyStore {
  return deviceStore
}

/**
 * Generate a fresh member + device keypair for joining and remember
 * the display name / device label. Any previous enrollment keys are
 * replaced. The active identity is not changed.
 */
export async function createEnrollmentIdentity(
  displayName: string,
  deviceLabel: string,
): Promise<EnrollmentMeta> {
  await initEnrollmentStores()
  await memberStore.generateKeypair()
  await memberStore.saveKeypair('')
  await deviceStore.generateKeypair()
  await deviceStore.saveKeypair('')
  const meta: EnrollmentMeta = {
    displayName,
    deviceLabel,
    memberPubkey: memberStore.getPublicKeyHex(),
    devicePubkey: deviceStore.getPublicKeyHex(),
    phase: 'keys',
  }
  saveMeta(meta)
  return meta
}

/**
 * Open a pairing on the node: build the member-signed device
 * certificate from the stored keys and POST /enroll/begin. On
 * success the meta moves to `pending` with the code to show a
 * parent. Re-beginning retires any earlier pending code for the
 * same member/device on the node, so this is also the retry path
 * after an expiry.
 */
export async function beginEnrollment(): Promise<EnrollBeginResult> {
  const meta = getEnrollmentMeta()
  if (!meta) throw new Error('No enrollment identity yet — create one first.')
  await initEnrollmentStores()
  if (!enrollmentKeysLoaded()) {
    throw new Error(
      'Enrollment keys are not loaded in this browser (storage was cleared?). Reset the enrollment identity and create a fresh one.',
    )
  }
  await sodium.ready
  const issuedAt = Math.floor(Date.now() / 1000)
  const built = buildDeviceCertificate(
    memberStore._getPrivateKey(),
    memberStore.getPublicKey(),
    deviceStore.getPublicKey(),
    meta.deviceLabel,
    issuedAt,
    0,
  )
  const res = await enrollBegin({
    member_pubkey: meta.memberPubkey,
    device_pubkey: meta.devicePubkey,
    display_name: meta.displayName,
    device_cert: toHex(built.bytes),
  })
  saveMeta({ ...meta, phase: 'pending', code: res.code, expiresAt: res.expires_at })
  return res
}

export type EnrollmentCheck =
  | { state: 'pending'; expiresAt: number }
  | { state: 'approved' }
  | { state: 'expired' }
  | { state: 'unknown' }

/**
 * Ask the node where the pending pairing stands. On `approved` the
 * enrolled member key is activated as the page identity before
 * returning. On `expired`/`unknown` the meta drops back to `keys`
 * so the view can offer a fresh begin.
 */
export async function checkEnrollment(): Promise<EnrollmentCheck> {
  const meta = getEnrollmentMeta()
  if (!meta?.code) throw new Error('No pending pairing to check.')
  const res = await enrollStatus(meta.code)
  if (res.status === 'approved') {
    await activateEnrolledIdentity()
    saveMeta({
      ...meta,
      phase: 'enrolled',
      code: undefined,
      expiresAt: undefined,
      enrolledAt: Math.floor(Date.now() / 1000),
    })
    return { state: 'approved' }
  }
  if (res.status === 'expired') {
    saveMeta({ ...meta, phase: 'keys', code: undefined, expiresAt: undefined })
    return { state: 'expired' }
  }
  if (res.status === 'unknown') {
    saveMeta({ ...meta, phase: 'keys', code: undefined, expiresAt: undefined })
    return { state: 'unknown' }
  }
  return { state: 'pending', expiresAt: res.expires_at ?? meta.expiresAt ?? 0 }
}

/**
 * Make the enrolled member key the page's active identity: import
 * it into the legacy singleton keystore (sealed as usual), so every
 * signed call — users, messages, location — goes out as the member.
 */
export async function activateEnrolledIdentity(): Promise<void> {
  await initEnrollmentStores()
  if (!memberStore.isKeypairLoaded()) {
    throw new Error('Member key is not loaded in this browser; cannot activate the enrolled identity.')
  }
  await keyStore.importKey(toHex(memberStore._getPrivateKey()))
  await keyStore.saveKeypair('')
}

/**
 * Forget the enrollment identity (member + device keys and the
 * bookkeeping). The active identity and the node-side enrollment
 * are deliberately NOT changed — this only clears the joining
 * material kept in this browser.
 */
export async function resetEnrollment(): Promise<void> {
  await initEnrollmentStores()
  memberStore.cleanup()
  memberStore.deleteStoredKeypair()
  deviceStore.cleanup()
  deviceStore.deleteStoredKeypair()
  localStorage.removeItem(META_KEY)
}
