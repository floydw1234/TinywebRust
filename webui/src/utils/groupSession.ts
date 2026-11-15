import sodium from 'libsodium-wrappers'
// SHA-256 comes from @noble/hashes: the standard libsodium-wrappers build
// does not export crypto_hash_sha256 (it exists only in the -sumo build).
import { sha256 } from '@noble/hashes/sha2.js'
import {
  getContentRecent,
  getGroupShareRecipients,
  submitContent,
  type NodeGroup,
} from '../api'
import { getDeviceStore, getEnrollmentMeta, getMemberStore, initEnrollmentStores } from './enrollment'
import { encryptPayloadMulti } from './encryption'
import { computeEnvelopeDigest } from './envelope'
import { fromHex, shortHex, toHex } from './hex'
import { computeMessageDigest } from './message'
import {
  decodeGroupMessage,
  deserializeGroupKeyShare,
  deserializeRawEnvelope,
  encodeGroupMessage,
  serializeConversationMetadata,
  serializeEnvelope,
  serializeGroupKeyShare,
  serializeRawEnvelope,
  type GroupKeyShareData,
  type RawEnvelope,
  type TinyMessage,
} from './protobuf'

/**
 * Group sender sessions — the client half of Phase B4
 * (rust/src/sessions.rs), byte-for-byte:
 *
 *   message_key(i) = SHA256("TWMESSAGEKEY\0" || chain(i))
 *   chain(i+1)     = SHA256("TWCHAINKEY\0"   || chain(i)),  chain(0) = root key
 *   nonce(i)       = SHA256("TWMSGNONCE\0"   || message_key(i))[..24]
 *   aad            = "TWGROUPMSG\0" || group_id || session_id
 *                    || message_index (LE u64) || sender_member_pubkey
 *   ciphertext     = XChaCha20-Poly1305(message_key, nonce, aad, plaintext)
 *                    (full 16-byte tag; libsodium's standard build does
 *                    expose crypto_aead_xchacha20poly1305_ietf_*, verified
 *                    against the Rust known-answer vector below)
 *
 * A session root key is handed out once per recipient device as a
 * GroupKeyShare (content type 25) in an envelope: the share record
 * rides in the clear as the payload, signed by the sender's device
 * key over the TWGROUPSHARE digest; the root key itself is the
 * envelope's single RecipientKeyWrap (crypto_box to the recipient
 * device's X25519 key). Shares are submitted and fetched through
 * the node's generalized content path (POST /content/submit,
 * GET /content/recent, Phase C2).
 *
 * Session state (ratchet position + skipped keys, window 1000)
 * persists in localStorage, mirroring the node's store semantics:
 * sender state advances and persists BEFORE sealing, receiver
 * state advances and persists BEFORE plaintext is returned.
 * Rejections (replay, too-far-ahead, bad shares) are returned as
 * visible error strings — nothing fails silently.
 */

export const CONTENT_GROUP_KEY_SHARE = 25
export const CONTENT_CONVERSATION_METADATA = 35
export const MAX_MESSAGE_GAP = 1000

const SESSIONS_KEY = 'tinyweb_group_sessions_v1'
const GROUP_STATE_KEY = 'tinyweb_group_state_v1'
/**
 * Decrypted group texts, cached page-locally by (session, sender,
 * index). The ratchet is destructive by design — a consumed index
 * cannot be opened twice — so the thread view would go blank on
 * reload without this. It is a display cache only; the ratchet
 * state above is the protocol state and stays byte-exact.
 */
const PLAINTEXT_KEY = 'tinyweb_group_plaintext_v1'

function loadPlaintextCache(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(PLAINTEXT_KEY) || '{}') as Record<string, string>
  } catch {
    return {}
  }
}

function cachePlaintext(sessionIdHex: string, senderHex: string, index: number, text: string): void {
  const cache = loadPlaintextCache()
  cache[`${sessionIdHex}:${senderHex}:${index}`] = text
  localStorage.setItem(PLAINTEXT_KEY, JSON.stringify(cache))
}

// ---------------------------------------------------------------------------
// Hash ratchet + AEAD (byte mirrors of sessions.rs)
// ---------------------------------------------------------------------------

function domain(s: string): Uint8Array {
  return new TextEncoder().encode(s + '\0')
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for ( const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

function u64le(v: number): Uint8Array {
  const b = new Uint8Array(8)
  const view = new DataView(b.buffer)
  view.setUint32(0, v & 0xffffffff, true)
  view.setUint32(4, Math.floor(v / 0x100000000), true)
  return b
}

export function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
  return sha256(concat([domain('TWMESSAGEKEY'), chainKey]))
}

export function advanceChainKey(chainKey: Uint8Array): Uint8Array {
  return sha256(concat([domain('TWCHAINKEY'), chainKey]))
}

export function messageNonce(messageKey: Uint8Array): Uint8Array {
  return sha256(concat([domain('TWMSGNONCE'), messageKey])).slice(0, 24)
}

export function messageAad(
  groupId: Uint8Array,
  sessionId: Uint8Array,
  index: number,
  senderMemberPubkey: Uint8Array,
): Uint8Array {
  return concat([domain('TWGROUPMSG'), groupId, sessionId, u64le(index), senderMemberPubkey])
}

export async function sealSessionMessage(
  messageKey: Uint8Array,
  groupId: Uint8Array,
  sessionId: Uint8Array,
  index: number,
  senderMemberPubkey: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  await sodium.ready
  const nonce = messageNonce(messageKey)
  const aad = messageAad(groupId, sessionId, index, senderMemberPubkey)
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    messageKey,
  )
  return { ciphertext, nonce }
}

export async function openSessionMessage(
  messageKey: Uint8Array,
  nonce: Uint8Array,
  groupId: Uint8Array,
  sessionId: Uint8Array,
  index: number,
  senderMemberPubkey: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  await sodium.ready
  const aad = messageAad(groupId, sessionId, index, senderMemberPubkey)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, messageKey)
}

export function groupShareDigest(
  groupId: Uint8Array,
  sessionId: Uint8Array,
  senderMemberPubkey: Uint8Array,
  senderDevicePubkey: Uint8Array,
  recipientMemberPubkey: Uint8Array,
  recipientDevicePubkey: Uint8Array,
  createdAt: number,
  wrappedKeyHash: Uint8Array,
): Uint8Array {
  return sha256(
    concat([
      domain('TWGROUPSHARE'),
      groupId,
      sessionId,
      senderMemberPubkey,
      senderDevicePubkey,
      recipientMemberPubkey,
      recipientDevicePubkey,
      u64le(createdAt),
      wrappedKeyHash,
    ]),
  )
}

// ---------------------------------------------------------------------------
// Known-answer check (vector produced by the node's own code and
// pinned in rust/src/sessions.rs::ratchet_known_answer_vector)
// ---------------------------------------------------------------------------

export interface KatResult {
  ok: boolean
  checks: Record<string, boolean>
}

export async function groupKatCheck(): Promise<KatResult> {
  await sodium.ready
  const checks: Record<string, boolean> = {}
  const root = new Uint8Array(32).fill(0x11)
  const mk0 = deriveMessageKey(root)
  checks.mk0 =
    toHex(mk0) === 'd00408aa711fd302fe2e80959c56642654223ca7058c36901a867afe92381787'
  const chain1 = advanceChainKey(root)
  checks.chain1 =
    toHex(chain1) === '3878f4eac1458397a520067d0087ba0967bd15e06d3b86b7312ef5d222fe2b31'
  const mk1 = deriveMessageKey(chain1)
  checks.mk1 =
    toHex(mk1) === '5f0db29d692d81264311840d4d68e37e2ebf6eee053ad432270396d996207a2a'
  const nonce0 = messageNonce(mk0)
  checks.nonce0 = toHex(nonce0) === '3c72c3cd2c2374b4aaf2d53c4c6f654c052753766220d39f'
  const group = new Uint8Array(16).fill(0x22)
  const session = new Uint8Array(16).fill(0x33)
  const sender = new Uint8Array(32).fill(0x44)
  const sealed = await sealSessionMessage(
    mk0,
    group,
    session,
    0,
    sender,
    new TextEncoder().encode('tinyweb group kat'),
  )
  checks.ct0 =
    toHex(sealed.ciphertext) ===
    '79689d035c8fdd061ea5f28fe42da76ff9606b049e1f7bd0c8bc2f47bab56e845e'
  checks.nonceMatches = toHex(sealed.nonce) === toHex(nonce0)
  const wrappedHash = sha256(new TextEncoder().encode('kat wrapped key'))
  const digest = groupShareDigest(
    group,
    session,
    sender,
    new Uint8Array(32).fill(0x55),
    new Uint8Array(32).fill(0x66),
    new Uint8Array(32).fill(0x77),
    1700000000,
    wrappedHash,
  )
  checks.shareDigest =
    toHex(digest) === 'ebca0a43923dd18692564345fcc5f2fc8c6439e3842b7f0dca484ab36fe72340'
  return { ok: Object.values(checks).every(Boolean), checks }
}

// ---------------------------------------------------------------------------
// Persistent session state (localStorage)
// ---------------------------------------------------------------------------

export interface StoredSession {
  sessionId: string // hex
  groupId: string // hex
  senderMember: string // hex
  senderDevice: string // hex
  direction: 'own' | 'received'
  /** Chain key for nextIndex (hex). Advances one-way; never rewinds. */
  chainKey: string
  nextIndex: number
  /** Received sessions: message keys for indices skipped over, by index. */
  skipped: Record<string, string>
  /** Own sessions: message key per sent index, so the sender can re-read. */
  sentKeys: Record<string, string>
  createdAt: number
}

interface GroupState {
  membersKey: string
  metadataParents: string[]
  ownSessionId?: string
}

function loadSessions(): Record<string, StoredSession> {
  try {
    return JSON.parse(localStorage.getItem(SESSIONS_KEY) || '{}') as Record<string, StoredSession>
  } catch {
    return {}
  }
}

function saveSessions(sessions: Record<string, StoredSession>): void {
  localStorage.setItem(SESSIONS_KEY, JSON.stringify(sessions))
}

function loadGroupState(): Record<string, GroupState> {
  try {
    return JSON.parse(localStorage.getItem(GROUP_STATE_KEY) || '{}') as Record<string, GroupState>
  } catch {
    return {}
  }
}

function saveGroupState(state: Record<string, GroupState>): void {
  localStorage.setItem(GROUP_STATE_KEY, JSON.stringify(state))
}

// ---------------------------------------------------------------------------
// Identity helpers (the enrolled member + device keys from the Enroll tab)
// ---------------------------------------------------------------------------

async function enrolledKeys(): Promise<{
  memberPubkey: Uint8Array
  memberSecret: Uint8Array
  devicePubkey: Uint8Array
  deviceSecret: Uint8Array
}> {
  await initEnrollmentStores()
  const meta = getEnrollmentMeta()
  if (!meta) {
    throw new Error(
      'Group chat needs the enrolled identity from the Enroll tab (member + device keys).',
    )
  }
  const memberStore = getMemberStore()
  const deviceStore = getDeviceStore()
  if (!memberStore.isKeypairLoaded() || !deviceStore.isKeypairLoaded()) {
    throw new Error(
      'Enrollment keys are not loaded in this browser (storage was cleared?). Reset and re-enroll from the Enroll tab.',
    )
  }
  return {
    memberPubkey: memberStore.getPublicKey(),
    memberSecret: memberStore._getPrivateKey(),
    devicePubkey: deviceStore.getPublicKey(),
    deviceSecret: deviceStore._getPrivateKey(),
  }
}

// ---------------------------------------------------------------------------
// Key wraps (crypto_box to the recipient device, as in encryption.rs)
// ---------------------------------------------------------------------------

async function wrapRootKey(
  recipientDevicePubkey: Uint8Array,
  rootKey: Uint8Array,
): Promise<{ ephemeralPubkey: Uint8Array; wrap: RawEnvelope['keywraps'][number] }> {
  await sodium.ready
  const ephemeral = sodium.crypto_box_keypair()
  const curvePubkey = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientDevicePubkey)
  const keyNonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const wrappedKey = sodium.crypto_box_easy(rootKey, keyNonce, curvePubkey, ephemeral.privateKey)
  sodium.memzero(ephemeral.privateKey)
  return {
    ephemeralPubkey: ephemeral.publicKey,
    wrap: { recipientPubkey: recipientDevicePubkey, keyNonce, wrappedKey },
  }
}

async function unwrapRootKey(
  ephemeralPubkey: Uint8Array,
  wrap: RawEnvelope['keywraps'][number],
): Promise<Uint8Array> {
  await sodium.ready
  const deviceStore = getDeviceStore()
  const secret = deviceStore._getEncryptionPrivateKey()
  return sodium.crypto_box_open_easy(wrap.wrappedKey, wrap.keyNonce, ephemeralPubkey, secret)
}

// ---------------------------------------------------------------------------
// Share construction + verification (mirror of sessions.rs)
// ---------------------------------------------------------------------------

export async function buildShareEnvelope(args: {
  recipientMember: Uint8Array
  recipientDevice: Uint8Array
  groupId: Uint8Array
  sessionId: Uint8Array
  rootKey: Uint8Array
  createdAt: number
}): Promise<Uint8Array> {
  await sodium.ready
  const keys = await enrolledKeys()
  const { ephemeralPubkey, wrap } = await wrapRootKey(args.recipientDevice, args.rootKey)
  const wrappedKeyHash = sha256(wrap.wrappedKey)
  const digest = groupShareDigest(
    args.groupId,
    args.sessionId,
    keys.memberPubkey,
    keys.devicePubkey,
    args.recipientMember,
    args.recipientDevice,
    args.createdAt,
    wrappedKeyHash,
  )
  const signature = sodium.crypto_sign_detached(digest, keys.deviceSecret)
  const share: GroupKeyShareData = {
    groupId: args.groupId,
    sessionId: args.sessionId,
    senderMemberPubkey: keys.memberPubkey,
    senderDevicePubkey: keys.devicePubkey,
    recipientMemberPubkey: args.recipientMember,
    recipientDevicePubkey: args.recipientDevice,
    createdAt: args.createdAt,
    wrappedKeyHash,
    signature,
  }
  const shareBytes = serializeGroupKeyShare(share)
  const header = {
    version: 1,
    contentType: CONTENT_GROUP_KEY_SHARE,
    schemaVersion: 1,
    timestamp: args.createdAt,
    senderPubkey: keys.devicePubkey,
    recipientsPubkey: [args.recipientDevice],
    groupId: args.groupId,
  }
  const envelopeDigest = computeEnvelopeDigest(header, shareBytes)
  const envelopeSignature = sodium.crypto_sign_detached(envelopeDigest, keys.deviceSecret)
  return serializeRawEnvelope({
    header,
    payloadNonce: new Uint8Array(24),
    ephemeralPubkey,
    payloadCiphertext: shareBytes,
    keywraps: [wrap],
    signature: envelopeSignature,
  })
}

/**
 * Client-side share verification, mirroring the structural and
 * signature checks of sessions::verify_share_envelope (the node
 * additionally checks device enrollment/trust at submit time).
 * Returns an error string, or null when the share is well-formed
 * and both signatures verify.
 */
export function verifyShareSignature(env: RawEnvelope, share: GroupKeyShareData): string | null {
  if (env.header.contentType !== CONTENT_GROUP_KEY_SHARE) return 'envelope is not a group key share'
  if (toHex(env.header.senderPubkey) !== toHex(share.senderDevicePubkey)) {
    return 'header sender is not the share sender device'
  }
  if (
    env.header.recipientsPubkey.length !== 1 ||
    toHex(env.header.recipientsPubkey[0]) !== toHex(share.recipientDevicePubkey)
  ) {
    return 'header recipients are not the share recipient device'
  }
  if (!env.header.groupId || toHex(env.header.groupId) !== toHex(share.groupId)) {
    return 'header group is not the share group'
  }
  if (env.keywraps.length !== 1) return 'share envelope must carry exactly one key wrap'
  const wrap = env.keywraps[0]
  if (toHex(wrap.recipientPubkey) !== toHex(share.recipientDevicePubkey)) {
    return 'key wrap does not name the share recipient device'
  }
  if (toHex(sha256(wrap.wrappedKey)) !== toHex(share.wrappedKeyHash)) {
    return 'key wrap does not match the share wrapped_key_hash'
  }
  const envelopeDigest = computeEnvelopeDigest(env.header, env.payloadCiphertext)
  if (!sodium.crypto_sign_verify_detached(env.signature, envelopeDigest, share.senderDevicePubkey)) {
    return 'envelope signature does not verify'
  }
  const digest = groupShareDigest(
    share.groupId,
    share.sessionId,
    share.senderMemberPubkey,
    share.senderDevicePubkey,
    share.recipientMemberPubkey,
    share.recipientDevicePubkey,
    share.createdAt,
    share.wrappedKeyHash,
  )
  if (!sodium.crypto_sign_verify_detached(share.signature, digest, share.senderDevicePubkey)) {
    return 'share signature does not verify'
  }
  return null
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/**
 * Start a fresh sender session for a group: generate the root
 * key, persist our own ratchet state, and hand one signed share
 * to every device in the node's B4 distribution for this group.
 * Used for the first send and for rotation after a membership
 * change. Share submission failures are collected as warnings;
 * if every share fails, the whole start fails loudly.
 */
export async function startGroupSession(
  groupIdHex: string,
): Promise<{ sessionId: string; warnings: string[] }> {
  await sodium.ready
  const keys = await enrolledKeys()
  const recipients = await getGroupShareRecipients(groupIdHex, toHex(keys.devicePubkey))
  const rootKey = sodium.randombytes_buf(32)
  const sessionId = sodium.randombytes_buf(16)
  const sessionIdHex = toHex(sessionId)
  const now = Math.floor(Date.now() / 1000)

  const sessions = loadSessions()
  sessions[sessionIdHex] = {
    sessionId: sessionIdHex,
    groupId: groupIdHex,
    senderMember: toHex(keys.memberPubkey),
    senderDevice: toHex(keys.devicePubkey),
    direction: 'own',
    chainKey: toHex(rootKey),
    nextIndex: 0,
    skipped: {},
    sentKeys: {},
    createdAt: now,
  }
  saveSessions(sessions)

  const state = loadGroupState()
  state[groupIdHex] = {
    membersKey: state[groupIdHex]?.membersKey || '',
    metadataParents: recipients.metadata_parents,
    ownSessionId: sessionIdHex,
  }
  saveGroupState(state)

  const warnings: string[] = []
  for (const device of recipients.devices) {
    try {
      const envelopeBytes = await buildShareEnvelope({
        recipientMember: fromHex(device.member_pubkey),
        recipientDevice: fromHex(device.device_pubkey),
        groupId: fromHex(groupIdHex),
        sessionId,
        rootKey,
        createdAt: now,
      })
      await submitContent(envelopeBytes)
    } catch (e) {
      warnings.push(
        `share to device ${shortHex(device.device_pubkey)} failed: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }
  if (recipients.devices.length > 0 && warnings.length === recipients.devices.length) {
    throw new Error(`Could not hand out the group key to any device: ${warnings.join('; ')}`)
  }
  return { sessionId: sessionIdHex, warnings }
}

/** The current own session for a group, starting one if none exists. */
export async function ensureGroupSession(
  groupIdHex: string,
): Promise<{ sessionId: string; warnings: string[] }> {
  const state = loadGroupState()
  const sessions = loadSessions()
  const existing = state[groupIdHex]?.ownSessionId
  if (existing && sessions[existing]?.direction === 'own') {
    return { sessionId: existing, warnings: [] }
  }
  return startGroupSession(groupIdHex)
}

/** Drop our own session for a group so the next send rotates. */
export function markGroupSessionStale(groupIdHex: string): void {
  const state = loadGroupState()
  const own = state[groupIdHex]?.ownSessionId
  if (own) {
    const sessions = loadSessions()
    delete sessions[own]
    saveSessions(sessions)
    delete state[groupIdHex].ownSessionId
    saveGroupState(state)
  }
}

/**
 * Record a group's current member list; returns true when it
 * changed since last seen — in which case our own session is
 * marked stale (the node retires old sessions server-side too),
 * so the next send starts a fresh session covering the new set.
 */
export function noteGroupMembers(group: NodeGroup): boolean {
  const membersKey = [...group.members].sort().join(',')
  const state = loadGroupState()
  const previous = state[group.group_id]?.membersKey
  state[group.group_id] = {
    membersKey,
    metadataParents: state[group.group_id]?.metadataParents || [],
    ownSessionId: state[group.group_id]?.ownSessionId,
  }
  saveGroupState(state)
  if (previous && previous !== membersKey) {
    markGroupSessionStale(group.group_id)
    return true
  }
  return false
}

/**
 * Fetch shares addressed to this device and accept the new ones:
 * verify, unwrap the root key with our device key, and persist
 * received ratchet state. Bad shares are reported as warnings,
 * never silently dropped.
 */
export async function acceptPendingShares(): Promise<{ accepted: string[]; warnings: string[] }> {
  const meta = getEnrollmentMeta()
  if (!meta) {
    throw new Error('Group chat needs the enrolled identity from the Enroll tab.')
  }
  await initEnrollmentStores()
  const fetched = await getContentRecent(meta.devicePubkey, CONTENT_GROUP_KEY_SHARE, 200)
  const accepted: string[] = []
  const warnings: string[] = []
  const sessions = loadSessions()
  for (const item of fetched) {
    try {
      const env = deserializeRawEnvelope(fromHex(item.envelope))
      const share = deserializeGroupKeyShare(env.payloadCiphertext)
      if (toHex(share.recipientDevicePubkey) !== meta.devicePubkey) continue
      const sessionIdHex = toHex(share.sessionId)
      if (sessions[sessionIdHex]) continue
      const problem = verifyShareSignature(env, share)
      if (problem) {
        warnings.push(`rejected a share from ${shortHex(toHex(share.senderMemberPubkey))}: ${problem}`)
        continue
      }
      if (env.keywraps.length !== 1) {
        warnings.push(`rejected a share from ${shortHex(toHex(share.senderMemberPubkey))}: no key wrap`)
        continue
      }
      const rootKey = await unwrapRootKey(env.ephemeralPubkey, env.keywraps[0])
      sessions[sessionIdHex] = {
        sessionId: sessionIdHex,
        groupId: toHex(share.groupId),
        senderMember: toHex(share.senderMemberPubkey),
        senderDevice: toHex(share.senderDevicePubkey),
        direction: 'received',
        chainKey: toHex(rootKey),
        nextIndex: 0,
        skipped: {},
        sentKeys: {},
        createdAt: share.createdAt,
      }
      accepted.push(sessionIdHex)
    } catch (e) {
      warnings.push(`could not process a fetched share: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  if (accepted.length > 0) saveSessions(sessions)
  return { accepted, warnings }
}

// ---------------------------------------------------------------------------
// Group messages
// ---------------------------------------------------------------------------

async function submitMetadataRecord(args: {
  groupId: Uint8Array
  sessionId: Uint8Array
  messageIndex: number
  timestamp: number
  members: string[]
  parentHex: string
  memberPubkey: Uint8Array
  memberSecret: Uint8Array
}): Promise<void> {
  await sodium.ready
  const metaBytes = serializeConversationMetadata({
    groupId: args.groupId,
    senderMemberPubkey: args.memberPubkey,
    recipientMemberPubkeys: args.members.map((m) => fromHex(m)),
    messageTimestamp: args.timestamp,
    sessionId: args.sessionId,
    messageIndex: args.messageIndex,
  })
  const parentCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(fromHex(args.parentHex))
  const encrypted = await encryptPayloadMulti(metaBytes, [parentCurve])
  const header = {
    version: 1,
    contentType: CONTENT_CONVERSATION_METADATA,
    schemaVersion: 1,
    timestamp: args.timestamp,
    senderPubkey: args.memberPubkey,
    recipientsPubkey: [fromHex(args.parentHex)],
    groupId: args.groupId,
  }
  const signature = sodium.crypto_sign_detached(
    computeEnvelopeDigest(header, encrypted.ciphertext),
    args.memberSecret,
  )
  await submitContent(serializeEnvelope({ header, encryptedPayload: encrypted, signature }))
}

export interface EncryptedGroupSend {
  message: TinyMessage
  sessionId: string
  index: number
  shareWarnings: string[]
  metadataWarnings: string[]
}

/**
 * Encrypt one group chat text under our sender session for the
 * group (starting/rotating the session first if needed), and
 * emit the recipients-and-times metadata records for non-member
 * parents in the current distribution. Sender ratchet state is
 * persisted BEFORE sealing, mirroring sessions.rs, so an index
 * is never reused even on failure.
 */
export async function encryptGroupMessage(
  groupIdHex: string,
  membersHex: string[],
  text: string,
): Promise<EncryptedGroupSend> {
  await sodium.ready
  const keys = await enrolledKeys()
  const ensured = await ensureGroupSession(groupIdHex)
  const sessionIdHex = ensured.sessionId
  const sessions = loadSessions()
  const session = sessions[sessionIdHex]
  if (!session || session.direction !== 'own') {
    throw new Error('Sender session state is missing; cannot encrypt the group message.')
  }
  const index = session.nextIndex
  const chainKey = fromHex(session.chainKey)
  const messageKey = deriveMessageKey(chainKey)
  session.chainKey = toHex(advanceChainKey(chainKey))
  session.nextIndex = index + 1
  session.sentKeys[String(index)] = toHex(messageKey)
  saveSessions(sessions)

  const groupId = fromHex(groupIdHex)
  const sessionId = fromHex(sessionIdHex)
  const timestamp = Math.floor(Date.now() / 1000)
  const plaintext = encodeGroupMessage({
    text,
    groupId,
    mediaRef: new Uint8Array(0),
    replyToTimestamp: 0,
  })
  const { ciphertext, nonce } = await sealSessionMessage(
    messageKey,
    groupId,
    sessionId,
    index,
    keys.memberPubkey,
    plaintext,
  )
  const header = {
    version: 1,
    timestamp,
    senderPubkey: keys.memberPubkey,
    recipientsPubkey: membersHex.map((m) => fromHex(m)),
    groupId,
  }
  const signature = sodium.crypto_sign_detached(
    computeMessageDigest(header, ciphertext),
    keys.memberSecret,
  )
  const message: TinyMessage = {
    header,
    encryptedPayload: {
      ciphertext,
      nonce,
      encryptedKeys: [],
      keyNonces: [],
      ephemeralPubkey: keys.devicePubkey,
      numRecipients: 0,
    },
    signature,
    sessionId,
    messageIndex: index,
  }

  const metadataWarnings: string[] = []
  const parents = loadGroupState()[groupIdHex]?.metadataParents || []
  for (const parentHex of parents) {
    try {
      await submitMetadataRecord({
        groupId,
        sessionId,
        messageIndex: index,
        timestamp,
        members: membersHex,
        parentHex,
        memberPubkey: keys.memberPubkey,
        memberSecret: keys.memberSecret,
      })
    } catch (e) {
      metadataWarnings.push(
        `metadata record for parent ${shortHex(parentHex)} failed: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }
  return {
    message,
    sessionId: sessionIdHex,
    index,
    shareWarnings: ensured.warnings,
    metadataWarnings,
  }
}

export interface GroupDecryptResult {
  text: string | null
  error?: string
}

/**
 * Decrypt one session message with this device's stored ratchet
 * state — a byte mirror of sessions::decrypt_session_message:
 * skipped-key cache (consumed once), replay and too-far-ahead
 * rejections with reasons, state persisted before plaintext is
 * returned. Own messages decrypt from the cached sent keys (the
 * node-side sender does not re-decrypt either; the page caches
 * the keys at seal time so the thread stays readable).
 */
export async function decryptGroupMessage(msg: TinyMessage): Promise<GroupDecryptResult> {
  if (!msg.sessionId || msg.sessionId.length === 0) {
    return { text: null, error: 'not a session message' }
  }
  const sessionIdHex = toHex(msg.sessionId)
  const cacheKey = `${sessionIdHex}:${toHex(msg.header.senderPubkey)}:${msg.messageIndex}`
  const cached = loadPlaintextCache()[cacheKey]
  if (cached !== undefined) return { text: cached }
  const sessions = loadSessions()
  const session = sessions[sessionIdHex]
  if (!session) {
    return {
      text: null,
      error: `no session key held for session ${shortHex(sessionIdHex)} — the share has not been received yet`,
    }
  }
  const index = msg.messageIndex
  const groupId = msg.header.groupId || fromHex(session.groupId)
  const senderMember = msg.header.senderPubkey
  const nonce = msg.encryptedPayload.nonce
  const ciphertext = msg.encryptedPayload.ciphertext

  const tryOpen = async (messageKey: Uint8Array): Promise<GroupDecryptResult> => {
    try {
      const plaintext = await openSessionMessage(
        messageKey,
        nonce,
        groupId,
        msg.sessionId,
        index,
        senderMember,
        ciphertext,
      )
      const text = decodeGroupMessage(plaintext).text
      cachePlaintext(sessionIdHex, toHex(senderMember), index, text)
      return { text }
    } catch {
      return { text: null, error: 'decryption failed (bad ciphertext or wrong session key)' }
    }
  }

  if (session.direction === 'own') {
    const sentKey = session.sentKeys[String(index)]
    if (!sentKey) return { text: null, error: 'own message key was not cached for this index' }
    return tryOpen(fromHex(sentKey))
  }

  const skippedKey = session.skipped[String(index)]
  if (skippedKey) {
    const result = await tryOpen(fromHex(skippedKey))
    if (result.text !== null) {
      delete session.skipped[String(index)]
      saveSessions(sessions)
    }
    return result
  }
  if (index < session.nextIndex) {
    return { text: null, error: `replay: message index ${index} was already consumed` }
  }
  if (index > session.nextIndex + MAX_MESSAGE_GAP) {
    return {
      text: null,
      error: `message index ${index} is too far ahead (next expected ${session.nextIndex})`,
    }
  }
  let chainKey = fromHex(session.chainKey)
  let current = session.nextIndex
  while (current < index) {
    session.skipped[String(current)] = toHex(deriveMessageKey(chainKey))
    chainKey = advanceChainKey(chainKey)
    current++
  }
  const messageKey = deriveMessageKey(chainKey)
  session.chainKey = toHex(advanceChainKey(chainKey))
  session.nextIndex = index + 1
  saveSessions(sessions)
  return tryOpen(messageKey)
}
