import sodium from 'libsodium-wrappers'
import { signRequest } from './utils/requestAuth'
import { decryptPayload } from './utils/encryption'
import { fromHex, toHex } from './utils/hex'
import {
  decodeLocationUpdate,
  deserializeClientRequest,
  deserializeEnvelope,
  deserializeMessageList,
  decodeConversationList,
  type ConversationSummary,
  type LocationUpdateData,
  type TinyMessage,
} from './utils/protobuf'

/**
 * Node API client.
 *
 * Base URL: stored in localStorage (`tinyweb_node_base`), default "/api".
 * The Vite dev server proxies /api/* to the node at http://localhost:8000
 * (prefix stripped), so the default path is same-origin. A direct node URL
 * (e.g. http://localhost:8001) also works — the node sends CORS headers.
 *
 * Signing always uses the path the NODE sees (e.g. /messages/recent),
 * never the /api-prefixed browser URL.
 */

const BASE_KEY = 'tinyweb_node_base'

export function getBaseUrl(): string {
  return localStorage.getItem(BASE_KEY) || '/api'
}

export function setBaseUrl(url: string): void {
  const v = url.trim()
  if (!v || v === '/api') localStorage.removeItem(BASE_KEY)
  else localStorage.setItem(BASE_KEY, v.replace(/\/$/, ''))
}

// ---- Raw call log (for the dashboard's raw response viewer) ----

export interface RawCall {
  id: number
  at: number
  method: string
  path: string // node path, e.g. /messages/recent?user=...
  url: string // actual URL fetched
  status: number | null
  ok: boolean
  body: string // text body, or a hex preview for binary bodies
  error?: string
}

const rawCalls: RawCall[] = []
const listeners = new Set<(calls: RawCall[]) => void>()
let nextId = 1

export function getRawCalls(): RawCall[] {
  return rawCalls
}

export function subscribeRawCalls(fn: (calls: RawCall[]) => void): () => void {
  listeners.add(fn)
  fn(rawCalls)
  return () => listeners.delete(fn)
}

function recordCall(call: RawCall): void {
  rawCalls.unshift(call)
  if (rawCalls.length > 50) rawCalls.length = 50
  for (const fn of listeners) fn(rawCalls)
}

// ---- Core fetch ----

export interface ApiResult {
  status: number
  ok: boolean
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any
  text: string
  bytes: Uint8Array
}

function describeBody(bytes: Uint8Array, contentType: string | null): { text: string; isText: boolean } {
  if (contentType && (contentType.includes('json') || contentType.includes('text'))) {
    return { text: new TextDecoder().decode(bytes), isText: true }
  }
  // Heuristic: printable ASCII/UTF-8 JSON-ish bodies are shown as text.
  if (bytes.length > 0 && (bytes[0] === 0x7b || bytes[0] === 0x5b)) {
    try {
      return { text: new TextDecoder().decode(bytes), isText: true }
    } catch {
      /* fall through */
    }
  }
  if (bytes.length === 0) return { text: '', isText: true }
  const preview = bytes.slice(0, 256)
  return {
    text: `<binary ${bytes.length} bytes>\nhex preview: ${toHex(preview)}${bytes.length > 256 ? '…' : ''}`,
    isText: false,
  }
}

async function rawFetch(
  method: string,
  nodePath: string,
  opts: { signed?: boolean; body?: BodyInit; headers?: Record<string, string> } = {},
): Promise<ApiResult> {
  const base = getBaseUrl()
  const url = base + nodePath
  const parsed = new URL(nodePath, 'http://node.local')
  const pathOnly = parsed.pathname
  const query = parsed.search ? parsed.search.substring(1) : ''

  const headers: Record<string, string> = { ...(opts.headers || {}) }
  if (opts.signed) {
    const auth = await signRequest(method, pathOnly, query)
    Object.assign(headers, auth)
  }

  const call: RawCall = {
    id: nextId++,
    at: Date.now(),
    method,
    path: nodePath,
    url,
    status: null,
    ok: false,
    body: '',
  }

  try {
    const response = await fetch(url, { method, headers, body: opts.body })
    const buf = new Uint8Array(await response.arrayBuffer())
    const { text } = describeBody(buf, response.headers.get('Content-Type'))
    call.status = response.status
    call.ok = response.ok
    call.body = text
    recordCall(call)

    let json = null
    try {
      json = JSON.parse(text)
    } catch {
      /* not JSON */
    }
    return { status: response.status, ok: response.ok, json, text, bytes: buf }
  } catch (e) {
    call.error = e instanceof Error ? e.message : String(e)
    call.body = `Network error: ${call.error}`
    recordCall(call)
    throw new Error(`Request to ${url} failed: ${call.error}`)
  }
}

function throwIfError(result: ApiResult, what: string): void {
  if (!result.ok) {
    const msg = result.json?.error || result.text || `HTTP ${result.status}`
    throw new Error(`${what}: ${msg}`)
  }
}

// ---- Endpoints ----

export async function getHealth(): Promise<unknown> {
  const r = await rawFetch('GET', '/health')
  throwIfError(r, 'Health check failed')
  return r.json ?? r.text
}

export async function getPeers(): Promise<unknown> {
  const r = await rawFetch('GET', '/gossip/peers')
  throwIfError(r, 'Failed to get peers')
  return r.json ?? r.text
}

/** POST /auth/login — verifies the signed request against the node's user registry. */
export async function login(): Promise<unknown> {
  const r = await rawFetch('POST', '/auth/login', {
    signed: true,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })
  throwIfError(r, 'Login failed')
  return r.json
}

export interface NodeUser {
  pubkey: string
  username: string
  age?: number
}

export async function getUsers(): Promise<NodeUser[]> {
  const r = await rawFetch('GET', '/users', { signed: true })
  throwIfError(r, 'Failed to get users')
  return (r.json?.users || []) as NodeUser[]
}

export async function submitMessage(messageBytes: Uint8Array): Promise<unknown> {
  const r = await rawFetch('POST', '/messages/submit', {
    signed: true,
    headers: { 'Content-Type': 'application/x-protobuf' },
    body: messageBytes as BodyInit,
  })
  throwIfError(r, 'Failed to send message')
  return r.json ?? r.text
}

export async function getRecentMessages(userPubkeyHex: string, limit = 50): Promise<TinyMessage[]> {
  const r = await rawFetch('GET', `/messages/recent?user=${userPubkeyHex}&limit=${limit}`, {
    signed: true,
    headers: { Accept: 'application/x-protobuf' },
  })
  throwIfError(r, 'Failed to get recent messages')
  return deserializeMessageList(r.bytes)
}

export async function getConversations(userPubkeyHex: string): Promise<ConversationSummary[]> {
  const r = await rawFetch('GET', `/messages/conversations?user=${userPubkeyHex}`, {
    signed: true,
    headers: { Accept: 'application/x-protobuf' },
  })
  throwIfError(r, 'Failed to get conversations')
  return decodeConversationList(r.bytes)
}

export async function getConversation(
  userPubkeyHex: string,
  withPubkeyHex: string,
): Promise<TinyMessage[]> {
  const r = await rawFetch(
    'GET',
    `/messages/conversation?user=${userPubkeyHex}&with=${withPubkeyHex}`,
    { signed: true, headers: { Accept: 'application/x-protobuf' } },
  )
  throwIfError(r, 'Failed to get conversation')
  return deserializeMessageList(r.bytes)
}

export async function submitLocation(requestBytes: Uint8Array): Promise<unknown> {
  const r = await rawFetch('POST', '/location/update', {
    signed: true,
    headers: { 'Content-Type': 'application/x-protobuf' },
    body: requestBytes as BodyInit,
  })
  throwIfError(r, 'Failed to submit location')
  return r.json ?? r.text
}

/** Decode + decrypt one stored location record (Envelope or ClientRequest bytes, hex). */
export async function decryptLocationRecord(
  dataHex: string,
  isEnvelope: boolean,
): Promise<LocationUpdateData> {
  await sodium.ready
  const bytes = fromHex(dataHex)
  const decoded = isEnvelope ? deserializeEnvelope(bytes) : deserializeClientRequest(bytes)
  const recipientsX = decoded.header.recipientsPubkey.map((pk) =>
    sodium.crypto_sign_ed25519_pk_to_curve25519(pk),
  )
  const plaintext = await decryptPayload(decoded.encryptedPayload, recipientsX)
  return decodeLocationUpdate(plaintext)
}

export async function getLocation(userPubkeyHex: string): Promise<LocationUpdateData> {
  const r = await rawFetch('GET', `/location/${userPubkeyHex}`, { signed: true })
  throwIfError(r, 'Failed to get location')
  if (!r.json?.data_hex) throw new Error('Invalid response (missing data_hex)')
  return decryptLocationRecord(r.json.data_hex, !!r.json.is_envelope)
}

export async function getLocationHistory(
  userPubkeyHex: string,
  limit = 50,
  offset = 0,
): Promise<{ updates: LocationUpdateData[]; failed: number }> {
  const r = await rawFetch(
    'GET',
    `/location/history/${userPubkeyHex}?limit=${limit}&offset=${offset}`,
    { signed: true },
  )
  throwIfError(r, 'Failed to get location history')
  const records = (r.json?.updates || []) as Array<{ data_hex?: string; is_envelope?: boolean }>
  const updates: LocationUpdateData[] = []
  let failed = 0
  for (const rec of records) {
    if (!rec.data_hex) {
      failed++
      continue
    }
    try {
      updates.push(await decryptLocationRecord(rec.data_hex, !!rec.is_envelope))
    } catch {
      failed++
    }
  }
  return { updates, failed }
}

// ---- Enrollment (Phase B3/B5) ----

export interface EnrollBeginRequest {
  member_pubkey: string
  device_pubkey: string
  display_name: string
  device_cert: string // hex of the serialized DeviceCertificate protobuf
}

export interface EnrollBeginResult {
  status: string
  code: string
  expires_at: number
  member_pubkey: string
  device_pubkey: string
}

/**
 * POST /enroll/begin — open a pairing for a joining member/device.
 * Unauthenticated by design: the device has no credentials yet; the
 * returned single-use code is the capability, and nothing is
 * enrolled until an approver signs.
 */
export async function enrollBegin(body: EnrollBeginRequest): Promise<EnrollBeginResult> {
  const r = await rawFetch('POST', '/enroll/begin', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  throwIfError(r, 'Enrollment begin failed')
  return r.json as EnrollBeginResult
}

export interface EnrollStatusResult {
  status: string // pending | approved | expired | unknown
  member_pubkey?: string
  device_pubkey?: string
  expires_at?: number
}

/** GET /enroll/status?code=... — poll a pairing (the code is the capability). */
export async function enrollStatus(code: string): Promise<EnrollStatusResult> {
  const r = await rawFetch('GET', `/enroll/status?code=${encodeURIComponent(code)}`)
  throwIfError(r, 'Enrollment status failed')
  return r.json as EnrollStatusResult
}

// ---- Message decryption helper ----

/** Decrypt a message's text with the loaded identity; null if not decryptable. */
export async function decryptMessageText(msg: TinyMessage): Promise<string | null> {
  try {
    await sodium.ready
    const recipientsX = msg.header.recipientsPubkey.map((pk) =>
      sodium.crypto_sign_ed25519_pk_to_curve25519(pk),
    )
    const plaintext = await decryptPayload(msg.encryptedPayload, recipientsX)
    return new TextDecoder().decode(plaintext)
  } catch {
    return null
  }
}
