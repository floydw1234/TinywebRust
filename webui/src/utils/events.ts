import sodium from 'libsodium-wrappers'
// SHA-256 comes from @noble/hashes: the standard libsodium-wrappers build
// does not export crypto_hash_sha256 (it exists only in the -sumo build).
import { sha256 } from '@noble/hashes/sha2.js'
import {
  getDeviceStore,
  getEnrollmentMeta,
  getMemberStore,
  initEnrollmentStores,
} from './enrollment'
import { computeEnvelopeDigest } from './envelope'
import {
  CONTENT_CALENDAR_EVENT,
  serializeCalendarEvent,
  serializeRawEnvelope,
  type CalendarEventData,
} from './protobuf'

/**
 * Calendar event construction + signing — the client half of
 * rust/src/events.rs (Phase C3).
 *
 * An event version is a CalendarEvent record carried in the
 * clear as the payload of a CONTENT_CALENDAR_EVENT envelope.
 * The record is signed by the acting member's DEVICE key over
 *
 *   SHA256( "TWEVENT\0" || fields 1-15 in order )
 *
 * (fixed-size fields raw, strings with a little-endian u32
 * length prefix — byte-identical to
 * `events::calendar_event_digest`), and the envelope is signed
 * by the same device key over the envelope digest. Create,
 * update and delete (tombstone) are the same record re-issued
 * with a later updatedAt; the node keeps the newest version
 * per event id.
 */

async function enrolledKeys(): Promise<{
  memberPubkey: Uint8Array
  devicePubkey: Uint8Array
  deviceSecret: Uint8Array
}> {
  await initEnrollmentStores()
  const meta = getEnrollmentMeta()
  if (!meta) {
    throw new Error(
      'Events need the enrolled identity from the Enroll tab (member + device keys).',
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
    devicePubkey: deviceStore.getPublicKey(),
    deviceSecret: deviceStore._getPrivateKey(),
  }
}

/** Whether the enrolled member + device keys are available. */
export async function eventsIdentityReady(): Promise<boolean> {
  try {
    await enrolledKeys()
    return true
  } catch {
    return false
  }
}

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

function i64le(v: number): Uint8Array {
  // Two's complement little-endian; unix seconds fit in the
  // low word for any realistic date, with sign extension above.
  const b = new Uint8Array(8)
  const view = new DataView(b.buffer)
  view.setUint32(0, v & 0xffffffff, true)
  view.setUint32(4, v < 0 ? 0xffffffff : Math.floor(v / 0x100000000), true)
  return b
}

/** The TWEVENT signing digest of a record (signature excluded). */
export function calendarEventDigest(ev: CalendarEventData): Uint8Array {
  const domain = new TextEncoder().encode('TWEVENT\0')
  const parts: Uint8Array[] = [domain]
  const lp = (bytes: Uint8Array) => {
    parts.push(u32le(bytes.length))
    parts.push(bytes)
  }
  const enc = new TextEncoder()
  parts.push(ev.eventId)
  lp(enc.encode(ev.title))
  lp(enc.encode(ev.notes))
  lp(enc.encode(ev.location))
  parts.push(i64le(ev.startUnix))
  parts.push(i64le(ev.endUnix))
  lp(enc.encode(ev.timezone))
  parts.push(new Uint8Array([ev.allDay ? 1 : 0]))
  lp(enc.encode(ev.rrule))
  parts.push(ev.createdBy)
  parts.push(ev.actorMemberPubkey)
  parts.push(ev.actorDevicePubkey)
  parts.push(u64le(ev.createdAt))
  parts.push(u64le(ev.updatedAt))
  parts.push(new Uint8Array([ev.deleted ? 1 : 0]))

  const total = parts.reduce((n, p) => n + p.length, 0)
  const combined = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    combined.set(p, offset)
    offset += p.length
  }
  return sha256(combined)
}

export interface EventFields {
  title: string
  notes: string
  location: string
  startUnix: number
  endUnix: number
  timezone: string
  allDay: boolean
  rrule: string
}

/**
 * Build the signed envelope bytes for one event version.
 *
 * - No `existing`: a create — a fresh event id, createdBy is
 *   the enrolled member, createdAt = updatedAt = now.
 * - With `existing` (and optionally `deleted`): a new version
 *   of that event — same id and createdAt/createdBy, fields
 *   from `fields` (for a tombstone, pass the existing fields),
 *   updatedAt strictly after the held version's.
 */
export async function buildEventEnvelope(args: {
  fields: EventFields
  existing?: CalendarEventData
  deleted?: boolean
}): Promise<Uint8Array> {
  await sodium.ready
  const keys = await enrolledKeys()
  const now = Math.floor(Date.now() / 1000)
  const existing = args.existing
  const record: CalendarEventData = {
    eventId: existing ? existing.eventId : sodium.randombytes_buf(16),
    title: args.fields.title,
    notes: args.fields.notes,
    location: args.fields.location,
    startUnix: args.fields.startUnix,
    endUnix: args.fields.endUnix,
    timezone: args.fields.timezone,
    allDay: args.fields.allDay,
    rrule: args.fields.rrule,
    createdBy: existing ? existing.createdBy : keys.memberPubkey,
    actorMemberPubkey: keys.memberPubkey,
    actorDevicePubkey: keys.devicePubkey,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: existing ? Math.max(now, existing.updatedAt + 1) : now,
    deleted: !!args.deleted,
    signature: new Uint8Array(0),
  }
  const digest = calendarEventDigest(record)
  record.signature = sodium.crypto_sign_detached(digest, keys.deviceSecret)
  const payload = serializeCalendarEvent(record)
  const header = {
    version: 1,
    contentType: CONTENT_CALENDAR_EVENT,
    schemaVersion: 1,
    timestamp: record.updatedAt,
    senderPubkey: keys.devicePubkey,
    recipientsPubkey: [] as Uint8Array[],
    groupId: null,
  }
  const envelopeDigest = computeEnvelopeDigest(header, payload)
  const envelopeSignature = sodium.crypto_sign_detached(envelopeDigest, keys.deviceSecret)
  return serializeRawEnvelope({
    header,
    payloadNonce: new Uint8Array(24),
    ephemeralPubkey: keys.devicePubkey,
    payloadCiphertext: payload,
    keywraps: [],
    signature: envelopeSignature,
  })
}

// ---------------------------------------------------------------------------
// Wall time <-> unix conversion in an arbitrary IANA timezone
// ---------------------------------------------------------------------------

/**
 * The unix instant of a wall-clock time in `timeZone`
 * (e.g. "2026-11-22T16:00" in "America/Denver"). Uses the
 * standard Intl offset-refinement: guess UTC, read the zone's
 * wall time at that instant, correct by the difference, and
 * repeat once (enough outside the ambiguous minutes at a DST
 * fold, where the first occurrence wins).
 */
export function zonedTimeToUnix(localIso: string, timeZone: string): number {
  const [datePart, timePart = '00:00'] = localIso.split('T')
  const [y, mo, d] = datePart.split('-').map((n) => parseInt(n, 10))
  const [hh, mm] = timePart.split(':').map((n) => parseInt(n, 10))
  const wallAsUtc = Date.UTC(y, mo - 1, d, hh, mm) / 1000
  let guess = wallAsUtc
  for (let i = 0; i < 2; i++) {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).formatToParts(new Date(guess * 1000))
    const get = (type: string) => parseInt(parts.find((p) => p.type === type)?.value || '0', 10)
    const seenAsUtc =
      Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second')) /
      1000
    const correction = wallAsUtc - seenAsUtc
    if (correction === 0) break
    guess += correction
  }
  return guess
}

/** Format an instant in the event's own timezone. */
export function formatEventTime(unixSeconds: number, timeZone: string, allDay: boolean): string {
  try {
    const fmt = new Intl.DateTimeFormat('en-US', {
      timeZone: timeZone || undefined,
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      ...(allDay ? {} : { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }),
    })
    return fmt.format(new Date(unixSeconds * 1000))
  } catch {
    return new Date(unixSeconds * 1000).toLocaleString()
  }
}
