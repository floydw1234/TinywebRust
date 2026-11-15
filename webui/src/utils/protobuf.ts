import protobuf from 'protobufjs'
import { emptyPayload, type EncryptedPayload } from './encryption'
import { toHex } from './hex'

/**
 * Protobuf wire types — schemas and (de)serializers ported from the C
 * web-ui helpers (messageHelper.js, clientRequestHelper.js,
 * envelopeHelper.js, protobufDecode.js), matching src/proto/*.proto.
 */

export interface MessageHeaderData {
  version: number
  timestamp: number // unix seconds
  senderPubkey: Uint8Array
  recipientsPubkey: Uint8Array[]
  groupId: Uint8Array | null
}

export interface TinyMessage {
  header: MessageHeaderData
  encryptedPayload: EncryptedPayload
  signature: Uint8Array
  /** Sender-session id (Message field 7); empty for legacy wrap messages. */
  sessionId: Uint8Array
  /** Sender-session ratchet index (Message field 8); 0 for legacy messages. */
  messageIndex: number
}

export interface ClientRequestHeaderData {
  version: number
  contentType: number
  schemaVersion: number
  timestamp: number // unix seconds
  senderPubkey: Uint8Array
  recipientsPubkey: Uint8Array[]
  groupId: Uint8Array | null
}

export interface TinyClientRequest {
  header: ClientRequestHeaderData
  encryptedPayload: EncryptedPayload
  signature: Uint8Array
}

export interface ConversationSummary {
  partnerPubkey: Uint8Array
  partnerPubkeyHex: string
  lastMessageTimestamp: number // unix seconds
  unreadCount: number
  lastMessagePreview: Uint8Array | null
}

export interface LocationUpdateData {
  lat: number
  lon: number
  accuracy_m: number
  timestamp: number // unix seconds
  location_name: string
}

/** CONTENT_LOCATION_UPDATE in envelope.proto. */
export const CONTENT_LOCATION_UPDATE = 33

const PROTO_DEFINITION = `
  syntax = "proto3";
  package tinyweb;

  message MessageHeader {
    uint32 version = 1;
    uint64 timestamp = 2;
    bytes sender_pubkey = 3;
    repeated bytes recipients_pubkey = 4;
    bytes group_id = 5;
  }

  message MessageRecipientKeyWrap {
    bytes recipient_pubkey = 1;
    bytes key_nonce = 2;
    bytes wrapped_key = 3;
  }

  message Message {
    MessageHeader header = 1;
    bytes payload_nonce = 2;
    bytes ephemeral_pubkey = 3;
    bytes payload_ciphertext = 4;
    repeated MessageRecipientKeyWrap keywraps = 5;
    bytes signature = 6;
    bytes session_id = 7;
    uint64 message_index = 8;
  }

  message GroupMessage {
    string text = 1;
    bytes group_id = 2;
    bytes media_ref = 3;
    uint64 reply_to_timestamp = 4;
  }

  message GroupKeyShare {
    bytes group_id = 1;
    bytes session_id = 2;
    bytes sender_member_pubkey = 3;
    bytes sender_device_pubkey = 4;
    bytes recipient_member_pubkey = 5;
    bytes recipient_device_pubkey = 6;
    uint64 created_at = 7;
    bytes wrapped_key_hash = 8;
    bytes signature = 9;
  }

  message ConversationMetadata {
    bytes group_id = 1;
    bytes sender_member_pubkey = 2;
    repeated bytes recipient_member_pubkeys = 3;
    uint64 message_timestamp = 4;
    bytes session_id = 5;
    uint64 message_index = 6;
  }

  message MessageList {
    repeated Message messages = 1;
    uint32 total_count = 2;
  }

  message ConversationSummary {
    bytes partner_pubkey = 1;
    uint64 last_message_timestamp = 2;
    uint32 unread_count = 3;
    bytes last_message_preview = 4;
  }

  message ConversationList {
    repeated ConversationSummary conversations = 1;
    uint32 total_count = 2;
  }

  message ClientRequestHeader {
    uint32 version = 1;
    uint32 content_type = 2;
    uint32 schema_version = 3;
    uint64 timestamp = 4;
    bytes sender_pubkey = 5;
    repeated bytes recipients_pubkey = 6;
    bytes group_id = 7;
  }

  message ClientRequestKeyWrap {
    bytes recipient_pubkey = 1;
    bytes key_nonce = 2;
    bytes wrapped_key = 3;
  }

  message ClientRequest {
    ClientRequestHeader header = 1;
    bytes payload_nonce = 2;
    bytes ephemeral_pubkey = 3;
    bytes payload_ciphertext = 4;
    repeated ClientRequestKeyWrap keywraps = 5;
    bytes signature = 6;
  }

  message EnvelopeHeader {
    uint32 version = 1;
    uint32 content_type = 2;
    uint32 schema_version = 3;
    uint64 timestamp = 4;
    bytes sender_pubkey = 5;
    repeated bytes recipients_pubkey = 6;
    bytes group_id = 7;
  }

  message RecipientKeyWrap {
    bytes recipient_pubkey = 1;
    bytes key_nonce = 2;
    bytes wrapped_key = 3;
  }

  message Envelope {
    EnvelopeHeader header = 1;
    bytes payload_nonce = 2;
    bytes ephemeral_pubkey = 3;
    bytes payload_ciphertext = 4;
    repeated RecipientKeyWrap keywraps = 5;
    bytes signature = 6;
  }

  message LocationUpdate {
    double lat = 1;
    double lon = 2;
    uint32 accuracy_m = 3;
    uint64 timestamp = 4;
    string location_name = 5;
  }

  message DeviceCertificate {
    bytes member_pubkey = 1;
    bytes device_pubkey = 2;
    string label = 3;
    uint64 issued_at = 4;
    uint64 expires_at = 5;
    bytes signature = 6;
  }

  message CalendarEvent {
    bytes event_id = 1;
    string title = 2;
    string notes = 3;
    string location = 4;
    int64 start_unix = 5;
    int64 end_unix = 6;
    string timezone = 7;
    bool all_day = 8;
    string rrule = 9;
    bytes created_by = 10;
    bytes actor_member_pubkey = 11;
    bytes actor_device_pubkey = 12;
    uint64 created_at = 13;
    uint64 updated_at = 14;
    bool deleted = 15;
    bytes signature = 16;
  }
`

interface Types {
  Message: protobuf.Type
  MessageList: protobuf.Type
  ConversationList: protobuf.Type
  ClientRequest: protobuf.Type
  Envelope: protobuf.Type
  LocationUpdate: protobuf.Type
  DeviceCertificate: protobuf.Type
  GroupMessage: protobuf.Type
  GroupKeyShare: protobuf.Type
  ConversationMetadata: protobuf.Type
  CalendarEvent: protobuf.Type
}

let cached: Types | null = null

function types(): Types {
  if (cached) return cached
  const root = protobuf.parse(PROTO_DEFINITION, { keepCase: true }).root
  cached = {
    Message: root.lookupType('tinyweb.Message'),
    MessageList: root.lookupType('tinyweb.MessageList'),
    ConversationList: root.lookupType('tinyweb.ConversationList'),
    ClientRequest: root.lookupType('tinyweb.ClientRequest'),
    Envelope: root.lookupType('tinyweb.Envelope'),
    LocationUpdate: root.lookupType('tinyweb.LocationUpdate'),
    DeviceCertificate: root.lookupType('tinyweb.DeviceCertificate'),
    GroupMessage: root.lookupType('tinyweb.GroupMessage'),
    GroupKeyShare: root.lookupType('tinyweb.GroupKeyShare'),
    ConversationMetadata: root.lookupType('tinyweb.ConversationMetadata'),
    CalendarEvent: root.lookupType('tinyweb.CalendarEvent'),
  }
  return cached
}

function asBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return new Uint8Array(v)
  if (Array.isArray(v)) return new Uint8Array(v as number[])
  return new Uint8Array(0)
}

interface KeyWrapLike {
  recipient_pubkey?: unknown
  key_nonce?: unknown
  wrapped_key?: unknown
}

/** Rebuild an EncryptedPayload from protobuf fields + keywraps, aligning
 *  wrapped keys to the header recipient order (as the C web-ui does). */
function payloadFromParts(
  ciphertext: unknown,
  nonce: unknown,
  ephemeralPubkey: unknown,
  keywraps: KeyWrapLike[] | undefined,
  recipients: Uint8Array[],
): EncryptedPayload {
  const payload = emptyPayload()
  payload.ciphertext = asBytes(ciphertext)
  payload.nonce = asBytes(nonce)
  payload.ephemeralPubkey = asBytes(ephemeralPubkey)
  payload.numRecipients = recipients.length

  const byRecipient = new Map<string, KeyWrapLike>()
  for (const kw of keywraps || []) {
    byRecipient.set(toHex(asBytes(kw.recipient_pubkey)), kw)
  }
  for (const rp of recipients) {
    const kw = byRecipient.get(toHex(rp))
    if (kw) {
      payload.encryptedKeys.push(asBytes(kw.wrapped_key))
      payload.keyNonces.push(asBytes(kw.key_nonce))
    } else {
      payload.encryptedKeys.push(new Uint8Array(0))
      payload.keyNonces.push(new Uint8Array(0))
    }
  }
  return payload
}

function keywrapsFromPayload(payload: EncryptedPayload, recipients: Uint8Array[]) {
  return recipients.map((rp, i) => ({
    recipient_pubkey: rp,
    key_nonce: payload.keyNonces[i] || new Uint8Array(0),
    wrapped_key: payload.encryptedKeys[i] || new Uint8Array(0),
  }))
}

// ---- Message ----

export function serializeMessage(msg: TinyMessage): Uint8Array {
  const t = types()
  const proto = {
    header: {
      version: msg.header.version,
      timestamp: msg.header.timestamp,
      sender_pubkey: msg.header.senderPubkey,
      recipients_pubkey: msg.header.recipientsPubkey,
      group_id: msg.header.groupId || new Uint8Array(0),
    },
    payload_nonce: msg.encryptedPayload.nonce,
    ephemeral_pubkey: msg.encryptedPayload.ephemeralPubkey,
    payload_ciphertext: msg.encryptedPayload.ciphertext,
    keywraps:
      msg.sessionId && msg.sessionId.length > 0
        ? []
        : keywrapsFromPayload(msg.encryptedPayload, msg.header.recipientsPubkey),
    signature: msg.signature,
    session_id: msg.sessionId || new Uint8Array(0),
    message_index: msg.messageIndex || 0,
  }
  const err = t.Message.verify(proto)
  if (err) throw new Error(`Invalid message: ${err}`)
  return new Uint8Array(t.Message.encode(t.Message.create(proto)).finish())
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function messageFromDecoded(m: any): TinyMessage {
  const recipients = (m.header.recipients_pubkey || []).map((pk: unknown) => asBytes(pk))
  return {
    header: {
      version: m.header.version,
      timestamp: Number(m.header.timestamp),
      senderPubkey: asBytes(m.header.sender_pubkey),
      recipientsPubkey: recipients,
      groupId:
        m.header.group_id && m.header.group_id.length > 0 ? asBytes(m.header.group_id) : null,
    },
    encryptedPayload: payloadFromParts(
      m.payload_ciphertext,
      m.payload_nonce,
      m.ephemeral_pubkey,
      m.keywraps,
      recipients,
    ),
    signature: asBytes(m.signature),
    sessionId: asBytes(m.session_id),
    messageIndex: Number(m.message_index || 0),
  }
}

export function deserializeMessage(bytes: Uint8Array): TinyMessage {
  const t = types()
  return messageFromDecoded(t.Message.decode(bytes))
}

export function deserializeMessageList(bytes: Uint8Array): TinyMessage[] {
  const t = types()
  const list = t.MessageList.decode(bytes) as unknown as { messages?: unknown[] }
  const out: TinyMessage[] = []
  for (const mp of list.messages || []) {
    // Re-encode then decode through the single-message path, as the C web-ui does.
    const encoded = t.Message.encode(mp as protobuf.Message).finish()
    out.push(messageFromDecoded(t.Message.decode(new Uint8Array(encoded))))
  }
  return out
}

export function decodeConversationList(bytes: Uint8Array): ConversationSummary[] {
  const t = types()
  const list = t.ConversationList.decode(bytes) as unknown as {
    conversations?: Array<{
      partner_pubkey?: unknown
      last_message_timestamp?: unknown
      unread_count?: number
      last_message_preview?: unknown
    }>
  }
  return (list.conversations || []).map((c) => {
    const partner = asBytes(c.partner_pubkey)
    return {
      partnerPubkey: partner,
      partnerPubkeyHex: toHex(partner),
      lastMessageTimestamp: Number(c.last_message_timestamp || 0),
      unreadCount: c.unread_count || 0,
      lastMessagePreview:
        c.last_message_preview && asBytes(c.last_message_preview).length > 0
          ? asBytes(c.last_message_preview)
          : null,
    }
  })
}

// ---- ClientRequest (legacy decode only: stored pre-envelope ----
// location records may still be ClientRequest bytes; new
// submissions are Envelopes, so there is no serializeClientRequest.)

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function clientRequestFromDecoded(r: any): TinyClientRequest {
  const recipients = (r.header.recipients_pubkey || []).map((pk: unknown) => asBytes(pk))
  return {
    header: {
      version: r.header.version,
      contentType: r.header.content_type,
      schemaVersion: r.header.schema_version,
      timestamp: Number(r.header.timestamp),
      senderPubkey: asBytes(r.header.sender_pubkey),
      recipientsPubkey: recipients,
      groupId:
        r.header.group_id && r.header.group_id.length > 0 ? asBytes(r.header.group_id) : null,
    },
    encryptedPayload: payloadFromParts(
      r.payload_ciphertext,
      r.payload_nonce,
      r.ephemeral_pubkey,
      r.keywraps,
      recipients,
    ),
    signature: asBytes(r.signature),
  }
}

export function deserializeClientRequest(bytes: Uint8Array): TinyClientRequest {
  const t = types()
  return clientRequestFromDecoded(t.ClientRequest.decode(bytes))
}

// ---- Envelope (same field layout as ClientRequest) ----

/**
 * Serialize a submission as an Envelope. Location updates are
 * envelopes on the wire (see utils/envelope.ts); the encoding is
 * byte-identical to the ClientRequest layout, only the protobuf
 * type — and the signing domain — differ.
 */
export function serializeEnvelope(req: TinyClientRequest): Uint8Array {
  const t = types()
  const proto = {
    header: {
      version: req.header.version,
      content_type: req.header.contentType,
      schema_version: req.header.schemaVersion,
      timestamp: req.header.timestamp,
      sender_pubkey: req.header.senderPubkey,
      recipients_pubkey: req.header.recipientsPubkey,
      group_id: req.header.groupId || new Uint8Array(0),
    },
    payload_nonce: req.encryptedPayload.nonce,
    ephemeral_pubkey: req.encryptedPayload.ephemeralPubkey,
    payload_ciphertext: req.encryptedPayload.ciphertext,
    keywraps: keywrapsFromPayload(req.encryptedPayload, req.header.recipientsPubkey),
    signature: req.signature,
  }
  const err = t.Envelope.verify(proto)
  if (err) throw new Error(`Invalid Envelope: ${err}`)
  return new Uint8Array(t.Envelope.encode(t.Envelope.create(proto)).finish())
}

export function deserializeEnvelope(bytes: Uint8Array): TinyClientRequest {
  const t = types()
  return clientRequestFromDecoded(t.Envelope.decode(bytes))
}

// ---- LocationUpdate ----

export function encodeLocationUpdate(loc: LocationUpdateData): Uint8Array {
  const t = types()
  const proto = {
    lat: loc.lat,
    lon: loc.lon,
    accuracy_m: loc.accuracy_m || 0,
    timestamp: loc.timestamp,
    location_name: loc.location_name || '',
  }
  const err = t.LocationUpdate.verify(proto)
  if (err) throw new Error(`Invalid LocationUpdate: ${err}`)
  return new Uint8Array(t.LocationUpdate.encode(t.LocationUpdate.create(proto)).finish())
}

export function decodeLocationUpdate(bytes: Uint8Array): LocationUpdateData {
  const t = types()
  const loc = t.LocationUpdate.decode(bytes) as unknown as {
    lat: number
    lon: number
    accuracy_m?: number
    timestamp?: unknown
    location_name?: string
  }
  return {
    lat: loc.lat,
    lon: loc.lon,
    accuracy_m: loc.accuracy_m || 0,
    timestamp: Number(loc.timestamp || 0),
    location_name: loc.location_name || '',
  }
}

// ---- DeviceCertificate (content.proto; enrollment, Phase B3) ----

/**
 * A member key's signed vouch for a device key. Field numbers and
 * semantics match content.proto exactly; the signature inside is
 * over the TWDEVCERT digest (see utils/deviceCert.ts).
 */
export interface DeviceCertificateData {
  memberPubkey: Uint8Array
  devicePubkey: Uint8Array
  label: string
  issuedAt: number // unix seconds
  expiresAt: number // unix seconds; 0 = never expires
  signature: Uint8Array
}

export function serializeDeviceCertificate(cert: DeviceCertificateData): Uint8Array {
  const t = types()
  const proto = {
    member_pubkey: cert.memberPubkey,
    device_pubkey: cert.devicePubkey,
    label: cert.label,
    issued_at: cert.issuedAt,
    expires_at: cert.expiresAt,
    signature: cert.signature,
  }
  const err = t.DeviceCertificate.verify(proto)
  if (err) throw new Error(`Invalid DeviceCertificate: ${err}`)
  return new Uint8Array(t.DeviceCertificate.encode(t.DeviceCertificate.create(proto)).finish())
}

export function deserializeDeviceCertificate(bytes: Uint8Array): DeviceCertificateData {
  const t = types()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const c = t.DeviceCertificate.decode(bytes) as any
  return {
    memberPubkey: asBytes(c.member_pubkey),
    devicePubkey: asBytes(c.device_pubkey),
    label: c.label || '',
    issuedAt: Number(c.issued_at || 0),
    expiresAt: Number(c.expires_at || 0),
    signature: asBytes(c.signature),
  }
}

// ---- GroupMessage (content.proto; group chat plaintext, Phase B4) ----

export interface GroupMessageData {
  text: string
  groupId: Uint8Array
  mediaRef: Uint8Array
  replyToTimestamp: number
}

export function encodeGroupMessage(msg: GroupMessageData): Uint8Array {
  const t = types()
  const proto = {
    text: msg.text,
    group_id: msg.groupId,
    media_ref: msg.mediaRef || new Uint8Array(0),
    reply_to_timestamp: msg.replyToTimestamp || 0,
  }
  const err = t.GroupMessage.verify(proto)
  if (err) throw new Error(`Invalid GroupMessage: ${err}`)
  return new Uint8Array(t.GroupMessage.encode(t.GroupMessage.create(proto)).finish())
}

export function decodeGroupMessage(bytes: Uint8Array): GroupMessageData {
  const t = types()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const m = t.GroupMessage.decode(bytes) as any
  return {
    text: m.text || '',
    groupId: asBytes(m.group_id),
    mediaRef: asBytes(m.media_ref),
    replyToTimestamp: Number(m.reply_to_timestamp || 0),
  }
}

// ---- GroupKeyShare (content.proto; sender-session handout, Phase B4) ----

export interface GroupKeyShareData {
  groupId: Uint8Array
  sessionId: Uint8Array
  senderMemberPubkey: Uint8Array
  senderDevicePubkey: Uint8Array
  recipientMemberPubkey: Uint8Array
  recipientDevicePubkey: Uint8Array
  createdAt: number
  wrappedKeyHash: Uint8Array
  signature: Uint8Array
}

export function serializeGroupKeyShare(share: GroupKeyShareData): Uint8Array {
  const t = types()
  const proto = {
    group_id: share.groupId,
    session_id: share.sessionId,
    sender_member_pubkey: share.senderMemberPubkey,
    sender_device_pubkey: share.senderDevicePubkey,
    recipient_member_pubkey: share.recipientMemberPubkey,
    recipient_device_pubkey: share.recipientDevicePubkey,
    created_at: share.createdAt,
    wrapped_key_hash: share.wrappedKeyHash,
    signature: share.signature,
  }
  const err = t.GroupKeyShare.verify(proto)
  if (err) throw new Error(`Invalid GroupKeyShare: ${err}`)
  return new Uint8Array(t.GroupKeyShare.encode(t.GroupKeyShare.create(proto)).finish())
}

export function deserializeGroupKeyShare(bytes: Uint8Array): GroupKeyShareData {
  const t = types()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const s = t.GroupKeyShare.decode(bytes) as any
  return {
    groupId: asBytes(s.group_id),
    sessionId: asBytes(s.session_id),
    senderMemberPubkey: asBytes(s.sender_member_pubkey),
    senderDevicePubkey: asBytes(s.sender_device_pubkey),
    recipientMemberPubkey: asBytes(s.recipient_member_pubkey),
    recipientDevicePubkey: asBytes(s.recipient_device_pubkey),
    createdAt: Number(s.created_at || 0),
    wrappedKeyHash: asBytes(s.wrapped_key_hash),
    signature: asBytes(s.signature),
  }
}

// ---- ConversationMetadata (content.proto; recipients-and-times, Phase B4) ----

export interface ConversationMetadataData {
  groupId: Uint8Array
  senderMemberPubkey: Uint8Array
  recipientMemberPubkeys: Uint8Array[]
  messageTimestamp: number
  sessionId: Uint8Array
  messageIndex: number
}

export function serializeConversationMetadata(meta: ConversationMetadataData): Uint8Array {
  const t = types()
  const proto = {
    group_id: meta.groupId,
    sender_member_pubkey: meta.senderMemberPubkey,
    recipient_member_pubkeys: meta.recipientMemberPubkeys,
    message_timestamp: meta.messageTimestamp,
    session_id: meta.sessionId,
    message_index: meta.messageIndex,
  }
  const err = t.ConversationMetadata.verify(proto)
  if (err) throw new Error(`Invalid ConversationMetadata: ${err}`)
  return new Uint8Array(
    t.ConversationMetadata.encode(t.ConversationMetadata.create(proto)).finish(),
  )
}

// ---- Raw envelopes (share + metadata transport, Phase C2) ----

/**
 * An Envelope whose payload fields are carried verbatim — unlike
 * TinyClientRequest, whose payload is an EncryptedPayload (the
 * location shape). Group key shares ride an envelope whose
 * payload_ciphertext is the serialized GroupKeyShare in the
 * clear and whose single key wrap carries the session root key,
 * so the share path needs the raw field layout.
 */
export interface RawEnvelope {
  header: ClientRequestHeaderData
  payloadNonce: Uint8Array
  ephemeralPubkey: Uint8Array
  payloadCiphertext: Uint8Array
  keywraps: Array<{
    recipientPubkey: Uint8Array
    keyNonce: Uint8Array
    wrappedKey: Uint8Array
  }>
  signature: Uint8Array
}

export function serializeRawEnvelope(env: RawEnvelope): Uint8Array {
  const t = types()
  const proto = {
    header: {
      version: env.header.version,
      content_type: env.header.contentType,
      schema_version: env.header.schemaVersion,
      timestamp: env.header.timestamp,
      sender_pubkey: env.header.senderPubkey,
      recipients_pubkey: env.header.recipientsPubkey,
      group_id: env.header.groupId || new Uint8Array(0),
    },
    payload_nonce: env.payloadNonce,
    ephemeral_pubkey: env.ephemeralPubkey,
    payload_ciphertext: env.payloadCiphertext,
    keywraps: env.keywraps.map((w) => ({
      recipient_pubkey: w.recipientPubkey,
      key_nonce: w.keyNonce,
      wrapped_key: w.wrappedKey,
    })),
    signature: env.signature,
  }
  const err = t.Envelope.verify(proto)
  if (err) throw new Error(`Invalid Envelope: ${err}`)
  return new Uint8Array(t.Envelope.encode(t.Envelope.create(proto)).finish())
}

export function deserializeRawEnvelope(bytes: Uint8Array): RawEnvelope {
  const t = types()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e = t.Envelope.decode(bytes) as any
  const recipients = (e.header.recipients_pubkey || []).map((pk: unknown) => asBytes(pk))
  return {
    header: {
      version: e.header.version,
      contentType: e.header.content_type,
      schemaVersion: e.header.schema_version,
      timestamp: Number(e.header.timestamp),
      senderPubkey: asBytes(e.header.sender_pubkey),
      recipientsPubkey: recipients,
      groupId:
        e.header.group_id && e.header.group_id.length > 0 ? asBytes(e.header.group_id) : null,
    },
    payloadNonce: asBytes(e.payload_nonce),
    ephemeralPubkey: asBytes(e.ephemeral_pubkey),
    payloadCiphertext: asBytes(e.payload_ciphertext),
    keywraps: (e.keywraps || []).map((w: KeyWrapLike) => ({
      recipientPubkey: asBytes(w.recipient_pubkey),
      keyNonce: asBytes(w.key_nonce),
      wrappedKey: asBytes(w.wrapped_key),
    })),
    signature: asBytes(e.signature),
  }
}

// ---- CalendarEvent (content.proto; family calendar, Phase C3) ----

/** CONTENT_CALENDAR_EVENT in envelope.proto. */
export const CONTENT_CALENDAR_EVENT = 162

/**
 * One version of a calendar event (see the CalendarEvent message
 * in content.proto). Create/update/delete are the same record
 * re-issued with a later updatedAt; deleted = true is the
 * tombstone. The record is signed by the acting member's device
 * key over the TWEVENT digest (see utils/events.ts).
 */
export interface CalendarEventData {
  eventId: Uint8Array // 16 bytes
  title: string
  notes: string
  location: string
  startUnix: number // seconds since epoch
  endUnix: number // seconds since epoch
  timezone: string // IANA TZID
  allDay: boolean
  rrule: string // '' = one-off
  createdBy: Uint8Array // member pubkey
  actorMemberPubkey: Uint8Array
  actorDevicePubkey: Uint8Array
  createdAt: number // unix seconds
  updatedAt: number // unix seconds; the version clock
  deleted: boolean
  signature: Uint8Array
}

export function serializeCalendarEvent(ev: CalendarEventData): Uint8Array {
  const t = types()
  const proto = {
    event_id: ev.eventId,
    title: ev.title,
    notes: ev.notes || '',
    location: ev.location || '',
    start_unix: ev.startUnix,
    end_unix: ev.endUnix,
    timezone: ev.timezone || '',
    all_day: ev.allDay || false,
    rrule: ev.rrule || '',
    created_by: ev.createdBy,
    actor_member_pubkey: ev.actorMemberPubkey,
    actor_device_pubkey: ev.actorDevicePubkey,
    created_at: ev.createdAt,
    updated_at: ev.updatedAt,
    deleted: ev.deleted || false,
    signature: ev.signature,
  }
  const err = t.CalendarEvent.verify(proto)
  if (err) throw new Error(`Invalid CalendarEvent: ${err}`)
  return new Uint8Array(t.CalendarEvent.encode(t.CalendarEvent.create(proto)).finish())
}

export function deserializeCalendarEvent(bytes: Uint8Array): CalendarEventData {
  const t = types()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e = t.CalendarEvent.decode(bytes) as any
  return {
    eventId: asBytes(e.event_id),
    title: e.title || '',
    notes: e.notes || '',
    location: e.location || '',
    startUnix: Number(e.start_unix || 0),
    endUnix: Number(e.end_unix || 0),
    timezone: e.timezone || '',
    allDay: !!e.all_day,
    rrule: e.rrule || '',
    createdBy: asBytes(e.created_by),
    actorMemberPubkey: asBytes(e.actor_member_pubkey),
    actorDevicePubkey: asBytes(e.actor_device_pubkey),
    createdAt: Number(e.created_at || 0),
    updatedAt: Number(e.updated_at || 0),
    deleted: !!e.deleted,
    signature: asBytes(e.signature),
  }
}
