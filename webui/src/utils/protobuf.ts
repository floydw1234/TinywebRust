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
`

interface Types {
  Message: protobuf.Type
  MessageList: protobuf.Type
  ConversationList: protobuf.Type
  ClientRequest: protobuf.Type
  Envelope: protobuf.Type
  LocationUpdate: protobuf.Type
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
    keywraps: keywrapsFromPayload(msg.encryptedPayload, msg.header.recipientsPubkey),
    signature: msg.signature,
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

// ---- ClientRequest ----

export function serializeClientRequest(req: TinyClientRequest): Uint8Array {
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
  const err = t.ClientRequest.verify(proto)
  if (err) throw new Error(`Invalid ClientRequest: ${err}`)
  return new Uint8Array(t.ClientRequest.encode(t.ClientRequest.create(proto)).finish())
}

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

// ---- Envelope (same field layout as ClientRequest, plus content type) ----

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
