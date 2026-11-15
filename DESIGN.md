# TinyWebC (Rust) — Integrated Family Platform Design

Status: **draft for review** · 2026-11-14
Directive (William, Nov 14, 2026): the Rust design must, from the first
designs, support a more integrated and functional version of what
tinywebStack is — one cohesive native system covering the full family
feature set, not just the C MVP's messaging + location.

This doc is grounded in two sources, both read 2026-11-14:

- **tinywebStack** (`PLAN.md`, `README.md`, `docs/FAMILY_LAYER_PLAN.md`):
  YunoHost + Synapse chat, OwnTracks location, Nextcloud calendar/files,
  Mobilizon events, optional Jellyfin, a parent dashboard, QR enrollment,
  and a hosted control plane — separate services glued together by a thin
  family layer.
- **TinyWebC C tree** (`src/proto/*.proto`, `src/packages/*`): gossip over
  UDP/9000, HTTP API on TCP/8000, SQLite store, libsodium crypto
  (Ed25519 sign / X25519 box), and a `content.proto` that already sketches
  far more than the implemented MVP.

Key observation: the C *protocol* design was already ambitious —
`content.proto` defines ~50 content types across four phases, and the
`gossip_envelopes` table is already a generic content store. What the C
MVP actually implements is messages + location. The Rust port's job is
to keep that protocol ambition, drop the accidental complexity, and
build the rest natively instead of bolting on other people's servers.

---

## 1. Feature map: tinywebStack → TinyWebC-native

| tinywebStack capability (how it works today) | TinyWebC-native design |
| --- | --- |
| **Chat** — Synapse homeserver, Matrix rooms/DMs, E2EE by default, app uses matrix-rust-sdk | Native. `DirectMessage` / `GroupMessage` payloads inside `Envelope`, gossiped between family nodes. Groups are `GroupCreate` content + membership state, not rooms on a server. E2EE is the envelope itself (per-recipient key wraps, Ed25519 signature) — there is no plaintext server mode. |
| **Location** — OwnTracks Recorder; app publishes OwnTracks JSON; parent-only web map | Native. `LocationUpdate` payloads (already in `content.proto`), stored in the `location_updates` projection. Visibility is a permission check on read, enforced by the node (see §3), not a separate app's ACL. |
| **Calendar** — Nextcloud CalDAV; app syncs via DAV | Native event content (§2): `EventCreate` extended with recurrence, stored as envelopes, projected to an events table. The app reads via our API (§5). **Open question:** do we also expose a CalDAV facade so stock calendar apps work, or app-only? (§8) |
| **Events (social)** — Mobilizon instance, federation via ActivityPub | Native. Same event content as calendar; "public to linked families" is a recipient/scope choice on the envelope. No ActivityPub — cross-household sharing rides gossip between linked nodes (§3). |
| **Files & photos** — Nextcloud file sync + sharing | Native blob layer (§6): files/photos are content-addressed encrypted blobs referenced by envelopes (`SharedAlbumCreate`, `MediaAddToAlbumRequest`, `CreationUpload` already gesture at this). No file ever travels inside a gossip payload. |
| **Media server** — Jellyfin (optional, separate login, LDAP not SSO) | **Out of scope to rebuild.** A Jellyfin-class streaming server is a product unto itself. Family photos/videos are covered by the blob layer + app playback. If a household wants Jellyfin, it runs beside TinyWebC as today. Revisit only if William directs otherwise. |
| **Family accounts & roles** — YunoHost LDAP users/groups (`parents`, `kids`), per-app permissions | Native identity (§3): members are Ed25519 keypairs, roles/permissions live in the existing `users` / `roles` / `permissions` / `transaction_permissions` tables and are *created by signed content* (`UserRegistration`, `RoleAssignment`, `PermissionEdit`), so every node in the family converges on the same member list via gossip. |
| **Parental controls** — custom Synapse module: per-kid contact allowlists, quiet hours, 3PID-invite block; metadata-only because E2EE | Native policy, enforced at envelope ingest on the kid's home node: the same checks the Synapse module does (allowlist, quiet hours) become node-side validation rules keyed on content type via `transaction_permissions`, driven by `ParentalControl` / `UsagePolicyUpdate` / `ContentFilter` content. Advantage over tinywebStack: policy is data in the same store, set from the same app, not a Python module reading a JSON file. Parent *content* oversight of E2EE chats stays deferred — same open problem as tinywebStack (§8). |
| **Parent dashboard** — FastAPI app at `/family/`: members, passwords, allowlists, quiet hours, invites, health, backups | Native API (§5) + the same app the family uses, in a parent role view. No separate dashboard service, no passwords to manage (identity is keys, §3). Health becomes `GET /family/health` computed from node state (gossip peers, store size, cert/blob status) instead of probing five services. Backups = export of the SQLite DB + blob directory + key material; no YunoHost backup hooks. |
| **App enrollment** — parent creates YunoHost account, box issues Matrix/CalDAV/OwnTracks credentials, app collects them via one QR code (single-use, ~10 min, code in URL fragment) | Native pairing (§3): one QR, one identity. The code provisions *keys and membership*, not three service passwords. This deletes the entire class of "chat linked, calendar didn't" failures the glue stack produces. |
| **Push notifications** — TinyWeb-owned APNs/FCM keys, push gateway service | Node cannot push to APNs/FCM without a relay holding TinyWeb's keys. Keep a minimal hosted push relay (control-plane function, below) that receives a content-free wake-up ("node X has data") — never payloads. App wakes and syncs from its home node. |
| **Control plane** — hosted service: family-slug reservation, DNS, Let's Encrypt certs, Cloudflare tunnel credentials, Stripe billing | **Stays a separate hosted service; the node is a client.** Slug/DNS/cert/tunnel/billing are business infrastructure, not family data, and must not be reimplemented per-node. The Rust node keeps the same integration points (claim slug at first boot, fetch tunnel creds) so a TinyWebC box can still be `<family>.tinyweb.win`. |
| **Cross-household linking** — Matrix federation allowlist + dashboard invite flow | Native node linking: two home nodes exchange `NodeRegistration` + a signed link grant; linked nodes gossip *only* the envelopes addressed across the link (recipient-keyed, so this falls out of the envelope model). Per-kid cross-household contact = the same allowlist policy as local contacts. No federation protocol, no public homeserver. |
| **Unboxing** — pre-imaged box, setup QR in the lid, phone-first setup | Unchanged as a product flow; the native version is simpler: first boot generates the node key, claims the slug via the control plane, and shows one pairing QR for the founding parent (§3). No YunoHost postinstall, no per-service setup steps. |
| **Node health / ops** — dashboard probes Synapse, OwnTracks, cert, disk | `GET /health` (exists) extended with per-feature status. One process = one thing to probe. |

Explicitly out of scope, with reasons:

- **Voice/video calls** — `VoiceCallRequest` exists as *signaling* content
  and can ride gossip, but media transport needs WebRTC/TURN
  infrastructure. Deferred; signaling designed-in, media not built.
- **Android device lockdown / ROM** — out of scope in tinywebStack too.
- **Public community / discovery** — `CommunityPostCreate` etc. exist in
  the proto sketch, but there is no public network and no moderation
  story. Content types stay reserved; no feature built until there is a
  trust model for it.

---

## 2. Unified content model

### 2.1 One envelope for everything

The C tree has **three near-identical wire formats**: `Envelope`
(envelope.proto), `Message` (message.proto), and `ClientRequest`
(client_request.proto), with a `client_request_converter.c` whose whole
job is converting between them. That triplication is accidental, and the
Rust port removes it:

- **`Envelope` is the only wire and storage format.** Header
  (`version`, `content_type`, `schema_version`, `timestamp`,
  `sender_pubkey`, `recipients_pubkey[]`, `group_id`), payload nonce,
  ephemeral pubkey, ciphertext, per-recipient key wraps, Ed25519
  signature. This format does not change per feature — it is frozen.
- `Message` becomes a *payload*: `DirectMessage` / `GroupMessage`
  content inside an envelope. The legacy `/messages/*` API (§5) is
  served from envelopes with message content types.
- `ClientRequest` disappears as a format. A client submission is an
  envelope the client signs with its device key (§3) and POSTs; "this
  is a request, not gossip" is a transport fact (HTTP vs UDP), not a
  different message shape. Request/response APIs that aren't content
  (health, blob upload) are plain HTTP+JSON/protobuf without envelopes.

Everything a family *does* — chat, location, events, policy changes,
membership — is an envelope with a typed payload. One signature rule,
one encryption rule, one dedup rule, one sync rule for all features.
This is the integration the glue stack cannot have.

### 2.2 Content types and extensibility

`ContentType` (envelope.proto) already allocates ranges by phase:
identity (1–9), groups (20–29), safety/control (30–39), network (40–49),
access (50–59), calls/media (60–99), education/family (100–149),
advanced (150–199). Rules for the Rust era:

1. **Enum values are forever.** Never renumber or reuse a value; new
   features take new values in the relevant range (or a new range).
   Old nodes must be able to store-and-forward types they don't
   understand — gossip relays ciphertext, so an unknown type is opaque,
   not an error. This is what makes the format forward-compatible.
2. **New feature = new payload message + new enum value.** The payload
   is a message in `content.proto` (or a sibling `.proto` once
   content.proto gets unwieldy), serialized and encrypted as the
   envelope payload. Envelope, store, and gossip code do not change.
3. **`schema_version` is per content type.** A payload can evolve
   (add proto fields — always additive) under its own version counter
   without touching the envelope `version`.
4. **Payloads reference, never embed, bulk data** (§6). The existing
   `media_ref` fields in `DirectMessage` / `GroupMessage` /
   `CommunityPostCreate` are the right instinct; §6 makes them a
   single shared `BlobRef` message instead of ad-hoc `bytes`.

### 2.3 Gaps in the current content sketch (to fix in proto, not code)

- **No calendar semantics.** `EventCreate` has title/description/
  start/end/location/invitees — fine for a one-off event, but there is
  no recurrence, no timezone field, no update/cancel type, no
  "calendar" grouping. Mobilizon/Nextcloud parity needs: `EventUpdate`,
  `EventCancel`, recurrence rule + timezone on `EventCreate`, and
  RSVP already exists (`EventRSVP`). Add these as new types/fields;
  don't overload `EventCreate`.
- **No blob type.** `MediaDownload` is a request, not a reference.
  Add `BlobRef { bytes content_hash; uint64 size; string mime_type;
  bytes wrapped_key; string filename; }` and use it everywhere
  `media_ref` / `cover_image` / `proof_image` / `content_data`
  currently appear.
- **No device type.** Identity content (§3) needs a device
  registration/cert type; the enum's user-management range has room.
- **No link type** for cross-household node linking (§1). Add to the
  network range (40–49).

---

## 3. Identity & enrollment

### 3.1 Three kinds of keys — the C design has one

The C keystore holds **a single Ed25519 keypair per process**
(passphrase-encrypted file, X25519 key derived for box encryption).
That conflates three different identities. The Rust design separates
them from the start:

| Key | Held by | Identifies | Signs |
| --- | --- | --- | --- |
| **Node key** | the home node | this household node on the gossip network | `NodeRegistration`, link grants, blob availability |
| **Member key** | a person (rooted on their first device) | a family member across all features | `UserRegistration` (by a parent), role/permission changes, group membership |
| **Device key** | one phone/laptop | one client of one member | envelope submissions from that device, API auth |

A member's public key is their identity everywhere — chat sender,
location subject, event organizer, file owner. This replaces the
tinywebStack situation where one person is simultaneously a YunoHost
LDAP user, a Matrix ID, a CalDAV principal, and an OwnTracks user.

Device keys exist so a lost phone is revocable without changing who
the member is: a **device certificate** (new content type, §2.3) is
the member key signing "device key D belongs to member M". Nodes and
other members accept envelopes from D as M. Revocation is a signed
content envelope too, gossiped like everything else. Envelope
`sender_pubkey` carries the *member* key; the device key appears in
the submission path and the signature chain is member←device.
(**Open question:** put the device pubkey in the header as an optional
field, or keep envelopes member-only and verify device certs only at
ingest on the home node? §8.)

### 3.2 Enrollment replaces account provisioning

tinywebStack enrollment: parent creates a YunoHost account in the
dashboard → box pre-provisions Matrix + CalDAV + OwnTracks credentials
→ app scans QR → app stores three credential sets → per-service
"linked / not linked" checklist, with a family password typed once
more for events. Every step exists because the backends are separate.

TinyWebC-native enrollment, one flow for the founding parent and for
every member after:

1. Parent (already enrolled) taps "add member" in the app and picks a
   role (parent / child). The app asks its home node to open a pairing
   window; the node returns a **single-use pairing code, ~10 min TTL**
   (same parameters as tinywebStack's `TWS_APP_CODE_TTL_S` — they were
   well chosen).
2. QR encodes `https://<family>.tinyweb.win/enroll#code=…` — code in
   the URL **fragment**, never sent to the server or logged (pattern
   borrowed directly from tinywebStack's `/family/join`).
3. New phone opens the link in the TinyWeb app, generates its **device
   keypair on-device** (private key never leaves the phone), and
   submits {pairing code, device pubkey, display name} to the node.
4. The node holds the request as *pending* until the parent approves
   in their app (name + device shown). Approval = parent signs a
   `UserRegistration` (member key created/registered per §3.1) and a
   device certificate; both gossip to linked nodes as ordinary
   content. No approval within the window = code dies, nothing exists.
5. The phone is done. There is no password, no per-service credential,
   no checklist of linked services — one identity lights up every
   feature, because there is only one backend.

First-boot is the same flow with roles reversed: the box generates
its node key, claims its slug from the control plane with the setup
code from the lid card, and the first phone to pair becomes the
founding parent (its `UserRegistration` is self-signed and marked
founder; the setup code is the authorization).

Recovery: tinywebStack generates a Matrix recovery key on the first
phone, shown once, written on a card in the box. Equivalent here: the
member key is backed by a recovery phrase / printed key card at
enrollment; a parent can re-issue a device certificate for a member
who lost a phone, and can re-key a *child's* member key outright.
A parent who loses their member key with no recovery card and no
second parent is unrecoverable by design — say so in the box, on a
card, like tinywebStack does. (**Open question:** threshold/social
recovery between two parents? §8.)

### 3.3 Authorization model

Keep the C schema's RBAC — it is genuinely good: `users`, `roles`,
`permissions` (flag-based), `user_roles`, `role_permissions`, and
`transaction_permissions` mapping **content type → required
permission**. In the glue stack, authorization is re-implemented per
service (YunoHost permissions, Synapse module, OwnTracks ACL). Here
there is exactly one check, at envelope ingest and at API read:

- May member M submit content type T? (`transaction_permissions`)
- May member M read this envelope? (recipient list / group membership
  / role rule — e.g. location: self + parents + approved viewers)
- Policy overlays for children (allowlist, quiet hours) evaluated at
  the same point, from policy content in the same store.

Because registrations, role assignments, and policy are themselves
gossiped content, every node enforces the *same* rules from the
*same* data — no config files drifting between services.

---

## 4. Store schema direction

### 4.1 What the C schema already gives us

From `src/packages/sql/schema.c` and friends — more than the MVP uses:

- `gossip_envelopes` — generic envelope store: `content_type`,
  `schema_version`, `timestamp`, `sender`, `group_id`,
  `payload_nonce`, `ephemeral_pubkey`, `encrypted_payload`,
  `signature`, `expires_at`. **This is already the unified content
  store.** Plus `gossip_envelope_recipients` (key wraps per
  recipient) — the read-authorization index.
- `gossip_seen` — dedup digests with expiry (gossip loop prevention).
- `gossip_peers` / `nodes` — peer and self-node state.
- Identity/RBAC: `users` (pubkey, username, age), `roles`,
  `permissions`, `user_roles`, `role_permissions`,
  `transaction_permissions` (§3.3).
- Per-type stores: `user_messages` + `message_recipients`,
  `location_updates` + `location_keywraps`, and a legacy
  `gossip_messages` (raw payloads, pre-envelope).

### 4.2 Direction: one source of truth, projections for queries

1. **`gossip_envelopes` is the only source of truth for content.**
   The Rust `store` module (Wave 1) ports the schema; the port keeps
   the envelope/recipient/seen/peer/identity tables as-is.
2. **Per-type tables become projections, not parallel stores.** The C
   code writes messages and locations twice (generic envelope path
   *and* `user_messages` / `location_updates`) — two sources of truth
   that can disagree. In Rust, a projection is a derived index built
   from envelopes, disposable and rebuildable: conversation lists
   (sender/recipient/timestamp per message envelope), location
   history (decrypted points per member — home node only, since only
   it holds wraps for its members), events by start time, blob
   metadata (§6). If a projection is corrupt, delete and rebuild.
3. **Retire `gossip_messages`** (legacy pre-envelope format) in the
   port; nothing new writes it.
4. **Fix the pubkey representation.** `users.pubkey` is `TEXT` (hex)
   while envelopes store `BLOB`. Standardize on 32-byte `BLOB`
   everywhere in the Rust schema; convert at migration.
5. **New tables the broader model needs** (added by migration, not by
   editing ported DDL in place): `devices` (member, device pubkey,
   cert envelope id, revoked flag), `blobs` (§6), `pairing_codes`
   (hashed, single-use, expiry — server-side only, never gossiped),
   `node_links` (linked household nodes + granted scopes).

### 4.3 TTL and sync semantics — where the C design fights us

The C store gives **every** envelope an `expires_at` (default 30-day
TTL with cleanup). That is right for a message relay and wrong for a
family platform:

- **Chat/location:** TTL is fine and desirable (30 days default;
  location history arguably shorter). Ephemeral by default.
- **Identity & control state** (registrations, role assignments,
  permissions, group membership, device certs, policy): this is
  *state*, not messages. If a `UserRegistration` expires in 30 days,
  the family forgets a member exists. These types must be exempt
  from TTL and instead follow **latest-wins state semantics**: the
  projection keeps the current value per key (member, group, device),
  superseded envelopes can be pruned once all linked nodes have
  acknowledged them — or kept; they are tiny.
- **Events:** retain until end time + a grace period, then TTL.
- **Blob references:** the envelope may expire; blob retention is a
  separate pin/GC decision (§6).

So retention becomes a **per-content-class policy table** (in code:
a function of `content_type`), replacing the single global TTL.
`gossip_seen` expiry must always outlive the longest envelope TTL or
dedup breaks and old envelopes resurrect — keep seen-expiry ≥ max
retention.

Sync between nodes is envelope gossip as in C: broadcast signed
envelopes, dedup by digest (`gossip_seen`), store-and-forward.
Because payloads are recipient-encrypted, relay nodes (and linked
households) can carry traffic they cannot read — the property Matrix
federation gets from servers, we get from the envelope.

---

## 5. API surface

The node HTTP API (TCP/8000) is how the app talks to its home node.
Existing C endpoints stay; the surface grows by the same patterns —
plural nouns, submit/read pairs, everything authenticated by device
key signature (the C `request_auth` model: signed requests, no
session cookies, no passwords).

Existing (keep, re-implemented over the unified store):

- `POST /messages/submit`, `GET /messages/recent`,
  `GET /messages/conversations`, `GET /messages/conversation`
- `POST /location/update`, `GET /location/:user_id`,
  `GET /location/history/:user_id`
- `GET /gossip/peers`, `GET /health`

Generalized content path (the pattern the specific endpoints are
shortcuts for):

- `POST /content/submit` — one signed `Envelope`, any content type;
  `/messages/submit` and `/location/update` become typed aliases.
- `GET /content/recent?content_type=&since=` — the app's sync cursor
  endpoint: "everything new for me since timestamp T", all features
  in one stream, ordered by timestamp. This is the endpoint the glue
  stack can't offer (it syncs four backends separately).

Per feature:

- **Members & devices:** `GET /members`, `GET /members/:pubkey`,
  `POST /enroll/begin` (parent: open pairing window),
  `POST /enroll/claim` (new device: present code + device pubkey),
  `POST /enroll/approve` (parent signs registration + device cert),
  `POST /devices/revoke`.
- **Groups:** `GET /groups`, `GET /groups/:id` (membership projected
  from group content).
- **Events/calendar:** `GET /events?from=&to=`,
  `GET /events/:id` (submit/RSVP via `/content/submit`).
- **Files/photos:** `POST /blobs` (upload, §6), `GET /blobs/:hash`,
  `GET /albums`, `GET /albums/:id` (album content projected).
- **Family/policy (dashboard equivalent):** `GET /family/health`
  (node status in plain buckets: ok / needs look / problem, per
  feature — mirroring tinywebStack's `/family/health`),
  `GET /family/policy/:member`, plus policy changes submitted as
  content, not API calls.
- **Linking:** `POST /links/invite`, `POST /links/accept`,
  `GET /links` (linked household nodes + scopes).

Rule: **mutations that are family facts go through content**
(signed, gossiped, auditable); **mutations that are local mechanics**
(pairing windows, blob upload, link handshakes) are API calls. If a
fact matters to another node, it's content.

---

## 6. Sync semantics for large payloads

Gossip is a broadcast of small signed envelopes over UDP. Photos and
files must never enter it — one 5 MB photo would flood every node and
blow the 30-day store on a Pi-class box. Design:

1. **Reference, don't carry.** File/photo content carries a `BlobRef`
   (§2.3): SHA-256 content hash, size, MIME type, filename, and the
   blob's symmetric key wrapped per recipient (same `RecipientKeyWrap`
   mechanism as envelopes). The envelope that *announces* a photo is
   a few hundred bytes and gossips normally.
2. **Blobs are content-addressed and encrypted at rest in transit.**
   The blob bytes are encrypted with a per-blob random key before
   they leave the originating device; the hash is over the
   *ciphertext*, so any node can store/serve blobs without being able
   to read them, and integrity is verified by hash before decrypt.
3. **Transfer is out-of-band, peer-to-peer, over HTTP.** A node (or
   the app) that wants a blob asks: home node first, then any linked
   node that announced availability. `GET /blobs/:hash` (§5) serves
   ciphertext to any requester — safe because it's encrypted and
   hash-checked; authorization lives in who holds a key wrap, not in
   the transfer. (Rate-limit and size caps still apply.)
4. **Availability & pinning.** The originating device uploads the blob
   to its home node at send time (that's the one required copy).
   Nodes pin blobs referenced by unexpired content addressed to their
   members; everything else is LRU-evictable cache. `MediaDownload`
   content doubles as an availability/fetch request signal.
5. **Thumbnails** small enough (target ≤ 32 KB) may travel as a
   separate tiny blob with the same reference pattern — still not
   inline in the envelope, so envelope size stays bounded. Set a hard
   envelope payload cap in validation (the C `SystemConfig` key
   `max_message_size` becomes a real enforced constant).

This gives Nextcloud-class behavior (share a photo to the family
album) with none of Nextcloud: the "share" is an envelope, the file
moves once, and every recipient's node can fetch from any holder.

---

## 7. Phasing

**Phase A — faithful C port (in flight).** Gossip transport, envelope
crypto, store schema, validation, discovery, and the existing
/messages + /location API, behavior-compatible with the C node.
Wave 1 (store, validation, discovery) is already running against
this. *No redesign in this phase* — but the schema and proto changes
in §2.3/§4.2 are additive and should land here if cheap (BLOB pubkeys,
projection discipline), because retrofitting them later costs more.

**Phase B — identity & enrollment (first redesign).** Split
node/member/device keys (§3.1), device certificates, pairing flow
(§3.2), RBAC enforcement at ingest (§3.3). This must precede any
app-facing feature work: every later feature depends on knowing who
a member is. The tinywebStack app's enrollment screens are the UX
reference; the backend behind them is entirely new.

**Phase C — content generalization.** `/content/submit` + sync
cursor (§5), events with recurrence (§2.3), group projections,
policy content (allowlists, quiet hours) enforced natively. At the
end of this phase the system covers chat + location + calendar/
events + parental controls — the tinywebStack v1 core — with one
backend.

**Phase D — blobs, albums, dashboard parity.** Blob layer (§6),
photo/file sharing, albums, `/family/health`, backup/export.
Covers the Nextcloud slice of tinywebStack.

**Phase E — linking & control-plane integration.** Cross-household
node links (§1), slug claim / tunnel / cert client against the
existing control plane, push relay client. This is where a
TinyWebC box becomes a shippable TinyWeb box.

Deferred (designed-for, not built): voice/video media, community
features, Jellyfin-class media serving, device lockdown.

---

## 8. Open questions (need William's call — not assumed)

1. **Calendar interop:** native-only calendar in the app, or also a
   CalDAV facade for stock apps? Facade is real work; app-only is
   the cohesive bet but locks the family calendar into our app.
2. **Parent oversight of kid chats:** tinywebStack deferred this
   (E2EE, metadata only). Our envelope model *could* add a parent
   key wrap to kid messages — a capability the glue stack doesn't
   have. Do we want it, and if so is it always-on or a disclosed
   family setting? This is a values call, not a technical one.
3. **Device pubkey in the envelope header** (§3.1): header field vs
   ingest-only verification. Header is cleaner for cross-node
   verification; ingest-only keeps the frozen header untouched.
4. **Parent key recovery:** printed recovery card only, or
   threshold recovery across two parents / a linked household?
5. **Push relay trust:** the hosted relay sees timing metadata
   (which node, when). Acceptable, or do we need the relay blinded
   (e.g. per-device tokens it can't correlate)?
6. **Media:** is "Jellyfin runs beside it" (§1) acceptable long
   term, or is native media serving an eventual goal? It changes
   Phase D scope (streaming, transcoding) by a lot.

## 9. Group encryption (decided Nov 14, 2026)

**Decision: Megolm-style sender sessions.** Each sender has one shared key per
conversation. That key is handed out **once** to each member's device, as an
authenticated, signed share carried by the existing per-recipient wrap
mechanism. The wrap machinery is kept — for this one-time handout and for 1:1
messages — but it no longer rides on every group message.

After the handout, messages are encrypted once with keys stepped forward from
the shared key: a hash ratchet derives one fresh key per message, one-way, so
an old message key cannot be recomputed from a newer one. There is no
per-message recipient wrap list. This replaces the C design, where every
envelope carried ~104 bytes of wrap per recipient (pubkey + nonce + wrapped
key), stored per message on every relaying node. William flagged that as
storage-costly for group chats: a one-word "hi" ended up carrying more key
material than message.

**Crypto:** use a modern AEAD — ChaCha20-Poly1305 or AES-256-GCM, with a
full-length authentication tag. Do **not** copy Megolm v1's AES-CBC plus
64-bit truncated HMAC. We do not need Matrix compatibility, so there is no
reason to inherit its dated primitives.

**Hard rule on key shares:** a shared key goes only to enrolled, verified
member devices, and every share is signed by the sender. This is the exact
spot Matrix's 2022 breaks hit — session keys shared out to rogue or
unverified devices, and key shares accepted without authentication. TinyWebC
has no homeserver, so enrollment and share verification carry that weight:
unsigned or unverifiable shares are rejected at ingest, and no key is ever
shared to a device that has not completed enrollment.

**Parents:** a parent is simply one of the members who receives the shared
key, matching the existing `parent_pubkey` design in content.proto. No
special mechanism, no separate parent key path.

**Rotation:** hand out a new shared key when membership changes — someone
joins or someone leaves. No other rotation schedule.

**Accepted risk:** we are not designing for lost phones. If a phone is lost,
its keys could read messages until membership changes and the key is
replaced. William accepted this on Nov 14, 2026, in his own framing:
iMessage keys never rotate either. MLS was considered and set aside — do not
reopen it unless William does.

**Fit with the rest of this design:**

- Session handouts ride the existing envelope/gossip transport as a content
  type, like any other envelope; no new transport is needed.
- The store keeps one row per session key handout instead of one row per
  recipient per message, so group history stays small no matter how chatty
  the group is.
- Validation checks the share signature and the recipient's enrollment status
  at ingest, the same place it checks envelope signatures today.

## 10. Wave 2 findings

During the Wave 2 two-node smoke test, a message submitted to node 1 never reached node 2. Root cause: node startup discovery/bootstrap persists peers with a NULL pubkey, and the peers-table upsert overwrites any existing node_pubkey with NULL. That wipes the ingest sender whitelist, so all gossip from that peer is silently rejected (there is no log on rejection, as in C). The Rust port faithfully reproduces the C behavior — the SQL is identical — so this is an inherited design flaw, not a porting bug.

Design implication for Phase B: the address book and the trust whitelist must not share one mutable column. Peer network addresses and verified member/node pubkeys need separate storage, and pubkey application must happen as part of enrollment/identity, not pre-seeding. Ingest should also log rejections, so this class of failure is visible instead of silent.
