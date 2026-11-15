// Known-answer check: the page's TWEVENT digest + CalendarEvent
// serialization against the vector produced by the node's own
// Rust code (pinned in rust/src/events.rs::event_known_answer_vector).
// Run: node scripts/events-kat.check.mjs
import { rolldown } from 'rolldown'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

class LocalStorageShim {
  constructor() {
    this.map = new Map()
  }
  getItem(k) {
    return this.map.has(k) ? this.map.get(k) : null
  }
  setItem(k, v) {
    this.map.set(k, String(v))
  }
  removeItem(k) {
    this.map.delete(k)
  }
  clear() {
    this.map.clear()
  }
}
globalThis.localStorage = new LocalStorageShim()

const out = join(mkdtempSync(join(tmpdir(), 'tw-kat-')), 'bundle.mjs')
const bundle = await rolldown({
  input: new URL('./events-kat.entry.ts', import.meta.url).pathname,
  platform: 'node',
  logLevel: 'silent',
})
await bundle.write({ file: out, format: 'esm' })
const mod = await import(pathToFileURL(out).href)

const fill = (byte, n) => new Uint8Array(n).fill(byte)
const record = {
  eventId: fill(0x11, 16),
  title: 'KAT event',
  notes: 'known answer',
  location: 'Test Range',
  startUnix: 1795388400,
  endUnix: 1795393800,
  timezone: 'America/Denver',
  allDay: false,
  rrule: 'FREQ=WEEKLY',
  createdBy: fill(0x22, 32),
  actorMemberPubkey: fill(0x22, 32),
  actorDevicePubkey: fill(0x33, 32),
  createdAt: 1700000000,
  updatedAt: 1700000100,
  deleted: false,
  signature: fill(0xaa, 64),
}

const expectedDigest =
  '932677988c074eee5803d8769949ab7e687c219732e5f93f9a6614b57786966d'
const expectedBytes =
  '0a101111111111111111111111111111111112094b4154206576656e741a0c6b6e6f776e20616e73776572220a546573742052616e676528f0e78dd8063088928ed8063a0e416d65726963612f44656e7665724a0b465245513d5745454b4c59522022222222222222222222222222222222222222222222222222222222222222225a202222222222222222222222222222222222222222222222222222222222222222622033333333333333333333333333333333333333333333333333333333333333336880e2cfaa0670e4e2cfaa06820140aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

const digest = mod.toHex(mod.calendarEventDigest(record))
const bytes = mod.toHex(mod.serializeCalendarEvent(record))
const checks = {
  digest: digest === expectedDigest,
  record_bytes: bytes === expectedBytes,
}
for (const [name, ok] of Object.entries(checks)) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`)
  if (!ok) {
    console.log(`  got:      ${name === 'digest' ? digest : bytes}`)
    console.log(`  expected: ${name === 'digest' ? expectedDigest : expectedBytes}`)
  }
}
const ok = Object.values(checks).every(Boolean)
console.log(ok ? 'KAT OK — page matches the Rust vector' : 'KAT FAILED')
process.exit(ok ? 0 : 1)
