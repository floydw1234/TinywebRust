// Known-answer check: the page's B4 ratchet + AEAD + share digest
// against the vector produced by the node's own Rust code
// (pinned in rust/src/sessions.rs::ratchet_known_answer_vector).
// Run: node scripts/group-kat.check.mjs
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
  input: new URL('./group-proof.entry.ts', import.meta.url).pathname,
  platform: 'node',
  logLevel: 'silent',
})
await bundle.write({ file: out, format: 'esm' })
const mod = await import(pathToFileURL(out).href)
const result = await mod.groupKatCheck()
for (const [name, ok] of Object.entries(result.checks)) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`)
}
console.log(result.ok ? 'KAT OK — page matches the Rust vector' : 'KAT FAILED')
process.exit(result.ok ? 0 : 1)
