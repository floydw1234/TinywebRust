// Headless proof for Phase C4 (Dashboard members & devices),
// using the page's REAL modules (only localStorage is shimmed).
//
// Scenario against the live test node:
//   A throwaway member enrolls via the real B3 flow + founder
//   approval (approve.py). As that member it reads the household
//   overview (GET /household/devices) and must see all four
//   members — the three standing household members plus itself —
//   with its own device active. It then revokes its own device
//   through the page's revoke path (POST /devices/revoke,
//   member mode); the overview must show the device revoked,
//   and a second revoke must answer already_revoked, not error.
// Prints a MANIFEST line (throwaway member/device pubkeys) so
// the caller can clean the throwaway out of the node database.
import { rolldown } from 'rolldown'
import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const APPROVE = '/home/william/tinywebc-node1/approve.py'
const HOUSEHOLD = [
  '1cd076576fd5d9c1b13b5ebfd11c426d510f4ea21787544b5ba944eda2e673a3', // testparent
  '293d9a8874a6ff87e9b3cf66c3a7ca4ed2d2f5fdd6d01d4321d66428fdd83646', // Headless Tester
  'c97c3743771b3c1041fad6613f0acf5a9a103a6f63fecef83894490e2e3c90ce', // Muse (browser)
]

class LocalStorageShim {
  constructor() {
    this.map = new Map()
    this.map.set('tinyweb_node_base', 'http://localhost:8000')
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

const entry = new URL('./household-proof.entry.ts', import.meta.url).pathname
const dir = mkdtempSync(join(tmpdir(), 'tw-c4proof-'))
const bundle = await rolldown({ input: entry, platform: 'node', logLevel: 'silent' })
const file = join(dir, 'bundle.mjs')
await bundle.write({ file, format: 'esm' })
globalThis.localStorage = new LocalStorageShim()
const mod = await import(pathToFileURL(file).href)

const log = (...args) => console.log(...args)
let failures = 0
function expect(cond, label) {
  log(`${cond ? 'PASS' : 'FAIL'} ${label}`)
  if (!cond) failures++
}

// Enroll the throwaway member through the real B3 flow.
const meta = await mod.createEnrollmentIdentity('C4 Proof Member', 'proof-phone')
const begin = await mod.beginEnrollment()
execFileSync('python3', [APPROVE, begin.code], { stdio: 'pipe' })
const check = await mod.checkEnrollment()
expect(check.state === 'approved', `throwaway enrolled (state=${check.state})`)
log(`throwaway member ${meta.memberPubkey} device ${meta.devicePubkey}`)

// 1) Overview as the throwaway: the whole household, itself included.
const before = await mod.getHouseholdDevices()
expect(before.length === 4, `overview lists 4 members (got ${before.length})`)
for (const pk of HOUSEHOLD) {
  expect(
    before.some((m) => m.member === pk),
    `overview includes household member ${pk.slice(0, 8)}...`,
  )
}
const self = before.find((m) => m.member === meta.memberPubkey)
expect(!!self, 'overview includes the throwaway member')
expect(
  self.devices.length === 1 && self.devices[0].device_pubkey === meta.devicePubkey,
  'own device listed',
)
expect(self.devices[0].status === 'active', 'own device starts active')

// 2) Revoke the own device through the page's revoke path.
const r1 = await mod.revokeOwnDevice(meta.memberPubkey, meta.devicePubkey)
expect(r1.status === 'revoked', `first revoke -> ${r1.status}`)

// 3) The overview now shows the device revoked, with a time.
const after = await mod.getHouseholdDevices()
const selfAfter = after.find((m) => m.member === meta.memberPubkey)
expect(selfAfter.devices[0].status === 'revoked', 'overview shows own device revoked')
expect(
  typeof selfAfter.devices[0].revoked_at === 'number' && selfAfter.devices[0].revoked_at > 0,
  'revoked_at is set',
)

// 4) A second revoke answers already_revoked — not an error.
const r2 = await mod.revokeOwnDevice(meta.memberPubkey, meta.devicePubkey)
expect(r2.status === 'already_revoked', `second revoke -> ${r2.status}`)

log(`MANIFEST ${JSON.stringify({ member: meta.memberPubkey, device: meta.devicePubkey })}`)
if (failures) {
  log(`PROOF FAIL (${failures} check(s))`)
  process.exit(1)
}
log('PROOF PASS')
