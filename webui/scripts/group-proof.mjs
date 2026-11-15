// Headless two-instance proof for Phase C2 group chat, using the
// page's REAL modules (only localStorage is shimmed, one store per
// instance; the module bundles are imported as separate copies so
// each instance has its own keystores).
//
// Scenario against the live test node:
//   A, B, D enroll fresh members (B3 flow + founder approval).
//   A creates a group with B and the browser member "Muse (browser)".
//   A -> group session message; B accepts the share and decrypts it.
//   B -> group reply; A accepts and decrypts it.
//   A adds D; A's next send hits the node's retired-session 403,
//   A rotates (fresh session) and the send lands; B decrypts it.
//   A removes D, rotates again, and sends the final message that
//   stays in the group for the real-browser check.
//   D (non-member at share time) cannot decrypt A's first message.
// Prints a JSON manifest (group id + proof member keys) for cleanup.
import { rolldown } from 'rolldown'
import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const CLAUDE_MEMBER = 'c97c3743771b3c1041fad6613f0acf5a9a103a6f63fecef83894490e2e3c90ce'
const APPROVE = '/home/william/tinywebc-node1/approve.py'

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

const entry = new URL('./group-proof.entry.ts', import.meta.url).pathname
const dir = mkdtempSync(join(tmpdir(), 'tw-proof-'))
async function buildBundle(name) {
  const file = join(dir, name)
  const bundle = await rolldown({ input: entry, platform: 'node', logLevel: 'silent' })
  await bundle.write({ file, format: 'esm' })
  return import(pathToFileURL(file).href)
}

const instances = {}
for (const name of ['A', 'B', 'D']) {
  instances[name] = { mod: await buildBundle(`bundle-${name}.mjs`), storage: new LocalStorageShim(), name }
}
async function withInstance(inst, fn) {
  globalThis.localStorage = inst.storage
  return fn(inst.mod)
}

const log = (...args) => console.log(...args)
let failures = 0
function expect(cond, label) {
  log(`${cond ? 'PASS' : 'FAIL'} ${label}`)
  if (!cond) failures++
}

async function enroll(inst, displayName) {
  return withInstance(inst, async (mod) => {
    const meta = await mod.createEnrollmentIdentity(displayName, 'proof-phone')
    const begin = await mod.beginEnrollment()
    execFileSync('python3', [APPROVE, begin.code], { stdio: 'pipe' })
    const check = await mod.checkEnrollment()
    if (check.state !== 'approved') throw new Error(`enroll ${displayName}: ${check.state}`)
    log(`enrolled ${displayName}: member ${meta.memberPubkey.slice(0, 8)}... device ${meta.devicePubkey.slice(0, 8)}...`)
    return meta
  })
}

async function decryptGroupThread(inst, myHex, groupId) {
  return withInstance(inst, async (mod) => {
    const recent = await mod.getRecentMessages(myHex, 100)
    const inGroup = recent
      .filter((m) => m.header.groupId && mod.toHex(m.header.groupId) === groupId)
      .sort((a, b) => {
        const sa = mod.toHex(a.sessionId)
        const sb = mod.toHex(b.sessionId)
        if (sa !== sb) return sa < sb ? -1 : 1
        return a.messageIndex - b.messageIndex
      })
    const rows = []
    for (const m of inGroup) {
      const r = await mod.decryptGroupMessage(m)
      rows.push({ sender: mod.toHex(m.header.senderPubkey), index: m.messageIndex, text: r.text, error: r.error })
    }
    return rows
  })
}

const metaA = await enroll(instances.A, 'C2 Proof A')
const metaB = await enroll(instances.B, 'C2 Proof B')
const metaD = await enroll(instances.D, 'C2 Proof Outsider')

let group = await withInstance(instances.A, async (mod) => {
  const g = await mod.createGroup('C2 Proof Group', [metaB.memberPubkey, CLAUDE_MEMBER])
  log(`group created: ${g.group_id} members=${g.members.length}`)
  return g
})

// 1) A -> group, B decrypts.
const MSG1 = 'proof one: A to the group'
await withInstance(instances.A, async (mod) => {
  const enc = await mod.encryptGroupMessage(group.group_id, group.members, MSG1)
  log('A share warnings:', enc.shareWarnings)
  await mod.submitMessage(mod.serializeMessage(enc.message))
  log('A sent msg1')
})
const accB = await withInstance(instances.B, (mod) => mod.acceptPendingShares())
log('B acceptPendingShares:', JSON.stringify(accB))
let rowsB = await decryptGroupThread(instances.B, metaB.memberPubkey, group.group_id)
log('B thread:', JSON.stringify(rowsB))
expect(rowsB.some((r) => r.text === MSG1), 'B decrypted A msg1 exactly')

// 2) B -> group, A decrypts.
const MSG2 = 'proof two: B replies to the group'
await withInstance(instances.B, async (mod) => {
  const enc = await mod.encryptGroupMessage(group.group_id, group.members, MSG2)
  log('B share warnings:', enc.shareWarnings)
  await mod.submitMessage(mod.serializeMessage(enc.message))
  log('B sent msg2')
})
const accA = await withInstance(instances.A, (mod) => mod.acceptPendingShares())
log('A acceptPendingShares:', JSON.stringify(accA))
let rowsA = await decryptGroupThread(instances.A, metaA.memberPubkey, group.group_id)
log('A thread:', JSON.stringify(rowsA))
expect(rowsA.some((r) => r.text === MSG2), 'A decrypted B msg2 exactly')
expect(rowsA.some((r) => r.text === MSG1), 'A re-reads its own msg1')

// 3) D (never a member yet) cannot decrypt msg1.
const msg1Obj = await withInstance(instances.A, async (mod) => {
  const recent = await mod.getRecentMessages(metaA.memberPubkey, 100)
  return recent.find(
    (m) => m.header.groupId && mod.toHex(m.header.groupId) === group.group_id && m.messageIndex === 0 && mod.toHex(m.header.senderPubkey) === metaA.memberPubkey,
  )
})
const dTry = await withInstance(instances.D, (mod) => mod.decryptGroupMessage(msg1Obj))
log('D decrypt attempt:', JSON.stringify(dTry))
expect(dTry.text === null && !!dTry.error, 'non-member D cannot decrypt (no session key)')

// 4) Membership change: add D -> stale session 403 -> rotate -> send lands.
group = await withInstance(instances.A, (mod) => mod.addGroupMember(group.group_id, metaD.memberPubkey))
log('D added; members now', group.members.length)
const MSG3 = 'proof three: A after rotation (D was added)'
await withInstance(instances.A, async (mod) => {
  const stale = await mod.encryptGroupMessage(group.group_id, group.members, 'stale session attempt')
  let rejected = ''
  try {
    await mod.submitMessage(mod.serializeMessage(stale.message))
  } catch (e) {
    rejected = e.message
  }
  log('stale-session submit result:', rejected || 'SUCCEEDED (unexpected)')
  expect(/retired/i.test(rejected), 'node retired the old session after membership change (403 surfaced)')
  mod.markGroupSessionStale(group.group_id)
  const fresh = await mod.encryptGroupMessage(group.group_id, group.members, MSG3)
  await mod.submitMessage(mod.serializeMessage(fresh.message))
  log('A sent msg3 on a fresh session')
})
await withInstance(instances.B, (mod) => mod.acceptPendingShares())
rowsB = await decryptGroupThread(instances.B, metaB.memberPubkey, group.group_id)
log('B thread after rotation:', JSON.stringify(rowsB))
expect(rowsB.some((r) => r.text === MSG3), 'B decrypted A msg3 on the rotated session')

// 5) Remove D, rotate, final message left waiting for the browser member.
group = await withInstance(instances.A, async (mod) => {
  const g = await mod.removeGroupMember(group.group_id, metaD.memberPubkey)
  mod.markGroupSessionStale(group.group_id)
  return g
})
log('D removed; members now', group.members.length)
const FINAL = 'Hello from the C2 proof — if you can read this in the browser, group chat works end to end.'
await withInstance(instances.A, async (mod) => {
  const enc = await mod.encryptGroupMessage(group.group_id, group.members, FINAL)
  log('final share warnings:', enc.shareWarnings)
  await mod.submitMessage(mod.serializeMessage(enc.message))
  log('A sent the final waiting message')
})
await withInstance(instances.B, (mod) => mod.acceptPendingShares())
rowsB = await decryptGroupThread(instances.B, metaB.memberPubkey, group.group_id)
expect(rowsB.some((r) => r.text === FINAL), 'B decrypted the final waiting message (same distribution as the browser member)')

log('MANIFEST ' + JSON.stringify({
  group_id: group.group_id,
  group_name: group.name,
  final_text: FINAL,
  members: { A: metaA.memberPubkey, B: metaB.memberPubkey, D: metaD.memberPubkey },
  devices: { A: metaA.devicePubkey, B: metaB.devicePubkey, D: metaD.devicePubkey },
}))
log(failures === 0 ? 'PROOF PASS' : `PROOF FAILED (${failures} checks)`)
process.exit(failures === 0 ? 0 : 1)
