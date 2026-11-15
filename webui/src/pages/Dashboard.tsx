import { useEffect, useState } from 'react'
import keyStore from '../utils/keystore'
import {
  getBaseUrl,
  setBaseUrl,
  getHealth,
  getPeers,
  getUsers,
  getHouseholdDevices,
  revokeOwnDevice,
  revokeDeviceAsParent,
  login,
  type NodeUser,
  type HouseholdMember,
  type RevokeDeviceResult,
  type RawCall,
} from '../api'
import { fromHex, shortHex } from '../utils/hex'
import {
  getEnrollmentMeta,
  initEnrollmentStores,
  enrollmentKeysLoaded,
  getDeviceStore,
  type EnrollmentMeta,
} from '../utils/enrollment'
import { buildDeviceRevocationAuth } from '../utils/deviceCert'

interface Props {
  identity: string | null
  onIdentityChanged: () => void
  rawCalls: RawCall[]
}

export default function Dashboard({ identity, onIdentityChanged, rawCalls }: Props) {
  const [baseUrl, setBaseUrlState] = useState(getBaseUrl())
  const [importHex, setImportHex] = useState('')
  const [identityMsg, setIdentityMsg] = useState('')
  const [identityErr, setIdentityErr] = useState('')
  const [loginResult, setLoginResult] = useState('')
  const [health, setHealth] = useState<unknown>(null)
  const [healthErr, setHealthErr] = useState('')
  const [peers, setPeers] = useState<unknown>(null)
  const [peersErr, setPeersErr] = useState('')
  const [users, setUsers] = useState<NodeUser[] | null>(null)
  const [usersErr, setUsersErr] = useState('')
  const [household, setHousehold] = useState<HouseholdMember[] | null>(null)
  const [householdErr, setHouseholdErr] = useState('')
  const [revokeTarget, setRevokeTarget] = useState<{
    member: string
    device: string
    label: string
  } | null>(null)
  const [revokeMsg, setRevokeMsg] = useState('')
  const [revokeErr, setRevokeErr] = useState('')
  const [revoking, setRevoking] = useState(false)
  const [selectedCall, setSelectedCall] = useState<number | null>(null)
  const [enrollMeta, setEnrollMeta] = useState<EnrollmentMeta | null>(null)

  const refreshHealth = async () => {
    setHealthErr('')
    try {
      setHealth(await getHealth())
    } catch (e) {
      setHealth(null)
      setHealthErr(e instanceof Error ? e.message : String(e))
    }
  }

  const refreshPeers = async () => {
    setPeersErr('')
    try {
      setPeers(await getPeers())
    } catch (e) {
      setPeers(null)
      setPeersErr(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    setEnrollMeta(getEnrollmentMeta())
  }, [identity])

  useEffect(() => {
    void refreshHealth()
    void refreshPeers()
    void keyStore.init().then(() => {
      const err = keyStore.getLoadError()
      if (err) setIdentityErr(`Stored identity could not be loaded: ${err}`)
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const doGenerate = async () => {
    if (identity && !window.confirm('Replace the current identity with a new keypair? The old key will be overwritten in local storage.')) return
    setIdentityErr('')
    try {
      await keyStore.generateKeypair()
      await keyStore.saveKeypair('')
      setIdentityMsg('New identity generated and saved to local storage.')
      onIdentityChanged()
    } catch (e) {
      console.error('Generate identity failed:', e)
      setIdentityMsg('')
      setIdentityErr(`Generate failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const doImport = async () => {
    setIdentityErr('')
    try {
      await keyStore.importKey(importHex)
      await keyStore.saveKeypair('')
      setImportHex('')
      setIdentityMsg('Identity imported and saved to local storage.')
      onIdentityChanged()
    } catch (e) {
      console.error('Import identity failed:', e)
      setIdentityMsg('')
      setIdentityErr(`Import failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const doDelete = async () => {
    if (!window.confirm('Delete the stored identity from this browser?')) return
    setIdentityErr('')
    try {
      keyStore.cleanup()
      keyStore.deleteStoredKeypair()
      setIdentityMsg('Identity deleted.')
      onIdentityChanged()
    } catch (e) {
      console.error('Delete identity failed:', e)
      setIdentityErr(`Delete failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const doLogin = async () => {
    setLoginResult('Calling POST /auth/login …')
    try {
      const res = await login()
      setLoginResult(`Login OK: ${JSON.stringify(res)}`)
    } catch (e) {
      setLoginResult(`Login failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const doUsers = async () => {
    setUsersErr('')
    try {
      setUsers(await getUsers())
    } catch (e) {
      setUsers(null)
      setUsersErr(e instanceof Error ? e.message : String(e))
    }
  }

  const refreshHousehold = async () => {
    setHouseholdErr('')
    try {
      setHousehold(await getHouseholdDevices())
    } catch (e) {
      setHousehold(null)
      setHouseholdErr(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    if (identity) void refreshHousehold()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identity])

  const myMember = identity?.toLowerCase() ?? null
  // This browser's enrollment device key belongs to the active
  // identity only when the enrollment meta names the same member;
  // it is what parent-mode revokes are signed with.
  const myDevicePubkey =
    enrollMeta && myMember && enrollMeta.memberPubkey.toLowerCase() === myMember
      ? enrollMeta.devicePubkey.toLowerCase()
      : null

  /**
   * Where may the Revoke button appear? Exactly where the node's
   * C1 rules allow the call: my own devices (member mode — the
   * request signature is my member key), and devices of members
   * who recorded me as a parent, when this browser holds my
   * enrollment device key to sign the parent authorization.
   * Anything else gets no button; if a call is still refused,
   * the node's error is shown, never swallowed.
   */
  const revokeModeFor = (m: HouseholdMember): 'member' | 'parent' | null => {
    if (!myMember) return null
    if (m.member.toLowerCase() === myMember) return 'member'
    if (myDevicePubkey && m.parents.some((p) => p.toLowerCase() === myMember)) return 'parent'
    return null
  }

  const doRevoke = async () => {
    if (!revokeTarget || !myMember) return
    setRevoking(true)
    setRevokeErr('')
    setRevokeMsg('')
    try {
      const target = household?.find((m) => m.member === revokeTarget.member)
      const mode = target ? revokeModeFor(target) : null
      let res: RevokeDeviceResult
      if (mode === 'parent') {
        await initEnrollmentStores()
        if (!enrollmentKeysLoaded()) {
          throw new Error(
            'Your device key is not loaded in this browser, so the parent authorization cannot be signed.',
          )
        }
        const deviceStore = getDeviceStore()
        const timestamp = Math.floor(Date.now() / 1000)
        const auth = buildDeviceRevocationAuth(
          deviceStore._getPrivateKey(),
          fromHex(myMember),
          deviceStore.getPublicKey(),
          fromHex(revokeTarget.member),
          fromHex(revokeTarget.device),
          '',
          timestamp,
        )
        res = await revokeDeviceAsParent(revokeTarget.member, revokeTarget.device, '', auth)
      } else {
        res = await revokeOwnDevice(revokeTarget.member, revokeTarget.device)
      }
      setRevokeMsg(
        res.status === 'revoked'
          ? `Device ${shortHex(revokeTarget.device)} (${revokeTarget.label}) revoked.`
          : `Device ${shortHex(revokeTarget.device)} (${revokeTarget.label}) was already revoked.`,
      )
      setRevokeTarget(null)
      await refreshHousehold()
    } catch (e) {
      console.error('Revoke device failed:', e)
      setRevokeErr(`Revoke failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setRevoking(false)
    }
  }

  const saveBase = () => {
    setBaseUrl(baseUrl)
    setBaseUrlState(getBaseUrl())
  }

  const lastCall = rawCalls[0]
  const shownCall = rawCalls.find((c) => c.id === selectedCall) || lastCall

  const healthStatus =
    health && typeof health === 'object' && 'status' in (health as Record<string, unknown>)
      ? String((health as Record<string, unknown>).status)
      : null

  const enrollmentText = !enrollMeta
    ? 'not enrolled'
    : enrollMeta.phase === 'enrolled'
      ? `enrolled as ${enrollMeta.displayName} (device ${shortHex(enrollMeta.devicePubkey)})`
      : enrollMeta.phase === 'pending'
        ? 'pairing code issued, waiting for approval'
        : 'identity created, not yet enrolled' 

  return (
    <div>
      <div className="card">
        <h2>Connection</h2>
        <label className="field">Node base URL (default /api → Vite proxy → http://localhost:8000)</label>
        <div className="row">
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrlState(e.target.value)}
            style={{ width: 340 }}
            placeholder="/api or http://localhost:8001"
          />
          <button onClick={saveBase}>Save</button>
          <button className="secondary" onClick={() => { setBaseUrlState('/api'); setBaseUrl('/api') }}>
            Reset to /api
          </button>
        </div>
        <p className="status-line">
          Requests are signed with the path the node sees (e.g. <span className="mono">/messages/recent</span>),
          regardless of the proxy prefix.
        </p>
      </div>

      <div className="card">
        <h2>Identity (Ed25519)</h2>
        {identity ? (
          <p className="mono">Public key: {identity}</p>
        ) : (
          <p className="status-line status-bad">No identity loaded. Generate or import one to sign requests.</p>
        )}
        <p className="status-line">
          Enrollment: <strong>{enrollmentText}</strong> — join this household from the Enroll tab.
        </p>
        <div className="row">
          <button onClick={doGenerate}>{identity ? 'Regenerate identity' : 'Generate identity'}</button>
          <button className="secondary" onClick={doLogin} disabled={!identity}>
            Test login (POST /auth/login)
          </button>
          <button className="danger" onClick={doDelete} disabled={!identity && !keyStore.hasStoredKeypair()}>
            Delete identity
          </button>
        </div>
        <label className="field">Import secret key (64-byte secret key hex, or 32-byte seed hex)</label>
        <div className="row">
          <input
            type="text"
            value={importHex}
            onChange={(e) => setImportHex(e.target.value)}
            style={{ width: 520 }}
            placeholder="hex…"
          />
          <button className="secondary" onClick={doImport} disabled={!importHex.trim()}>
            Import
          </button>
        </div>
        {identityErr && <p className="status-line status-bad">{identityErr}</p>}
        {identityMsg && <p className="status-line">{identityMsg}</p>}
        {loginResult && <p className="status-line">{loginResult}</p>}
        <p className="status-line">
          Keys live in this browser's local storage (<span className="mono">tinyweb_keypair</span>),
          sealed with an empty passphrase for test convenience — the same scheme as the C web-ui.
        </p>
      </div>

      <div className="card">
        <h2>Node health</h2>
        <div className="row">
          <button onClick={refreshHealth}>Refresh GET /health</button>
          {healthStatus && (
            <span className={healthStatus === 'healthy' ? 'status-ok' : 'status-bad'}>
              status: {healthStatus}
            </span>
          )}
        </div>
        {healthErr && <p className="status-line status-bad">{healthErr}</p>}
        {health != null && <pre className="raw">{JSON.stringify(health, null, 2)}</pre>}
      </div>

      <div className="card">
        <h2>Gossip peers</h2>
        <div className="row">
          <button onClick={refreshPeers}>Refresh GET /gossip/peers</button>
          {peers != null && (
            <span>
              {Array.isArray((peers as { peers?: unknown[] }).peers)
                ? `${(peers as { peers: unknown[] }).peers.length} peer(s)`
                : ''}
            </span>
          )}
        </div>
        {peersErr && <p className="status-line status-bad">{peersErr}</p>}
        {peers != null && <pre className="raw">{JSON.stringify(peers, null, 2)}</pre>}
      </div>

      <div className="card">
        <h2>Registered users (GET /users, signed)</h2>
        <button onClick={doUsers} disabled={!identity}>
          Load users
        </button>
        {usersErr && <p className="status-line status-bad">{usersErr}</p>}
        {users && (
          <table className="simple">
            <thead>
              <tr>
                <th>Username</th>
                <th>Public key</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.pubkey}>
                  <td>{u.username}</td>
                  <td className="mono" title={u.pubkey}>{shortHex(u.pubkey)}</td>
                  <td>{u.age ?? ''}</td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={3}>No users returned.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>Members & devices (GET /household/devices)</h2>
        <div className="row">
          <button onClick={refreshHousehold} disabled={!identity}>
            Refresh members & devices
          </button>
          {household != null && <span>{household.length} member(s)</span>}
        </div>
        {householdErr && <p className="status-line status-bad">{householdErr}</p>}
        {revokeErr && <p className="status-line status-bad">{revokeErr}</p>}
        {revokeMsg && <p className="status-line status-ok">{revokeMsg}</p>}
        {revokeTarget && (
          <div className="banner">
            <p className="status-line">
              Revoke device <strong>{revokeTarget.label}</strong>{' '}
              <span className="mono">{shortHex(revokeTarget.device)}</span> of member{' '}
              <span className="mono">{shortHex(revokeTarget.member)}</span>? The device stops
              being trusted and no longer receives group keys. This cannot be undone here.
            </p>
            <div className="row">
              <button className="danger" onClick={doRevoke} disabled={revoking}>
                {revoking ? 'Revoking…' : 'Confirm revoke'}
              </button>
              <button className="secondary" onClick={() => setRevokeTarget(null)} disabled={revoking}>
                Cancel
              </button>
            </div>
          </div>
        )}
        {household &&
          household.map((m) => {
            const mode = revokeModeFor(m)
            return (
              <div key={m.member}>
                <p className="status-line">
                  <strong>{m.username || '(no name)'}</strong>{' '}
                  <span className="mono" title={m.member}>
                    {shortHex(m.member)}
                  </span>
                  {myMember && m.member.toLowerCase() === myMember ? ' (you)' : ''}
                </p>
                <table className="simple">
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Label</th>
                      <th>Status</th>
                      <th>Issued</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {m.devices.map((d) => (
                      <tr key={d.device_pubkey}>
                        <td className="mono" title={d.device_pubkey}>
                          {shortHex(d.device_pubkey)}
                        </td>
                        <td>{d.label}</td>
                        <td>
                          {d.status === 'active' ? (
                            <span className="status-ok">active</span>
                          ) : (
                            <span className="status-bad">
                              revoked
                              {d.revoked_at
                                ? ` (${new Date(d.revoked_at * 1000).toLocaleDateString()})`
                                : ''}
                            </span>
                          )}
                        </td>
                        <td>{new Date(d.issued_at * 1000).toLocaleDateString()}</td>
                        <td>
                          {mode && d.status === 'active' && (
                            <button
                              className="danger"
                              onClick={() =>
                                setRevokeTarget({
                                  member: m.member,
                                  device: d.device_pubkey,
                                  label: d.label,
                                })
                              }
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                    {m.devices.length === 0 && (
                      <tr>
                        <td colSpan={5}>No devices on record.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )
          })}
      </div>

      <div className="card">
        <h2>Raw API responses</h2>
        {rawCalls.length === 0 && <p className="status-line">No API calls yet.</p>}
        {shownCall && (
          <div>
            <p className="status-line">
              <strong>
                {shownCall.method} {shownCall.path}
              </strong>{' '}
              → {shownCall.status ?? 'no response'}
              {shownCall.error ? ` (${shownCall.error})` : ''} ·{' '}
              {new Date(shownCall.at).toLocaleTimeString()}
            </p>
            <pre className="raw">{shownCall.body || '(empty body)'}</pre>
          </div>
        )}
        {rawCalls.length > 1 && (
          <table className="simple">
            <thead>
              <tr>
                <th>Time</th>
                <th>Call</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rawCalls.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => setSelectedCall(c.id)}
                  style={{ cursor: 'pointer', background: shownCall?.id === c.id ? '#eff6ff' : undefined }}
                >
                  <td>{new Date(c.at).toLocaleTimeString()}</td>
                  <td className="mono">
                    {c.method} {c.path}
                  </td>
                  <td>{c.status ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
