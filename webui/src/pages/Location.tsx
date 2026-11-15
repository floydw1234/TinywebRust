import { useEffect, useState } from 'react'
import {
  getLocation,
  getLocationHistory,
  getUsers,
  submitLocation,
  type NodeUser,
} from '../api'
import { fromHex, shortHex } from '../utils/hex'
import keyStore from '../utils/keystore'
import { createSignedLocationEnvelope } from '../utils/envelope'
import { serializeEnvelope, type LocationUpdateData } from '../utils/protobuf'

interface Props {
  identity: string | null
}

function formatTime(unixSeconds: number): string {
  if (!unixSeconds) return ''
  return new Date(unixSeconds * 1000).toLocaleString()
}

function osmLink(lat: number, lon: number): string {
  return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}`
}

function LocationPlot({ points }: { points: LocationUpdateData[] }) {
  if (points.length === 0) return null
  const W = 340
  const H = 220
  const PAD = 18
  const lats = points.map((p) => p.lat)
  const lons = points.map((p) => p.lon)
  const minLat = Math.min(...lats)
  const maxLat = Math.max(...lats)
  const minLon = Math.min(...lons)
  const maxLon = Math.max(...lons)
  const spanLat = maxLat - minLat || 0.001
  const spanLon = maxLon - minLon || 0.001
  const x = (lon: number) => PAD + ((lon - minLon) / spanLon) * (W - 2 * PAD)
  const y = (lat: number) => H - PAD - ((lat - minLat) / spanLat) * (H - 2 * PAD)
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.lon).toFixed(1)},${y(p.lat).toFixed(1)}`).join(' ')
  return (
    <div>
      <svg width={W} height={H} style={{ border: '1px solid #d4d4d8', borderRadius: 6, background: '#fafafa' }}>
        {points.length > 1 && <path d={path} fill="none" stroke="#2563eb" strokeWidth="1.5" />}
        {points.map((p, i) => (
          <circle key={i} cx={x(p.lon)} cy={y(p.lat)} r={i === points.length - 1 ? 5 : 3.5} fill={i === points.length - 1 ? '#dc2626' : '#2563eb'}>
            <title>{`${p.lat}, ${p.lon} — ${formatTime(p.timestamp)}`}</title>
          </circle>
        ))}
      </svg>
      <p className="status-line">
        lon {minLon.toFixed(5)}…{maxLon.toFixed(5)} · lat {minLat.toFixed(5)}…{maxLat.toFixed(5)} ·
        latest point in red
      </p>
    </div>
  )
}

export default function Location({ identity }: Props) {
  const [users, setUsers] = useState<NodeUser[]>([])
  const [target, setTarget] = useState('')
  const [latest, setLatest] = useState<LocationUpdateData | null>(null)
  const [latestErr, setLatestErr] = useState('')
  const [history, setHistory] = useState<LocationUpdateData[]>([])
  const [historyFailed, setHistoryFailed] = useState(0)
  const [historyErr, setHistoryErr] = useState('')
  const [limit, setLimit] = useState(50)
  const [offset, setOffset] = useState(0)

  const [lat, setLat] = useState('')
  const [lon, setLon] = useState('')
  const [accuracy, setAccuracy] = useState('10')
  const [placeName, setPlaceName] = useState('')
  const [extraRecipients, setExtraRecipients] = useState('')
  const [postStatus, setPostStatus] = useState('')
  const [busy, setBusy] = useState(false)

  const myHex = identity || ''

  useEffect(() => {
    if (myHex && !target) setTarget(myHex)
  }, [myHex, target])

  const loadUsers = async () => {
    try {
      setUsers(await getUsers())
    } catch {
      // surfaced in the raw viewer; the manual pubkey field still works
    }
  }

  const doLatest = async () => {
    if (!target) return
    setLatestErr('')
    setLatest(null)
    try {
      setLatest(await getLocation(target))
    } catch (e) {
      setLatestErr(e instanceof Error ? e.message : String(e))
    }
  }

  const doHistory = async () => {
    if (!target) return
    setHistoryErr('')
    try {
      const { updates, failed } = await getLocationHistory(target, limit, offset)
      setHistory(updates)
      setHistoryFailed(failed)
    } catch (e) {
      setHistory([])
      setHistoryErr(e instanceof Error ? e.message : String(e))
    }
  }

  const useMyLocation = () => {
    if (!navigator.geolocation) {
      setPostStatus('Geolocation is not available in this browser/context.')
      return
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLat(pos.coords.latitude.toFixed(6))
        setLon(pos.coords.longitude.toFixed(6))
        setAccuracy(String(Math.round(pos.coords.accuracy)))
      },
      (err) => setPostStatus(`Geolocation failed: ${err.message} (note: browsers may block it over plain HTTP)`),
    )
  }

  const doPost = async () => {
    const latNum = parseFloat(lat)
    const lonNum = parseFloat(lon)
    if (Number.isNaN(latNum) || Number.isNaN(lonNum)) {
      setPostStatus('Enter numeric latitude and longitude.')
      return
    }
    setBusy(true)
    setPostStatus('Encrypting, signing, submitting…')
    try {
      // Recipients: ourselves (as in the C web-ui) plus any extra pubkeys.
      const recipientHexes = [myHex]
      for (const h of extraRecipients.split(/[\s,]+/).filter(Boolean)) recipientHexes.push(h)
      const recipients = recipientHexes.map((h) => fromHex(h))
      const req = await createSignedLocationEnvelope(
        {
          lat: latNum,
          lon: lonNum,
          accuracy_m: parseInt(accuracy || '0', 10) || 0,
          timestamp: Math.floor(Date.now() / 1000),
          location_name: placeName,
        },
        recipients,
      )
      const res = await submitLocation(serializeEnvelope(req))
      setPostStatus(`Posted: ${JSON.stringify(res)}`)
      if (target === myHex) {
        void doLatest()
        void doHistory()
      }
    } catch (e) {
      setPostStatus(`Post failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setBusy(false)
    }
  }

  if (!identity) {
    return (
      <div className="card">
        <h2>Location</h2>
        <p className="status-line status-bad">
          No identity loaded. Generate or import one on the Dashboard tab first.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="card">
        <h2>Whose location?</h2>
        <div className="row">
          <button className="secondary" onClick={loadUsers}>
            Load user list (GET /users)
          </button>
          <select value={target} onChange={(e) => setTarget(e.target.value)} style={{ maxWidth: 420 }}>
            <option value={myHex}>Me ({shortHex(myHex)})</option>
            {users
              .filter((u) => u.pubkey !== myHex)
              .map((u) => (
                <option key={u.pubkey} value={u.pubkey}>
                  {u.username} ({shortHex(u.pubkey)})
                </option>
              ))}
          </select>
        </div>
        <label className="field">…or enter a public key directly (hex)</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value.trim())}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="hex pubkey…"
        />
      </div>

      <div className="card">
        <h2>Latest location (GET /location/:user)</h2>
        <button onClick={doLatest} disabled={!target}>
          Load latest
        </button>
        {latestErr && <p className="status-line status-bad">{latestErr}</p>}
        {latest && (
          <div className="status-line">
            <strong>
              {latest.lat.toFixed(6)}, {latest.lon.toFixed(6)}
            </strong>{' '}
            · ±{latest.accuracy_m} m · {formatTime(latest.timestamp)}
            {latest.location_name ? ` · ${latest.location_name}` : ''} ·{' '}
            <a href={osmLink(latest.lat, latest.lon)} target="_blank" rel="noreferrer">
              OpenStreetMap
            </a>
          </div>
        )}
      </div>

      <div className="card">
        <h2>History (GET /location/history/:user)</h2>
        <div className="row">
          <label>
            limit{' '}
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(parseInt(e.target.value || '50', 10))}
              style={{ width: 70 }}
            />
          </label>
          <label>
            offset{' '}
            <input
              type="number"
              value={offset}
              onChange={(e) => setOffset(parseInt(e.target.value || '0', 10))}
              style={{ width: 70 }}
            />
          </label>
          <button onClick={doHistory} disabled={!target}>
            Load history
          </button>
        </div>
        {historyErr && <p className="status-line status-bad">{historyErr}</p>}
        {historyFailed > 0 && (
          <p className="status-line">
            {historyFailed} record(s) could not be decrypted with this identity and were skipped.
          </p>
        )}
        <LocationPlot points={history} />
        {history.map((p, i) => (
          <div className="msg" key={i}>
            <div className="meta">{formatTime(p.timestamp)}</div>
            <div>
              {p.lat.toFixed(6)}, {p.lon.toFixed(6)} · ±{p.accuracy_m} m
              {p.location_name ? ` · ${p.location_name}` : ''} ·{' '}
              <a href={osmLink(p.lat, p.lon)} target="_blank" rel="noreferrer">
                map
              </a>
            </div>
          </div>
        ))}
        {history.length === 0 && !historyErr && <p className="status-line">No history loaded.</p>}
      </div>

      <div className="card">
        <h2>Post a location update (POST /location/update)</h2>
        <div className="row">
          <label>
            lat{' '}
            <input type="text" value={lat} onChange={(e) => setLat(e.target.value)} placeholder="40.7608" style={{ width: 110 }} />
          </label>
          <label>
            lon{' '}
            <input type="text" value={lon} onChange={(e) => setLon(e.target.value)} placeholder="-111.8910" style={{ width: 110 }} />
          </label>
          <label>
            accuracy m{' '}
            <input type="text" value={accuracy} onChange={(e) => setAccuracy(e.target.value)} style={{ width: 60 }} />
          </label>
          <label>
            name{' '}
            <input type="text" value={placeName} onChange={(e) => setPlaceName(e.target.value)} placeholder="Salt Lake City" />
          </label>
          <button className="secondary" onClick={useMyLocation}>
            Use my current location
          </button>
        </div>
        <label className="field">
          Extra recipient pubkeys (comma/space separated hex). You are always a recipient, as in the
          C web-ui, so you can read your own updates back.
        </label>
        <input
          type="text"
          value={extraRecipients}
          onChange={(e) => setExtraRecipients(e.target.value)}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="optional…"
        />
        <div className="row" style={{ marginTop: 10 }}>
          <button onClick={doPost} disabled={busy}>
            Post update
          </button>
          <span className="status-line">
            Signed as {shortHex(keyStore.getPublicKeyHex())}
          </span>
        </div>
        {postStatus && <p className="status-line">{postStatus}</p>}
      </div>
    </div>
  )
}
