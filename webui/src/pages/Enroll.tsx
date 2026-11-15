import { useEffect, useState } from 'react'
import {
  beginEnrollment,
  checkEnrollment,
  createEnrollmentIdentity,
  getEnrollmentMeta,
  resetEnrollment,
  type EnrollmentMeta,
} from '../utils/enrollment'
import { shortHex } from '../utils/hex'

interface Props {
  onIdentityChanged: () => void
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, totalSeconds)
  const m = Math.floor(s / 60)
  const r = s % 60
  return `${m}:${r.toString().padStart(2, '0')}`
}

function groupCode(code: string): string {
  return (code.match(/.{1,4}/g) || []).join(' ')
}

/**
 * The Enroll view — the real pairing flow against the live node
 * (Phase B5). Create an identity, get a pairing code, a parent
 * approves it from their device, and this browser lands enrolled
 * with the member key as its active identity. Every failure shows
 * its reason here; nothing fails silently.
 */
export default function Enroll({ onIdentityChanged }: Props) {
  const [meta, setMeta] = useState<EnrollmentMeta | null>(() => getEnrollmentMeta())
  const [name, setName] = useState('Web Tester')
  const [label, setLabel] = useState('browser')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000))

  const refresh = () => setMeta(getEnrollmentMeta())
  const pending = meta?.phase === 'pending' && !!meta.code
  const remaining = meta?.expiresAt ? meta.expiresAt - nowSec : 0

  // Tick once a second while a code is on screen so the countdown is live.
  useEffect(() => {
    if (!pending) return
    const t = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000)
    return () => window.clearInterval(t)
  }, [pending])

  // Poll the node while a pairing is pending. Every outcome is
  // surfaced: approval activates the enrolled identity, expiry and
  // unknown codes say so plainly with a way to retry, and a failed
  // check shows its error (polling continues; the next successful
  // check clears it).
  useEffect(() => {
    if (!pending) return
    let cancelled = false
    const tick = async () => {
      try {
        const res = await checkEnrollment()
        if (cancelled) return
        if (res.state === 'approved') {
          setError('')
          setNote('Approved — enrollment complete. This browser now signs as the enrolled member.')
          onIdentityChanged()
          refresh()
        } else if (res.state === 'expired') {
          setError('The pairing code expired before it was approved. Begin again to get a fresh code.')
          refresh()
        } else if (res.state === 'unknown') {
          setError('The node no longer knows this pairing code. Begin again to get a fresh code.')
          refresh()
        } else {
          setError('')
        }
      } catch (e) {
        if (!cancelled) setError(`Status check failed: ${errText(e)}`)
      }
    }
    void tick()
    const t = window.setInterval(tick, 3000)
    return () => {
      cancelled = true
      window.clearInterval(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending, meta?.code])

  const doCreateAndBegin = async () => {
    setBusy(true)
    setError('')
    setNote('')
    try {
      await createEnrollmentIdentity(name.trim() || 'Member', label.trim() || 'device')
      const res = await beginEnrollment()
      setNote(
        `Pairing opened — the code below is live until ${new Date(res.expires_at * 1000).toLocaleTimeString()}.`,
      )
      refresh()
    } catch (e) {
      console.error('Create/begin enrollment failed:', e)
      setError(`Could not start enrollment: ${errText(e)}`)
      refresh()
    } finally {
      setBusy(false)
    }
  }

  const doBeginAgain = async () => {
    setBusy(true)
    setError('')
    setNote('')
    try {
      const res = await beginEnrollment()
      setNote(
        `New pairing opened — the code below is live until ${new Date(res.expires_at * 1000).toLocaleTimeString()}.`,
      )
      refresh()
    } catch (e) {
      console.error('Begin enrollment failed:', e)
      setError(`Could not begin enrollment: ${errText(e)}`)
      refresh()
    } finally {
      setBusy(false)
    }
  }

  const doReset = async () => {
    if (
      !window.confirm(
        'Forget this enrollment identity (the member + device keys kept for joining)? The active identity and the node-side enrollment are not changed.',
      )
    )
      return
    setBusy(true)
    setError('')
    setNote('')
    try {
      await resetEnrollment()
      setNote('Enrollment identity forgotten. You can create a fresh one.')
      refresh()
    } catch (e) {
      console.error('Reset enrollment failed:', e)
      setError(`Reset failed: ${errText(e)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="card">
        <h2>Join this household</h2>
        <p className="status-line">
          The real enrollment flow — no database inserts. This browser makes a member key and a
          device key, the member key signs a certificate for the device, and the node issues a
          one-time pairing code. A parent approves the code from their own device; the moment
          they do, this browser is enrolled and signs as the member — chat, location, everything.
        </p>

        {!meta && (
          <div>
            <label className="field">Display name (how the family sees this member)</label>
            <div className="row">
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{ width: 260 }}
                placeholder="e.g. Web Tester"
              />
            </div>
            <label className="field">Device label (names this browser in the member's device list)</label>
            <div className="row">
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                style={{ width: 260 }}
                placeholder="e.g. browser"
              />
              <button onClick={doCreateAndBegin} disabled={busy}>
                {busy ? 'Working…' : 'Create identity & begin enrollment'}
              </button>
            </div>
          </div>
        )}

        {meta && (
          <div>
            <p className="status-line">
              Member:{' '}
              <span className="mono" title={meta.memberPubkey}>
                {shortHex(meta.memberPubkey)}
              </span>
              {' · '}Device ({meta.deviceLabel}):{' '}
              <span className="mono" title={meta.devicePubkey}>
                {shortHex(meta.devicePubkey)}
              </span>
              {' · '}Name: {meta.displayName}
            </p>

            {meta.phase === 'keys' && (
              <div>
                <p className="status-line">
                  Identity created and stored in this browser. Begin enrollment to get a pairing
                  code.
                </p>
                <button onClick={doBeginAgain} disabled={busy}>
                  {busy ? 'Working…' : 'Begin enrollment'}
                </button>
              </div>
            )}

            {meta.phase === 'pending' && meta.code && (
              <div>
                <p className="status-line">
                  Show this code to a parent — they approve it from their own device:
                </p>
                <div className="pairing-code">{groupCode(meta.code)}</div>
                <p className="status-line" style={{ textAlign: 'center' }}>
                  {remaining > 0 ? (
                    <>
                      Expires in <strong>{formatCountdown(remaining)}</strong> · waiting for
                      approval — this page checks every few seconds…
                    </>
                  ) : (
                    <>Code expired — checking with the node…</>
                  )}
                </p>
              </div>
            )}

            {meta.phase === 'enrolled' && (
              <div>
                <p className="status-line status-ok">
                  Enrolled as {meta.displayName}
                  {meta.enrolledAt
                    ? ` since ${new Date(meta.enrolledAt * 1000).toLocaleString()}`
                    : ''}
                  .
                </p>
                <p className="status-line">
                  This browser's active identity is now the member key above, so Messages and
                  Location sign as this member. To test another join, reset below and start over.
                </p>
              </div>
            )}

            <div className="row" style={{ marginTop: 10 }}>
              <button className="secondary" onClick={doReset} disabled={busy}>
                Reset enrollment identity
              </button>
            </div>
          </div>
        )}

        {error && <p className="status-line status-bad">{error}</p>}
        {note && <p className="status-line">{note}</p>}
      </div>
    </div>
  )
}
