import { useCallback, useEffect, useState } from 'react'
import keyStore from './utils/keystore'
import { checkEnrollment, getEnrollmentMeta } from './utils/enrollment'
import { getRawCalls, subscribeRawCalls, type RawCall } from './api'
import { shortHex } from './utils/hex'
import Dashboard from './pages/Dashboard'
import Messages from './pages/Messages'
import Location from './pages/Location'
import Events from './pages/Events'
import Enroll from './pages/Enroll'

type Tab = 'dashboard' | 'messages' | 'location' | 'events' | 'enroll'

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [identity, setIdentity] = useState<string | null>(null)
  const [rawCalls, setRawCalls] = useState<RawCall[]>(getRawCalls())

  const refreshIdentity = useCallback(() => {
    setIdentity(keyStore.isKeypairLoaded() ? keyStore.getPublicKeyHex() : null)
  }, [])

  /**
   * Re-read the stored identity/enrollment state. Approval only
   * takes effect inside the Enroll tab's poll — checkEnrollment is
   * what activates the member key and flips the stored meta to
   * 'enrolled' — so if a parent approves while another tab is in
   * front (or in another browser tab), the header badge and the
   * Dashboard keep showing "no identity / waiting for approval"
   * until the Enroll tab is revisited. Re-checking when the window
   * regains focus, becomes visible, sees a storage write from
   * another tab, or returns to the Dashboard closes that gap: a
   * pending pairing is polled once, a keypair another tab
   * activated is picked up from local storage, and the badge is
   * refreshed from the keystore.
   */
  const rereadStoredState = useCallback(async () => {
    try {
      if (getEnrollmentMeta()?.phase === 'pending') {
        await checkEnrollment()
      }
    } catch (e) {
      console.error('Enrollment re-check failed:', e)
    }
    try {
      const raw = localStorage.getItem('tinyweb_keypair')
      if (raw) {
        const storedPubkey = (JSON.parse(raw) as { publicKey?: string }).publicKey
        const loadedPubkey = keyStore.isKeypairLoaded() ? keyStore.getPublicKeyHex() : null
        if (storedPubkey && storedPubkey !== loadedPubkey) {
          keyStore.cleanup()
          await keyStore.loadKeypair('')
        }
      }
    } catch (e) {
      console.error('Identity re-read from storage failed:', e)
    }
    refreshIdentity()
  }, [refreshIdentity])

  useEffect(() => {
    const onFocusOrStorage = () => void rereadStoredState()
    const onVisible = () => {
      if (document.visibilityState === 'visible') void rereadStoredState()
    }
    window.addEventListener('focus', onFocusOrStorage)
    window.addEventListener('storage', onFocusOrStorage)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      window.removeEventListener('focus', onFocusOrStorage)
      window.removeEventListener('storage', onFocusOrStorage)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [rereadStoredState])

  // Returning to the Dashboard is where a stale identity hurts
  // most, and a tab click fires none of the window events above —
  // re-read on arrival there too.
  useEffect(() => {
    if (tab === 'dashboard') void rereadStoredState()
  }, [tab, rereadStoredState])

  useEffect(() => {
    let cancelled = false
    keyStore
      .init()
      .then(() => {
        if (!cancelled) refreshIdentity()
      })
      .catch((e) => console.error('KeyStore init failed:', e))
    const unsub = subscribeRawCalls((calls) => setRawCalls([...calls]))
    return () => {
      cancelled = true
      unsub()
    }
  }, [refreshIdentity])

  const last = rawCalls[0]

  return (
    <div>
      <header className="app-header">
        <h1>TinyWebC Test UI</h1>
        <nav className="tabs">
          <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>
            Dashboard
          </button>
          <button className={tab === 'messages' ? 'active' : ''} onClick={() => setTab('messages')}>
            Messages
          </button>
          <button className={tab === 'location' ? 'active' : ''} onClick={() => setTab('location')}>
            Location
          </button>
          <button className={tab === 'events' ? 'active' : ''} onClick={() => setTab('events')}>
            Events
          </button>
          <button className={tab === 'enroll' ? 'active' : ''} onClick={() => setTab('enroll')}>
            Enroll
          </button>
        </nav>
        <span className="identity-chip">
          {identity ? `identity: ${shortHex(identity)}` : 'no identity'}
        </span>
      </header>

      <main>
        {tab === 'dashboard' && (
          <Dashboard identity={identity} onIdentityChanged={refreshIdentity} rawCalls={rawCalls} />
        )}
        {tab === 'messages' && <Messages identity={identity} />}
        {tab === 'location' && <Location identity={identity} />}
        {tab === 'events' && <Events identity={identity} />}
        {tab === 'enroll' && <Enroll onIdentityChanged={refreshIdentity} />}
      </main>

      <footer className="last-call">
        {last
          ? `last call: ${last.method} ${last.path} → ${last.status ?? 'error'}`
          : 'no API calls yet'}
      </footer>
    </div>
  )
}
