import { useCallback, useEffect, useState } from 'react'
import keyStore from './utils/keystore'
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
