import { useCallback, useEffect, useState } from 'react'
import {
  decryptMessageText,
  getConversation,
  getConversations,
  getRecentMessages,
  submitMessage,
} from '../api'
import { fromHex, shortHex, toHex } from '../utils/hex'
import { createDirectMessage } from '../utils/message'
import { serializeMessage, type ConversationSummary, type TinyMessage } from '../utils/protobuf'

interface Props {
  identity: string | null
}

interface DecodedMessage {
  msg: TinyMessage
  text: string | null
  senderHex: string
  mine: boolean
  partnerHex: string
}

async function decodeAll(messages: TinyMessage[], myHex: string): Promise<DecodedMessage[]> {
  const out: DecodedMessage[] = []
  for (const msg of messages) {
    const senderHex = toHex(msg.header.senderPubkey)
    const text = await decryptMessageText(msg)
    let partnerHex = senderHex
    if (senderHex === myHex) {
      const other = msg.header.recipientsPubkey
        .map((pk) => toHex(pk))
        .find((h) => h !== myHex)
      partnerHex = other || senderHex
    }
    out.push({ msg, text, senderHex, mine: senderHex === myHex, partnerHex })
  }
  return out
}

function formatTime(unixSeconds: number): string {
  if (!unixSeconds) return ''
  return new Date(unixSeconds * 1000).toLocaleString()
}

export default function Messages({ identity }: Props) {
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [convErr, setConvErr] = useState('')
  const [partner, setPartner] = useState('')
  const [thread, setThread] = useState<DecodedMessage[]>([])
  const [threadErr, setThreadErr] = useState('')
  const [recent, setRecent] = useState<DecodedMessage[]>([])
  const [recentErr, setRecentErr] = useState('')
  const [draft, setDraft] = useState('')
  const [sendStatus, setSendStatus] = useState('')
  const [busy, setBusy] = useState(false)

  const myHex = identity || ''

  const loadConversations = useCallback(async () => {
    if (!myHex) return
    setConvErr('')
    try {
      setConversations(await getConversations(myHex))
    } catch (e) {
      setConvErr(e instanceof Error ? e.message : String(e))
    }
  }, [myHex])

  useEffect(() => {
    void loadConversations()
  }, [loadConversations])

  const openThread = async (partnerHex: string) => {
    setPartner(partnerHex)
    setThreadErr('')
    setSendStatus('')
    try {
      const messages = await getConversation(myHex, partnerHex)
      setThread(await decodeAll(messages, myHex))
    } catch (e) {
      setThread([])
      setThreadErr(e instanceof Error ? e.message : String(e))
    }
  }

  const loadRecent = async () => {
    setRecentErr('')
    try {
      const messages = await getRecentMessages(myHex, 50)
      setRecent(await decodeAll(messages, myHex))
    } catch (e) {
      setRecent([])
      setRecentErr(e instanceof Error ? e.message : String(e))
    }
  }

  const doSend = async () => {
    if (!partner || !draft.trim()) return
    setBusy(true)
    setSendStatus('Encrypting, signing, submitting…')
    try {
      const msg = await createDirectMessage(fromHex(partner), draft.trim())
      const bytes = serializeMessage(msg)
      const res = await submitMessage(bytes)
      setSendStatus(`Sent: ${JSON.stringify(res)}`)
      setDraft('')
      await openThread(partner)
      void loadConversations()
    } catch (e) {
      setSendStatus(`Send failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setBusy(false)
    }
  }

  if (!identity) {
    return (
      <div className="card">
        <h2>Messages</h2>
        <p className="status-line status-bad">
          No identity loaded. Generate or import one on the Dashboard tab first.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="columns">
        <div className="col-list">
          <div className="card">
            <h2>Conversations</h2>
            <button onClick={loadConversations}>Refresh (GET /messages/conversations)</button>
            {convErr && <p className="status-line status-bad">{convErr}</p>}
            <div style={{ marginTop: 10 }}>
              {conversations.map((c) => (
                <div
                  key={c.partnerPubkeyHex}
                  className={`list-item ${partner === c.partnerPubkeyHex ? 'selected' : ''}`}
                  onClick={() => openThread(c.partnerPubkeyHex)}
                >
                  <div className="mono" title={c.partnerPubkeyHex}>
                    {shortHex(c.partnerPubkeyHex)}
                  </div>
                  <div>
                    last: {formatTime(c.lastMessageTimestamp)}
                    {c.unreadCount > 0 ? ` · ${c.unreadCount} unread` : ''}
                  </div>
                </div>
              ))}
              {conversations.length === 0 && !convErr && (
                <p className="status-line">No conversations yet.</p>
              )}
            </div>
            <h3>Open a conversation</h3>
            <label className="field">Partner public key (hex)</label>
            <input
              type="text"
              value={partner}
              onChange={(e) => setPartner(e.target.value.trim())}
              style={{ width: '100%', boxSizing: 'border-box' }}
              placeholder="hex pubkey…"
            />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="secondary" onClick={() => partner && openThread(partner)} disabled={!partner}>
                Open thread
              </button>
              <button className="secondary" onClick={() => openThread(myHex)}>
                Chat with myself
              </button>
            </div>
          </div>
        </div>

        <div className="col-main">
          <div className="card">
            <h2>
              Thread{' '}
              {partner && (
                <span className="mono" title={partner}>
                  with {shortHex(partner)}
                </span>
              )}
            </h2>
            {!partner && <p className="status-line">Pick or enter a partner to open a thread.</p>}
            {threadErr && <p className="status-line status-bad">{threadErr}</p>}
            {thread.map((d, i) => (
              <div className="msg" key={i}>
                <div className="meta">
                  {d.mine ? 'You' : shortHex(d.senderHex)} ·{' '}
                  {formatTime(d.msg.header.timestamp)}
                </div>
                <div>{d.text !== null ? d.text : <em>[could not decrypt]</em>}</div>
              </div>
            ))}
            {partner && thread.length === 0 && !threadErr && (
              <p className="status-line">No messages in this thread yet.</p>
            )}
            <label className="field">New message (POST /messages/submit)</label>
            <textarea
              rows={3}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Type a message…"
              disabled={!partner}
            />
            <div className="row" style={{ marginTop: 8 }}>
              <button onClick={doSend} disabled={busy || !partner || !draft.trim()}>
                Send
              </button>
              {partner && (
                <button className="secondary" onClick={() => openThread(partner)}>
                  Reload thread
                </button>
              )}
            </div>
            {sendStatus && <p className="status-line">{sendStatus}</p>}
          </div>

          <div className="card">
            <h2>Recent messages</h2>
            <button onClick={loadRecent}>Load (GET /messages/recent)</button>
            {recentErr && <p className="status-line status-bad">{recentErr}</p>}
            {recent.map((d, i) => (
              <div className="msg" key={i}>
                <div className="meta">
                  {d.mine ? `You → ${shortHex(d.partnerHex)}` : `From ${shortHex(d.senderHex)}`} ·{' '}
                  {formatTime(d.msg.header.timestamp)}
                </div>
                <div>{d.text !== null ? d.text : <em>[could not decrypt]</em>}</div>
              </div>
            ))}
            {recent.length === 0 && !recentErr && (
              <p className="status-line">Nothing loaded yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
