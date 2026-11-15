import { useCallback, useEffect, useState } from 'react'
import {
  addGroupMember,
  createGroup,
  decryptMessageText,
  getConversation,
  getConversations,
  getGroups,
  getRecentMessages,
  getUsers,
  removeGroupMember,
  submitMessage,
  type NodeGroup,
  type NodeUser,
} from '../api'
import {
  acceptPendingShares,
  decryptGroupMessage,
  encryptGroupMessage,
  markGroupSessionStale,
  noteGroupMembers,
} from '../utils/groupSession'
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

interface GroupRow {
  msg: TinyMessage
  text: string | null
  error?: string
  senderHex: string
  mine: boolean
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

  // Groups (Phase C2: B4 sender sessions in the browser)
  const [users, setUsers] = useState<NodeUser[]>([])
  const [groups, setGroups] = useState<NodeGroup[]>([])
  const [groupName, setGroupName] = useState('')
  const [groupPicks, setGroupPicks] = useState<Set<string>>(new Set())
  const [groupStatus, setGroupStatus] = useState('')
  const [groupError, setGroupError] = useState('')
  const [selectedGroup, setSelectedGroup] = useState<NodeGroup | null>(null)
  const [groupThread, setGroupThread] = useState<GroupRow[]>([])
  const [groupDraft, setGroupDraft] = useState('')
  const [groupBusy, setGroupBusy] = useState(false)
  const [addPick, setAddPick] = useState<Record<string, string>>({})

  const myHex = identity || ''

  const userLabel = (hex: string): string => {
    const user = users.find((u) => u.pubkey === hex)
    return user ? user.username : shortHex(hex)
  }

  const loadConversations = useCallback(async () => {
    if (!myHex) return
    setConvErr('')
    try {
      setConversations(await getConversations(myHex))
    } catch (e) {
      setConvErr(e instanceof Error ? e.message : String(e))
    }
  }, [myHex])

  const loadGroups = useCallback(async () => {
    try {
      const [gs, us] = await Promise.all([getGroups(), getUsers()])
      setUsers(us)
      setGroups(gs)
      const notes: string[] = []
      for (const g of gs) {
        if (noteGroupMembers(g)) {
          notes.push(
            `Membership changed in "${g.name}" — your next send there starts a fresh session.`,
          )
        }
        setSelectedGroup((prev) =>
          prev && prev.group_id === g.group_id ? g : prev,
        )
      }
      if (notes.length > 0) setGroupStatus(notes.join(' '))
    } catch (e) {
      setGroupError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    void loadConversations()
    void loadGroups()
  }, [loadConversations, loadGroups])

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

  const openGroupThread = async (group: NodeGroup) => {
    setSelectedGroup(group)
    setGroupError('')
    setGroupBusy(true)
    try {
      const accepted = await acceptPendingShares()
      if (accepted.warnings.length > 0) {
        setGroupStatus(`Share check: ${accepted.warnings.join('; ')}`)
      } else if (accepted.accepted.length > 0) {
        setGroupStatus(
          `Accepted ${accepted.accepted.length} new group key share(s).`,
        )
      }
      const messages = await getRecentMessages(myHex, 100)
      const inGroup = messages
        .filter(
          (m) => m.header.groupId && toHex(m.header.groupId) === group.group_id,
        )
        .sort(
          (a, b) =>
            a.header.timestamp - b.header.timestamp ||
            a.messageIndex - b.messageIndex,
        )
      const rows: GroupRow[] = []
      for (const m of inGroup) {
        const senderHex = toHex(m.header.senderPubkey)
        const mine = senderHex === myHex
        if (m.sessionId && m.sessionId.length > 0) {
          const r = await decryptGroupMessage(m)
          rows.push({ msg: m, text: r.text, error: r.error, senderHex, mine })
        } else {
          rows.push({
            msg: m,
            text: null,
            error: 'group message without a sender session (legacy format)',
            senderHex,
            mine,
          })
        }
      }
      setGroupThread(rows)
    } catch (e) {
      setGroupThread([])
      setGroupError(e instanceof Error ? e.message : String(e))
    } finally {
      setGroupBusy(false)
    }
  }

  const doCreateGroup = async () => {
    if (!groupName.trim()) {
      setGroupError('Group name is required.')
      return
    }
    setGroupBusy(true)
    setGroupError('')
    try {
      const g = await createGroup(groupName.trim(), [...groupPicks])
      noteGroupMembers(g)
      setGroupName('')
      setGroupPicks(new Set())
      setGroupStatus(`Group "${g.name}" created.`)
      await loadGroups()
    } catch (e) {
      setGroupError(e instanceof Error ? e.message : String(e))
    } finally {
      setGroupBusy(false)
    }
  }

  const doAddMember = async (group: NodeGroup) => {
    const pk = addPick[group.group_id]
    if (!pk) return
    setGroupBusy(true)
    setGroupError('')
    try {
      const g = await addGroupMember(group.group_id, pk)
      if (noteGroupMembers(g)) {
        setGroupStatus(
          `Member added to "${g.name}" — your next send starts a fresh session.`,
        )
      }
      await loadGroups()
      if (selectedGroup?.group_id === g.group_id) await openGroupThread(g)
    } catch (e) {
      setGroupError(e instanceof Error ? e.message : String(e))
    } finally {
      setGroupBusy(false)
    }
  }

  const doRemoveMember = async (group: NodeGroup, memberHex: string) => {
    setGroupBusy(true)
    setGroupError('')
    try {
      const g = (await removeGroupMember(group.group_id, memberHex)) as NodeGroup
      if (g && g.group_id) {
        if (noteGroupMembers(g)) {
          setGroupStatus(
            `Member removed from "${g.name}" — your next send starts a fresh session.`,
          )
        }
        await loadGroups()
        if (selectedGroup?.group_id === g.group_id) await openGroupThread(g)
      } else {
        await loadGroups()
      }
    } catch (e) {
      setGroupError(e instanceof Error ? e.message : String(e))
    } finally {
      setGroupBusy(false)
    }
  }

  const doGroupSend = async () => {
    const group = selectedGroup
    if (!group || !groupDraft.trim()) return
    setGroupBusy(true)
    setGroupError('')
    setGroupStatus('Starting session if needed, encrypting, submitting…')
    try {
      const enc = await encryptGroupMessage(
        group.group_id,
        group.members,
        groupDraft.trim(),
      )
      const warnings = [...enc.shareWarnings, ...enc.metadataWarnings]
      try {
        await submitMessage(serializeMessage(enc.message))
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e)
        if (/retired/i.test(message) || /\b403\b/.test(message)) {
          markGroupSessionStale(group.group_id)
          setGroupError(
            `The node retired this session because membership changed (${message}). ` +
              'Your draft is still here — press Send again and a fresh session will start.',
          )
          return
        }
        throw e
      }
      setGroupDraft('')
      setGroupStatus(
        warnings.length > 0
          ? `Sent (session message #${enc.index}). Warnings: ${warnings.join('; ')}`
          : `Sent (session message #${enc.index}).`,
      )
      await openGroupThread(group)
    } catch (e) {
      setGroupError(`Group send failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setGroupBusy(false)
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

          <div className="card">
            <h2>Groups</h2>
            <button onClick={loadGroups}>Refresh (GET /groups)</button>
            {groupError && <p className="status-line status-bad">{groupError}</p>}
            {groupStatus && <p className="status-line">{groupStatus}</p>}
            <div style={{ marginTop: 10 }}>
              {groups.map((g) => (
                <div
                  key={g.group_id}
                  className={`list-item ${selectedGroup?.group_id === g.group_id ? 'selected' : ''}`}
                  onClick={() => openGroupThread(g)}
                >
                  <div>{g.name}</div>
                  <div className="mono" title={g.group_id}>
                    {shortHex(g.group_id)} · {g.members.length} member(s)
                  </div>
                </div>
              ))}
              {groups.length === 0 && (
                <p className="status-line">No groups yet. Create one below.</p>
              )}
            </div>
            <h3>New group</h3>
            <label className="field">Name</label>
            <input
              type="text"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
              placeholder="Family chat…"
            />
            <label className="field">Members (only enrolled members can be added)</label>
            {users
              .filter((u) => u.pubkey !== myHex)
              .map((u) => (
                <label key={u.pubkey} className="row" style={{ gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={groupPicks.has(u.pubkey)}
                    onChange={(e) => {
                      const next = new Set(groupPicks)
                      if (e.target.checked) next.add(u.pubkey)
                      else next.delete(u.pubkey)
                      setGroupPicks(next)
                    }}
                  />
                  <span>{u.username}</span>
                  <span className="mono">{shortHex(u.pubkey)}</span>
                </label>
              ))}
            <div className="row" style={{ marginTop: 8 }}>
              <button onClick={doCreateGroup} disabled={groupBusy || !groupName.trim()}>
                Create group (POST /groups)
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

          {selectedGroup && (
            <div className="card">
              <h2>
                Group: {selectedGroup.name}{' '}
                <span className="mono" title={selectedGroup.group_id}>
                  {shortHex(selectedGroup.group_id)}
                </span>
              </h2>
              <h3>Members</h3>
              {selectedGroup.members.map((m) => (
                <div key={m} className="row" style={{ gap: 6 }}>
                  <span>{userLabel(m)}</span>
                  <span className="mono">{shortHex(m)}</span>
                  {m === myHex && <span>(you)</span>}
                  {m !== myHex && m !== selectedGroup.creator && (
                    <button
                      className="secondary"
                      disabled={groupBusy}
                      onClick={() => doRemoveMember(selectedGroup, m)}
                    >
                      Remove
                    </button>
                  )}
                </div>
              ))}
              <div className="row" style={{ marginTop: 6, gap: 6 }}>
                <select
                  value={addPick[selectedGroup.group_id] || ''}
                  onChange={(e) =>
                    setAddPick({ ...addPick, [selectedGroup.group_id]: e.target.value })
                  }
                >
                  <option value="">Add a member…</option>
                  {users
                    .filter((u) => !selectedGroup.members.includes(u.pubkey))
                    .map((u) => (
                      <option key={u.pubkey} value={u.pubkey}>
                        {u.username}
                      </option>
                    ))}
                </select>
                <button
                  className="secondary"
                  disabled={groupBusy || !addPick[selectedGroup.group_id]}
                  onClick={() => doAddMember(selectedGroup)}
                >
                  Add member
                </button>
                <button
                  className="secondary"
                  disabled={groupBusy}
                  onClick={() => openGroupThread(selectedGroup)}
                >
                  Reload group thread
                </button>
              </div>
              <h3>Thread</h3>
              {groupThread.map((d, i) => (
                <div className="msg" key={i}>
                  <div className="meta">
                    {d.mine ? 'You' : userLabel(d.senderHex)} ·{' '}
                    {formatTime(d.msg.header.timestamp)} · session #
                    {d.msg.messageIndex}
                  </div>
                  <div>
                    {d.text !== null ? (
                      d.text
                    ) : (
                      <em>[could not decrypt: {d.error || 'unknown error'}]</em>
                    )}
                  </div>
                </div>
              ))}
              {groupThread.length === 0 && (
                <p className="status-line">No group messages yet.</p>
              )}
              <label className="field">New group message (sender session, POST /messages/submit)</label>
              <textarea
                rows={3}
                value={groupDraft}
                onChange={(e) => setGroupDraft(e.target.value)}
                placeholder="Type a group message…"
              />
              <div className="row" style={{ marginTop: 8 }}>
                <button onClick={doGroupSend} disabled={groupBusy || !groupDraft.trim()}>
                  Send to group
                </button>
              </div>
              <p className="status-line">
                Group messages use a sender session: one key per sender, shared once with
                each member's devices. Adding or removing a member retires the old session;
                your next send starts a fresh one.
              </p>
            </div>
          )}

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
