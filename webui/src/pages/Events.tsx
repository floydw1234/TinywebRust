import { useCallback, useEffect, useState } from 'react'
import {
  deleteEvent,
  getEvents,
  getUsers,
  submitEvent,
  type NodeEvent,
  type NodeUser,
} from '../api'
import { fromHex, shortHex } from '../utils/hex'
import {
  buildEventEnvelope,
  eventsIdentityReady,
  formatEventTime,
  zonedTimeToUnix,
  type EventFields,
} from '../utils/events'
import type { CalendarEventData } from '../utils/protobuf'

interface Props {
  identity: string | null
}

const DAY = 86400

/** The CalendarEventData a tombstone/update builds on, from the list JSON. */
function existingFrom(ev: NodeEvent): CalendarEventData {
  return {
    eventId: fromHex(ev.event_id),
    title: ev.title,
    notes: ev.notes,
    location: ev.location,
    startUnix: ev.start_unix,
    endUnix: ev.end_unix,
    timezone: ev.timezone,
    allDay: ev.all_day,
    rrule: ev.rrule,
    createdBy: fromHex(ev.created_by),
    actorMemberPubkey: new Uint8Array(0),
    actorDevicePubkey: new Uint8Array(0),
    createdAt: ev.created_at,
    updatedAt: ev.updated_at,
    deleted: ev.deleted,
    signature: new Uint8Array(0),
  }
}

function fieldsFrom(ev: NodeEvent): EventFields {
  return {
    title: ev.title,
    notes: ev.notes,
    location: ev.location,
    startUnix: ev.start_unix,
    endUnix: ev.end_unix,
    timezone: ev.timezone,
    allDay: ev.all_day,
    rrule: ev.rrule,
  }
}

export default function Events({ identity }: Props) {
  const [events, setEvents] = useState<NodeEvent[]>([])
  const [users, setUsers] = useState<NodeUser[]>([])
  const [listErr, setListErr] = useState('')
  // False until the first list fetch settles. Without it the first
  // paint claimed "0 events / No events in the next 30 days" while
  // the mount fetch was still in flight, which read as "the view
  // does not auto-load" — the fetch below did fire on mount, the
  // empty state was simply shown before its answer landed.
  const [loaded, setLoaded] = useState(false)
  const [showDeleted, setShowDeleted] = useState(false)
  const [enrolled, setEnrolled] = useState<boolean | null>(null)
  const [busyId, setBusyId] = useState('')
  const [rowStatus, setRowStatus] = useState<Record<string, string>>({})

  const [title, setTitle] = useState('')
  const [location, setLocation] = useState('')
  const [notes, setNotes] = useState('')
  const [startLocal, setStartLocal] = useState('')
  const [endLocal, setEndLocal] = useState('')
  const [timezone, setTimezone] = useState('America/Denver')
  const [allDay, setAllDay] = useState(false)
  const [rrule, setRrule] = useState('')
  const [createStatus, setCreateStatus] = useState('')
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    setListErr('')
    try {
      const now = Math.floor(Date.now() / 1000)
      setEvents(await getEvents(now - DAY, now + 30 * DAY, showDeleted))
    } catch (e) {
      setEvents([])
      setListErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoaded(true)
    }
  }, [showDeleted])

  useEffect(() => {
    if (identity) void load()
  }, [identity, load])

  useEffect(() => {
    void eventsIdentityReady().then(setEnrolled)
    getUsers()
      .then(setUsers)
      .catch(() => {
        // names are decoration; short pubkeys still show
      })
  }, [])

  const nameOf = (pubkeyHex: string): string => {
    const user = users.find((u) => u.pubkey === pubkeyHex)
    return user ? user.username : shortHex(pubkeyHex)
  }

  const doCreate = async () => {
    if (!title.trim()) {
      setCreateStatus('Enter a title.')
      return
    }
    if (!startLocal) {
      setCreateStatus('Pick a start time.')
      return
    }
    setCreating(true)
    setCreateStatus('Signing and submitting…')
    try {
      let startUnix: number
      let endUnix: number
      if (allDay) {
        startUnix = zonedTimeToUnix(`${startLocal.slice(0, 10)}T00:00`, timezone)
        const endDate = endLocal ? endLocal.slice(0, 10) : startLocal.slice(0, 10)
        endUnix = zonedTimeToUnix(`${endDate}T00:00`, timezone)
        if (endUnix <= startUnix) endUnix = startUnix + DAY
      } else {
        startUnix = zonedTimeToUnix(startLocal, timezone)
        endUnix = endLocal ? zonedTimeToUnix(endLocal, timezone) : startUnix + 3600
        if (endUnix <= startUnix) {
          setCreateStatus('End must be after start.')
          setCreating(false)
          return
        }
      }
      const envelope = await buildEventEnvelope({
        fields: {
          title: title.trim(),
          notes: notes.trim(),
          location: location.trim(),
          startUnix,
          endUnix,
          timezone: timezone.trim() || 'America/Denver',
          allDay,
          rrule: rrule.trim(),
        },
      })
      const res = await submitEvent(envelope)
      setCreateStatus(`Created: ${JSON.stringify(res)}`)
      setTitle('')
      setLocation('')
      setNotes('')
      setRrule('')
      await load()
    } catch (e) {
      setCreateStatus(`Create failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setCreating(false)
    }
  }

  const doDelete = async (ev: NodeEvent) => {
    setBusyId(ev.event_id)
    setRowStatus((s) => ({ ...s, [ev.event_id]: 'Signing tombstone…' }))
    try {
      const envelope = await buildEventEnvelope({
        fields: fieldsFrom(ev),
        existing: existingFrom(ev),
        deleted: true,
      })
      await deleteEvent(ev.event_id, envelope)
      setRowStatus((s) => ({ ...s, [ev.event_id]: 'Deleted.' }))
      await load()
    } catch (e) {
      setRowStatus((s) => ({
        ...s,
        [ev.event_id]: `Delete failed: ${e instanceof Error ? e.message : String(e)}`,
      }))
    } finally {
      setBusyId('')
    }
  }

  if (!identity) {
    return (
      <div className="card">
        <h2>Events</h2>
        <p className="status-line status-bad">
          No identity loaded. Generate or import one on the Dashboard tab first.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="card">
        <h2>Upcoming events (GET /events, next 30 days)</h2>
        <div className="row">
          <button onClick={() => void load()}>Refresh</button>
          <label>
            <input
              type="checkbox"
              checked={showDeleted}
              onChange={(e) => setShowDeleted(e.target.checked)}
            />{' '}
            show deleted
          </label>
          <span className="status-line">
            {!loaded ? 'Loading…' : `${events.length} event${events.length === 1 ? '' : 's'}`}
          </span>
        </div>
        {enrolled === false && (
          <p className="status-line status-bad">
            Listing works with the active identity, but creating or deleting needs the enrolled
            member + device keys from the Enroll tab.
          </p>
        )}
        {listErr && <p className="status-line status-bad">{listErr}</p>}
        {!loaded && !listErr && <p className="status-line">Loading…</p>}
        {events.map((ev) => (
          <div className="msg" key={ev.event_id}>
            <div className="meta">
              {formatEventTime(ev.start_unix, ev.timezone, ev.all_day)}
              {!ev.all_day && ` → ${formatEventTime(ev.end_unix, ev.timezone, false)}`}
              {ev.all_day && ' · all day'}
              {ev.recurring && ` · repeats (${ev.rrule})`}
              {ev.deleted && ' · deleted'}
            </div>
            <div>
              <strong>{ev.title}</strong>
              {ev.location ? ` · ${ev.location}` : ''}
            </div>
            {ev.notes && <div>{ev.notes}</div>}
            <div className="meta">
              by {nameOf(ev.created_by)} · id {shortHex(ev.event_id)} · updated{' '}
              {new Date(ev.updated_at * 1000).toLocaleString()}
            </div>
            {!ev.deleted && (
              <div className="row">
                <button
                  className="secondary"
                  onClick={() => void doDelete(ev)}
                  disabled={busyId === ev.event_id}
                >
                  Delete
                </button>
                {rowStatus[ev.event_id] && (
                  <span className="status-line">{rowStatus[ev.event_id]}</span>
                )}
              </div>
            )}
          </div>
        ))}
        {loaded && events.length === 0 && !listErr && (
          <p className="status-line">No events in the next 30 days.</p>
        )}
      </div>

      <div className="card">
        <h2>New event (POST /events)</h2>
        <label className="field">Title</label>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="Family hike"
        />
        <div className="row">
          <label>
            Start{' '}
            <input
              type={allDay ? 'date' : 'datetime-local'}
              value={startLocal}
              onChange={(e) => setStartLocal(e.target.value)}
            />
          </label>
          <label>
            End{' '}
            <input
              type={allDay ? 'date' : 'datetime-local'}
              value={endLocal}
              onChange={(e) => setEndLocal(e.target.value)}
            />
          </label>
          <label>
            Timezone{' '}
            <input
              type="text"
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              style={{ width: 160 }}
            />
          </label>
          <label>
            <input type="checkbox" checked={allDay} onChange={(e) => setAllDay(e.target.checked)} />{' '}
            all day
          </label>
        </div>
        <label className="field">Location</label>
        <input
          type="text"
          value={location}
          onChange={(e) => setLocation(e.target.value)}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="Deer Ridge Trailhead, Draper"
        />
        <label className="field">Notes</label>
        <input
          type="text"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="optional…"
        />
        <label className="field">Recurrence (iCalendar RRULE, optional)</label>
        <input
          type="text"
          value={rrule}
          onChange={(e) => setRrule(e.target.value)}
          style={{ width: '100%', boxSizing: 'border-box' }}
          placeholder="FREQ=WEEKLY"
        />
        <div className="row" style={{ marginTop: 10 }}>
          <button onClick={() => void doCreate()} disabled={creating}>
            Create event
          </button>
          <span className="status-line">Signed as {shortHex(identity)}</span>
        </div>
        {createStatus && <p className="status-line">{createStatus}</p>}
      </div>
    </div>
  )
}
