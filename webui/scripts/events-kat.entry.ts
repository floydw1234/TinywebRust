// Entry point for the headless calendar-event known-answer
// check (scripts/events-kat.check.mjs). Re-exports the page's
// real modules so the runner exercises exactly what the
// browser runs.
export { calendarEventDigest } from '../src/utils/events'
export { serializeCalendarEvent, type CalendarEventData } from '../src/utils/protobuf'
export { toHex } from '../src/utils/hex'
