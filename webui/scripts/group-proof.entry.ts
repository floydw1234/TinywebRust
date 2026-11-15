// Entry point for the headless group-chat checks (scripts/group-proof.mjs
// and scripts/group-kat.check.mjs). Re-exports the page's real modules
// so the runners exercise exactly what the browser runs — only
// localStorage is shimmed.
export {
  createEnrollmentIdentity,
  beginEnrollment,
  checkEnrollment,
  getEnrollmentMeta,
} from '../src/utils/enrollment'
export {
  acceptPendingShares,
  decryptGroupMessage,
  encryptGroupMessage,
  groupKatCheck,
  markGroupSessionStale,
  noteGroupMembers,
} from '../src/utils/groupSession'
export {
  addGroupMember,
  createGroup,
  getGroups,
  getRecentMessages,
  removeGroupMember,
  submitMessage,
} from '../src/api'
export { serializeMessage } from '../src/utils/protobuf'
export { toHex } from '../src/utils/hex'
