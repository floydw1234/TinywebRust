// Entry point for the headless household-devices proof
// (scripts/household-proof.mjs). Re-exports the page's real
// modules so the runner exercises exactly what the browser
// runs — only localStorage is shimmed.
export {
  createEnrollmentIdentity,
  beginEnrollment,
  checkEnrollment,
  getEnrollmentMeta,
} from '../src/utils/enrollment'
export { getHouseholdDevices, revokeOwnDevice } from '../src/api'
