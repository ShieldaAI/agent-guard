/**
 * Building blocks shared by first-party Agent Guard packages (the durable executor,
 * MCP and scenarios). Not part of the stable API: no semver guarantees, and any
 * export may change in a minor release. Import from `@shieldaai/agent-guard/internal`.
 */
export { PolicyAdmission } from './policy-admission.js';
export { assertActionAuthority, containsLiteralSecret } from './authorization.js';
export type { AuthorityPhase, AuthorityState } from './authorization.js';
export { immutableJson, canonicalJson, digestJson } from './json.js';
