/**
 * Deprecated root aliases for the internal SPI. They keep 0.1 imports working for one
 * minor release; import these from `@shieldaai/agent-guard/internal` instead.
 */
import * as internal from './internal.js';
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const PolicyAdmission = internal.PolicyAdmission;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export type PolicyAdmission = internal.PolicyAdmission;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const assertActionAuthority = internal.assertActionAuthority;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const containsLiteralSecret = internal.containsLiteralSecret;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export type AuthorityPhase = internal.AuthorityPhase;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export type AuthorityState = internal.AuthorityState;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const immutableJson = internal.immutableJson;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const canonicalJson = internal.canonicalJson;
/** @deprecated Import from `@shieldaai/agent-guard/internal`; this root alias is removed in 0.3. */
export const digestJson = internal.digestJson;
