import { McpBoundaryError } from './boundary.js';

/** Claims already authenticated by the host's maintained OAuth/JWT verifier. */
export interface VerifiedMcpClaims {
  issuer: string;
  audience: string | readonly string[];
  subject: string;
  expiresAt: number;
  notBefore?: number;
  scopes?: readonly string[];
}
export interface McpAuthorizationPolicy {
  issuer: string;
  audience: string;
  subject: string;
  requiredScopes?: readonly string[];
}

/**
 * Checks resource/issuer/subject/scope/time binding AFTER cryptographic validation.
 * This never parses a token, verifies a signature, discovers an issuer, or authenticates
 * arbitrary claims. Passing decoded-but-unverified JWT claims is unsafe.
 * Times are Unix seconds. There is deliberately no expiry clock-skew allowance.
 */
export function assertVerifiedMcpClaims(claims: VerifiedMcpClaims, policy: McpAuthorizationPolicy, now = Date.now() / 1000): void {
  const strings = [claims.issuer, claims.subject, policy.issuer, policy.audience, policy.subject];
  if (strings.some(value => typeof value !== 'string' || !value.trim() || value.length > 4096) || !Number.isFinite(now)) throw new McpBoundaryError('AUTHORIZATION_DENIED');
  const audiences = typeof claims.audience === 'string' ? [claims.audience] : claims.audience;
  if (!Array.isArray(audiences) || audiences.length > 64 || audiences.some(value => typeof value !== 'string') ||
      claims.issuer !== policy.issuer || claims.subject !== policy.subject || !audiences.includes(policy.audience) ||
      !Number.isFinite(claims.expiresAt) || claims.expiresAt <= now ||
      (claims.notBefore !== undefined && (!Number.isFinite(claims.notBefore) || claims.notBefore > now))) throw new McpBoundaryError('AUTHORIZATION_DENIED');
  const scopes = claims.scopes ?? []; const required = policy.requiredScopes ?? [];
  if (!Array.isArray(scopes) || !Array.isArray(required) || scopes.length > 256 || required.length > 256 ||
      [...scopes, ...required].some(value => typeof value !== 'string' || !value || value.length > 1024) || required.some(scope => !scopes.includes(scope))) throw new McpBoundaryError('AUTHORIZATION_DENIED');
}
