/** Version of the synthetic acceptance cases, independent of package releases. */
export const SCENARIO_CATALOG_VERSION = '1.1.0' as const;

export type ScenarioId = 'S01' | 'S02' | 'S03' | 'S04' | 'S05' | 'S06' | 'S07' | 'S08' | 'S09' | 'S10';

export interface ScenarioDefinition {
  readonly id: ScenarioId;
  readonly title: string;
  readonly boundary: string;
  readonly malicious: readonly string[];
  readonly benign: string;
  readonly limitations: readonly string[];
}

const definitions: ScenarioDefinition[] = [
  {
    id: 'S01', title: 'Deny unknown tools and unauthorized resources',
    boundary: 'Approved registry and exact tool/resource grants before handler dispatch.',
    malicious: ['Unknown tool', 'Unauthorized resource with a claimed administrator role', 'Forged task handle'],
    benign: 'One explicitly granted document read returns the intended document.',
    limitations: ['The host must resolve canonical resources and enforce aliases and redirects at use time.'],
  },
  {
    id: 'S02', title: 'Reduce authority along local delegation',
    boundary: 'Child authority and admission remain bounded by every ancestor.',
    malicious: ['Broader tool/resource grant', 'Broader recipient/control-plane/budget authority', 'Spoofed parent identity', 'Revoked ancestor'],
    benign: 'A narrower child preserves its principal and tenant and reads its granted resource.',
    limitations: ['Local opaque handles are not remotely verifiable credentials.'],
  },
  {
    id: 'S03', title: 'Keep administration outside untrusted content',
    boundary: 'Trusted host administration is distinct from model-callable tools.',
    malicious: ['Unregistered administration tool', 'Claimed approval in arguments', 'Control-plane tool without authority'],
    benign: 'A trusted host policy update permits a subsequent authorized read.',
    limitations: ['Compromised host JavaScript can bypass this boundary.'],
  },
  {
    id: 'S04', title: 'Constrain external sends after sensitive access',
    boundary: 'Exact recipients and a monotonic sensitive flag shared by a delegation tree.',
    malicious: ['Unauthorized recipient on an allowed domain', 'External send after sensitive read', 'Child send and prepared send after sensitivity changes'],
    benign: 'Public content reaches its explicitly allowed recipient exactly once.',
    limitations: ['Labels are host assertions; copied data in an independent task requires host propagation.'],
  },
  {
    id: 'S05', title: 'Require exact, expiring, single-use approval',
    boundary: 'Approval binds one immutable prepared invocation and is consumed immediately before dispatch.',
    malicious: ['Changed action', 'Mutated caller input', 'Concurrent replay', 'Expired approval', 'Revoked task'],
    benign: 'A timely approval executes the unchanged action exactly once.',
    limitations: ['Replay protection is in memory; external resource versions and uncertain outcomes need service controls.'],
  },
  {
    id: 'S06', title: 'Review tool-definition changes',
    boundary: 'Explicit metadata approval and invalidation on tool re-registration.',
    malicious: ['Unapproved changed definition', 'Unapproved added tool', 'Old prepared action after code re-registration'],
    benign: 'Approved v1 works; explicitly reviewed v2 works after registration.',
    limitations: ['These core checks do not certify MCP discovery or transport; stable metadata does not attest implementation.'],
  },
  {
    id: 'S07', title: 'Stop configured secrets and canaries in arguments',
    boundary: 'Every outbound JSON string leaf is scanned for configured literal values.',
    malicious: ['Nested secret', 'Nested array canary', 'JSON-decoded Unicode representation'],
    benign: 'Public text and a similar but nonmatching identifier reach the synthetic sink.',
    limitations: ['Encoded, chunked, unknown or internally acquired secrets are outside the literal scanner guarantee.'],
  },
  {
    id: 'S08', title: 'Recheck revocation, policy and approval before dispatch',
    boundary: 'Current mandatory gates are rechecked after asynchronous policy evaluation.',
    malicious: ['Revocation during policy wait', 'Policy revision during policy wait', 'Missing approval', 'Invalid or throwing policy', 'Policy cannot override a grant denial'],
    benign: 'Current policy, live task and timely approval permit one intended action.',
    limitations: ['Revocation cannot retract accepted remote effects or forcibly stop an uncooperative handler.'],
  },
  {
    id: 'S09', title: 'Use trusted tenant context',
    boundary: 'Trusted task identity is compared with canonical resource ownership.',
    malicious: ['Claimed tenant', 'Misleading alias', 'Omitted tenant', 'Approval transferred between tenants'],
    benign: 'An alpha task returns only its granted alpha document.',
    limitations: ['The host authenticates the principal and supplies correct ownership resolution.'],
  },
  {
    id: 'S10', title: 'Bound admitted work',
    boundary: 'Synchronous call, concurrency and cost reservations apply to every ancestor.',
    malicious: ['Concurrent burst', 'Exhausted calls/cost', 'Ancestor budget shared by children', 'Expired deadline', 'Overrun cost report'],
    benign: 'Authorized work releases concurrency, reconciles cost and cooperates with cancellation.',
    limitations: ['Quotas are local and nondurable; the provider must enforce declared upper costs and handlers must honor cancellation.'],
  },
];

/** Read-only scenario descriptions. Call runConformance() to run the fixtures. */
export const scenarioCatalog: readonly ScenarioDefinition[] = Object.freeze(definitions.map((entry) => Object.freeze({
  ...entry,
  malicious: Object.freeze([...entry.malicious]),
  limitations: Object.freeze([...entry.limitations]),
})));
