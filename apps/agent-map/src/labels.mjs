// The one place that turns the service's codes into words. Every enum, boolean and reason the
// viewer shows goes through a table here, so no view prints `snake_case`, `true` or `false`.
// A code this viewer does not know yet still reads as words: underscores become spaces and
// the first letter is capitalised.

const table = entries => Object.freeze(entries);

export const LABELS = Object.freeze({
  /** Graph node kinds (`MapNode.label`), plus the nodes the viewer draws for outside-guard evidence. */
  nodeKind: table({
    GuardAgent: 'Agent',
    GuardDeployment: 'Deployment',
    GuardTask: 'Task',
    GuardPrincipal: 'Principal',
    GuardTool: 'Tool',
    GuardGrant: 'Declared grant',
    GuardResource: 'Resource',
    GuardResourceBinding: 'Resource binding',
    GuardExecutionBinding: 'Execution binding',
    GuardExternalIdentity: 'Cloud identity',
    GuardExternalResource: 'External resource',
    GuardMcpConnection: 'MCP connection',
    GuardMcpOperation: 'MCP operation',
    GuardOwner: 'Owner',
    GuardCredentialReference: 'Credential reference',
    GuardDirectAccess: 'Direct access (outside guard)',
    OutsideGuardAccess: 'Direct access (outside guard)',
    OutsideGuardTarget: 'Direct path target',
    OutsideGuardBucket: 'Bucket reached by tool identity (candidate)',
  }),
  /** Graph relationships (`MapEdge.kind`), read from source to target. */
  relation: table({
    G_OWNED_BY: 'is owned by',
    G_RESOURCE_OWNED_BY: 'resource is owned by',
    G_USES_CREDENTIAL: 'uses credential reference',
    G_DEPENDS_ON: 'depends on',
    G_INSTANCE_OF: 'is a deployment of',
    G_ASSIGNED_TO: 'is assigned to',
    G_ACTS_AS: 'acts as',
    G_DELEGATED_FROM: 'is delegated from',
    G_DERIVED_FROM: 'is derived from',
    G_HAS_GRANT: 'has declared grant',
    G_FOR_TOOL: 'declares tool',
    G_TARGETS: 'targets selector',
    G_BINDS_SELECTOR: 'binds selector',
    G_MAPS_TO: 'maps to collected resource',
    G_EXECUTES_FOR: 'executes for',
    G_EXECUTES_TOOL: 'executes tool',
    G_USES_IDENTITY: 'uses identity',
    G_VIA_CONNECTION: 'uses connection',
    G_EXPOSES_OPERATION: 'exposes operation',
    G_OPERATION_TOOL: 'maps operation to tool',
    G_DIRECT_ACCESS_FOR: 'is a direct path of',
  }),
  /** IAM policy candidate relationships. */
  policyRelationship: table({ CAN_READ: 'Can read', CAN_WRITE: 'Can write', CAN_LIST: 'Can list' }),

  // Boundary flags ("dangerous three").
  flagStatus: table({ exposed: 'Exposed', mitigated: 'Mitigated', unknown: 'Unknown' }),
  flagLeg: table({ privateData: 'Private data', outsideContent: 'Outside content', externalSend: 'Can send out' }),
  legState: table({ present: 'Present', absent: 'Absent', unknown: 'Unknown' }),
  flagReason: table({
    binding_restricted: 'Resource binding labelled restricted',
    binding_confidential: 'Resource binding labelled confidential',
    task_sensitive: 'Task marked sensitive',
    tool_reads_untrusted: 'Tool declares it reads untrusted content',
    task_untrusted: 'Task marked untrusted',
    tool_sends_external: 'Tool declares it sends externally',
    no_effective_recipients: 'No effective recipients across the task lineage',
    sensitive_egress_denied: 'Task is sensitive, so declared external sends are refused',
    untrusted_context_require_approval: 'Sending tool requires approval with untrusted context',
    untrusted_context_deny: 'Sending tool is denied with untrusted context',
  }),
  flagNote: table({
    no_live_tasks: 'No live tasks in this snapshot.',
    ancestor_evidence_outside_visible_scope: 'A delegating ancestor task is outside your visible scope.',
    delegation_not_recorded: 'This snapshot predates delegation data; republishing the source restores it.',
    delegation_depth_exceeded: 'A recorded parent or handoff source lies more than 16 links away.',
    delegation_ancestors_not_loaded: 'Ancestor and handoff source tasks were too many to load in this view.',
    flags_limit_exceeded: 'The flag needed more work than this view allows.',
    flags_timeout: 'Evaluating the flag took too long.',
    delegation_parent_missing: 'A recorded parent or handoff source task is missing from this snapshot.',
    delegation_evidence_ambiguous: 'A task has more than one parent or handoff source.',
    task_liveness_unverified: 'A task does not say whether it is revoked or when it expires.',
  }),
  /** Why a page of agents shows every flag as unknown (`list_agents.flagsUnavailable`). */
  flagsUnavailable: table({
    flags_limit_exceeded: 'this page is too large to evaluate',
    flags_timeout: 'evaluating them took too long',
    flags_read_unavailable: 'the evaluation was unavailable',
  }),

  // Outside the guard.
  directAccessStatus: table({
    found: 'Direct paths declared',
    none_declared: 'None declared (host claim, not checked)',
    unknown: 'Unknown: the host has not declared direct paths',
  }),
  directAccessKind: table({
    shell: 'Shell',
    database: 'Database',
    network: 'Network',
    sdk: 'SDK',
    mcp: 'MCP',
    other: 'Other',
  }),
  identityScopeStatus: table({
    broader_than_grants: 'Broader than grants (candidate)',
    matches_grants: 'Matches grants for checked identity policies',
    unknown: 'Unknown',
  }),
  identityScopeReason: table({
    binding_ambiguous: 'Binding evidence is ambiguous',
    cloud_unresolved: 'Cloud association unresolved',
    provider_missing: 'Provider evidence unavailable',
    collection_invalid: 'The AWS collection could not be verified',
    stale: 'The AWS collection is stale',
    changed: 'Provider evidence changed during the read',
    boundary_unresolved: 'Permissions boundary unresolved',
    unsupported_policy: 'Unsupported policy expression',
    evidence_invalid: 'Policy evidence could not be verified',
    identity_not_static: 'Execution identity is selected at run time',
    cloud_not_collected: 'Cloud inventory not collected',
    collection_missing: 'No AWS collection for this account',
    disabled: 'Policy collection disabled',
    unsupported_identity: 'Identity type is not supported',
    not_evaluated: 'Not evaluated in this read',
    wildcard_grant: 'A grant covers every resource, so nothing is beyond it',
    binding_narrower_than_candidate: 'A binding is narrower than the bucket the policy names',
    grant_lineage_unknown: 'The task lineage of a grant is unknown',
    truncated: 'More buckets than one read lists',
  }),
  /** `list_resources` / `get_resource_access` reach. */
  reach: table({ yes: 'Yes', none_found: 'None found', unknown: 'Unknown' }),
  reachUnknownReason: table({
    direct_access_undeclared: 'A visible deployment has not declared its direct paths',
    resource_not_collected: 'The AWS collection has not resolved this bucket',
    binding_ambiguous: 'The binding does not map to exactly one resource',
    identity_scope_not_collected_for_resource: 'No collected S3 bucket maps to this resource',
    identity_scope_not_collected: 'Tool identity scope was not collected',
    identity_scope_unknown: 'A visible tool identity could not be evaluated',
    identity_scope_other_account: 'A tool identity is in another AWS account and was never compared with this bucket',
    direct_access_untargeted: 'A declared direct path has no target, so it may reach any resource',
    direct_access_target_unresolved: 'A declared direct path names a resource this view cannot match',
    execution_identity_undeclared: 'A granted tool has no declared execution identity',
    outside_visible_scope: 'Deployments or tasks outside your scope may reach it',
    reach_not_evaluated: 'Reach was not judged: the source is too large, or the read ran out of time',
  }),

  // Changes.
  changeCategory: table({
    permissions: 'Declared permissions',
    ownership: 'Ownership',
    bindings: 'Bindings and connections',
    outside_guard: 'Outside-guard paths (declared)',
    inventory: 'Other inventory details',
  }),
  changeKind: table({ added: 'Added', removed: 'Removed', changed: 'Changed' }),

  // IAM policy evidence.
  policyReason: table({
    no_candidate: 'No policy candidate observed',
    binding_ambiguous: 'Binding evidence is ambiguous',
    cloud_unresolved: 'Cloud association unresolved',
    provider_missing: 'Provider evidence unavailable',
    collection_invalid: 'Policy collection could not be verified',
    stale: 'Policy evidence is stale',
    changed: 'Provider evidence changed',
    boundary_unresolved: 'Permissions boundary unresolved',
    unsupported_policy: 'Unsupported policy expression',
    evidence_invalid: 'Policy evidence could not be verified',
    unsupported_action: 'Action outside collected policy mappings',
    identity_not_static: 'Execution identity is selected at runtime',
    unsupported_binding: 'Binding is outside collected policy mappings',
    cloud_not_collected: 'Cloud inventory not collected',
    collection_missing: 'Policy collection unavailable',
    disabled: 'Policy collection disabled',
  }),

  // Explanations (`explain_access`).
  blocker: table({
    task_revoked: 'The task was revoked',
    deadline_expired: 'The task deadline has passed',
    call_budget_exhausted: 'The task has used all its calls',
    concurrency_full_at_capture: 'The task was at its concurrency limit when captured',
    cost_budget_exceeded: 'The call would exceed the task cost budget',
    control_plane_disabled: 'The task may not use control-plane tools',
    tool_unregistered_at_capture: 'The tool was not registered when captured',
    tool_metadata_unapproved: 'The tool metadata is not approved',
    declared_grant_missing: 'The task has no declared grant for this tool and resource',
    ancestor_declared_grant_missing: 'A delegating ancestor task has no declared grant for this tool and resource',
  }),
  unknownCheck: table({
    live_authorization: 'Live authorization at request time',
    request_arguments_and_resolution: 'The request arguments and how they resolve',
    custom_policy: 'Custom policy',
    backend_authorization: 'Authorization in the backend system',
    action_approval: 'Approval of the action',
    ancestor_evidence_outside_visible_scope: 'Ancestor tasks outside your visible scope',
    tool_registration: 'Whether the tool is registered',
    tool_metadata_approval: 'Whether the tool metadata is approved',
    delegation_depth_or_cycle: 'A delegation chain that is too deep or loops',
    delegation_evidence_ambiguous: 'A task with more than one delegating parent',
    sensitive_egress_and_recipient_checks: 'Sensitive-data sending and recipient checks',
  }),
  /** Why `find_agents_with_access` stopped early. */
  truncatedReason: table({ work_limit: 'the search reached its work limit' }),

  // Health and collection.
  healthComponent: table({
    tasks: 'Tasks',
    tools: 'Tools',
    manifest: 'Host manifest',
    mcp: 'MCP connections',
    cloud: 'Cloud inventory',
    policy: 'Policy evidence',
    undeclaredActivity: 'Undeclared activity',
  }),
  coverageStatus: table({
    complete: 'Complete',
    partial: 'Partial',
    unavailable: 'Unavailable',
    not_collected: 'Not collected',
    unknown: 'Unknown',
  }),
  coverageReason: table({ limit_exceeded: 'too many task and binding pairs to evaluate' }),
  activityReason: table({
    read_unavailable: 'the count could not be read',
    read_timeout: 'the count ran out of time',
    limit_exceeded: 'the count exceeded a read limit',
    publication_changed: 'a new snapshot was published during the read',
    not_reported: 'this service did not report a count',
  }),
  accountReason: table({
    stale: 'The last AWS collection is older than the enrolled age limit.',
    collection_invalid: 'The AWS collection record is incomplete or malformed.',
    changed: 'The AWS collection changed while it was read, or its members do not match it.',
    limit_exceeded: 'The account holds more identities than one read may judge.',
    claims_limit_exceeded: 'More identities are declared than one read may compare.',
  }),
  identityKind: table({ role: 'IAM role', user: 'IAM user' }),

  // Inventory values.
  ownership: table({ assigned: 'Assigned owner', unassigned: 'Unassigned owner', unknown: 'Ownership unknown' }),
  ownershipFilter: table({ assigned: 'Assigned', unassigned: 'Unassigned', unknown: 'Unknown / legacy' }),
  /** Agents (active, inactive, retired) and credential references (active, rotating, revoked, expired). */
  lifecycle: table({
    active: 'Active',
    inactive: 'Inactive',
    retired: 'Retired',
    rotating: 'Rotating',
    revoked: 'Revoked',
    expired: 'Expired',
    unknown: 'Unknown',
  }),
  rotation: table({ current: 'Current', due: 'Due', overdue: 'Overdue', unknown: 'Unknown' }),
  sensitivity: table({
    public: 'Public',
    internal: 'Internal',
    confidential: 'Confidential',
    restricted: 'Restricted',
    unknown: 'Unknown',
  }),
  ownerKind: table({ person: 'Person', team: 'Team', service: 'Service' }),
  /** Kinds of host resources, direct paths and MCP operations. */
  kind: table({
    person: 'Person',
    team: 'Team',
    service: 'Service',
    repository: 'Repository',
    database: 'Database',
    queue: 'Queue',
    storage: 'Storage',
    shell: 'Shell',
    network: 'Network',
    sdk: 'SDK',
    mcp: 'MCP',
    bucket: 'Bucket',
    object: 'Object',
    prefix: 'Prefix',
    file: 'File',
    tool: 'Tool',
    resource: 'Resource',
    prompt: 'Prompt',
    other: 'Other',
  }),
  provider: table({ aws: 'AWS', host: 'Host', gcp: 'Google Cloud', azure: 'Azure' }),
  evidenceKind: table({
    declared: 'Declared',
    observed: 'Observed',
    declared_and_observed: 'Declared and observed',
    host_asserted: 'Asserted by the host',
    provider_inventory: 'Provider inventory',
    mcp_observation: 'MCP observation',
    iam_identity_policy_candidate: 'IAM identity-policy candidate',
  }),
  assessment: table({ unknown: 'Unknown', blocked: 'Blocked' }),
  identitySelection: table({
    static: 'Static (one fixed identity)',
    dynamic: 'Chosen at run time',
    unknown: 'Unknown',
  }),
  matchScope: table({
    exact: 'Exact',
    wildcard: 'Wildcard',
    prefix: 'Prefix',
    containment: 'Containing resource',
    bucket_summary: 'Bucket summary',
  }),
  cloudStatus: table({
    resolved: 'Resolved',
    unresolved: 'Unresolved',
    stale: 'Stale',
    missing: 'Missing',
    not_collected: 'Not collected',
  }),
  connectionState: table({
    ready: 'Ready',
    connecting: 'Connecting',
    refreshing: 'Refreshing',
    quarantined: 'Quarantined',
    closed: 'Closed',
    unavailable: 'Unavailable',
  }),
  metadataState: table({ current: 'Current', stale: 'Stale', unknown: 'Unknown' }),
  captureStatus: table({ observed: 'Observed', unavailable: 'Unavailable', complete: 'Complete' }),
  approvalMode: table({ allow: 'Allowed', require_approval: 'Approval required', deny: 'Denied' }),

  /** Property names of graph nodes, as shown in the evidence panel and in change tables. */
  field: table({
    agent_id: 'Agent ID',
    name: 'Name',
    owner_id: 'Owner ID',
    team_id: 'Team',
    purpose: 'Purpose',
    lifecycle_state: 'Lifecycle',
    ownership_status: 'Ownership status',
    ownership_source: 'Ownership source',
    evidence_kind: 'Evidence',
    assessment: 'Assessment',
    manifest_id: 'Host manifest',
    manifest_revision: 'Manifest revision',
    manifest_observed_at: 'Manifest observed',
    authority_id: 'Host authority',
    manifest_schema_version: 'Manifest schema version',
    deployment_id: 'Deployment ID',
    environment: 'Environment',
    runtime_ref: 'Runtime reference',
    workload_generation: 'Workload generation',
    build_ref: 'Build reference',
    binding_authority: 'Binding authority',
    direct_access_status: 'Direct paths',
    task_id: 'Task ID',
    principal_id: 'Principal',
    revoked: 'Revocation',
    delegated: 'Delegated',
    derived: 'Derived from a handoff',
    sensitive: 'Sensitive',
    untrusted: 'Untrusted content',
    allowed_recipients: 'Allowed recipients',
    allow_control_plane: 'Control-plane tools',
    max_calls: 'Call limit',
    max_concurrent: 'Concurrency limit',
    max_cost: 'Cost limit',
    deadline: 'Deadline',
    calls: 'Calls used',
    concurrent: 'Running calls',
    spent: 'Cost spent',
    reserved: 'Cost reserved',
    tool: 'Tool',
    resources: 'Resource selectors',
    fingerprint: 'Fingerprint',
    revision: 'Revision',
    registered: 'Registration',
    approved: 'Metadata approval',
    known_metadata: 'Metadata known',
    requires_approval: 'Action approval',
    control_plane: 'Control-plane tool',
    reads_untrusted: 'Reads untrusted content',
    untrusted_context: 'With untrusted content',
    sends_external: 'Sends externally',
    untrusted_context_default: 'With untrusted content (default)',
    resource_id: 'Resource selector',
    selector_kind: 'Selector kind',
    binding_id: 'Binding ID',
    resource_ref: 'Resource reference',
    actions: 'Declared actions',
    scope: 'Scope',
    display_name: 'Display name',
    sensitivity: 'Sensitivity',
    approved_destinations: 'Approved destinations',
    connection_id: 'Connection ID',
    identity_selection: 'Identity selection',
    provider: 'Provider',
    partition: 'Partition',
    account_id: 'Account',
    region: 'Region',
    arn: 'ARN',
    kind: 'Kind',
    host_resource_id: 'Host resource ID',
    cloud_status: 'Cloud status',
    cloud_reason: 'Cloud reason',
    cloud_observed_at: 'Cloud observed',
    cloud_assessment: 'Cloud assessment',
    cloud_provider_label: 'Provider type',
    cloud_provider_id: 'Provider ID',
    cloud_match_kind: 'Cloud match',
    cloud_node_updated: 'Provider record updated',
    cloud_ownership_updated: 'Provider ownership updated',
    cloud_account_updated: 'Provider account updated',
    capture_status: 'Capture status',
    unavailable_reason: 'Reason unavailable',
    capture_observed_at: 'Capture observed',
    server_id: 'Server ID',
    transport_ref: 'Transport reference',
    state: 'State',
    metadata_state: 'Metadata',
    observed_at: 'Observed',
    credential_id: 'Credential reference',
    issuer_ref: 'Issuer reference',
    audience_refs: 'Audience references',
    recipient_refs: 'Recipient references',
    expires_at: 'Expires',
    rotation_status: 'Rotation',
    access_id: 'Access reference',
    target_ref: 'Target reference',
    description: 'Description',
    // Fields of the nodes the viewer draws for outside-guard evidence.
    bucket_name: 'Bucket',
    undrawn: 'Buckets not drawn',
    list_shortened: 'List shortened',
  }),
});

/** Which value table a node property uses; properties not listed here hold names, ids or numbers. */
const FIELD_TABLES = Object.freeze({
  lifecycle_state: 'lifecycle',
  ownership_status: 'ownership',
  sensitivity: 'sensitivity',
  direct_access_status: 'directAccessStatus',
  evidence_kind: 'evidenceKind',
  assessment: 'assessment',
  cloud_assessment: 'assessment',
  identity_selection: 'identitySelection',
  cloud_status: 'cloudStatus',
  cloud_match_kind: 'matchScope',
  capture_status: 'captureStatus',
  state: 'connectionState',
  metadata_state: 'metadataState',
  rotation_status: 'rotation',
  provider: 'provider',
  kind: 'kind',
  selector_kind: 'matchScope',
  scope: 'matchScope',
  untrusted_context: 'approvalMode',
  untrusted_context_default: 'approvalMode',
  // Free-form codes without a fixed list: shown as words.
  cloud_reason: null,
  unavailable_reason: null,
});
/** Words for the two values of a boolean property; anything else reads Yes / No. */
const BOOLEAN_FIELDS = Object.freeze({
  revoked: ['Revoked', 'Not revoked'],
  registered: ['Registered', 'Not registered'],
  approved: ['Approved', 'Not approved'],
  requires_approval: ['Required', 'Not required'],
  allow_control_plane: ['Allowed', 'Not allowed'],
});

/** A code as words: underscores become spaces and the first letter is capitalised. */
export function words(value) {
  const text = String(value).replaceAll('_', ' ').trim();
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}
/** True when `value` is a string the named table knows. Own keys only, never inherited members. */
export const hasLabel = (name, value) =>
  typeof value === 'string' && Object.hasOwn(LABELS, name) && Object.hasOwn(LABELS[name], value);
/** The label for `value` in the named table; an unknown code reads as words, a missing one as `fallback`. */
export function label(name, value, fallback = 'Unknown') {
  if (typeof value !== 'string' || !value) return fallback;
  return hasLabel(name, value) ? LABELS[name][value] : words(value);
}
/** `true` / `false` in words; anything else is unknown. */
export function booleanLabel(value, yes = 'Yes', no = 'No', unknown = 'Unknown') {
  return value === true ? yes : value === false ? no : unknown;
}
/** A node property name in words. */
export const fieldLabel = name => label('field', name, 'Unknown field');
/**
 * A node property value in words where the property holds a code or a boolean. Names,
 * identifiers and numbers are returned unchanged, so an id that reads like a code stays an id.
 */
export function fieldValue(name, value) {
  // Own keys only: a property named `constructor` or `__proto__` must not pick up an inherited member.
  if (typeof value === 'boolean')
    return booleanLabel(value, ...(Object.hasOwn(BOOLEAN_FIELDS, name) ? BOOLEAN_FIELDS[name] : []));
  if (typeof value === 'string' && Object.hasOwn(FIELD_TABLES, name)) {
    const tableName = FIELD_TABLES[name];
    return tableName ? label(tableName, value) : words(value);
  }
  return value;
}
/** Any value as display text: unknown, empty and "none recorded" stay distinct, booleans read Yes / No. */
export function displayValue(value) {
  if (value === undefined || value === null) return 'Unknown';
  if (value === '') return 'Empty';
  if (typeof value === 'boolean') return booleanLabel(value);
  if (Array.isArray(value)) return value.length ? value.map(displayValue).join(', ') : 'None recorded';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
/** A node property value as display text. */
export const fieldText = (name, value) => displayValue(fieldValue(name, value));
/** Host-supplied text that may be a code: a `snake_case` value reads as words, anything else is kept. */
export function codeText(value) {
  return typeof value === 'string' && /^[a-z0-9]+(?:_[a-z0-9]+)+$/.test(value) ? words(value) : displayValue(value);
}
