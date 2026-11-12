import { type Json } from '@shieldaai/agent-guard';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { fail } from '../common.js';
import { mapIdentifier, type JsonObject, type JsonValue } from '../types.js';

export const MAP_OPERATIONS = [
  'list_agents',
  'get_agent_access',
  'explain_access',
  'find_agents_with_access',
  'get_changes',
  'get_inventory_health',
  'list_owners',
  'list_resources',
  'get_resource_access',
  'get_agent_inventory',
  'list_undeclared_activity',
  'list_unclaimed_identities',
] as const;
export type MapOperation = (typeof MAP_OPERATIONS)[number];
export type QueryArguments = Readonly<Record<string, JsonValue>>;

/** What each operation answers, in one sentence. Shown to MCP clients as the tool description. */
export const MAP_OPERATION_DESCRIPTIONS: Readonly<Record<MapOperation, string>> = Object.freeze({
  list_agents:
    'Lists the declared agents you may see, with owner, team, lifecycle and environments; filter by text, owner, team, environment, ownership, lifecycle or the dangerous-three boundary flag.',
  get_agent_access:
    "Shows one agent's tasks, declared grants, bindings, MCP connections, IAM policy evidence, boundary flags and access outside the guard, with a graph of that neighborhood when it is small enough to draw. An empty policy list whose policyCoverage status is unknown was not evaluated; it does not mean no policy applies.",
  explain_access:
    'Explains, for one task, tool and resource selector, which declared grants match, which known blockers apply and which checks remain unknown; it never states that access is allowed.',
  find_agents_with_access:
    'Finds the agents whose declared grants and host bindings map to one exact resource reference or ARN for one cloud action; the results are candidates, not effective permissions.',
  get_changes:
    "Compares a source's current snapshot with its previous retained one and lists what was added, removed or changed, optionally for one agent, one resource or one kind of change.",
  get_inventory_health:
    'Reports, for each source you may see, when each part of the inventory was captured, whether it is stale, how complete it is and how much activity no declared agent accounts for.',
  list_owners: 'Lists the owners and teams that hosts name, with how many visible agents and resources each one owns.',
  list_resources:
    'Lists host-bound resources with their owner, sensitivity and scope, and whether something can reach each one outside the guard.',
  get_resource_access:
    'Shows one host-bound resource, the agents with a declared grant mapped to it, and the declared direct paths and tool identities that reach it outside the guard.',
  get_agent_inventory:
    "Returns one page of one section of an agent's inventory (deployments, tasks, permissions, resources, connections, credentials, relationships, tools, bindings, identities or policies) with the size of every section. A size or total of null means that section was not evaluated, not that it is empty.",
  list_undeclared_activity:
    'Lists tasks or caller principals that ran through an enrolled executor but belong to no declared agent; it answers only for readers with all-teams visibility.',
  list_unclaimed_identities:
    'Lists IAM roles and users in enrolled AWS accounts that no declared agent names, as candidates to review; it answers only for readers with all-teams visibility.',
});

/** A parameter schema with the sentence MCP clients show for it. */
const described = <T extends object>(definition: T, description: string): T & { description: string } => ({
  ...definition,
  description,
});
const idSchema = { type: 'string', minLength: 1, maxLength: 4096 };
const searchSchema = { type: 'string', maxLength: 256 };
const limitSchema = { type: 'integer', minimum: 1, maximum: 100 };
const offsetSchema = { type: 'integer', minimum: 0, maximum: 100_000 };
const choice = (...values: string[]) => ({ type: 'string', enum: values });
const limit = (rows: string) => described(limitSchema, `The most ${rows} to return, 1 to 100 (default 50).`);
const offset = (rows: string) => described(offsetSchema, `How many ${rows} to skip, for paging (default 0).`);
const source = (purpose: string) =>
  described(idSchema, `${purpose} Use the \`id\` of a source from get_inventory_health, or an agent's \`sourceId\`.`);
const agent = (purpose: string) =>
  described(idSchema, `${purpose} Use the agent's \`id\` or its declared \`agentId\` from list_agents.`);
export const sections = [
  'overview',
  'owners',
  'deployments',
  'tasks',
  'permissions',
  'resources',
  'connections',
  'credentials',
  'relationships',
  'tools',
  'bindings',
  'identities',
  'policies',
] as const;
export type InventorySection = (typeof sections)[number];
const schema = (properties: Record<string, unknown>, required: readonly string[] = []): JsonObject =>
  immutableJson({ type: 'object', additionalProperties: false, properties, required }) as JsonObject;

export const MAP_INPUT_SCHEMAS: Readonly<Record<MapOperation, JsonObject>> = Object.freeze({
  list_agents: schema({
    search: described(searchSchema, 'Keep agents whose name or agent ID contains this text, ignoring case.'),
    sourceId: source('Keep agents of this source only.'),
    ownerId: described(idSchema, 'Keep agents whose declared owner has exactly this owner ID.'),
    teamId: described(idSchema, 'Keep agents of exactly this team ID.'),
    environment: described(idSchema, 'Keep agents with a deployment in exactly this environment.'),
    ownershipStatus: described(
      choice('assigned', 'unassigned', 'unknown'),
      'Keep agents whose ownership is assigned, unassigned or unknown.',
    ),
    lifecycleState: described(
      choice('active', 'inactive', 'retired', 'unknown'),
      'Keep agents in this declared lifecycle state.',
    ),
    flag: described(
      choice('dangerous_three'),
      'Keep only agents that carry this boundary flag with status exposed, mitigated or unknown.',
    ),
    flagStatus: described(
      choice('exposed', 'mitigated', 'unknown', 'absent'),
      'Keep only agents whose dangerous-three flag has this status; `absent` cannot be combined with `flag`.',
    ),
    includeFlags: described(
      { type: 'boolean' },
      'Add the dangerous-three status to every returned agent. It reads tasks, so it costs more than the plain list.',
    ),
    limit: limit('agents'),
    offset: offset('agents'),
  }),
  get_agent_access: schema(
    { sourceId: source('The source that holds the agent.'), agentId: agent('The agent to show.') },
    ['sourceId', 'agentId'],
  ),
  explain_access: schema(
    {
      sourceId: source('The source that holds the task.'),
      taskId: described(idSchema, "The task to explain. Use its `id` or its `taskId` from an agent's tasks."),
      tool: described(idSchema, 'The exact tool name, as written in the declared grant.'),
      resourceId: described(
        idSchema,
        'The exact resource selector, as written in the declared grant (a selector, not an ARN).',
      ),
    },
    ['sourceId', 'taskId', 'tool', 'resourceId'],
  ),
  find_agents_with_access: schema(
    {
      resourceRef: described(
        idSchema,
        'The exact resource reference of a host binding, or the exact ARN that binding maps to.',
      ),
      action: described(
        { type: 'string', minLength: 3, maxLength: 256, pattern: '^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$' },
        'The cloud action in `service:Action` form, for example `s3:GetObject`.',
      ),
      sourceId: source('Search this source only.'),
      limit: limit('candidate agents'),
    },
    ['resourceRef', 'action'],
  ),
  get_changes: schema(
    {
      sourceId: source('The source whose snapshots to compare.'),
      since: described(
        idSchema,
        'The snapshot to compare from: `previous` (the default), or the id or snapshot id of the current or previous snapshot.',
      ),
      agentId: agent('Keep only changes that affect this agent.'),
      resourceId: described(
        idSchema,
        'Keep only changes that touch this resource binding. Use its `id` or `bindingId` from list_resources.',
      ),
      changeKind: described(
        choice('all', 'permissions', 'ownership', 'bindings', 'outside_guard', 'inventory'),
        'Keep only changes of this kind; `all` (the default) keeps every change.',
      ),
      offset: offset('changes'),
      limit: limit('changes'),
    },
    ['sourceId'],
  ),
  get_inventory_health: schema({ sourceId: source('Report this source only.') }),
  list_owners: schema({
    sourceId: source('Keep owners of this source only.'),
    search: described(searchSchema, 'Keep owners whose name or owner ID contains this text, ignoring case.'),
    kind: described(choice('person', 'team', 'service'), 'Keep owners of this kind.'),
    offset: offset('owners'),
    limit: limit('owners'),
  }),
  list_resources: schema({
    sourceId: source('Keep resources of this source only.'),
    search: described(
      searchSchema,
      'Keep resources whose display name, owner ID, binding ID or resource reference contains this text, ignoring case.',
    ),
    ownerId: described(idSchema, 'Keep resources whose declared owner has exactly this owner ID.'),
    sensitivity: described(
      choice('public', 'internal', 'confidential', 'restricted', 'unknown'),
      'Keep resources with this declared sensitivity.',
    ),
    offset: offset('resources'),
    limit: limit('resources'),
  }),
  get_resource_access: schema(
    {
      sourceId: source('The source that holds the resource.'),
      resourceId: described(idSchema, 'The resource binding to show. Use its `id` or `bindingId` from list_resources.'),
      offset: offset('connected agents'),
      limit: limit('connected agents'),
    },
    ['sourceId', 'resourceId'],
  ),
  get_agent_inventory: schema(
    {
      sourceId: source('The source that holds the agent.'),
      agentId: agent('The agent whose inventory to read.'),
      section: described(
        choice(...sections),
        'The section to page through; `overview` (the default) returns one summary row.',
      ),
      offset: offset('rows of the section'),
      limit: limit('rows of the section'),
    },
    ['sourceId', 'agentId'],
  ),
  /** Tasks or caller principals of one source that no declared agent accounts for; all-teams readers. */
  list_undeclared_activity: schema(
    {
      sourceId: source('The source whose activity to list.'),
      kind: described(
        choice('tasks', 'principals'),
        'List undeclared `tasks` (the default) or the caller `principals` behind them.',
      ),
      offset: offset('rows'),
      limit: limit('rows'),
    },
    ['sourceId'],
  ),
  /** IAM roles and users of the enrolled AWS accounts that no declared agent names; all-teams readers. */
  list_unclaimed_identities: schema({ offset: offset('identities'), limit: limit('identities') }),
});

const invalid = (): never => fail('MAP_REQUEST_INVALID');
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
/** The arguments of one operation, copied and checked against its closed schema. */
export function validateQueryArguments(operation: unknown, value: unknown): QueryArguments {
  if (typeof operation !== 'string' || !(MAP_OPERATIONS as readonly string[]).includes(operation)) invalid();
  let copied: Json;
  try {
    copied = immutableJson(value, 4, 512, 64 * 1024);
  } catch {
    return invalid();
  }
  if (!copied || typeof copied !== 'object' || Array.isArray(copied)) invalid();
  const args = copied as Record<string, JsonValue>;
  const definition = MAP_INPUT_SCHEMAS[operation as MapOperation];
  const properties = definition.properties as JsonObject;
  const required = definition.required as readonly string[];
  if (Object.keys(args).some(key => !Object.hasOwn(properties, key)) || required.some(key => !Object.hasOwn(args, key)))
    invalid();
  for (const [key, item] of Object.entries(args)) {
    if (key === 'limit' || key === 'offset') {
      if (
        typeof item !== 'number' ||
        !Number.isSafeInteger(item) ||
        item < (key === 'offset' ? 0 : 1) ||
        item > (key === 'offset' ? 100_000 : 100)
      )
        invalid();
    } else if ((properties[key] as JsonObject).type === 'boolean') {
      if (typeof item !== 'boolean') invalid();
    } else if (key === 'search') {
      if (typeof item !== 'string' || [...item].length > 256 || item.includes('\0') || LONE_SURROGATE.test(item))
        invalid();
    } else {
      mapIdentifier(item);
      const allowed = (properties[key] as JsonObject).enum;
      if (Array.isArray(allowed) && !allowed.includes(item)) invalid();
      if (
        key === 'action' &&
        (typeof item !== 'string' || item.length > 256 || !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(item))
      )
        invalid();
    }
  }
  return args;
}
/** The page an operation was asked for; 50 rows from the start unless the caller says otherwise. */
export function pageArguments(args: QueryArguments): { offset: number; limit: number } {
  return { offset: (args.offset as number | undefined) ?? 0, limit: (args.limit as number | undefined) ?? 50 };
}
