import { randomUUID } from 'node:crypto';
import { AgentGuard, digestJson, type Json, type ResolvedAction, type TaskIdentity } from '@shieldaai/agent-guard';
import { Client, type Transport, type JSONRPCMessage, type TransportSendOptions, type Tool } from '@modelcontextprotocol/client';
import { boundedJson, compileBoundedSchema, McpBoundaryError, passiveJson } from './boundary.js';
import { mcpToolName, type RegisteredMcpTool } from './index.js';
import { mcpInventorySnapshot, opaqueTransportRef, type McpConnectionInventory, type McpConnectionState } from './inventory.js';

/** Supplied by a trusted executor after transport/credential authorization, never by a model. */
export interface McpConnectionIdentity {
  serverId: string;
  /** Opaque binding to approved endpoint/launch configuration and authentication context. No secrets. */
  transportIdentity: string;
  principalId: string;
  tenantId: string;
}
export interface McpBinding {
  name: string;
  resolve(args: Record<string, Json>, task: Readonly<TaskIdentity>): ResolvedAction;
  requiresApproval?: boolean;
  controlPlane?: boolean;
  maxCost?: number;
  measureCost?: (result: Json) => number;
}
export interface McpResourceBinding extends McpBinding { uri: string }
export interface ManagedMcpOptions {
  guard: Pick<AgentGuard, 'registerTool'>;
  identity: McpConnectionIdentity;
  /** Exclusive ownership is transferred. This package does not launch servers or perform OAuth. */
  transport: Transport;
  /** Trusted synchronous auth/revocation check, run at connection, preparation and dispatch. */
  authorize?: () => void;
  tools?: readonly McpBinding[];
  /** Exact, advertised resource URIs only; no templates or automatic link fetching. */
  resources?: readonly McpResourceBinding[];
  prompts?: readonly McpBinding[];
  limits?: { requestTimeoutMs?: number; maxEntries?: number; maxMessages?: number; maxPages?: number };
}
export interface ManagedMcpRegistration extends RegisteredMcpTool {
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  readonly descriptor: Json;
}
const EPOCH_META = 'shielda/connection-epoch';
const SESSION_META = 'shielda/connection-session';
const allowedControlMethods = new Set(['initialize', 'notifications/initialized', 'ping', 'notifications/cancelled']);
const lists = new Set(['tools/list', 'resources/list', 'prompts/list']);
const operations = new Set(['tools/call', 'resources/read', 'prompts/get']);

function identifier(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 1024) throw new McpBoundaryError('INVALID_CONFIGURATION');
  return value;
}
function limit(value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > maximum) throw new McpBoundaryError('INVALID_CONFIGURATION');
  return result;
}
function object(value: Json): Record<string, Json> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new McpBoundaryError('INVALID_ARGUMENTS');
  return value as Record<string, Json>;
}
function bindings(input: readonly McpBinding[] | undefined): readonly McpBinding[] {
  const seen = new Set<string>();
  return Object.freeze((input ?? []).map(binding => {
    const name = identifier(binding.name);
    if (seen.has(name) || typeof binding.resolve !== 'function') throw new McpBoundaryError('INVALID_CONFIGURATION');
    seen.add(name); return Object.freeze({ ...binding, name });
  }));
}

/**
 * Owns one SDK client, one principal/tenant and one transport lifetime. There is no
 * raw request/client escape hatch. Reconnection requires a new instance and review.
 */
export class ManagedMcpConnection {
  readonly #guard: Pick<AgentGuard, 'registerTool'>;
  readonly #identity: Readonly<McpConnectionIdentity>;
  readonly #session = randomUUID();
  readonly #transportRef: string;
  readonly #client: Client;
  readonly #transport: Transport;
  readonly #tools: readonly McpBinding[];
  readonly #resources: readonly McpResourceBinding[];
  readonly #prompts: readonly McpBinding[];
  readonly #timeout: number;
  readonly #maxEntries: number;
  readonly #maxMessages: number;
  readonly #authorize: (() => void) | undefined;
  #messages = 0;
  #epoch = 0;
  // Observation revision includes ready transitions without changing execution epochs.
  #inventoryRevision = 0;
  #metadataRevision = 0;
  #metadataDigest: string | undefined;
  #state: McpConnectionState = 'connecting';
  #registrations: readonly ManagedMcpRegistration[] = Object.freeze([]);
  #known = new Set<string>();
  #refreshTail: Promise<void> = Promise.resolve();

  private constructor(options: ManagedMcpOptions) {
    this.#guard = options.guard;
    if (options.authorize !== undefined && typeof options.authorize !== 'function') throw new McpBoundaryError('INVALID_CONFIGURATION');
    this.#authorize = options.authorize;
    this.#identity = Object.freeze({ serverId: identifier(options.identity.serverId), transportIdentity: identifier(options.identity.transportIdentity), principalId: identifier(options.identity.principalId), tenantId: identifier(options.identity.tenantId) });
    this.#transportRef = opaqueTransportRef(this.#identity.transportIdentity);
    this.#tools = bindings(options.tools);
    this.#prompts = bindings(options.prompts);
    this.#resources = bindings(options.resources) as readonly McpResourceBinding[];
    for (const resource of this.#resources) identifier(resource.uri);
    this.#timeout = limit(options.limits?.requestTimeoutMs, 10_000, 120_000);
    this.#maxEntries = limit(options.limits?.maxEntries, 64, 256);
    this.#maxMessages = limit(options.limits?.maxMessages, 10_000, 100_000);
    if (this.#tools.length + this.#resources.length + this.#prompts.length > this.#maxEntries) throw new McpBoundaryError('REGISTRY_LIMIT');
    this.#client = new Client({ name: 'shielda-agent-guard', version: '0.1.0' }, {
      capabilities: {}, versionNegotiation: { mode: 'legacy' },
      listMaxPages: limit(options.limits?.maxPages, 4, 16),
      cachePartition: this.#session,
      jsonSchemaValidator: { getValidator: <T>(schema: unknown) => {
        const validate = compileBoundedSchema(schema);
        return (value: unknown) => validate(value)
          ? { valid: true as const, data: value as T, errorMessage: undefined }
          : { valid: false as const, data: undefined, errorMessage: 'SCHEMA_VALIDATION_FAILED' };
      } },
    });
    this.#transport = this.#wrap(options.transport);
    this.#client.onclose = () => { if (this.#state !== 'closed') this.#invalidate('closed'); };
    // SDK request dispatch rejects unadvertised sampling/elicitation/roots capabilities.
    this.#client.fallbackRequestHandler = async () => { throw new McpBoundaryError('CAPABILITY_DENIED'); };
    for (const method of ['notifications/tools/list_changed', 'notifications/resources/list_changed', 'notifications/prompts/list_changed'] as const) {
      this.#client.setNotificationHandler(method, () => { this.#invalidate('quarantined'); });
    }
  }

  static async connect(options: ManagedMcpOptions): Promise<ManagedMcpConnection> {
    const connection = new ManagedMcpConnection(options);
    try {
      connection.#checkAuthorization();
      await connection.#client.connect(connection.#transport, { timeout: connection.#timeout });
      connection.#state = 'quarantined';
      connection.#inventoryRevision++;
      await connection.refresh();
      return connection;
    } catch {
      await connection.close().catch(() => {});
      throw new McpBoundaryError('CONNECTION_FAILED');
    }
  }

  get status(): McpConnectionState { return this.#state; }
  get sessionId(): string { return this.#session; }
  get revision(): number { return this.#epoch; }
  get inventoryRevision(): number { return this.#inventoryRevision; }
  get registrations(): readonly ManagedMcpRegistration[] { return this.#registrations; }

  /** A pure observation: no authorization checks, discovery, resolvers or dispatch. */
  inventory(): McpConnectionInventory {
    return mcpInventorySnapshot({
      identity: { serverId: this.#identity.serverId, transportRef: this.#transportRef,
        principalId: this.#identity.principalId, tenantId: this.#identity.tenantId },
      sessionId: this.#session, revision: this.#inventoryRevision, authorizationEpoch: this.#epoch,
      metadataRevision: this.#metadataRevision, state: this.#state, registrations: this.#registrations,
    });
  }

  /** Explicit refresh after quarantine. Every successful refresh requires renewed approval. */
  refresh(): Promise<void> {
    if (this.#state === 'closed' || this.#state === 'connecting') return Promise.reject(new McpBoundaryError('CONNECTION_UNAVAILABLE'));
    this.#invalidate('refreshing');
    const epoch = this.#epoch;
    const pending = this.#refreshTail.catch(() => {}).then(() => this.#load(epoch));
    this.#refreshTail = pending;
    return pending;
  }

  async close(): Promise<void> {
    this.#invalidate('closed');
    await this.#client.close();
  }

  #invalidate(state: McpConnectionState): void {
    if (this.#state === 'closed') return;
    this.#state = state; this.#epoch++; this.#inventoryRevision++; this.#registrations = Object.freeze([]);
    for (const name of this.#known) this.#guard.registerTool({
      name, description: 'Unavailable MCP operation', metadata: { session: this.#session, epoch: this.#epoch },
      resolve: () => { throw new McpBoundaryError('CONNECTION_UNAVAILABLE'); },
      execute: () => { throw new McpBoundaryError('CONNECTION_UNAVAILABLE'); },
    });
  }

  #assertEpoch(epoch: number): void {
    if (this.#state !== 'ready' || epoch !== this.#epoch) throw new McpBoundaryError('CONNECTION_CHANGED');
    this.#checkAuthorization();
  }

  #checkAuthorization(): void {
    try {
      const returned = this.#authorize?.();
      if (returned !== undefined) {
        // Reject async callbacks without leaving a rejected Promise unobserved.
        void Promise.resolve(returned).catch(() => {});
        throw new McpBoundaryError('AUTHORIZATION_DENIED');
      }
    } catch {
      this.#invalidate('quarantined');
      throw new McpBoundaryError('AUTHORIZATION_DENIED');
    }
  }

  #wrap(inner: Transport): Transport {
    const wrapper: Transport = {
      ...(inner.hasPerRequestStream === undefined ? {} : { hasPerRequestStream: inner.hasPerRequestStream }),
      get sessionId() { return inner.sessionId; },
      setProtocolVersion: version => inner.setProtocolVersion?.(version),
      setSupportedProtocolVersions: versions => inner.setSupportedProtocolVersions?.(versions),
      start: async () => {
        inner.onclose = () => wrapper.onclose?.();
        inner.onerror = error => wrapper.onerror?.(error);
        inner.onmessage = (message, extra) => {
          try {
            if (++this.#messages > this.#maxMessages) throw new McpBoundaryError('MESSAGE_BUDGET');
            const safe = boundedJson(message) as unknown as JSONRPCMessage;
            // Quarantine synchronously before SDK async notification dispatch.
            if ('method' in safe && ['notifications/tools/list_changed', 'notifications/resources/list_changed', 'notifications/prompts/list_changed'].includes(safe.method)) this.#invalidate('quarantined');
            wrapper.onmessage?.(safe, extra);
          } catch {
            this.#invalidate('closed'); wrapper.onerror?.(new McpBoundaryError('MESSAGE_REJECTED'));
            void inner.close().catch(() => {});
          }
        };
        await inner.start();
      },
      close: () => inner.close(),
      send: async (message: JSONRPCMessage, options?: TransportSendOptions) => {
        if (this.#state === 'closed') throw new McpBoundaryError('CONNECTION_UNAVAILABLE');
        const safe = boundedJson(message) as unknown as JSONRPCMessage;
        if ('method' in safe) {
          if (operations.has(safe.method)) {
            const meta = (safe.params as { _meta?: Record<string, unknown> } | undefined)?._meta;
            if (meta?.[SESSION_META] !== this.#session || meta?.[EPOCH_META] !== this.#epoch) throw new McpBoundaryError('CONNECTION_CHANGED');
            this.#assertEpoch(this.#epoch);
          } else if (lists.has(safe.method)) {
            if (this.#state !== 'refreshing') throw new McpBoundaryError('CAPABILITY_DENIED');
            this.#checkAuthorization();
          } else if (!allowedControlMethods.has(safe.method)) throw new McpBoundaryError('CAPABILITY_DENIED');
        }
        await inner.send(safe, options);
      },
    };
    return wrapper;
  }

  async #load(epoch: number): Promise<void> {
    if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
    try {
      const requestOptions = { timeout: this.#timeout, cacheMode: 'bypass' as const };
      const toolList = this.#tools.length ? (await this.#client.listTools(undefined, requestOptions)).tools : [];
      const resourceList = this.#resources.length ? (await this.#client.listResources(undefined, requestOptions)).resources : [];
      const promptList = this.#prompts.length ? (await this.#client.listPrompts(undefined, requestOptions)).prompts : [];
      if (toolList.length + resourceList.length + promptList.length > this.#maxEntries) throw new McpBoundaryError('REGISTRY_LIMIT');
      const all = boundedJson({ tools: toolList, resources: resourceList, prompts: promptList });
      void all;
      const tools = this.#unique(toolList, 'name'); const resources = this.#unique(resourceList, 'uri'); const prompts = this.#unique(promptList, 'name');
      const prepared: Array<() => ManagedMcpRegistration> = [];
      for (const binding of this.#tools) {
        const descriptor = tools.get(binding.name); if (!descriptor) continue;
        const input = compileBoundedSchema(descriptor.inputSchema);
        if (descriptor.outputSchema !== undefined) compileBoundedSchema(descriptor.outputSchema);
        const safe = passiveJson(descriptor) as unknown as Tool;
        prepared.push(() => this.#register('tool', binding, safe, descriptor.inputSchema as Json, input, epoch));
      }
      for (const binding of this.#resources) {
        const descriptor = resources.get(binding.uri); if (!descriptor) continue;
        const schema = { type: 'object', additionalProperties: false };
        prepared.push(() => this.#register('resource', binding, descriptor, schema, compileBoundedSchema(schema), epoch));
      }
      for (const binding of this.#prompts) {
        const descriptor = prompts.get(binding.name); if (!descriptor) continue;
        const args = descriptor.arguments ?? [];
        if (!Array.isArray(args) || args.length > 64) throw new McpBoundaryError('SCHEMA_INVALID');
        const properties: Record<string, Json> = Object.create(null); const required: string[] = [];
        for (const argument of args) {
          const name = identifier(argument.name); if (Object.hasOwn(properties, name)) throw new McpBoundaryError('SCHEMA_INVALID');
          properties[name] = { type: 'string', maxLength: 16_384 };
          if (argument.required === true) required.push(name);
        }
        const schema = { type: 'object', properties, required, additionalProperties: false };
        prepared.push(() => this.#register('prompt', binding, descriptor, schema, compileBoundedSchema(schema), epoch));
      }
      if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
      const registrations = prepared.map(register => register());
      if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
      // Exclude the authorization epoch/session so an unchanged explicit refresh
      // does not masquerade as a change in the accepted remote descriptors.
      const metadata = registrations.map(({ name, kind, descriptor }) => ({ name, kind, descriptor }))
        .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      const metadataDigest = digestJson(metadata);
      if (metadataDigest !== this.#metadataDigest) { this.#metadataDigest = metadataDigest; this.#metadataRevision++; }
      this.#registrations = Object.freeze(registrations);
      this.#state = 'ready';
      this.#inventoryRevision++;
    } catch {
      if (epoch === this.#epoch) this.#invalidate('quarantined');
      throw new McpBoundaryError('REGISTRY_REJECTED');
    }
  }

  #unique<T extends object>(values: T[], key: keyof T): Map<string, T> {
    const map = new Map<string, T>();
    for (const value of values) {
      const name = identifier(value[key]); if (map.has(name)) throw new McpBoundaryError('REGISTRY_REJECTED');
      map.set(name, value);
    }
    return map;
  }

  #register(kind: 'tool' | 'resource' | 'prompt', binding: McpBinding, descriptor: unknown, schema: Json, validate: (input: unknown) => boolean, epoch: number): ManagedMcpRegistration {
    const name = kind === 'tool' ? mcpToolName(this.#identity.serverId, binding.name) : `mcp-${kind}:${encodeURIComponent(this.#identity.serverId)}:${encodeURIComponent(binding.name)}`;
    const safe = passiveJson(descriptor);
    const fingerprint = this.#guard.registerTool({
      name, description: `${kind} ${binding.name}`, inputSchema: schema,
      metadata: { descriptor: safe, identity: { ...this.#identity }, session: this.#session, epoch },
      ...(binding.requiresApproval === undefined ? {} : { requiresApproval: binding.requiresApproval }),
      ...(binding.controlPlane === undefined ? {} : { controlPlane: binding.controlPlane }),
      ...(binding.maxCost === undefined ? {} : { maxCost: binding.maxCost }),
      resolve: (args, task) => {
        this.#assertEpoch(epoch);
        if (task.principalId !== this.#identity.principalId || task.tenantId !== this.#identity.tenantId) throw new McpBoundaryError('IDENTITY_DENIED');
        if (!validate(args)) throw new McpBoundaryError('ARGUMENTS_INVALID');
        return binding.resolve(object(args), task);
      },
      execute: async (args, { signal }) => {
        this.#assertEpoch(epoch);
        const _meta = { [SESSION_META]: this.#session, [EPOCH_META]: epoch };
        const options = { signal, timeout: this.#timeout };
        let result: unknown;
        try {
          if (kind === 'tool') result = await this.#client.callTool({ name: binding.name, arguments: object(args), _meta }, { ...options, toolDefinition: safe as unknown as Tool });
          else if (kind === 'resource') result = await this.#client.readResource({ uri: (binding as McpResourceBinding).uri, _meta }, { ...options, cacheMode: 'bypass' });
          else result = await this.#client.getPrompt({ name: binding.name, arguments: object(args) as Record<string, string>, _meta }, options);
          this.#assertEpoch(epoch);
          const value = passiveJson(result);
          if (kind === 'resource') {
            const contents = object(value).contents;
            if (!Array.isArray(contents) || contents.some(item => object(item).uri !== (binding as McpResourceBinding).uri)) throw new McpBoundaryError('RESOURCE_MISMATCH');
          }
          return binding.measureCost ? { value, actualCost: binding.measureCost(value) } : { value };
        } catch {
          // A failed/aborted request may still have had a remote effect. Never retry it.
          this.#invalidate('quarantined');
          throw new McpBoundaryError('MCP_OPERATION_FAILED');
        }
      },
    });
    this.#known.add(name);
    return Object.freeze({ name, fingerprint, kind, remoteName: binding.name, descriptor: safe });
  }
}
