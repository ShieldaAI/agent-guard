import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { AgentGuard, type Json, type ResolvedAction, type TaskIdentity } from '@shieldaai/agent-guard';
import { containsLiteralSecret, digestJson } from '@shieldaai/agent-guard/internal';
import {
  Client,
  SdkError,
  SdkErrorCode,
  type Transport,
  type JSONRPCMessage,
  type TransportSendOptions,
  type Tool,
} from '@modelcontextprotocol/client';
import {
  boundedJson,
  compileBoundedSchema,
  compileSchemaWithLimits,
  DEFAULT_MESSAGE_BYTES,
  McpBoundaryError,
  messageLimits,
  passiveJson,
  wellFormedIdentifier,
  type JsonLimits,
  type McpBoundaryErrorCode,
} from './boundary.js';
import { mcpToolName, type RegisteredMcpTool } from './index.js';
import {
  mcpInventorySnapshot,
  opaqueTransportRef,
  type McpConnectionInventory,
  type McpConnectionState,
} from './inventory.js';

/** Reported MCP client version: the installed package's own version, never a hand-maintained copy. */
const PACKAGE_VERSION = (createRequire(import.meta.url)('../package.json') as { version: string }).version;

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
  /** Outside-content labels passed to the guard (see ToolDefinition). */
  readsUntrusted?: boolean;
  untrustedContext?: 'allow' | 'require_approval' | 'deny';
  sendsExternal?: boolean;
}
export interface McpResourceBinding extends McpBinding {
  uri: string;
}
export interface ManagedMcpOptions {
  guard: Pick<AgentGuard, 'registerTool'>;
  identity: McpConnectionIdentity;
  /** Exclusive ownership is transferred. This package does not launch servers or perform OAuth. */
  transport: Transport;
  /** Trusted synchronous auth/revocation check, run at connection, preparation and dispatch. */
  authorize?: () => void;
  /** Close on a decoded inbound message containing one of these exact host secrets in any key or string. */
  protectedValues?: readonly string[];
  tools?: readonly McpBinding[];
  /** Exact, advertised resource URIs only; no templates or automatic link fetching. */
  resources?: readonly McpResourceBinding[];
  prompts?: readonly McpBinding[];
  /**
   * Mark every operation on this connection as reading outside content, for a server whose
   * results people outside the trust boundary can write. A binding's own readsUntrusted wins.
   * Default false.
   */
  readsUntrusted?: boolean;
  /** Bounds on this connection. Every value has a default; one outside its range fails INVALID_CONFIGURATION. */
  limits?: {
    /** Longest one request may take, in milliseconds. 1-120,000, default 10,000. */
    requestTimeoutMs?: number;
    /** Most bindings, and most definitions the server may advertise. 1-256, default 64. */
    maxEntries?: number;
    /**
     * Sliding-window rate: at most this many inbound messages per messageWindowMs.
     * 1-100,000, default 10,000. Exceeding it quarantines; refresh() recovers.
     */
    maxMessages?: number;
    /** Length of the inbound rate window, in milliseconds. 1-600,000, default 10,000. */
    messageWindowMs?: number;
    /** Most pages read from one list request. 1-16, default 4. */
    maxPages?: number;
    /**
     * Largest protocol message in either direction, and so the largest result, in bytes of
     * JSON. 1,048,576-16,777,216 (1 MiB to 16 MiB), default 1,048,576. A larger result
     * fails only its own call. When raising it, raise the guard's `limits.maxJsonBytes` to
     * at least the same value: a result the guard refuses fails RESULT_INVALID and revokes
     * the task. Call arguments and the advertised registry stay limited to 1 MiB.
     */
    maxMessageBytes?: number;
  };
}
/** A configured binding the server advertised but this manager could not accept. */
export interface McpSkippedOperation {
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  /** Stable code such as SCHEMA_UNSUPPORTED, SCHEMA_INVALID, SCHEMA_LIMIT or ACTIVE_CONTENT_DENIED. */
  readonly reason: string;
}
export interface ManagedMcpRegistration extends RegisteredMcpTool {
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  readonly descriptor: Json;
  /**
   * `sha256:` digest of the kind, remote name and accepted descriptor. Unlike `fingerprint`,
   * it is the same on every connection and after every refresh while the server advertises
   * the same definition: store it when you review a tool, and compare it before approving.
   */
  readonly descriptorDigest: string;
}
const EPOCH_META = 'shielda/connection-epoch';
const SESSION_META = 'shielda/connection-session';
const allowedControlMethods = new Set(['initialize', 'notifications/initialized', 'ping', 'notifications/cancelled']);
const lists = new Set(['tools/list', 'resources/list', 'prompts/list']);
const operations = new Set(['tools/call', 'resources/read', 'prompts/get']);
const listChanged = [
  'notifications/tools/list_changed',
  'notifications/resources/list_changed',
  'notifications/prompts/list_changed',
];
/** Outbound request ids remembered for matching an oversized reply to its call. */
const MAX_TRACKED_REQUESTS = 1024;
/**
 * Failures that say something about the connection or server, not one call. Everything
 * else (abort, timeout, a JSON-RPC error reply, an invalid or oversized result, a resource
 * mismatch, a throwing measureCost) fails only the call.
 */
const connectionFailures = new Set<string>([
  'CONNECTION_CHANGED',
  'CONNECTION_UNAVAILABLE',
  'CAPABILITY_DENIED',
  'ACTIVE_CONTENT_DENIED',
  'AUTHORIZATION_DENIED',
  SdkErrorCode.ConnectionClosed,
  SdkErrorCode.SendFailed,
  SdkErrorCode.NotConnected,
]);
function connectionFailure(error: unknown): boolean {
  return (error instanceof McpBoundaryError || error instanceof SdkError) && connectionFailures.has(error.code);
}
/** Reads a response id from an unvalidated message without invoking accessors. */
function responseId(message: unknown): string | number | undefined {
  if (message === null || typeof message !== 'object' || Array.isArray(message)) return undefined;
  const own = (key: string) => Object.getOwnPropertyDescriptor(message, key);
  const id = own('id');
  if (!id || !('value' in id) || (!own('result') && !own('error'))) return undefined;
  return typeof id.value === 'string' || (typeof id.value === 'number' && Number.isSafeInteger(id.value))
    ? id.value
    : undefined;
}

/**
 * The same rule the inventory applies, so a connection that constructs can always be observed.
 * `code` is INVALID_CONFIGURATION for a host option; a name the server advertised fails with
 * a code that points at the server instead.
 */
function identifier(value: unknown, code: McpBoundaryErrorCode = 'INVALID_CONFIGURATION'): string {
  if (!wellFormedIdentifier(value) || value.length > 1024) throw new McpBoundaryError(code);
  return value;
}
/** The guard's limit on a tool name. A longer operation name could never be registered. */
const MAX_OPERATION_NAME = 4096;
/** The name an operation is registered under: `mcp:`, `mcp-resource:` or `mcp-prompt:`, then both parts URL-encoded. */
function operationName(kind: 'tool' | 'resource' | 'prompt', serverId: string, remoteName: string): string {
  return kind === 'tool'
    ? mcpToolName(serverId, remoteName)
    : `mcp-${kind}:${encodeURIComponent(serverId)}:${encodeURIComponent(remoteName)}`;
}
function limit(value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > maximum)
    throw new McpBoundaryError('INVALID_CONFIGURATION');
  return result;
}
function object(value: Json): Record<string, Json> {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new McpBoundaryError('ARGUMENTS_INVALID');
  return value as Record<string, Json>;
}
function bindings(input: readonly McpBinding[] | undefined): readonly McpBinding[] {
  const seen = new Set<string>();
  return Object.freeze(
    (input ?? []).map(binding => {
      const name = identifier(binding.name);
      if (seen.has(name) || typeof binding.resolve !== 'function') throw new McpBoundaryError('INVALID_CONFIGURATION');
      seen.add(name);
      return Object.freeze({ ...binding, name });
    }),
  );
}

/** ManagedMcpOptions after every check that needs no transport. */
export interface CheckedManagedMcpOptions {
  readonly authorize: (() => void) | undefined;
  readonly protectedValues: readonly string[];
  readonly readsUntrusted: boolean;
  readonly identity: Readonly<McpConnectionIdentity>;
  readonly tools: readonly McpBinding[];
  readonly prompts: readonly McpBinding[];
  readonly resources: readonly McpResourceBinding[];
  readonly requestTimeoutMs: number;
  readonly maxEntries: number;
  readonly maxMessages: number;
  readonly messageWindowMs: number;
  readonly maxMessageBytes: number;
  readonly maxPages: number;
}
/**
 * Checks and copies every option that can be judged without a transport, so a caller that
 * builds the transport later (VerifiedMcpHttpSession) can refuse bad options before any
 * network call. Throws INVALID_CONFIGURATION, or REGISTRY_LIMIT for too many bindings.
 */
export function checkManagedMcpOptions(
  options: Omit<ManagedMcpOptions, 'guard' | 'transport'>,
): CheckedManagedMcpOptions {
  if (options.authorize !== undefined && typeof options.authorize !== 'function')
    throw new McpBoundaryError('INVALID_CONFIGURATION');
  const protectedValues = options.protectedValues ?? [];
  if (
    !Array.isArray(protectedValues) ||
    protectedValues.length > 32 ||
    protectedValues.some(value => typeof value !== 'string' || !value.length || value.length > 16_384)
  )
    throw new McpBoundaryError('INVALID_CONFIGURATION');
  if (options.readsUntrusted !== undefined && typeof options.readsUntrusted !== 'boolean')
    throw new McpBoundaryError('INVALID_CONFIGURATION');
  const identity = Object.freeze({
    serverId: identifier(options.identity.serverId),
    transportIdentity: identifier(options.identity.transportIdentity),
    principalId: identifier(options.identity.principalId),
    tenantId: identifier(options.identity.tenantId),
  });
  const tools = bindings(options.tools);
  const prompts = bindings(options.prompts);
  const resources = bindings(options.resources) as readonly McpResourceBinding[];
  for (const resource of resources) identifier(resource.uri);
  // Encoding can make a name several times longer. Refuse here what the guard would refuse
  // at registration, where it would only surface as a failed connection.
  const longest = (kind: 'tool' | 'resource' | 'prompt', list: readonly McpBinding[]): number =>
    Math.max(0, ...list.map(binding => operationName(kind, identity.serverId, binding.name).length));
  if (
    operationName('tool', identity.serverId, 'x').length > MAX_OPERATION_NAME ||
    Math.max(longest('tool', tools), longest('prompt', prompts), longest('resource', resources)) > MAX_OPERATION_NAME
  )
    throw new McpBoundaryError('INVALID_CONFIGURATION');
  const requestTimeoutMs = limit(options.limits?.requestTimeoutMs, 10_000, 120_000);
  const maxEntries = limit(options.limits?.maxEntries, 64, 256);
  const maxMessages = limit(options.limits?.maxMessages, 10_000, 100_000);
  const messageWindowMs = limit(options.limits?.messageWindowMs, 10_000, 600_000);
  const maxMessageBytes = limit(options.limits?.maxMessageBytes, DEFAULT_MESSAGE_BYTES, 16_777_216);
  if (maxMessageBytes < DEFAULT_MESSAGE_BYTES) throw new McpBoundaryError('INVALID_CONFIGURATION');
  if (tools.length + resources.length + prompts.length > maxEntries) throw new McpBoundaryError('REGISTRY_LIMIT');
  const maxPages = limit(options.limits?.maxPages, 4, 16);
  return Object.freeze({
    authorize: options.authorize,
    protectedValues: Object.freeze([...protectedValues]),
    readsUntrusted: options.readsUntrusted === true,
    identity,
    tools,
    prompts,
    resources,
    requestTimeoutMs,
    maxEntries,
    maxMessages,
    messageWindowMs,
    maxMessageBytes,
    maxPages,
  });
}

/**
 * Owns one SDK client, one principal/tenant and one transport lifetime. There is no
 * raw request/client escape hatch. Reconnection requires a new instance and review.
 */
export class ManagedMcpConnection {
  readonly #guard: Pick<AgentGuard, 'registerTool'>;
  readonly #identity: Readonly<McpConnectionIdentity>;
  readonly #session = randomUUID();
  readonly #validators = new WeakMap<object, (value: unknown) => boolean>();
  readonly #transportRef: string;
  readonly #client: Client;
  readonly #transport: Transport;
  readonly #tools: readonly McpBinding[];
  readonly #resources: readonly McpResourceBinding[];
  readonly #prompts: readonly McpBinding[];
  readonly #timeout: number;
  readonly #maxEntries: number;
  readonly #maxMessages: number;
  readonly #messageWindow: number;
  readonly #messageLimits: Readonly<JsonLimits>;
  /** Ring of inbound message times; the oldest entry bounds the sliding window. */
  readonly #messageTimes: Float64Array;
  #messageHead = 0;
  #messageCount = 0;
  readonly #pendingRequests = new Set<string | number>();
  readonly #authorize: (() => void) | undefined;
  readonly #protectedValues: readonly string[];
  readonly #readsUntrusted: boolean;
  #epoch = 0;
  // Observation revision includes ready transitions without changing execution epochs.
  #inventoryRevision = 0;
  #metadataRevision = 0;
  #metadataDigest: string | undefined;
  #state: McpConnectionState = 'connecting';
  #registrations: readonly ManagedMcpRegistration[] = Object.freeze([]);
  #skipped: readonly McpSkippedOperation[] = Object.freeze([]);
  #known = new Set<string>();
  #failureReason: McpBoundaryErrorCode | undefined;
  #refreshTail: Promise<void> = Promise.resolve();

  private constructor(options: ManagedMcpOptions) {
    this.#guard = options.guard;
    const checked = checkManagedMcpOptions(options);
    this.#authorize = checked.authorize;
    this.#protectedValues = checked.protectedValues;
    this.#readsUntrusted = checked.readsUntrusted;
    this.#identity = checked.identity;
    this.#transportRef = opaqueTransportRef(this.#identity.transportIdentity);
    this.#tools = checked.tools;
    this.#prompts = checked.prompts;
    this.#resources = checked.resources;
    this.#timeout = checked.requestTimeoutMs;
    this.#maxEntries = checked.maxEntries;
    this.#maxMessages = checked.maxMessages;
    this.#messageWindow = checked.messageWindowMs;
    this.#messageTimes = new Float64Array(this.#maxMessages);
    this.#messageLimits = messageLimits(checked.maxMessageBytes);
    this.#client = new Client(
      { name: 'shielda-agent-guard', version: PACKAGE_VERSION },
      {
        capabilities: {},
        versionNegotiation: { mode: 'legacy' },
        listMaxPages: checked.maxPages,
        cachePartition: this.#session,
        jsonSchemaValidator: {
          getValidator: <T>(schema: unknown) => {
            // The SDK asks again on every call; a schema object is compiled once.
            const known = typeof schema === 'object' && schema !== null ? this.#validators.get(schema) : undefined;
            // The SDK validates results here (a tool's output schema), so the connection's
            // message limit applies. Arguments are checked in resolve() and stay at 1 MiB.
            const validate = known ?? compileSchemaWithLimits(schema, this.#messageLimits);
            if (!known && typeof schema === 'object' && schema !== null) this.#validators.set(schema, validate);
            return (value: unknown) =>
              validate(value)
                ? { valid: true as const, data: value as T, errorMessage: undefined }
                : { valid: false as const, data: undefined, errorMessage: 'SCHEMA_VALIDATION_FAILED' };
          },
        },
      },
    );
    this.#transport = this.#wrap(options.transport);
    this.#client.onclose = () => {
      // The transport went away without close() being called: say so in failureReason.
      if (this.#state !== 'closed') this.#invalidate('closed', 'CONNECTION_UNAVAILABLE');
    };
    // SDK request dispatch rejects unadvertised sampling/elicitation/roots capabilities.
    this.#client.fallbackRequestHandler = async () => {
      throw new McpBoundaryError('CAPABILITY_DENIED');
    };
    for (const method of listChanged as (
      'notifications/tools/list_changed' | 'notifications/resources/list_changed' | 'notifications/prompts/list_changed'
    )[]) {
      this.#client.setNotificationHandler(method, () => {
        this.#invalidate('quarantined', 'REGISTRY_CHANGED');
      });
    }
  }

  /**
   * Connects, loads the registry and registers each accepted operation with the guard,
   * unapproved. Rejects with INVALID_CONFIGURATION or REGISTRY_LIMIT for bad options, and
   * with CONNECTION_FAILED (the connection is then closed) when the handshake, the
   * authorization check or the first registry load fails.
   */
  static async connect(options: ManagedMcpOptions): Promise<ManagedMcpConnection> {
    const connection = new ManagedMcpConnection(options);
    try {
      connection.#checkAuthorization();
      await connection.#client.connect(connection.#transport, { timeout: connection.#timeout });
      // The transport may have closed while the handshake settled: closed is final.
      if (connection.#state === 'closed') throw new McpBoundaryError('CONNECTION_UNAVAILABLE');
      connection.#state = 'quarantined';
      connection.#inventoryRevision++;
      await connection.refresh();
      return connection;
    } catch {
      await connection.close().catch(() => {});
      throw new McpBoundaryError('CONNECTION_FAILED');
    }
  }

  /** `ready` is the only state in which operations can be prepared or run. */
  get status(): McpConnectionState {
    return this.#state;
  }
  /** Random ID of this connection; a new connection always has a new one. */
  get sessionId(): string {
    return this.#session;
  }
  /** Advances whenever prepared calls and approvals are invalidated: every refresh, quarantine and close. */
  get revision(): number {
    return this.#epoch;
  }
  /** Advances on every state change, including a refresh completing. Same as `inventory().revision`. */
  get inventoryRevision(): number {
    return this.#inventoryRevision;
  }
  /** The operations accepted by the last refresh. Empty unless the connection is `ready`. */
  get registrations(): readonly ManagedMcpRegistration[] {
    return this.#registrations;
  }
  /**
   * Why the connection last left `ready` for a reason other than an explicit refresh or close:
   * for example `REGISTRY_CHANGED` (the server announced changed definitions), `MESSAGE_BUDGET`,
   * `MESSAGE_REJECTED`, `CREDENTIAL_REFLECTED`, `AUTHORIZATION_DENIED`, or
   * `CONNECTION_UNAVAILABLE` when the transport closed or a send failed. Cleared by the next
   * successful refresh. A code only, never server data.
   */
  get failureReason(): McpBoundaryErrorCode | undefined {
    return this.#failureReason;
  }
  /** Advertised bindings skipped by the last successful refresh, with the reason. */
  get skipped(): readonly McpSkippedOperation[] {
    return this.#skipped;
  }

  /**
   * A pure observation: no authorization checks, discovery, resolvers or dispatch. Throws
   * MCP_INVENTORY_CLOCK_INVALID, MCP_INVENTORY_INVALID or MCP_INVENTORY_LIMIT_EXCEEDED
   * when the observation cannot be produced.
   */
  inventory(): McpConnectionInventory {
    return mcpInventorySnapshot({
      identity: {
        serverId: this.#identity.serverId,
        transportRef: this.#transportRef,
        principalId: this.#identity.principalId,
        tenantId: this.#identity.tenantId,
      },
      sessionId: this.#session,
      revision: this.#inventoryRevision,
      authorizationEpoch: this.#epoch,
      metadataRevision: this.#metadataRevision,
      state: this.#state,
      registrations: this.#registrations,
    });
  }

  /**
   * Loads the registry again, for example after quarantine. Every successful refresh issues
   * new fingerprints, so each operation needs `approveTool()` again. Rejects with
   * CONNECTION_UNAVAILABLE when the connection is closed, REGISTRY_REJECTED when this
   * refresh could not accept the server's registry (the connection is then quarantined),
   * and CONNECTION_CHANGED when something else changed the connection before this refresh
   * finished: a newer refresh, a change notification, an authorization failure or a close.
   */
  refresh(): Promise<void> {
    if (this.#state === 'closed' || this.#state === 'connecting')
      return Promise.reject(new McpBoundaryError('CONNECTION_UNAVAILABLE'));
    this.#invalidate('refreshing');
    const epoch = this.#epoch;
    const pending = this.#refreshTail.catch(() => {}).then(() => this.#load(epoch));
    this.#refreshTail = pending;
    return pending;
  }

  /** Closes for good and invalidates every registration. A closed connection cannot be refreshed. */
  async close(): Promise<void> {
    this.#invalidate('closed');
    await this.#client.close();
  }

  #invalidate(state: McpConnectionState, reason?: McpBoundaryErrorCode): void {
    if (this.#state === 'closed') return;
    if (reason !== undefined) this.#failureReason = reason;
    this.#state = state;
    this.#epoch++;
    this.#inventoryRevision++;
    this.#registrations = Object.freeze([]);
    for (const name of this.#known)
      this.#guard.registerTool({
        name,
        description: 'Unavailable MCP operation',
        metadata: { session: this.#session, epoch: this.#epoch },
        resolve: () => {
          throw new McpBoundaryError('CONNECTION_UNAVAILABLE');
        },
        execute: () => {
          throw new McpBoundaryError('CONNECTION_UNAVAILABLE');
        },
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
      this.#invalidate('quarantined', 'AUTHORIZATION_DENIED');
      throw new McpBoundaryError('AUTHORIZATION_DENIED');
    }
  }

  #wrap(inner: Transport): Transport {
    const wrapper: Transport = {
      ...(inner.hasPerRequestStream === undefined ? {} : { hasPerRequestStream: inner.hasPerRequestStream }),
      get sessionId() {
        return inner.sessionId;
      },
      setProtocolVersion: version => inner.setProtocolVersion?.(version),
      setSupportedProtocolVersions: versions => inner.setSupportedProtocolVersions?.(versions),
      start: async () => {
        inner.onclose = () => wrapper.onclose?.();
        inner.onerror = error => wrapper.onerror?.(error);
        inner.onmessage = (message, extra) => {
          if (this.#state === 'closed') return;
          if (!this.#admitMessage()) {
            // A flood is a server problem, not a reason to lose the connection for good.
            this.#invalidate('quarantined', 'MESSAGE_BUDGET');
            wrapper.onerror?.(new McpBoundaryError('MESSAGE_BUDGET'));
            return;
          }
          let data: Json;
          try {
            data = boundedJson(message, this.#messageLimits);
          } catch {
            // An oversized or malformed reply fails only the call it answers.
            const id = responseId(message);
            if (id !== undefined && this.#pendingRequests.delete(id)) {
              wrapper.onmessage?.(
                { jsonrpc: '2.0', id, error: { code: -32603, message: 'MESSAGE_REJECTED' } } as JSONRPCMessage,
                extra,
              );
            } else {
              this.#invalidate('quarantined', 'MESSAGE_REJECTED');
              wrapper.onerror?.(new McpBoundaryError('MESSAGE_REJECTED'));
            }
            return;
          }
          try {
            if (this.#protectedValues.length && containsLiteralSecret(data, this.#protectedValues))
              throw new McpBoundaryError('CREDENTIAL_REFLECTED');
          } catch {
            // A reflected host secret is a hostile server: close, a new reviewed connection is required.
            this.#invalidate('closed', 'CREDENTIAL_REFLECTED');
            wrapper.onerror?.(new McpBoundaryError('MESSAGE_REJECTED'));
            void inner.close().catch(() => {});
            return;
          }
          const safe = data as unknown as JSONRPCMessage;
          const id = responseId(safe);
          if (id !== undefined) this.#pendingRequests.delete(id);
          // Quarantine synchronously before SDK async notification dispatch.
          if ('method' in safe && listChanged.includes(safe.method))
            this.#invalidate('quarantined', 'REGISTRY_CHANGED');
          wrapper.onmessage?.(safe, extra);
        };
        await inner.start();
      },
      close: () => inner.close(),
      send: async (message: JSONRPCMessage, options?: TransportSendOptions) => {
        if (this.#state === 'closed') throw new McpBoundaryError('CONNECTION_UNAVAILABLE');
        const safe = boundedJson(message, this.#messageLimits) as unknown as JSONRPCMessage;
        if ('method' in safe) {
          if (operations.has(safe.method)) {
            const meta = (safe.params as { _meta?: Record<string, unknown> } | undefined)?._meta;
            if (meta?.[SESSION_META] !== this.#session || meta?.[EPOCH_META] !== this.#epoch)
              throw new McpBoundaryError('CONNECTION_CHANGED');
            this.#assertEpoch(this.#epoch);
          } else if (lists.has(safe.method)) {
            if (this.#state !== 'refreshing') throw new McpBoundaryError('CAPABILITY_DENIED');
            this.#checkAuthorization();
          } else if (!allowedControlMethods.has(safe.method)) throw new McpBoundaryError('CAPABILITY_DENIED');
        }
        if ('method' in safe && 'id' in safe && (typeof safe.id === 'string' || typeof safe.id === 'number')) {
          if (this.#pendingRequests.size >= MAX_TRACKED_REQUESTS)
            this.#pendingRequests.delete(this.#pendingRequests.values().next().value!);
          this.#pendingRequests.add(safe.id);
        }
        await inner.send(safe, options);
      },
    };
    return wrapper;
  }

  /** Sliding-window inbound rate: at most maxMessages per messageWindowMs. */
  #admitMessage(): boolean {
    const now = performance.now();
    if (this.#messageCount === this.#maxMessages && now - this.#messageTimes[this.#messageHead]! < this.#messageWindow)
      return false;
    this.#messageTimes[this.#messageHead] = now;
    this.#messageHead = (this.#messageHead + 1) % this.#maxMessages;
    if (this.#messageCount < this.#maxMessages) this.#messageCount++;
    return true;
  }

  async #load(epoch: number): Promise<void> {
    if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
    try {
      const requestOptions = { timeout: this.#timeout, cacheMode: 'bypass' as const };
      const toolList = this.#tools.length ? (await this.#client.listTools(undefined, requestOptions)).tools : [];
      const resourceList = this.#resources.length
        ? (await this.#client.listResources(undefined, requestOptions)).resources
        : [];
      const promptList = this.#prompts.length
        ? (await this.#client.listPrompts(undefined, requestOptions)).prompts
        : [];
      if (toolList.length + resourceList.length + promptList.length > this.#maxEntries)
        throw new McpBoundaryError('REGISTRY_LIMIT');
      const all = boundedJson({ tools: toolList, resources: resourceList, prompts: promptList });
      void all;
      const tools = this.#unique(toolList, 'name');
      const resources = this.#unique(resourceList, 'uri');
      const prompts = this.#unique(promptList, 'name');
      const prepared: Array<() => ManagedMcpRegistration> = [];
      const skipped: McpSkippedOperation[] = [];
      // A descriptor this profile cannot accept removes only that operation.
      const accept = (
        kind: McpSkippedOperation['kind'],
        remoteName: string,
        build: () => () => ManagedMcpRegistration,
      ): void => {
        try {
          prepared.push(build());
        } catch (error) {
          skipped.push(
            Object.freeze({
              kind,
              remoteName,
              reason: error instanceof McpBoundaryError ? error.code : 'SCHEMA_INVALID',
            }),
          );
        }
      };
      for (const binding of this.#tools) {
        const descriptor = tools.get(binding.name);
        if (!descriptor) continue;
        accept('tool', binding.name, () => {
          const input = compileBoundedSchema(descriptor.inputSchema);
          if (descriptor.outputSchema !== undefined) compileBoundedSchema(descriptor.outputSchema);
          const safe = passiveJson(descriptor) as unknown as Tool;
          return () => this.#register('tool', binding, safe, descriptor.inputSchema as Json, input, epoch);
        });
      }
      for (const binding of this.#resources) {
        const descriptor = resources.get(binding.uri);
        if (!descriptor) continue;
        accept('resource', binding.name, () => {
          passiveJson(descriptor);
          const schema = { type: 'object', additionalProperties: false };
          return () => this.#register('resource', binding, descriptor, schema, compileBoundedSchema(schema), epoch);
        });
      }
      for (const binding of this.#prompts) {
        const descriptor = prompts.get(binding.name);
        if (!descriptor) continue;
        accept('prompt', binding.name, () => {
          passiveJson(descriptor);
          const args = descriptor.arguments ?? [];
          if (!Array.isArray(args) || args.length > 64) throw new McpBoundaryError('SCHEMA_INVALID');
          const properties: Record<string, Json> = Object.create(null);
          const required: string[] = [];
          for (const argument of args) {
            const name = identifier(argument.name, 'SCHEMA_INVALID');
            if (Object.hasOwn(properties, name)) throw new McpBoundaryError('SCHEMA_INVALID');
            properties[name] = { type: 'string', maxLength: 16_384 };
            if (argument.required === true) required.push(name);
          }
          const schema = { type: 'object', properties, required, additionalProperties: false };
          return () => this.#register('prompt', binding, descriptor, schema, compileBoundedSchema(schema), epoch);
        });
      }
      if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
      const registrations = prepared.map(register => register());
      if (epoch !== this.#epoch || this.#state !== 'refreshing') throw new McpBoundaryError('CONNECTION_CHANGED');
      // Exclude the authorization epoch/session so an unchanged explicit refresh
      // does not masquerade as a change in the accepted remote descriptors.
      const metadata = registrations
        .map(({ name, kind, descriptor }) => ({ name, kind, descriptor }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const metadataDigest = digestJson(metadata);
      if (metadataDigest !== this.#metadataDigest) {
        this.#metadataDigest = metadataDigest;
        this.#metadataRevision++;
      }
      this.#registrations = Object.freeze(registrations);
      this.#skipped = Object.freeze(skipped);
      this.#failureReason = undefined;
      this.#state = 'ready';
      this.#inventoryRevision++;
    } catch (error) {
      // Something else moved the connection on (a newer refresh, a change notification, an
      // authorization failure or a close). This refresh was superseded, however far it got.
      if (epoch !== this.#epoch) throw new McpBoundaryError('CONNECTION_CHANGED');
      this.#invalidate('quarantined', error instanceof McpBoundaryError ? error.code : 'REGISTRY_REJECTED');
      throw new McpBoundaryError('REGISTRY_REJECTED');
    }
  }

  #unique<T extends object>(values: T[], key: keyof T): Map<string, T> {
    const map = new Map<string, T>();
    for (const value of values) {
      // A malformed name is the server's fault, never a host option.
      const name = identifier(value[key], 'REGISTRY_REJECTED');
      if (map.has(name)) throw new McpBoundaryError('REGISTRY_REJECTED');
      map.set(name, value);
    }
    return map;
  }

  #register(
    kind: 'tool' | 'resource' | 'prompt',
    binding: McpBinding,
    descriptor: unknown,
    schema: Json,
    validate: (input: unknown) => boolean,
    epoch: number,
  ): ManagedMcpRegistration {
    const name = operationName(kind, this.#identity.serverId, binding.name);
    const safe = passiveJson(descriptor);
    const fingerprint = this.#guard.registerTool({
      name,
      description: `${kind} ${binding.name}`,
      inputSchema: schema,
      metadata: { descriptor: safe, identity: { ...this.#identity }, session: this.#session, epoch },
      ...(binding.requiresApproval === undefined ? {} : { requiresApproval: binding.requiresApproval }),
      ...(binding.controlPlane === undefined ? {} : { controlPlane: binding.controlPlane }),
      ...(binding.maxCost === undefined ? {} : { maxCost: binding.maxCost }),
      // A binding's explicit `false` is kept: the inventory reads only a declared `false` as
      // "does not read outside content"; an omitted label stays unknown.
      ...(binding.readsUntrusted !== undefined
        ? { readsUntrusted: binding.readsUntrusted }
        : this.#readsUntrusted
          ? { readsUntrusted: true }
          : {}),
      ...(binding.untrustedContext === undefined ? {} : { untrustedContext: binding.untrustedContext }),
      ...(binding.sendsExternal === undefined ? {} : { sendsExternal: binding.sendsExternal }),
      resolve: (args, task) => {
        this.#assertEpoch(epoch);
        if (task.principalId !== this.#identity.principalId || task.tenantId !== this.#identity.tenantId)
          throw new McpBoundaryError('IDENTITY_DENIED');
        if (!validate(args)) throw new McpBoundaryError('ARGUMENTS_INVALID');
        return binding.resolve(object(args), task);
      },
      execute: async (args, { signal }) => {
        this.#assertEpoch(epoch);
        const _meta = { [SESSION_META]: this.#session, [EPOCH_META]: epoch };
        const options = { signal, timeout: this.#timeout };
        let result: unknown;
        try {
          if (kind === 'tool')
            result = await this.#client.callTool(
              { name: binding.name, arguments: object(args), _meta },
              { ...options, toolDefinition: safe as unknown as Tool },
            );
          else if (kind === 'resource')
            result = await this.#client.readResource(
              { uri: (binding as McpResourceBinding).uri, _meta },
              { ...options, cacheMode: 'bypass' },
            );
          else
            result = await this.#client.getPrompt(
              { name: binding.name, arguments: object(args) as Record<string, string>, _meta },
              options,
            );
          this.#assertEpoch(epoch);
          const value = passiveJson(result, this.#messageLimits);
          if (kind === 'resource') {
            const contents = object(value).contents;
            if (
              !Array.isArray(contents) ||
              contents.some(item => object(item).uri !== (binding as McpResourceBinding).uri)
            )
              throw new McpBoundaryError('RESOURCE_MISMATCH');
          }
          return binding.measureCost ? { value, actualCost: binding.measureCost(value) } : { value };
        } catch (error) {
          // A failed/aborted request may still have had a remote effect; the guard records it
          // as unknown and never retries it. Only connection-level failures quarantine.
          if (epoch === this.#epoch && connectionFailure(error))
            this.#invalidate('quarantined', error instanceof McpBoundaryError ? error.code : 'CONNECTION_UNAVAILABLE');
          throw new McpBoundaryError('MCP_OPERATION_FAILED');
        }
      },
    });
    this.#known.add(name);
    const descriptorDigest = `sha256:${digestJson({ kind, remoteName: binding.name, descriptor: safe })}`;
    return Object.freeze({ name, fingerprint, kind, remoteName: binding.name, descriptor: safe, descriptorDigest });
  }
}
