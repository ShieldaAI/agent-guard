import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createRemoteJWKSet, customFetch, decodeProtectedHeader, jwtVerify } from 'jose';
import type { FetchLike } from '@modelcontextprotocol/client';
import { boundedJson, McpBoundaryError, type McpBoundaryErrorCode } from './boundary.js';
import { assertVerifiedMcpClaims, type VerifiedMcpClaims } from './authorization.js';
import {
  checkManagedMcpOptions,
  ManagedMcpConnection,
  type ManagedMcpOptions,
  type McpConnectionIdentity,
} from './managed.js';
import { createRestrictedMcpHttpTransport } from './http.js';

export interface McpJwtAuthorization {
  readonly issuer: string;
  /** Exact host-enrolled HTTPS location. Token-selected jku/jwk/x5u keys are forbidden. */
  readonly jwksUri: string;
  /** Exact HTTPS resource indicator expected in the access token's audience. */
  readonly audience: string;
  readonly subject: string;
  readonly requiredScopes?: readonly string[];
  readonly algorithms?: readonly ('RS256' | 'ES256')[];
}
export interface VerifiedMcpHttpOptions extends Pick<
  ManagedMcpOptions,
  'guard' | 'tools' | 'resources' | 'prompts' | 'limits' | 'readsUntrusted'
> {
  readonly identity: Omit<McpConnectionIdentity, 'transportIdentity'>;
  readonly endpoint: string;
  readonly authorization: McpJwtAuthorization;
  /** Trusted host fetch enforcing TLS and socket-time DNS/egress policy. Never a model callback. */
  readonly fetch: FetchLike;
  readonly verificationTimeoutMs?: number;
  readonly maxJwksBytes?: number;
  readonly maxResponseBytes?: number;
  readonly maxTokenLifetimeSeconds?: number;
}
function deny(code: McpBoundaryErrorCode = 'AUTHORIZATION_DENIED'): never {
  throw new McpBoundaryError(code);
}
function text(value: unknown, maximum = 4096): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) deny('INVALID_CONFIGURATION');
  return value;
}
function https(value: unknown): string {
  const input = text(value);
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return deny('INVALID_CONFIGURATION');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || /[\s\\]/u.test(input))
    deny('INVALID_CONFIGURATION');
  return input;
}
function integer(value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) deny('INVALID_CONFIGURATION');
  return result;
}
const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(new McpBoundaryError('AUTHORIZATION_DENIED'));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

/**
 * One host-owned JWT access-token session. No OAuth login, token acquisition, automatic
 * renewal, raw client, or credential getter. Replacement closes old authority first.
 */
export class VerifiedMcpHttpSession {
  readonly #options: VerifiedMcpHttpOptions;
  readonly #policy: McpJwtAuthorization;
  readonly #timeout: number;
  readonly #maxJwks: number;
  readonly #lifetime: number;
  #connection: ManagedMcpConnection | undefined;
  #generation = 0;
  #closed = false;
  #busy = false;
  #sessionAbort: AbortController | undefined;
  #pending: Promise<void> | undefined;

  private constructor(options: VerifiedMcpHttpOptions) {
    if (typeof options.fetch !== 'function') deny('INVALID_CONFIGURATION');
    const policy = boundedJson(options.authorization, {
      maxBytes: 32_768,
      maxNodes: 1024,
      maxDepth: 4,
    }) as unknown as McpJwtAuthorization;
    if (
      Object.keys(policy).some(
        key => !['issuer', 'jwksUri', 'audience', 'subject', 'requiredScopes', 'algorithms'].includes(key),
      )
    )
      deny('INVALID_CONFIGURATION');
    https(policy.issuer);
    https(policy.jwksUri);
    https(policy.audience);
    text(policy.subject);
    const scopes = policy.requiredScopes ?? [];
    if (
      !Array.isArray(scopes) ||
      scopes.length > 256 ||
      scopes.some(scope => typeof scope !== 'string' || scope.length > 1024 || !scopePattern.test(scope)) ||
      new Set(scopes).size !== scopes.length
    )
      deny('INVALID_CONFIGURATION');
    const algorithms = policy.algorithms ?? ['RS256'];
    if (
      !Array.isArray(algorithms) ||
      algorithms.length < 1 ||
      algorithms.length > 2 ||
      algorithms.some(algorithm => !['RS256', 'ES256'].includes(algorithm)) ||
      new Set(algorithms).size !== algorithms.length
    )
      deny('INVALID_CONFIGURATION');
    this.#policy = Object.freeze({
      ...policy,
      algorithms: Object.freeze([...algorithms]),
      requiredScopes: Object.freeze([...scopes]),
    });
    // The connection is only built once a token has been verified. Apply its option checks
    // now, so a malformed identifier, binding or limit fails INVALID_CONFIGURATION before any
    // network call instead of surfacing later as AUTHORIZATION_DENIED.
    const checked = checkManagedMcpOptions({
      identity: { ...options.identity, transportIdentity: 'jwt-session:unassigned' },
      ...(options.tools === undefined ? {} : { tools: options.tools }),
      ...(options.resources === undefined ? {} : { resources: options.resources }),
      ...(options.prompts === undefined ? {} : { prompts: options.prompts }),
      ...(options.limits === undefined ? {} : { limits: options.limits }),
      ...(options.readsUntrusted === undefined ? {} : { readsUntrusted: options.readsUntrusted }),
    });
    const identity = Object.freeze({
      serverId: checked.identity.serverId,
      principalId: checked.identity.principalId,
      tenantId: checked.identity.tenantId,
    });
    this.#options = Object.freeze({
      ...options,
      endpoint: new URL(https(options.endpoint)).href,
      identity,
      ...(options.tools === undefined
        ? {}
        : { tools: Object.freeze(options.tools.map(value => Object.freeze({ ...value }))) }),
      ...(options.resources === undefined
        ? {}
        : { resources: Object.freeze(options.resources.map(value => Object.freeze({ ...value }))) }),
      ...(options.prompts === undefined
        ? {}
        : { prompts: Object.freeze(options.prompts.map(value => Object.freeze({ ...value }))) }),
      ...(options.limits === undefined ? {} : { limits: Object.freeze({ ...options.limits }) }),
    });
    this.#timeout = integer(options.verificationTimeoutMs, 5000, 30_000);
    this.#maxJwks = integer(options.maxJwksBytes, 262_144, 1_048_576);
    this.#lifetime = integer(options.maxTokenLifetimeSeconds, 3600, 86_400);
    integer(options.maxResponseBytes, 1_048_576, 16_777_216);
  }

  static async connect(options: VerifiedMcpHttpOptions, accessToken: string): Promise<VerifiedMcpHttpSession> {
    const session = new VerifiedMcpHttpSession(options);
    try {
      await session.replaceCredential(accessToken);
      return session;
    } catch (error) {
      await session.close().catch(() => {});
      throw error;
    }
  }
  get status() {
    return this.#closed
      ? ('closed' as const)
      : this.#busy
        ? ('connecting' as const)
        : (this.#connection?.status ?? ('quarantined' as const));
  }
  get sessionId() {
    return this.#connection?.sessionId;
  }
  get registrations() {
    return this.#connection?.registrations ?? Object.freeze([]);
  }
  /** Bindings the server advertised that the last refresh could not accept, with the reason. */
  get skipped() {
    return this.#connection?.skipped ?? Object.freeze([]);
  }
  /** Why the current connection last left `ready`; see ManagedMcpConnection.failureReason. */
  get failureReason() {
    return this.#connection?.failureReason;
  }
  inventory() {
    return this.#connection?.inventory();
  }
  /** See ManagedMcpConnection.operationChanges. CONNECTION_UNAVAILABLE while there is no ready connection. */
  operationChanges(name: string) {
    if (this.#closed || this.#busy || !this.#connection) deny('CONNECTION_UNAVAILABLE');
    return this.#connection.operationChanges(name);
  }
  /** Metadata refresh does not fetch keys or renew a credential. */
  async refresh(): Promise<void> {
    if (this.#closed || this.#busy || !this.#connection) deny('CONNECTION_UNAVAILABLE');
    await this.#connection.refresh();
  }

  /** Concurrent replacements are rejected. A failed replacement never revives the old session. */
  async replaceCredential(accessToken: string): Promise<void> {
    if (this.#closed) deny('CONNECTION_UNAVAILABLE');
    if (this.#busy) deny('CREDENTIAL_REPLACEMENT_PENDING');
    this.#busy = true;
    const previous = this.#connection;
    this.#connection = undefined;
    // close() invalidates registrations synchronously, before any key retrieval.
    const closing = previous?.close();
    const generation = ++this.#generation;
    this.#sessionAbort?.abort();
    const controller = new AbortController();
    this.#sessionAbort = controller;
    const timer = setTimeout(() => controller.abort(), this.#timeout);
    timer.unref();
    const check = (): void => {
      if (this.#closed || this.#generation !== generation || controller.signal.aborted) deny();
    };
    const work = async (): Promise<void> => {
      await closing;
      check();
      const verified = await this.#verify(accessToken, controller.signal);
      check();
      clearTimeout(timer);
      const wallNow = Date.now() / 1000,
        monotonicExpiry = performance.now() + (verified.expiresAt - wallNow) * 1000;
      const authorize = (): void => {
        if (
          this.#closed ||
          this.#generation !== generation ||
          controller.signal.aborted ||
          performance.now() >= monotonicExpiry
        )
          deny();
        assertVerifiedMcpClaims(verified, this.#policy);
      };
      const protectedFetch: FetchLike = async (input, init) => {
        authorize();
        const response = await this.#options.fetch(input, {
          ...init,
          signal: AbortSignal.any([controller.signal, ...(init?.signal ? [init.signal] : [])]),
        });
        try {
          authorize();
          return response;
        } catch (error) {
          void response.body?.cancel().catch(() => {});
          throw error;
        }
      };
      const transport = createRestrictedMcpHttpTransport({
        endpoint: this.#options.endpoint,
        fetch: protectedFetch,
        headers: { authorization: `Bearer ${accessToken}` },
        ...(this.#options.maxResponseBytes === undefined ? {} : { maxResponseBytes: this.#options.maxResponseBytes }),
      });
      const connection = await ManagedMcpConnection.connect({
        ...this.#options,
        // A late completion from a cancelled host fetch cannot replace a newer session's registry.
        guard: {
          registerTool: definition =>
            this.#generation === generation && !this.#closed && !controller.signal.aborted
              ? this.#options.guard.registerTool(definition)
              : 'inactive-credential-session',
          ...(typeof this.#options.guard.toolChanges === 'function'
            ? { toolChanges: (name: string) => this.#options.guard.toolChanges!(name) }
            : {}),
        },
        identity: { ...this.#options.identity, transportIdentity: `jwt-session:${randomUUID()}` },
        transport,
        authorize,
        protectedValues: [accessToken],
      });
      try {
        check();
        this.#connection = connection;
      } catch (error) {
        await connection.close();
        throw error;
      }
    };
    this.#pending = abortable(work(), controller.signal);
    try {
      await this.#pending;
    } catch {
      controller.abort();
      deny();
    } finally {
      clearTimeout(timer);
      this.#pending = undefined;
      this.#busy = false;
    }
  }
  /** Host revocation is terminal, invalidates before awaiting I/O, and cancels pending verification. */
  async revoke(): Promise<void> {
    await this.close();
  }
  async close(): Promise<void> {
    const closing = this.#connection?.close();
    this.#closed = true;
    this.#generation++;
    this.#sessionAbort?.abort();
    await Promise.all([closing, this.#pending?.catch(() => {})]);
  }

  async #verify(token: string, signal: AbortSignal): Promise<VerifiedMcpClaims> {
    if (
      typeof token !== 'string' ||
      token.length > 16_384 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
    )
      deny();
    const header = decodeProtectedHeader(token);
    if (
      Object.keys(header).some(key => !['alg', 'typ', 'kid'].includes(key)) ||
      !['at+jwt', 'application/at+jwt'].includes(header.typ ?? '') ||
      !this.#policy.algorithms!.includes(header.alg as 'RS256' | 'ES256') ||
      typeof header.kid !== 'string' ||
      !header.kid ||
      header.kid.length > 256
    )
      deny();
    const fetchKeys: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.href !== new URL(this.#policy.jwksUri).href || signal.aborted) deny();
      const response = await this.#options.fetch(url.href, {
        method: 'GET',
        redirect: 'error',
        headers: { accept: 'application/jwk-set+json, application/json' },
        signal: AbortSignal.any([signal, ...(init?.signal ? [init.signal] : [])]),
      });
      if (
        response.status !== 200 ||
        response.redirected ||
        (response.url && response.url !== url.href) ||
        !/^application\/(?:json|jwk-set\+json)(?:\s*;\s*charset=utf-8)?$/i.test(
          response.headers.get('content-type') ?? '',
        )
      ) {
        await response.body?.cancel();
        deny();
      }
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > this.#maxJwks)) {
        await response.body?.cancel();
        deny();
      }
      const reader = response.body?.getReader();
      if (!reader) deny();
      const chunks: Uint8Array[] = [];
      let size = 0;
      const cancel = (): void => {
        void reader.cancel().catch(() => {});
      };
      signal.addEventListener('abort', cancel, { once: true });
      try {
        for (;;) {
          if (signal.aborted) deny();
          const item = await reader.read();
          if (item.done) break;
          size += item.value.byteLength;
          if (size > this.#maxJwks) deny();
          chunks.push(item.value);
        }
        if (signal.aborted) deny();
        const keys = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!keys || !Array.isArray(keys.keys) || keys.keys.length < 1 || keys.keys.length > 32) deny();
        return new Response(Buffer.concat(chunks), { status: 200, headers: { 'content-type': 'application/json' } });
      } finally {
        signal.removeEventListener('abort', cancel);
        void reader.cancel().catch(() => {});
        reader.releaseLock();
      }
    };
    // Fresh verifier per credential replacement: no stale key cache silently retains removed keys.
    const keys = createRemoteJWKSet(new URL(this.#policy.jwksUri), {
      [customFetch]: fetchKeys,
      timeoutDuration: this.#timeout,
    });
    const { payload } = await jwtVerify(token, keys, {
      issuer: this.#policy.issuer,
      audience: this.#policy.audience,
      subject: this.#policy.subject,
      algorithms: [...this.#policy.algorithms!],
      typ: 'at+jwt',
      clockTolerance: 0,
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
    });
    const now = Date.now() / 1000;
    if (
      !Number.isSafeInteger(payload.exp) ||
      !Number.isSafeInteger(payload.iat) ||
      payload.iat! > now ||
      payload.exp! <= payload.iat! ||
      payload.exp! - payload.iat! > this.#lifetime ||
      typeof payload.jti !== 'string' ||
      !payload.jti ||
      payload.jti.length > 1024 ||
      typeof payload.client_id !== 'string' ||
      !payload.client_id ||
      payload.client_id.length > 1024 ||
      (payload.nbf !== undefined && !Number.isSafeInteger(payload.nbf)) ||
      (payload.scope !== undefined && (typeof payload.scope !== 'string' || payload.scope.length > 16_384))
    )
      deny();
    const scopes = payload.scope === undefined ? [] : (payload.scope as string).split(' ');
    if (scopes.some(scope => !scopePattern.test(scope)) || new Set(scopes).size !== scopes.length) deny();
    const claims = Object.freeze({
      issuer: payload.iss!,
      audience: typeof payload.aud === 'string' ? payload.aud : Object.freeze([...payload.aud!]),
      subject: payload.sub!,
      expiresAt: payload.exp!,
      scopes: Object.freeze(scopes),
      ...(payload.nbf === undefined ? {} : { notBefore: payload.nbf }),
    });
    assertVerifiedMcpClaims(claims, this.#policy, now);
    return claims;
  }
}
