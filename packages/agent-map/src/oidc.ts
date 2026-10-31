import { request as httpsRequest } from 'node:https';
import type { ClientRequest } from 'node:http';
import { lookup } from 'node:dns';
import { X509Certificate } from 'node:crypto';
import { rootCertificates, createSecureContext } from 'node:tls';
import type { LookupFunction } from 'node:net';
import { immutableJson } from '@shieldaai/agent-guard';
import * as oidc from 'openid-client';
import { fields, integer, fail, parseRequest } from './boundary.js';
import { MapQueryError, mapIdentifier } from './types.js';

export interface MapOidcOptions {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly clientAuthMethod?: 'client_secret_basic' | 'client_secret_post';
  readonly endpointOrigins?: readonly string[];
  readonly ca?: string;
  readonly requestTimeoutMs?: number;
  readonly maxResponseBytes?: number;
}
export interface MapOidcTransaction { readonly state: string; readonly nonce: string; readonly codeVerifier: string }
export interface MapOidcClient {
  begin(): Promise<MapOidcTransaction & { readonly authorizationUrl: string }>;
  complete(callbackUrl: URL, transaction: MapOidcTransaction, signal?: AbortSignal): Promise<{ readonly subject: string; readonly expiresAt: number }>;
}
const INVALID = 'MAP_IDENTITY_INVALID', UNAVAILABLE = 'MAP_IDENTITY_UNAVAILABLE';
function httpsUrl(value: unknown, code: string, query = false): URL {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) fail(code);
  let url: URL; try { url = new URL(value); } catch { return fail(code); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || (!query && url.search)) fail(code);
  return url;
}
function opaque(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(value)) fail(INVALID);
  return value;
}

/** Confidential OIDC client: provider tokens never leave this module. */
export async function createMapOidcClient(options: MapOidcOptions): Promise<MapOidcClient> {
  let copied: unknown;
  try { copied = immutableJson(options, 4, 128, 512 * 1024); } catch { return fail('MAP_CONFIG_INVALID'); }
  const config = fields(copied, ['issuer', 'clientId', 'clientSecret', 'redirectUri', 'clientAuthMethod',
    'endpointOrigins', 'ca', 'requestTimeoutMs', 'maxResponseBytes'], ['issuer', 'clientId', 'clientSecret', 'redirectUri']);
  const issuer = httpsUrl(config.issuer, 'MAP_CONFIG_INVALID');
  if (issuer.pathname.includes('/.well-known/')) fail('MAP_CONFIG_INVALID');
  const redirect = httpsUrl(config.redirectUri, 'MAP_CONFIG_INVALID');
  if (redirect.pathname !== '/auth/callback') fail('MAP_CONFIG_INVALID');
  const clientId = mapIdentifier(config.clientId, 'MAP_CONFIG_INVALID');
  const secret = mapIdentifier(config.clientSecret, 'MAP_CONFIG_INVALID');
  if (clientId.length > 512 || secret.length > 4096) fail('MAP_CONFIG_INVALID');
  const method = config.clientAuthMethod ?? 'client_secret_basic';
  if (method !== 'client_secret_basic' && method !== 'client_secret_post') fail('MAP_CONFIG_INVALID');
  const authentication = () => method === 'client_secret_basic' ? oidc.ClientSecretBasic(secret) : oidc.ClientSecretPost(secret);
  const timeout = integer(config.requestTimeoutMs, 5000, 50, 10_000);
  const maxBytes = integer(config.maxResponseBytes, 256 * 1024, 1024, 1024 * 1024);
  const origins = new Set([issuer.origin]);
  if (config.endpointOrigins !== undefined) {
    if (!Array.isArray(config.endpointOrigins) || config.endpointOrigins.length > 8) fail('MAP_CONFIG_INVALID');
    for (const entry of config.endpointOrigins) {
      const url = httpsUrl(entry, 'MAP_CONFIG_INVALID');
      if (entry !== url.origin || origins.has(url.origin)) fail('MAP_CONFIG_INVALID');
      origins.add(url.origin);
    }
  }
  let ca: string[] | undefined;
  if (config.ca !== undefined) {
    if (typeof config.ca !== 'string' || !config.ca || Buffer.byteLength(config.ca) > 256 * 1024) fail('MAP_CONFIG_INVALID');
    const certificates = config.ca.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if (!certificates?.length || certificates.length > 16 || config.ca.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g, '').trim()) fail('MAP_CONFIG_INVALID');
    try { for (const certificate of certificates) new X509Certificate(certificate); } catch { fail('MAP_CONFIG_INVALID'); }
    ca = [...rootCertificates, config.ca];
    try { createSecureContext({ ca, minVersion: 'TLSv1.2' }); } catch { fail('MAP_CONFIG_INVALID'); }
  }
  let requests = 0, pendingLookups = 0;
  function operation(external?: AbortSignal) {
    const deadline = performance.now() + timeout, active = new Set<ClientRequest>();
    let closed = false, failure: MapQueryError | undefined;
    const check = (): void => { if (closed || external?.aborted || performance.now() >= deadline) fail(UNAVAILABLE); };
    const fetch: oidc.CustomFetch = (input, init) => new Promise<Response>((resolve, reject) => {
      let request: ClientRequest | undefined, settled = false, counted = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const abort = (): void => stop(UNAVAILABLE);
      const clean = (): void => {
        if (timer) clearTimeout(timer);
        external?.removeEventListener('abort', abort); init.signal?.removeEventListener('abort', abort);
        if (request) active.delete(request); if (counted) requests--;
      };
      const stop = (code: string): void => {
        if (settled) return; settled = true;
        failure = new MapQueryError(code); clean(); request?.destroy(); reject(failure);
      };
      try {
        check(); if (init.signal?.aborted) fail(UNAVAILABLE);
        const url = httpsUrl(input, INVALID, true);
        if (!origins.has(url.origin)) fail(INVALID);
        if (!['GET', 'POST'].includes(init.method) || requests >= 8) fail(UNAVAILABLE);
        let body: string | undefined;
        if (init.body !== undefined && init.body !== null) {
          if (typeof init.body === 'string' || init.body instanceof URLSearchParams) body = init.body.toString();
          else fail(INVALID);
          if (init.method !== 'POST' || Buffer.byteLength(body) > 65_536) fail(INVALID);
        }
        requests++; counted = true;
        const boundedLookup: LookupFunction = (hostname, lookupOptions, callback) => {
          if (closed || external?.aborted || performance.now() >= deadline || pendingLookups >= 8) {
            callback(new Error('OIDC_LOOKUP_UNAVAILABLE'), lookupOptions.all ? [] : ''); return;
          }
          pendingLookups++;
          lookup(hostname, { ...lookupOptions, all: true }, (error, addresses) => {
            pendingLookups--;
            // A late DNS completion must never reconnect or dispatch credentials.
            if (closed || settled || external?.aborted || performance.now() >= deadline) {
              callback(new Error('OIDC_LOOKUP_UNAVAILABLE'), lookupOptions.all ? [] : ''); return;
            }
            if (lookupOptions.all) callback(error, addresses);
            else callback(error, addresses?.[0]?.address ?? '', addresses?.[0]?.family);
          });
        };
        request = httpsRequest(url, { method: init.method, headers: { ...init.headers, 'accept-encoding': 'identity', connection: 'close' },
          agent: false, rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 8192,
          lookup: boundedLookup, ...(ca === undefined ? {} : { ca }) }, response => {
          const status = response.statusCode ?? 0;
          const count = (name: string): number => response.rawHeaders.filter((item, index) => index % 2 === 0 && item.toLowerCase() === name).length;
          const length = response.headers['content-length'];
          if ((status >= 300 && status < 400) || status >= 500 || status < 200 ||
              count('content-length') > 1 || count('content-type') !== 1 || count('transfer-encoding') > 1 ||
              response.headers['content-encoding'] !== undefined || (length !== undefined && response.headers['transfer-encoding'] !== undefined) ||
              !/^application\/(?:json|jwk-set\+json)(?:\s*;\s*charset=utf-8)?$/i.test(response.headers['content-type'] ?? '') ||
              (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > maxBytes))) {
            response.destroy(); stop(UNAVAILABLE); return;
          }
          const chunks: Buffer[] = []; let size = 0;
          response.on('data', (chunk: Buffer) => { size += chunk.length;
            if (size > maxBytes || performance.now() >= deadline) { response.destroy(); stop(UNAVAILABLE); }
            else chunks.push(chunk);
          });
          response.once('aborted', () => stop(UNAVAILABLE)); response.once('error', () => stop(UNAVAILABLE));
          response.once('end', () => {
            if (settled) return;
            try {
              check(); if (!response.complete || (length !== undefined && Number(length) !== size)) fail(UNAVAILABLE);
              // Reject ambiguous or malformed JSON before the protocol library consumes it.
              const bytes = Buffer.concat(chunks, size);
              parseRequest(bytes, maxBytes);
              const headers = new Headers();
              for (let index = 0; index < response.rawHeaders.length; index += 2) headers.append(response.rawHeaders[index]!, response.rawHeaders[index + 1]!);
              const result = new Response(new Uint8Array(bytes), { status, headers });
              settled = true; clean(); resolve(result);
            } catch { stop(UNAVAILABLE); }
          });
        });
        active.add(request); request.once('error', () => stop(UNAVAILABLE));
        timer = setTimeout(abort, Math.max(1, deadline - performance.now())); timer.unref();
        external?.addEventListener('abort', abort, { once: true }); init.signal?.addEventListener('abort', abort, { once: true });
        if (external?.aborted || init.signal?.aborted) { stop(UNAVAILABLE); return; }
        request.end(body);
      } catch (error) { stop(error instanceof MapQueryError ? error.code : UNAVAILABLE); }
    });
    return { fetch, check, get failure() { return failure; }, close() { closed = true; for (const request of active) request.destroy(); } };
  }
  const clientMetadata = { id_token_signed_response_alg: 'RS256', [oidc.clockTolerance]: 0 };
  const discovery = operation();
  let metadata: oidc.ServerMetadata;
  try {
    const discovered = await oidc.discovery(issuer, clientId, clientMetadata, authentication(),
      { [oidc.customFetch]: discovery.fetch, timeout: timeout / 1000 });
    discovery.check();
    const remote = discovered.serverMetadata();
    if (remote.issuer !== config.issuer || !Array.isArray(remote.id_token_signing_alg_values_supported) ||
        !remote.id_token_signing_alg_values_supported.includes('RS256') ||
        !Array.isArray(remote.code_challenge_methods_supported) || !remote.code_challenge_methods_supported.includes('S256') ||
        (remote.token_endpoint_auth_methods_supported === undefined ? method !== 'client_secret_basic' :
          !Array.isArray(remote.token_endpoint_auth_methods_supported) || !remote.token_endpoint_auth_methods_supported.includes(method))) fail(INVALID);
    for (const name of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
      if (!origins.has(httpsUrl(remote[name], INVALID).origin)) fail(INVALID);
    }
    metadata = { issuer: remote.issuer, authorization_endpoint: remote.authorization_endpoint!,
      token_endpoint: remote.token_endpoint!, jwks_uri: remote.jwks_uri!, id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: [method],
      authorization_response_iss_parameter_supported: remote.authorization_response_iss_parameter_supported === true };
  } catch (error) { throw discovery.failure ?? new MapQueryError(error instanceof MapQueryError ? error.code : INVALID); }
  finally { discovery.close(); }
  const configuration = (fetch: oidc.CustomFetch): oidc.Configuration => {
    const client = new oidc.Configuration(metadata, clientId, clientMetadata, authentication());
    client[oidc.customFetch] = fetch; client.timeout = timeout / 1000; oidc.enableNonRepudiationChecks(client); return client;
  };
  return Object.freeze({
    async begin() {
      const op = operation();
      try {
        const state = oidc.randomState(), nonce = oidc.randomNonce(), codeVerifier = oidc.randomPKCECodeVerifier();
        const authorizationUrl = oidc.buildAuthorizationUrl(configuration(op.fetch), { response_type: 'code', scope: 'openid',
          redirect_uri: redirect.href, state, nonce, code_challenge_method: 'S256', code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier) });
        op.check(); return Object.freeze({ authorizationUrl: authorizationUrl.href, state, nonce, codeVerifier });
      } catch { throw new MapQueryError(UNAVAILABLE); } finally { op.close(); }
    },
    async complete(callbackUrl: URL, transaction: MapOidcTransaction, signal?: AbortSignal) {
      const op = operation(signal);
      try {
        op.check();
        if (!(callbackUrl instanceof URL) || callbackUrl.href.length > 8192 || callbackUrl.origin !== redirect.origin ||
            callbackUrl.pathname !== redirect.pathname || callbackUrl.hash || callbackUrl.username || callbackUrl.password) fail(INVALID);
        const callback = new URL(callbackUrl.href), names = [...callback.searchParams.keys()];
        if (names.length > 16 || new Set(names).size !== names.length || names.some(name => !name || name.length > 128) ||
            callback.searchParams.get('error') !== null || callback.searchParams.get('response') !== null ||
            !callback.searchParams.get('code') || !callback.searchParams.get('state')) fail(INVALID);
        const value = fields(transaction, ['state', 'nonce', 'codeVerifier'], ['state', 'nonce', 'codeVerifier']);
        const state = opaque(value.state), nonce = opaque(value.nonce), verifier = opaque(value.codeVerifier);
        const tokens = await oidc.authorizationCodeGrant(configuration(op.fetch), callback,
          { expectedState: state, expectedNonce: nonce, pkceCodeVerifier: verifier, idTokenExpected: true });
        op.check(); const claims = tokens.claims(), now = Date.now();
        if (!claims || claims.iss !== config.issuer || (claims.azp !== undefined && claims.azp !== clientId) ||
            !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) || claims.iat > Math.floor(now / 1000) ||
            claims.exp <= claims.iat || !Number.isSafeInteger(claims.exp * 1000) || claims.exp * 1000 <= now) fail(INVALID);
        const subject = mapIdentifier(claims.sub, INVALID);
        return Object.freeze({ subject, expiresAt: claims.exp * 1000 });
      } catch (error) { throw op.failure ?? new MapQueryError(error instanceof MapQueryError && error.code === UNAVAILABLE ? UNAVAILABLE : INVALID); }
      finally { op.close(); }
    },
  });
}
