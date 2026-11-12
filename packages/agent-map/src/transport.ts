import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { MapQueryError } from './types.js';
import { fail, integer } from './common.js';
import { fields, parseRequest } from './boundary.js';

// Request plumbing shared by the reference-credential server (http.ts) and the company
// sign-in server (identity-http.ts): the same headers, limits, error bodies and refusals.

const CODES = new Map([
  ['MAP_UNAUTHENTICATED', 401],
  ['MAP_REQUEST_DENIED', 403],
  ['MAP_NOT_FOUND', 404],
  ['MAP_REQUEST_INVALID', 400],
  ['MAP_SCOPE_INVALID', 403],
  ['MAP_LIMIT_EXCEEDED', 413],
  ['MAP_REQUEST_TOO_LARGE', 413],
  ['MAP_RESPONSE_TOO_LARGE', 413],
  ['MAP_TIMEOUT', 408],
  ['MAP_BUSY', 503],
  ['MAP_RATE_LIMITED', 429],
  ['MAP_UNAVAILABLE', 503],
  ['MAP_SESSION_REQUIRED', 401],
  ['MAP_IDENTITY_INVALID', 401],
  ['MAP_IDENTITY_UNAVAILABLE', 503],
]);
export function safeError(error: unknown): string {
  return error instanceof MapQueryError && CODES.has(error.code) ? error.code : 'MAP_UNAVAILABLE';
}
/** A refusal HTTP names more exactly than the code's usual status (an unmet `Expect` is 417). */
class StatusError extends MapQueryError {
  constructor(
    code: string,
    readonly status: number,
  ) {
    super(code);
  }
}
/** Answers a failed request with its safe code; nothing from the error itself is sent. */
export function respondError(response: ServerResponse, error: unknown): void {
  errorResponse(response, safeError(error), error instanceof StatusError ? error.status : undefined);
}
export function headers(response: ServerResponse, size: number, mime = 'application/json'): void {
  response.setHeader('Content-Type', mime);
  response.setHeader('Content-Length', size);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Connection', 'close');
  response.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  );
}
/** `status` overrides the code's usual status, for a refusal HTTP names more exactly (417). */
export function errorResponse(response: ServerResponse, code: string, status?: number): void {
  if (response.writableEnded || response.destroyed) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const body = Buffer.from(JSON.stringify({ error: code }));
  headers(response, body.length);
  if (code === 'MAP_UNAUTHENTICATED') response.setHeader('WWW-Authenticate', 'Bearer realm="agent-guard-reference"');
  response.writeHead(status ?? CODES.get(code) ?? 503);
  response.end(body);
}
export const count = (request: IncomingMessage, name: string): number =>
  request.rawHeaders.filter((entry, i) => i % 2 === 0 && entry.toLowerCase() === name).length;
export type Bucket = { since: number; count: number };
export function consume(bucket: Bucket, max: number, window: number): void {
  const now = performance.now();
  if (now - bucket.since >= window) {
    bucket.since = now;
    bucket.count = 0;
  }
  if (++bucket.count > max) fail('MAP_RATE_LIMITED');
}
export function readBody(request: IncomingMessage, max: number, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const cleanup = (): void => {
      request.off('data', data);
      request.off('end', end);
      request.off('error', aborted);
      request.off('aborted', aborted);
      signal.removeEventListener('abort', timeout);
    };
    const stop = (code: string): void => {
      cleanup();
      request.pause();
      reject(new MapQueryError(code));
    };
    const data = (chunk: Buffer): void => {
      size += chunk.length;
      if (size > max) {
        stop('MAP_REQUEST_TOO_LARGE');
        return;
      }
      chunks.push(chunk);
    };
    const end = (): void => {
      cleanup();
      resolve(Buffer.concat(chunks, size));
    };
    const aborted = (): void => stop('MAP_REQUEST_INVALID');
    const timeout = (): void => stop('MAP_TIMEOUT');
    if (signal.aborted) {
      timeout();
      return;
    }
    request.on('data', data);
    request.once('end', end);
    request.once('error', aborted);
    request.once('aborted', aborted);
    signal.addEventListener('abort', timeout, { once: true });
  });
}

/** Per-credential or per-session rate limit: `maxRequests` in each `windowMs`. */
export function rateLimit(value: unknown, defaultMaxRequests: number): { maxRequests: number; windowMs: number } {
  const rate = value === undefined ? {} : fields(value, ['maxRequests', 'windowMs'], ['maxRequests', 'windowMs']);
  return {
    maxRequests: integer(rate.maxRequests, defaultMaxRequests, 1, 10_000),
    windowMs: integer(rate.windowMs, 60_000, 10, 60_000),
  };
}
/**
 * The JSON body of an admitted POST. Call it only after the credential (or session and CSRF)
 * and rate checks have passed: it is what tells a client that sent `Expect: 100-continue` to go
 * on, and a refusal before it has already answered with its own status.
 */
export async function readJsonBody(
  request: IncomingMessage,
  response: ServerResponse,
  limit: number,
  signal: AbortSignal,
): Promise<unknown> {
  if (
    count(request, 'content-type') !== 1 ||
    !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '') ||
    count(request, 'content-length') > 1 ||
    count(request, 'transfer-encoding') > 1 ||
    request.headers['content-encoding'] !== undefined
  )
    fail('MAP_REQUEST_INVALID');
  const length = request.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length))))
    fail('MAP_REQUEST_INVALID');
  if (length !== undefined && Number(length) > limit) fail('MAP_REQUEST_TOO_LARGE');
  const expectation = request.headers.expect;
  if (expectation !== undefined) {
    // Only `100-continue` can be met; anything else, or anything added to it, is 417.
    if (expectation.trim().toLowerCase() !== '100-continue') throw new StatusError('MAP_REQUEST_INVALID', 417);
    // Interim responses exist only in HTTP/1.1. An HTTP/1.0 client that sends the expectation
    // is not waiting for one (RFC 9110, 10.1.1): its body is read without an invitation.
    if (request.httpVersionMajor === 1 && request.httpVersionMinor === 1) response.writeContinue();
  }
  return parseRequest(await readBody(request, limit, signal), limit);
}
/** The `{ operation, args }` envelope of `POST /v1/query`. */
export function queryEnvelope(parsed: unknown): { operation: unknown; args: unknown } {
  try {
    const envelope = fields(parsed, ['operation', 'args'], ['operation', 'args']);
    return { operation: envelope.operation, args: envelope.args };
  } catch {
    return fail('MAP_REQUEST_INVALID');
  }
}
/** A body that must be the empty object, as the sign-in and sign-out routes require. */
export function emptyObject(parsed: unknown): void {
  try {
    fields(parsed, [], []);
  } catch {
    fail('MAP_REQUEST_INVALID');
  }
}
/** Sends one fixed viewer asset. */
export function sendAsset(response: ServerResponse, asset: { body: Buffer; mime: string }): void {
  headers(response, asset.body.length, asset.mime);
  response.writeHead(200);
  response.end(asset.body);
}
/**
 * What neither server speaks: a request that arrives with `Expect: 100-continue` still goes
 * through the normal handler, any other expectation is 417, and tunnels, upgrades and
 * malformed requests are dropped.
 */
export function refuseOtherTraffic(
  server: Server,
  handle: (request: IncomingMessage, response: ServerResponse) => Promise<void>,
): void {
  server.on('checkContinue', (request, response) => {
    void handle(request, response);
  });
  server.on('checkExpectation', (_request, response) => errorResponse(response, 'MAP_REQUEST_INVALID', 417));
  server.on('connect', (_request, socket: Duplex) => socket.destroy());
  server.on('upgrade', (_request, socket: Duplex) => socket.destroy());
  server.on('clientError', (_error, socket: Duplex) => socket.destroy());
}
