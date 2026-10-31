import type { IncomingMessage, ServerResponse } from 'node:http';
import { MapQueryError } from './types.js';
import { fail } from './boundary.js';

const CODES = new Map([
  ['MAP_UNAUTHENTICATED', 401], ['MAP_REQUEST_DENIED', 403], ['MAP_NOT_FOUND', 404],
  ['MAP_REQUEST_INVALID', 400], ['MAP_ARGUMENT_INVALID', 400], ['MAP_OPERATION_INVALID', 400],
  ['MAP_SCOPE_INVALID', 403], ['MAP_LIMIT_EXCEEDED', 413], ['MAP_REQUEST_TOO_LARGE', 413],
  ['MAP_RESPONSE_TOO_LARGE', 413], ['MAP_TIMEOUT', 408], ['MAP_BUSY', 503],
  ['MAP_RATE_LIMITED', 429], ['MAP_UNAVAILABLE', 503],
  ['MAP_SESSION_REQUIRED', 401], ['MAP_IDENTITY_INVALID', 401], ['MAP_IDENTITY_UNAVAILABLE', 503],
]);
export function safeError(error: unknown): string {
  return error instanceof MapQueryError && CODES.has(error.code) ? error.code : 'MAP_UNAVAILABLE';
}
export function headers(response: ServerResponse, size: number, mime = 'application/json'): void {
  response.setHeader('Content-Type', mime); response.setHeader('Content-Length', size);
  response.setHeader('Cache-Control', 'no-store'); response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer'); response.setHeader('Connection', 'close');
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
}
export function errorResponse(response: ServerResponse, code: string): void {
  if (response.writableEnded || response.destroyed) return;
  if (response.headersSent) { response.destroy(); return; }
  const body = Buffer.from(JSON.stringify({ error: code })); headers(response, body.length);
  if (code === 'MAP_UNAUTHENTICATED') response.setHeader('WWW-Authenticate', 'Bearer realm="agent-guard-reference"');
  response.writeHead(CODES.get(code) ?? 503); response.end(body);
}
export const count = (request: IncomingMessage, name: string): number => request.rawHeaders.filter((entry, i) => i % 2 === 0 && entry.toLowerCase() === name).length;
export type Bucket = { since: number; count: number };
export function consume(bucket: Bucket, max: number, window: number): void {
  const now = performance.now();
  if (now - bucket.since >= window) { bucket.since = now; bucket.count = 0; }
  if (++bucket.count > max) fail('MAP_RATE_LIMITED');
}
export function readBody(request: IncomingMessage, max: number, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    const cleanup = (): void => { request.off('data', data); request.off('end', end); request.off('error', aborted); request.off('aborted', aborted); signal.removeEventListener('abort', timeout); };
    const stop = (code: string): void => { cleanup(); request.pause(); reject(new MapQueryError(code)); };
    const data = (chunk: Buffer): void => { size += chunk.length; if (size > max) { stop('MAP_REQUEST_TOO_LARGE'); return; } chunks.push(chunk); };
    const end = (): void => { cleanup(); resolve(Buffer.concat(chunks, size)); };
    const aborted = (): void => stop('MAP_REQUEST_INVALID');
    const timeout = (): void => stop('MAP_TIMEOUT');
    if (signal.aborted) { timeout(); return; }
    request.on('data', data); request.once('end', end); request.once('error', aborted); request.once('aborted', aborted);
    signal.addEventListener('abort', timeout, { once: true });
  });
}
