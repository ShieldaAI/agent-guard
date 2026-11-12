// Transport to the service: one bounded, same-origin JSON request at a time per call.
import { ERROR_MESSAGES, GENERIC_ERROR_MESSAGE } from './contract.js';

const RESPONSE_LIMIT = 1_048_576;
const TIMEOUT_MS = 12_000;

export class ApiError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}
/** The request belonged to a session that has ended since; its answer must be ignored. */
export class SessionEnded extends Error {
  constructor() {
    super('SESSION_ENDED');
  }
}

/** A refusal as the service worded it. The shared table is the fallback, not a second wording. */
export function failure(body) {
  const code = body?.error?.code;
  if (typeof code !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(code)) return new ApiError(GENERIC_ERROR_MESSAGE);
  const served = body.error.message;
  return new ApiError(
    typeof served === 'string' && served ? served.slice(0, 400) : (ERROR_MESSAGES[code] ?? GENERIC_ERROR_MESSAGE),
    code,
  );
}

export async function readJson(response) {
  if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json'))
    throw new ApiError('The service sent an unexpected response. Check the connection and refresh.');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > RESPONSE_LIMIT))
    throw new ApiError('The service response was too large to show.');
  const reader = response.body?.getReader();
  if (!reader) throw new ApiError('The service returned an empty response.');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > RESPONSE_LIMIT) throw new ApiError('The service response was too large to show.');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new ApiError('The service response could not be read. Refresh to check the current state.');
  }
}

/**
 * `epoch()` identifies the current session; a response that arrives after it changed is dropped.
 * `onUnauthorized(message)` is told when the service says the session ended or lacks the role.
 */
export function createApi({ epoch, csrfToken, signedIn, onUnauthorized, fetch = globalThis.fetch }) {
  const pending = new Set();
  async function send(path, { method = 'GET', body, token = csrfToken(), etag } = {}) {
    const started = epoch();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    pending.add(controller);
    try {
      const headers = { Accept: 'application/json' };
      if (etag) headers['If-None-Match'] = etag;
      if (method !== 'GET') {
        if (typeof token !== 'string' || !token) throw new ApiError('Check your session before continuing.');
        headers['Content-Type'] = 'application/json';
        headers['X-CSRF-Token'] = token;
      }
      const response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      if (started !== epoch()) throw new SessionEnded();
      if (response.status === 304 && etag) return { notModified: true, etag };
      if (response.status === 401 || response.status === 403) {
        // A 403 for an out-of-date page (CSRF_INVALID) is not a role problem; say what the service said.
        let stale;
        if (response.status === 403) {
          const refused = await readJson(response).catch(() => null);
          if (started !== epoch()) throw new SessionEnded();
          if (refused?.error?.code === 'CSRF_INVALID') stale = failure(refused);
        }
        // Before sign-in there is no workspace to end: the caller renews the pre-login cookie.
        if (stale && !signedIn()) throw stale;
        onUnauthorized(
          stale
            ? stale.message
            : response.status === 403
              ? 'Your account is not allowed to do that. Sign in again to continue.'
              : 'Your session ended. Sign in again to continue.',
        );
        throw new SessionEnded();
      }
      const result = await readJson(response);
      if (started !== epoch() || controller.signal.aborted) throw new SessionEnded();
      if (!response.ok) throw failure(result);
      return { body: result, etag: response.headers.get('etag') };
    } catch (error) {
      if (started !== epoch() || error instanceof SessionEnded) throw new SessionEnded();
      if (error?.name === 'AbortError')
        throw new ApiError('The request timed out. Refresh to check the current state before doing anything else.');
      if (error instanceof TypeError)
        throw new ApiError('The service is unavailable. Refresh to check the current state.');
      throw error;
    } finally {
      clearTimeout(timer);
      pending.delete(controller);
    }
  }
  return {
    /** The response body of a successful request. */
    async request(path, options) {
      return (await send(path, options)).body;
    },
    /** A conditional GET: `{ notModified }` or `{ body, etag }`. */
    conditional: (path, etag) => send(path, { etag }),
    abortAll() {
      for (const controller of pending) controller.abort();
      pending.clear();
    },
  };
}
