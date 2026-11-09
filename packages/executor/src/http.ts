import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { type Json, type TaskOptions } from '@shieldaai/agent-guard';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { DurableExecutor } from './executor.js';
import { ExecutorError } from './store.js';
import { executorErrorResponse, executorResponseRetryable, executorResponseStatus } from './response-code.js';

export interface ExecutorServerOptions {
  executor: DurableExecutor;
  /** Independent random secret, at least 32 bytes encoded as base64url. Never pass into the workload. */
  adminToken: string;
  /** Authenticated operator identity fixed by the host, never supplied in approval arguments. */
  operatorId: string;
  port?: number;
  maxRequestBytes?: number;
  requestTimeoutMs?: number;
  /** Open TCP connections. Integer 1-4096, default 64. */
  maxConnections?: number;
  /** Requests being handled at once; more get REQUEST_RATE_LIMITED. Integer 1-1024, default 32. */
  maxActiveRequests?: number;
  /** Requests per minute per bearer credential (valid or not). Integer 1-1,000,000, default 600. */
  requestsPerMinutePerCredential?: number;
  /** Requests per minute across the server. Integer 1-1,000,000, default 6,000. */
  requestsPerMinute?: number;
}
const WINDOW_MS = 60_000;
const MAX_TRACKED_CREDENTIALS = 4096;
function object(value: unknown): Record<string, Json> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ExecutorError('REQUEST_INVALID');
  return value as Record<string, Json>;
}
function keys(value: Record<string, Json>, allowed: string[]): void {
  if (Object.keys(value).some(key => !allowed.includes(key))) throw new ExecutorError('REQUEST_INVALID');
}
function string(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > 4096) throw new ExecutorError('REQUEST_INVALID');
  return value;
}
const digest = (token: string): Buffer => createHash('sha256').update(token).digest();
async function body(request: IncomingMessage, limit: number): Promise<Record<string, Json>> {
  if (request.headers['content-type']?.split(';')[0]?.trim() !== 'application/json')
    throw new ExecutorError('REQUEST_INVALID');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > limit) throw new ExecutorError('REQUEST_TOO_LARGE');
    chunks.push(bytes);
  }
  try {
    return object(immutableJson(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))));
  } catch {
    throw new ExecutorError('REQUEST_INVALID');
  }
}

/** Local reference service. Use an isolated, authenticated transport bridge for a remote workload. */
export async function startExecutorServer(
  options: ExecutorServerOptions,
): Promise<{ server: Server; url: string; close(): Promise<void> }> {
  if (!/^[A-Za-z0-9_-]{43,256}$/.test(options.adminToken) || !options.operatorId?.trim())
    throw new ExecutorError('SERVER_CONFIG_INVALID');
  const adminHash = digest(options.adminToken);
  const operatorId = options.operatorId;
  const limit = options.maxRequestBytes ?? 256 * 1024;
  const timeout = options.requestTimeoutMs ?? 10_000;
  if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(timeout) || timeout < 1)
    throw new ExecutorError('SERVER_CONFIG_INVALID');
  const bounded = (value: number | undefined, fallback: number, max: number): number => {
    const selected = value ?? fallback;
    if (!Number.isSafeInteger(selected) || selected < 1 || selected > max)
      throw new ExecutorError('SERVER_CONFIG_INVALID');
    return selected;
  };
  const maxConnections = bounded(options.maxConnections, 64, 4096);
  const maxActive = bounded(options.maxActiveRequests, 32, 1024);
  const perCredential = bounded(options.requestsPerMinutePerCredential, 600, 1_000_000);
  const perServer = bounded(options.requestsPerMinute, 6000, 1_000_000);
  // Fixed one-minute windows. A full credential table drops its oldest window rather than refusing everyone.
  const windows = new Map<string, { started: number; count: number }>();
  let global = { started: performance.now(), count: 0 };
  let active = 0;
  const admit = (credential: Buffer): void => {
    const now = performance.now();
    if (now - global.started >= WINDOW_MS) global = { started: now, count: 0 };
    if (++global.count > perServer) throw new ExecutorError('REQUEST_RATE_LIMITED');
    const key = credential.toString('hex');
    let window = windows.get(key);
    if (!window || now - window.started >= WINDOW_MS) {
      windows.delete(key);
      if (windows.size >= MAX_TRACKED_CREDENTIALS) windows.delete(windows.keys().next().value!);
      windows.set(key, (window = { started: now, count: 0 }));
    }
    if (++window.count > perCredential) throw new ExecutorError('REQUEST_RATE_LIMITED');
  };
  const executor = options.executor;
  const server = createServer(
    { maxHeaderSize: 8192, requestTimeout: timeout, headersTimeout: timeout },
    async (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      let counted = false;
      try {
        if (active >= maxActive) throw new ExecutorError('REQUEST_RATE_LIMITED');
        active++;
        counted = true;
        if (req.headers.origin !== undefined || req.headers['sec-fetch-site'] !== undefined || req.method !== 'POST')
          throw new ExecutorError('REQUEST_DENIED');
        const route = req.url;
        if (!route || !/^\/v1\/(?:task|admin)\/[a-z-]+$/.test(route)) throw new ExecutorError('REQUEST_DENIED');
        const auth = req.headers.authorization;
        if (!auth?.startsWith('Bearer ') || auth.length > 270 || req.headersDistinct.authorization?.length !== 1)
          throw new ExecutorError('UNAUTHENTICATED');
        const token = auth.slice(7);
        admit(digest(token));
        const admin = route.startsWith('/v1/admin/');
        const taskId = admin ? undefined : executor.authenticate(token);
        if (admin && !timingSafeEqual(digest(token), adminHash)) throw new ExecutorError('UNAUTHENTICATED');
        let bodyTimedOut = false;
        const bodyDeadline = performance.now() + timeout;
        const timer = setTimeout(() => {
          bodyTimedOut = true;
          req.destroy();
        }, timeout);
        timer.unref();
        let input: Record<string, Json>;
        try {
          input = await body(req, limit);
          if (route === '/v1/task/prepare' || route === '/v1/task/execute') {
            // Give pending I/O a scheduling opportunity before another synchronous
            // ledger chain. No authority state or reservation crosses this yield.
            // Keep the original body timer running: this is not a timeout reset.
            await yieldToEventLoop();
            if (bodyTimedOut || performance.now() >= bodyDeadline) throw new ExecutorError('REQUEST_TIMEOUT');
            // A normally consumed IncomingMessage can be destroyed; that alone
            // does not mean the peer disconnected. Inspect the live transport.
            if (req.aborted || res.destroyed || req.socket.destroyed) return;
          }
        } finally {
          clearTimeout(timer);
        }
        // The bearer (or a provenance ancestor) can expire or be revoked while the body arrives.
        if (!admin && executor.authenticate(token) !== taskId) throw new ExecutorError('UNAUTHENTICATED');
        let output: unknown;
        switch (route) {
          case '/v1/task/prepare':
            keys(input, ['tool', 'args']);
            if (!Object.hasOwn(input, 'args')) throw new ExecutorError('REQUEST_INVALID');
            output = await executor.prepare(taskId!, { tool: string(input.tool), args: input.args! });
            break;
          case '/v1/task/execute':
            keys(input, ['actionId', 'approvalId']);
            output = {
              value: await executor.execute(
                taskId!,
                string(input.actionId),
                input.approvalId === undefined ? {} : { approvalId: string(input.approvalId) },
              ),
            };
            break;
          case '/v1/task/snapshot':
            keys(input, []);
            output = executor.snapshot(taskId!);
            break;
          case '/v1/task/cancel':
            keys(input, ['actionId']);
            executor.cancel(taskId!, string(input.actionId));
            output = { cancellationRequested: true };
            break;
          case '/v1/task/execution':
            keys(input, ['actionId']);
            output = executor.execution(taskId!, string(input.actionId));
            break;
          case '/v1/task/delegate':
            keys(input, ['options']);
            {
              const child = object(input.options);
              keys(child, ['id', 'grants', 'budget', 'allowedRecipients', 'allowControlPlane']);
              output = executor.delegateTask(
                taskId!,
                child as unknown as Omit<TaskOptions, 'principalId' | 'tenantId'>,
              );
              break;
            }
          case '/v1/admin/create-task':
            keys(input, ['options', 'provenance']);
            if (input.provenance !== undefined) keys(object(input.provenance), ['sensitive', 'sourceTaskId']);
            output = executor.createTask(
              object(input.options) as unknown as TaskOptions,
              input.provenance as { sensitive?: boolean; sourceTaskId?: string } | undefined,
            );
            break;
          case '/v1/admin/approve':
            keys(input, ['actionId', 'expiresAt']);
            output = {
              approvalId: executor.approve(string(input.actionId), {
                approverId: operatorId,
                expiresAt: input.expiresAt as number,
              }),
            };
            break;
          case '/v1/admin/revoke':
            keys(input, ['taskId']);
            executor.revokeTask(string(input.taskId));
            output = { revoked: true };
            break;
          case '/v1/admin/reconcile':
            keys(input, ['actionId', 'outcome', 'actualCost', 'reference']);
            if (input.outcome !== 'SUCCEEDED' && input.outcome !== 'FAILED') throw new ExecutorError('REQUEST_INVALID');
            executor.reconcile(string(input.actionId), {
              outcome: input.outcome,
              actualCost: input.actualCost as number,
              reference: string(input.reference),
            });
            output = { reconciled: true };
            break;
          case '/v1/admin/audit':
            keys(input, []);
            output = executor.audit();
            break;
          default:
            throw new ExecutorError('REQUEST_DENIED');
        }
        res.writeHead(200);
        res.end(JSON.stringify(output));
      } catch (error) {
        const code = executorErrorResponse(error);
        res.writeHead(executorResponseStatus(code));
        res.end(JSON.stringify({ error: code, retryable: executorResponseRetryable(code) }));
      } finally {
        if (counted) active--;
      }
    },
  );
  server.maxConnections = maxConnections;
  server.on('upgrade', (_request, socket) => {
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new ExecutorError('SERVER_CONFIG_INVALID');
  return {
    server,
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(error => (error ? reject(error) : resolve()));
        server.closeIdleConnections();
      }),
  };
}
