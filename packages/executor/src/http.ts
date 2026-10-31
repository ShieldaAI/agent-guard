import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { GuardError, immutableJson, type Json, type TaskOptions } from '@shieldaai/agent-guard';
import { DurableExecutor } from './executor.js';
import { ExecutorError } from './store.js';

export interface ExecutorServerOptions {
  executor: DurableExecutor;
  /** Independent random secret, at least 32 bytes encoded as base64url. Never pass into the workload. */
  adminToken: string;
  /** Authenticated operator identity fixed by the host, never supplied in approval arguments. */
  operatorId: string;
  port?: number;
  maxRequestBytes?: number;
  requestTimeoutMs?: number;
}
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
  if (request.headers['content-type']?.split(';')[0]?.trim() !== 'application/json') throw new ExecutorError('REQUEST_INVALID');
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk); size += bytes.length;
    if (size > limit) throw new ExecutorError('REQUEST_TOO_LARGE');
    chunks.push(bytes);
  }
  try { return object(immutableJson(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))))); }
  catch { throw new ExecutorError('REQUEST_INVALID'); }
}

/** Local reference service. Use an isolated, authenticated transport bridge for a remote workload. */
export async function startExecutorServer(options: ExecutorServerOptions): Promise<{ server: Server; url: string; close(): Promise<void> }> {
  if (!/^[A-Za-z0-9_-]{43,256}$/.test(options.adminToken) || !options.operatorId?.trim()) throw new ExecutorError('SERVER_CONFIG_INVALID');
  const adminHash = digest(options.adminToken);
  const limit = options.maxRequestBytes ?? 256 * 1024;
  const timeout = options.requestTimeoutMs ?? 10_000;
  if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(timeout) || timeout < 1) throw new ExecutorError('SERVER_CONFIG_INVALID');
  const executor = options.executor;
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: timeout, headersTimeout: timeout }, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    try {
      if (req.headers.origin !== undefined || req.headers['sec-fetch-site'] !== undefined || req.method !== 'POST') throw new ExecutorError('REQUEST_DENIED');
      if (!req.url || !/^\/v1\/(?:task|admin)\/[a-z-]+$/.test(req.url)) throw new ExecutorError('REQUEST_DENIED');
      const auth = req.headers.authorization;
      if (!auth?.startsWith('Bearer ') || auth.length > 270 || req.rawHeaders.filter(value => value.toLowerCase() === 'authorization').length !== 1) throw new ExecutorError('UNAUTHENTICATED');
      const token = auth.slice(7);
      const admin = req.url.startsWith('/v1/admin/');
      const taskId = admin ? undefined : executor.authenticate(token);
      if (admin && !timingSafeEqual(digest(token), adminHash)) throw new ExecutorError('UNAUTHENTICATED');
      const timer = setTimeout(() => req.destroy(), timeout); timer.unref();
      let input: Record<string, Json>;
      try { input = await body(req, limit); } finally { clearTimeout(timer); }
      let output: unknown;
      switch (req.url) {
        case '/v1/task/prepare': keys(input, ['tool', 'args']);
          if (!Object.hasOwn(input, 'args')) throw new ExecutorError('REQUEST_INVALID');
          output = await executor.prepare(taskId!, { tool: string(input.tool), args: input.args! }); break;
        case '/v1/task/execute': keys(input, ['actionId', 'approvalId']);
          output = { value: await executor.execute(taskId!, string(input.actionId), input.approvalId === undefined ? {} : { approvalId: string(input.approvalId) }) }; break;
        case '/v1/task/snapshot': keys(input, []); output = executor.snapshot(taskId!); break;
        case '/v1/task/cancel': keys(input, ['actionId']); executor.cancel(taskId!, string(input.actionId)); output = { cancellationRequested: true }; break;
        case '/v1/task/execution': keys(input, ['actionId']); output = executor.execution(taskId!, string(input.actionId)); break;
        case '/v1/task/delegate': keys(input, ['options']); {
          const child = object(input.options); keys(child, ['id', 'grants', 'budget', 'allowedRecipients', 'allowControlPlane']);
          output = executor.delegateTask(taskId!, child as unknown as Omit<TaskOptions, 'principalId' | 'tenantId'>); break;
        }
        case '/v1/admin/create-task': keys(input, ['options', 'provenance']);
          if (input.provenance !== undefined) keys(object(input.provenance), ['sensitive', 'sourceTaskId']);
          output = executor.createTask(object(input.options) as unknown as TaskOptions, input.provenance as { sensitive?: boolean; sourceTaskId?: string } | undefined); break;
        case '/v1/admin/approve': keys(input, ['actionId', 'expiresAt']);
          output = { approvalId: executor.approve(string(input.actionId), { approverId: options.operatorId, expiresAt: input.expiresAt as number }) }; break;
        case '/v1/admin/revoke': keys(input, ['taskId']); executor.revokeTask(string(input.taskId)); output = { revoked: true }; break;
        case '/v1/admin/reconcile': keys(input, ['actionId', 'outcome', 'actualCost', 'reference']);
          if (input.outcome !== 'SUCCEEDED' && input.outcome !== 'FAILED') throw new ExecutorError('REQUEST_INVALID');
          executor.reconcile(string(input.actionId), { outcome: input.outcome, actualCost: input.actualCost as number, reference: string(input.reference) }); output = { reconciled: true }; break;
        case '/v1/admin/audit': keys(input, []); output = executor.audit(); break;
        default: throw new ExecutorError('REQUEST_DENIED');
      }
      res.writeHead(200); res.end(JSON.stringify(output));
    } catch (error) {
      const code = error instanceof GuardError || error instanceof ExecutorError ? error.code : 'REQUEST_INVALID';
      res.writeHead(code === 'UNAUTHENTICATED' ? 401 : 400); res.end(JSON.stringify({ error: code }));
    }
  });
  server.on('upgrade', (_request, socket) => { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(options.port ?? 0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new ExecutorError('SERVER_CONFIG_INVALID');
  return { server, url: `http://127.0.0.1:${address.port}`, close: () => new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve()); server.closeIdleConnections();
  }) };
}
