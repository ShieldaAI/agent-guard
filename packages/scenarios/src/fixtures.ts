import {
  AgentGuard,
  isGuardError,
  type GuardError,
  type Budget,
  type Capability,
  type GuardOptions,
  type Json,
  type PreparedAction,
  type TaskHandle,
  type TaskOptions,
  type ToolDefinition,
} from '@shieldaai/agent-guard';
import type { ConformanceCaseResult, ConformanceGuardFactory } from './types.js';

/** Shared synthetic fixtures for the scenario cases: in-memory tools, a ledger of effects and the check recorder. */
export class CheckFailure extends Error {}
export type Variant = ConformanceCaseResult['variant'];
export type Case = (checks: Checks) => Promise<void>;
export type Pair = Readonly<Record<Variant, Case>>;
export type Fields = { readonly [key: string]: Json };

export const GUIDE = 'alpha/docs/guide';
export const PAYROLL = 'alpha/docs/payroll';
export const BETA = 'beta/docs/private';
export const RECORD_A = 'alpha/records/a';
export const RECORD_B = 'alpha/records/b';
export const RECIPIENT = 'reviewer@example.test';
export const OTHER_RECIPIENT = 'outsider@example.test';
export const SECRET = 'fixture-secret-9c1e';
export const CANARY = 'fixture-canary-7f2b';

export function fields(value: Json): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Fixture requires object arguments');
  return value as Fields;
}

export function stringField(value: Json, key: string): string {
  const result = fields(value)[key];
  if (typeof result !== 'string') throw new Error('Fixture requires a string field');
  return result;
}

export function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>(done => {
    resolve = done;
  });
  return { promise, resolve };
}

export async function bounded<T>(promise: Promise<T>, label: string, timeoutMs = 1500): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new CheckFailure(label)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function safeCode(error: GuardError): string {
  return typeof error.code === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(error.code) ? error.code : 'INVALID_ERROR_CODE';
}

export class Checks {
  assertions = 0;
  handlerInvocations = 0;
  denialCodes: string[] = [];

  constructor(readonly createGuard: ConformanceGuardFactory = options => new AgentGuard(options)) {}

  assert(condition: unknown, label: string): asserts condition {
    this.assertions += 1;
    if (!condition) throw new CheckFailure(label);
  }

  async denied(operation: () => unknown | Promise<unknown>, label: string, expectedCode?: string): Promise<void> {
    const before = this.handlerInvocations;
    let rejection: unknown;
    let rejected = false;
    try {
      await operation();
    } catch (error) {
      rejection = error;
      rejected = true;
    }
    this.assert(rejected, `${label}: operation must reject`);
    this.assert(isGuardError(rejection), `${label}: rejection must be GuardError`);
    this.assert(safeCode(rejection) !== 'INVALID_ERROR_CODE', `${label}: stable safe reason code`);
    if (expectedCode !== undefined) this.assert(rejection.code === expectedCode, `${label}: expected denial reason`);
    this.denialCodes.push(safeCode(rejection));
    this.assert(
      !rejection.message.includes(SECRET) && !rejection.message.includes(CANARY),
      `${label}: error must not disclose fixture secrets`,
    );
    this.assert(this.handlerInvocations === before, `${label}: no handler invocation`);
  }

  effect<T extends Json>(value: T): { value: T } {
    this.handlerInvocations += 1;
    return { value };
  }
}

export function fixture(checks: Checks, options: GuardOptions = {}) {
  let now = 1000;
  const guard = checks.createGuard({ clock: () => now, ...options });
  let serial = 0;
  const ledger: string[] = [];
  const budget = (overrides: Partial<Budget> = {}): Budget => ({
    maxCalls: 30,
    maxConcurrent: 10,
    maxCost: 100,
    deadline: 61000,
    ...overrides,
  });
  const task = (grants: readonly Capability[], overrides: Partial<TaskOptions> = {}): TaskHandle =>
    guard.createTask({
      id: `task-${++serial}`,
      principalId: 'user-1',
      tenantId: 'alpha',
      grants,
      budget: budget(),
      ...overrides,
    });
  const register = (tool: ToolDefinition, approved = true): string => {
    const fingerprint = guard.registerTool(tool);
    if (approved) guard.approveTool(tool.name, fingerprint);
    return fingerprint;
  };
  const read = (overrides: Partial<ToolDefinition> = {}): string =>
    register({
      name: 'read_document',
      description: 'Read a synthetic document',
      resolve(args) {
        const requested = stringField(args, 'resource');
        const resourceId = requested === 'alpha/docs/beta-alias' ? BETA : requested;
        return { resourceId, tenantId: resourceId.split('/')[0]!, sensitive: resourceId === PAYROLL };
      },
      execute(args, { action, task: identity }) {
        ledger.push(`read:${action.resourceId}:${identity.tenantId}`);
        return checks.effect({
          resource: action.resourceId,
          text: action.resourceId === GUIDE ? 'Public guide' : 'Fixture confidential text',
        });
      },
      ...overrides,
    });
  const remove = (overrides: Partial<ToolDefinition> = {}): string =>
    register({
      name: 'delete_record',
      description: 'Delete one synthetic record',
      requiresApproval: true,
      resolve(args) {
        const resourceId = stringField(args, 'resource');
        return { resourceId, tenantId: resourceId.split('/')[0]! };
      },
      execute(_args, { action }) {
        ledger.push(`delete:${action.resourceId}`);
        return checks.effect({ deleted: action.resourceId });
      },
      ...overrides,
    });
  const send = (overrides: Partial<ToolDefinition> = {}): string =>
    register({
      name: 'send_message',
      description: 'Append to a synthetic outbox',
      resolve(args) {
        return {
          resourceId: 'alpha/outbox',
          tenantId: 'alpha',
          external: true,
          recipient: stringField(args, 'recipient'),
        };
      },
      execute(args) {
        ledger.push(`send:${stringField(args, 'recipient')}`);
        return checks.effect(args);
      },
      ...overrides,
    });
  const invoke = async (handle: TaskHandle, tool: string, args: Json): Promise<Json> =>
    guard.execute(await guard.prepare(handle, { tool, args }));
  const approve = (prepared: PreparedAction, expiresAt = 2000): string =>
    guard.approve(prepared, { approverId: 'reviewer-1', expiresAt });
  return {
    guard,
    ledger,
    budget,
    task,
    register,
    read,
    remove,
    send,
    invoke,
    approve,
    setTime: (value: number) => {
      now = value;
    },
  };
}

export const readGrant = (resource = GUIDE): Capability[] => [{ tool: 'read_document', resources: [resource] }];
export const deleteGrant = (resource = '*'): Capability[] => [{ tool: 'delete_record', resources: [resource] }];
export const sendGrant = (): Capability[] => [{ tool: 'send_message', resources: ['alpha/outbox'] }];
