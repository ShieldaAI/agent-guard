import type { Json, ToolDefinition } from '@shieldaai/agent-guard';
import type { ScenarioId } from '../catalog.js';
import {
  GUIDE,
  RECORD_A,
  RECORD_B,
  SECRET,
  fields,
  stringField,
  fixture,
  type Checks,
  type Pair,
} from '../fixtures.js';

/** Tool definitions and arguments: definition changes (S06) and parsed, normalized arguments (S11). */
export const toolIntegrityCases = {
  S06: {
    async malicious(c: Checks) {
      const f = fixture(c);
      const definition: ToolDefinition = {
        name: 'metadata_tool',
        description: 'Definition v1',
        inputSchema: { type: 'object' },
        resolve: () => ({ resourceId: GUIDE, tenantId: 'alpha' }),
        execute: () => c.effect('v1'),
      };
      f.register(definition);
      const task = f.task([
        { tool: 'metadata_tool', resources: [GUIDE] },
        { tool: 'added_tool', resources: [GUIDE] },
      ]);
      const old = await f.guard.prepare(task, { tool: 'metadata_tool', args: {} });
      const v2 = f.register(
        { ...definition, description: 'Definition v2', inputSchema: { type: 'object', required: ['newField'] } },
        false,
      );
      await c.denied(() => f.invoke(task, 'metadata_tool', {}), 'unapproved definition change', 'TOOL_UNAPPROVED');
      await c.denied(() => f.guard.execute(old), 'prepared action invalidated by metadata change', 'TOOL_CHANGED');
      f.guard.approveTool('metadata_tool', v2);
      const approvedV2 = await f.guard.prepare(task, { tool: 'metadata_tool', args: { newField: true } });
      f.register({
        ...definition,
        description: 'Definition v2',
        inputSchema: { type: 'object', required: ['newField'] },
        execute: () => c.effect('new-code'),
      });
      await c.denied(
        () => f.guard.execute(approvedV2),
        'code re-registration invalidates prepared action',
        'TOOL_CHANGED',
      );
      f.register({ ...definition, name: 'added_tool' }, false);
      await c.denied(() => f.invoke(task, 'added_tool', {}), 'added tool is not auto-approved', 'TOOL_UNAPPROVED');
    },
    async benign(c: Checks) {
      const f = fixture(c);
      const definition: ToolDefinition = {
        name: 'metadata_tool',
        description: 'Definition v1',
        resolve: () => ({ resourceId: GUIDE, tenantId: 'alpha' }),
        execute: () => c.effect('v1'),
      };
      f.register(definition);
      const task = f.task([{ tool: 'metadata_tool', resources: [GUIDE] }]);
      c.assert((await f.invoke(task, 'metadata_tool', {})) === 'v1', 'approved v1 executes');
      const v2 = f.register({ ...definition, description: 'Definition v2', execute: () => c.effect('v2') }, false);
      f.guard.approveTool('metadata_tool', v2);
      c.assert((await f.invoke(task, 'metadata_tool', {})) === 'v2', 'reviewed v2 executes');
      c.assert(c.handlerInvocations === 2, 'exactly two reviewed metadata effects');
    },
  },
  S11: {
    async malicious(c: Checks) {
      const f = fixture(c);
      let resolutions = 0;
      f.register({
        name: 'typed_write',
        description: 'Write a typed synthetic record',
        parse(input) {
          const value = fields(input);
          if (
            Object.keys(value).some(key => !['resource', 'quantity'].includes(key)) ||
            typeof value.resource !== 'string' ||
            !value.resource.trim() ||
            typeof value.quantity !== 'number' ||
            !Number.isSafeInteger(value.quantity) ||
            value.quantity < 1 ||
            value.quantity > 10
          ) {
            throw new Error(SECRET);
          }
          return { resource: value.resource.trim(), quantity: value.quantity };
        },
        resolve(args) {
          resolutions++;
          return { resourceId: stringField(args, 'resource'), tenantId: 'alpha' };
        },
        execute: args => c.effect(args),
      });
      const task = f.task([{ tool: 'typed_write', resources: [RECORD_A] }]);
      for (const args of [
        { resource: RECORD_A, quantity: '1' },
        { resource: RECORD_A, quantity: 1, command: 'unexpected' },
        { quantity: 1 },
        { resource: RECORD_A, quantity: 0 },
        { resource: RECORD_A, quantity: 1.5 },
      ])
        await c.denied(() => f.invoke(task, 'typed_write', args), 'invalid typed arguments', 'ARGUMENT_INVALID');
      c.assert(resolutions === 0, 'invalid typed arguments never reach resource resolution');
      for (const parse of [
        () => ({ unsafe: undefined }) as unknown as Json,
        () => Promise.resolve(null) as unknown as Json,
      ]) {
        f.register({
          name: 'invalid_parser',
          description: 'Invalid trusted parser fixture',
          parse,
          resolve: () => {
            resolutions++;
            return { resourceId: RECORD_A, tenantId: 'alpha' };
          },
          execute: args => c.effect(args),
        });
        const parserTask = f.task([{ tool: 'invalid_parser', resources: [RECORD_A] }]);
        await c.denied(() => f.invoke(parserTask, 'invalid_parser', null), 'invalid parser result', 'ARGUMENT_INVALID');
      }
      c.assert(resolutions === 0 && c.handlerInvocations === 0, 'parser failures prevent resolution and effects');
    },
    async benign(c: Checks) {
      const observed: Json[] = [];
      const f = fixture(c, {
        policy: action => {
          observed.push(action.args);
          return 'allow';
        },
      });
      let parses = 0;
      let normalized: { resource: string; quantity: number } | undefined;
      f.register({
        name: 'typed_write',
        description: 'Write a normalized synthetic record',
        requiresApproval: true,
        parse(input) {
          parses++;
          const value = fields(input);
          if (typeof value.resource !== 'string' || !Number.isSafeInteger(value.quantity))
            throw new Error('invalid fixture');
          normalized = { resource: value.resource.trim(), quantity: Number(value.quantity) };
          return normalized;
        },
        resolve(args) {
          return { resourceId: stringField(args, 'resource'), tenantId: 'alpha' };
        },
        execute(args, { action }) {
          c.assert(args === action.args && Object.isFrozen(args), 'handler receives the immutable approved arguments');
          f.ledger.push(`${action.resourceId}:${fields(args).quantity}`);
          return c.effect(args);
        },
      });
      const task = f.task([{ tool: 'typed_write', resources: [RECORD_A] }]);
      const input = { resource: ` ${RECORD_A} `, quantity: 3 };
      const prepared = await f.guard.prepare(task, { tool: 'typed_write', args: input });
      c.assert(
        prepared.action.resourceId === RECORD_A && fields(prepared.action.args).resource === RECORD_A,
        'normalized resource is resolved and bound',
      );
      const approvalId = f.approve(prepared);
      input.resource = RECORD_B;
      input.quantity = 9;
      normalized!.resource = RECORD_B;
      normalized!.quantity = 8;
      const value = await f.guard.execute(prepared, { approvalId });
      c.assert(
        fields(value).resource === RECORD_A && fields(value).quantity === 3,
        'caller and parser mutations do not alter the approved write',
      );
      c.assert(
        observed.length === 2 &&
          observed.every(args => fields(args).resource === RECORD_A && fields(args).quantity === 3),
        'preparation and execution policy see normalized arguments',
      );
      c.assert(
        parses === 1 && c.handlerInvocations === 1 && f.ledger[0] === `${RECORD_A}:3`,
        'one parser pass and one normalized approved effect',
      );
    },
  },
} satisfies Partial<Record<ScenarioId, Pair>>;
