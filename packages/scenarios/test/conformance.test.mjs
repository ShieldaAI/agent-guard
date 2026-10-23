import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentGuard, GuardError } from '@shieldaai/agent-guard';
import { SCENARIO_CATALOG_VERSION, scenarioCatalog, runConformance } from '../dist/index.js';

test('catalog contains ten immutable, explicitly scoped protection scenarios', () => {
  assert.match(SCENARIO_CATALOG_VERSION, /^\d+\.\d+\.\d+$/);
  assert.deepEqual(scenarioCatalog.map(({ id }) => id), Array.from({ length: 10 }, (_, i) => `S${String(i + 1).padStart(2, '0')}`));
  assert.ok(Object.isFrozen(scenarioCatalog));
  for (const scenario of scenarioCatalog) {
    assert.ok(Object.isFrozen(scenario));
    assert.ok(Object.isFrozen(scenario.malicious));
    assert.ok(Object.isFrozen(scenario.limitations));
    assert.ok(scenario.boundary && scenario.benign && scenario.malicious.length && scenario.limitations.length);
  }
});

test('all ten protection scenarios deny hostile effects and allow their benign pair', { timeout: 15000 }, async () => {
  const report = await runConformance();
  assert.equal(report.catalogVersion, SCENARIO_CATALOG_VERSION);
  assert.equal(report.scenarioCount, 10);
  assert.equal(report.caseCount, 20);
  assert.equal(report.passed, true, JSON.stringify(report.results.filter(({ passed }) => !passed), null, 2));
  assert.equal(report.passedCases, 20);
  assert.equal(report.failedCases, 0);
  assert.ok(report.results.every(({ assertions }) => assertions > 0));
  assert.ok(Object.isFrozen(report) && Object.isFrozen(report.results));
  assert.equal(JSON.stringify(report).includes('fixture-secret-9c1e'), false);
  assert.equal(JSON.stringify(report).includes('fixture-canary-7f2b'), false);
});

test('selected scenarios still run both paired variants', async () => {
  const report = await runConformance({ scenarioIds: ['S07'] });
  assert.equal(report.passed, true);
  assert.equal(report.scenarioCount, 1);
  assert.equal(report.caseCount, 2);
  assert.deepEqual(report.results.map(({ scenarioId, variant }) => [scenarioId, variant]), [['S07', 'malicious'], ['S07', 'benign']]);
});

test('empty, duplicated and unknown selections cannot create a vacuous pass', async () => {
  await assert.rejects(runConformance({ scenarioIds: [] }), TypeError);
  await assert.rejects(runConformance({ scenarioIds: ['S01', 'S01'] }), TypeError);
  await assert.rejects(runConformance({ scenarioIds: ['S99'] }), TypeError);
});

test('a compatible adapter factory receives isolated fixtures and cannot pass by denying everything', async () => {
  let instances = 0;
  const report = await runConformance({
    scenarioIds: ['S01'],
    createGuard(options) {
      instances += 1;
      return new AgentGuard({ ...options, policy: () => 'deny' });
    },
  });
  assert.equal(instances, 2);
  assert.equal(report.passed, false);
  assert.equal(report.passedCases, 1);
  assert.equal(report.failedCases, 1);
  assert.equal(report.results[0].passed, true);
  assert.equal(report.results[1].passed, false);
  assert.equal(report.results[1].failure, 'Unexpected guard rejection (POLICY_DENIED).');
});

test('conformance rejects a handler dispatched before the asynchronous policy barrier', async () => {
  const report = await runConformance({
    createGuard(options) {
      const guard = new AgentGuard(options);
      const definitions = new Map();
      const register = guard.registerTool.bind(guard);
      const execute = guard.execute.bind(guard);
      guard.registerTool = (tool) => {
        definitions.set(tool.name, tool);
        return register(tool);
      };
      guard.execute = async (prepared, executionOptions) => {
        const tool = definitions.get(prepared.action.tool);
        // Model an adapter that prematurely invokes an approved handler before its custom policy settles.
        if (options.policy && tool.requiresApproval && executionOptions?.approvalId) {
          await tool.execute(prepared.action.args, {
            signal: new AbortController().signal, action: prepared.action,
            task: { id: 'premature-task', principalId: 'user-1', tenantId: 'alpha' },
          });
        }
        return execute(prepared, executionOptions);
      };
      return guard;
    },
  });
  assert.equal(report.passed, false);
  assert.equal(report.passedCases, 19);
  const failure = report.results.find(({ scenarioId, variant }) => scenarioId === 'S08' && variant === 'malicious');
  assert.equal(failure.passed, false);
  assert.equal(failure.handlerInvocations, 1);
  assert.equal(failure.failure, 'revoke during asynchronous policy: no handler invocation');
});

test('a nonsettling adapter produces a failed case and allows the next variant to run', { timeout: 2000 }, async () => {
  let instances = 0;
  const report = await runConformance({
    scenarioIds: ['S01'], caseTimeoutMs: 50,
    createGuard(options) {
      const guard = new AgentGuard(options);
      if (++instances === 1) guard.prepare = () => new Promise(() => {});
      return guard;
    },
  });
  assert.equal(instances, 2);
  assert.equal(report.passed, false);
  assert.equal(report.failedCases, 1);
  assert.equal(report.results[0].failure, 'case exceeded its asynchronous timeout');
  assert.equal(report.results[1].passed, true);
});

test('case timeouts reject invalid or overflowing timer values', async () => {
  for (const caseTimeoutMs of [null, 0, -1, 0.5, NaN, Infinity, 2_147_483_648, '50']) {
    await assert.rejects(runConformance({ caseTimeoutMs }), TypeError);
  }
});

test('S10 rejects treating omitted actual cost as zero', async () => {
  const report = await runConformance({
    scenarioIds: ['S10'],
    createGuard(options) {
      const guard = new AgentGuard(options);
      const register = guard.registerTool.bind(guard);
      guard.registerTool = (tool) => register({
        ...tool,
        async execute(...args) {
          const result = await tool.execute(...args);
          return { ...result, actualCost: result.actualCost ?? 0 };
        },
      });
      return guard;
    },
  });
  assert.equal(report.passed, false);
  assert.equal(report.results[0].passed, true);
  assert.equal(report.results[1].failure, 'omitted actual cost charges the full declared maximum');
});

test('S10 rejects refunding the charge for a failed handler', async () => {
  const report = await runConformance({
    scenarioIds: ['S10'],
    createGuard(options) {
      const guard = new AgentGuard(options);
      const register = guard.registerTool.bind(guard);
      const execute = guard.execute.bind(guard);
      const failedArguments = new WeakSet();
      guard.registerTool = (tool) => register({
        ...tool,
        async execute(args, context) {
          try { return await tool.execute(args, context); }
          catch {
            failedArguments.add(args);
            return { value: null, actualCost: 0 };
          }
        },
      });
      guard.execute = async (prepared, executionOptions) => {
        const value = await execute(prepared, executionOptions);
        if (failedArguments.has(prepared.action.args)) throw new GuardError('TOOL_FAILED');
        return value;
      };
      return guard;
    },
  });
  assert.equal(report.passed, false);
  assert.equal(report.results[0].passed, true);
  assert.equal(report.results[1].failure, 'failed handler retains the full declared charge');
});

test('S10 rejects retaining an adapter concurrency slot after a handler settles', async () => {
  const report = await runConformance({
    scenarioIds: ['S10'],
    createGuard(options) {
      const guard = new AgentGuard(options);
      const execute = guard.execute.bind(guard);
      let occupied = false;
      guard.execute = async (...args) => {
        if (occupied) throw new GuardError('CONCURRENCY_EXCEEDED');
        occupied = true;
        return execute(...args);
      };
      return guard;
    },
  });
  assert.equal(report.passed, false);
  assert.equal(report.results[1].failure, 'Unexpected guard rejection (CONCURRENCY_EXCEEDED).');
});
