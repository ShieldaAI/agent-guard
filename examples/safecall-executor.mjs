// An integration check with the separate llm-safecall package, which is not a dependency of
// this repository. It is not a usage example of Agent Guard on its own.
//
// Run: npm run build, then node examples/safecall-executor.mjs [path to llm-safecall's built
// index.js]. Without the argument, llm-safecall must be installed where Node can resolve it.
// Synthetic provider output and an in-memory ledger; no cloud credentials.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  DurableExecutor,
  ExecutorClient,
  startExecutorServer,
  createModelTool,
  createExecutorModelProvider,
} from '@shieldaai/agent-guard-executor';

const { SafeCall, PolicyEngine } = await import(
  process.argv[2] ? pathToFileURL(resolve(process.argv[2])).href : 'llm-safecall'
).catch(error => {
  if (error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
  console.error('This check needs the llm-safecall package: install it, or pass the path to its built index.js.');
  process.exit(1);
});
const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
let calls = 0;
const tool = createModelTool({
  name: 'model',
  model: 'fixture',
  tenantId: 'demo',
  recipient: 'fixture-provider',
  maxCost: 5,
  maxOutputTokens: 10,
  complete: async () => ({
    response: { text: ++calls === 1 ? 'Public response' : 'AKIA1234567890ABCDEF', outputComplete: true },
    actualCost: 2,
  }),
});
executor.approveTool(tool.name, executor.registerTool(tool));
const credential = executor.createTask({
  id: 'demo',
  principalId: 'host',
  tenantId: 'demo',
  grants: [{ tool: tool.name, resources: ['fixture'] }],
  allowedRecipients: ['fixture-provider'],
  budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 10, deadline: Date.now() + 60_000 },
});
const server = await startExecutorServer({
  executor,
  adminToken: randomBytes(32).toString('base64url'),
  operatorId: 'host-reviewer',
});
try {
  const provider = createExecutorModelProvider({
    client: new ExecutorClient({ endpoint: server.url, token: credential.token }),
    tool: tool.name,
    model: 'fixture',
    maxOutputTokens: 10,
  });
  const safe = new SafeCall({
    llm: provider,
    streamMode: 'buffered',
    maxTokens: 10,
    policy: new PolicyEngine({ redactSecrets: false }),
    failSafe: true,
  });
  assert.deepEqual(await Array.fromAsync(safe.streamGenerate('Public request')), ['Public response']);
  const released = [];
  await assert.rejects(async () => {
    for await (const text of safe.streamGenerate('Second request')) released.push(text);
  });
  assert.equal(released.length, 0);
  await assert.rejects(async () => Array.fromAsync(safe.streamGenerate('Exhausted request')));
  assert.equal(calls, 2);
  assert.equal(executor.snapshot('demo').spent, 4);
  console.log(
    'Integration passed: public output accepted; secret output released zero chunks; exhausted provider call denied; cost retained.',
  );
} finally {
  await server.close();
  executor.close();
}
