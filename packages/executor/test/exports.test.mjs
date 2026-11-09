import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import * as root from '@shieldaai/agent-guard-executor';
import * as sandbox from '@shieldaai/agent-guard-executor/sandbox';
import * as inventory from '@shieldaai/agent-guard-executor/inventory';
import * as pilot from '@shieldaai/agent-guard-executor/pilot';
import * as ops from '@shieldaai/agent-guard-executor/ops';
import * as internal from '@shieldaai/agent-guard-executor/internal';

const ROOT = [
  'DurableExecutor',
  'ExecutorClient',
  'ExecutorError',
  'LEDGER_FORMAT_VERSION',
  'createExecutorModelProvider',
  'createHttpGetTool',
  'createModelTool',
  'createOutboundJsonTool',
  'createPrivateFileTools',
  'createRestrictedFetch',
  'isPublicAddress',
  'publicToolDefinition',
  'startExecutorServer',
];
const SUBPATHS = { sandbox, inventory, pilot, ops };

test('each subpath exports its own area', () => {
  assert.deepEqual(Object.keys(sandbox).sort(), [
    'ArtifactBroker',
    'buildDockerCreateArgs',
    'createSandboxTool',
    'readSandboxArchive',
    'runDockerSandbox',
    'runGovernedSandbox',
    'validateSandboxProfile',
    'writeReviewedExports',
  ]);
  assert.deepEqual(Object.keys(inventory).sort(), [
    'composeInventorySnapshot',
    'composeMcpInventorySnapshot',
    'createInventoryObserverToken',
    'startInventoryServer',
    'validateInventoryManifest',
    'validateMcpConnectionInventory',
    'validateMcpInventorySources',
  ]);
  assert.deepEqual(Object.keys(pilot), ['verifyPilotReview']);
  assert.deepEqual(Object.keys(ops).sort(), [
    'LEDGER_FORMAT_VERSION',
    'configureLedgerKeyring',
    'createLedgerKeyring',
    'describeLedgerFormat',
    'loadLedgerKey',
    'manageLedgerCustody',
    'manageLedgerRecovery',
    'readLedgerKeyring',
    'readLedgerKeyringPolicy',
    'rotateLedgerKey',
    'rotateLedgerKeyring',
  ]);
  assert.ok(typeof internal.LedgerStore === 'function' && typeof internal.TaskFamilyLifecycle === 'function');
});

test('the root keeps every 0.1 export: its own API plus deprecated aliases bound to the same values', () => {
  const moved = Object.entries(SUBPATHS)
    .flatMap(([, module]) => Object.keys(module))
    .filter(name => !ROOT.includes(name) && name !== 'describeLedgerFormat');
  assert.deepEqual(Object.keys(root).sort(), [...new Set([...ROOT, ...moved])].sort());
  for (const [name, module] of Object.entries(SUBPATHS)) {
    for (const key of Object.keys(module)) if (key in root) assert.equal(root[key], module[key], `${name}.${key}`);
  }
  const declarations = readFileSync(new URL('../dist/deprecated.d.ts', import.meta.url), 'utf8');
  for (const name of moved)
    assert.match(
      declarations,
      new RegExp(`@deprecated[^\\n]*\\n\\s*export (?:declare )?(?:const|type) ${name}\\b`),
      name,
    );
});

test("application sources import packages by name, never another package's dist/", () => {
  const repo = new URL('../../../', import.meta.url).pathname;
  const offenders = [];
  const walk = directory => {
    for (const name of readdirSync(directory)) {
      if (['node_modules', 'test', 'dist', 'public'].includes(name)) continue;
      const path = join(directory, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (
        /\.(mjs|js|ts)$/.test(name) &&
        /['"](?:\.\.\/)+packages\/[a-z-]+\/dist\//.test(readFileSync(path, 'utf8'))
      )
        offenders.push(path.slice(repo.length));
    }
  };
  walk(join(repo, 'apps'));
  assert.deepEqual(offenders, []);
});
