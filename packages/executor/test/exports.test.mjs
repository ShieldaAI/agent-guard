import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import * as root from '@shieldaai/agent-guard-executor';
import * as sandbox from '@shieldaai/agent-guard-executor/sandbox';
import * as inventory from '@shieldaai/agent-guard-executor/inventory';
import * as pilot from '@shieldaai/agent-guard-executor/pilot';
import * as ops from '@shieldaai/agent-guard-executor/ops';
import * as internal from '@shieldaai/agent-guard-executor/internal';
import { fileURLToPath } from 'node:url';

const ROOT = [
  'DurableExecutor',
  'ExecutorClient',
  'ExecutorError',
  'LEDGER_FORMAT_VERSION',
  'NUMBERED_TASK_PREFIX',
  'createExecutorModelProvider',
  'createHttpGetTool',
  'createModelTool',
  'createOutboundJsonTool',
  'createPrivateFileTools',
  'createRestrictedFetch',
  'isPublicAddress',
  'numberedTaskId',
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
    'loadInventoryManifestFile',
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

test('the root exports exactly its own API: subpath names have no root alias', () => {
  assert.deepEqual(Object.keys(root).sort(), [...ROOT].sort());
  for (const [name, module] of Object.entries(SUBPATHS)) {
    for (const key of Object.keys(module)) if (key in root) assert.equal(root[key], module[key], `${name}.${key}`);
  }
});

test("application sources import packages by name, never another package's dist/", () => {
  const repo = fileURLToPath(new URL('../../../', import.meta.url));
  const offenders = [];
  const walk = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const name = entry.name;
      if (['node_modules', 'test', 'dist', 'public'].includes(name)) continue;
      const path = join(directory, name);
      if (entry.isDirectory()) walk(path);
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
