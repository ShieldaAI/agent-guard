import test from 'node:test';
import assert from 'node:assert/strict';
import { TicketWorkflow } from '../workflow.mjs';
import { companyHistory, historyState } from '../history-state.mjs';
import { normalizeLimits } from '../limits.mjs';
import { createOpsTelemetry, operationalStatus, monitoringSummary, prometheusStatus } from '../observability.mjs';
import { httpsSetup } from './helpers.mjs';

const operator = { id: 'owner', tenantId: 'acme', roles: ['operator'] };
const limits = normalizeLimits();

test('maintenance reports global committed history plus pending reservation, separate from tenant history', () => {
  const data = { tickets: {}, requests: {}, receipts: {}, audit: [] };
  for (const [tenant, segments] of [
    ['acme', 3000],
    ['private-tenant-reference', 4999],
  ]) {
    const company = companyHistory(data, tenant, true);
    company.head = { index: segments, hash: 'a'.repeat(64), keyBase64: Buffer.alloc(32).toString('base64') };
  }
  historyState(data).pending = { tenantId: 'acme' };
  const host = {
    data: () => data,
    store: { read: () => ({ ticketService: data }) },
    limits,
    executor: { maintenanceStatistics: () => ({ ledgerBytes: 100, ledgerByteLimit: limits.maxLedgerBytes }) },
  };
  const result = TicketWorkflow.prototype.maintenance.call(host, operator);
  assert.deepEqual(result.historyCapacity, { committed: 7999, reserved: 1, total: 8000, limit: 10_000 });
  assert.equal(result.history.segments, 3000);
  assert.equal(result.capacityWarning, true);
  assert.equal(JSON.stringify(result).includes('private-tenant-reference'), false);
  historyState(data).pending = null;
  assert.equal(TicketWorkflow.prototype.maintenance.call(host, operator).capacityWarning, false);
});

test('status, stdout and fixed metrics count reservations at the exact 80% and 95% history boundaries', () => {
  const now = 1_000_000,
    telemetry = createOpsTelemetry({ clock: () => now, securityLoggingEnabled: true });
  for (const [total, expected] of [
    [7999, 'ok'],
    [8000, 'warning'],
    [9499, 'warning'],
    [9500, 'critical'],
    [10_000, 'critical'],
  ]) {
    const historyCapacity = { committed: total - 1, reserved: 1, total, limit: 10_000 };
    const workflow = {
      health() {},
      data: () => ({ requests: {}, audit: [] }),
      maintenance: () => ({
        limits,
        usage: { tickets: 0, requests: 0, receipts: 0, backendBytes: 0 },
        statistics: { ledgerBytes: 0 },
        historyCapacity,
      }),
    };
    const options = {
      workflow,
      operator,
      telemetry,
      keyring: { keyCount: 1, maxKeys: 4 },
      tenantIdForStatistics: 'acme',
      now,
    };
    const status = operationalStatus(options),
      row = status.capacity.find(value => value.id === 'history_segments');
    assert.equal(row.used, total);
    assert.equal(row.limit, 10_000);
    assert.equal(row.committed, total - 1);
    assert.equal(row.reserved, 1);
    assert.equal(row.limitKind, 'fixed-recovery-profile');
    assert.equal(row.state, expected);
    const alert = status.alerts.find(value => value.id === 'capacity_history_segments');
    if (expected === 'ok') assert.equal(alert, undefined);
    else {
      assert.equal(alert.severity, expected);
      if (expected === 'critical') {
        assert.match(alert.message, /Pause new compaction/);
        assert.match(alert.message, /Preserve all records, history, witnesses and keys/);
        assert.equal(alert.message.includes('configure-limits'), false);
      }
    }
    if (total === 10_000) assert.match(alert.message, /capacity is exhausted/);
    const summary = monitoringSummary(options);
    assert.deepEqual(
      summary.capacity.find(value => value.id === 'history_segments'),
      row,
    );
    const metrics = prometheusStatus(status);
    assert.match(metrics, new RegExp(`agent_ops_capacity_used\\{resource="history_segments"\\} ${total}\\n`));
    assert.match(metrics, /agent_ops_capacity_limit\{resource="history_segments"\} 10000\n/);
    assert.match(metrics, new RegExp(`agent_ops_history_segments_committed ${total - 1}\\n`));
    assert.match(metrics, /agent_ops_history_segments_reserved 1\n/);
    assert.equal(metrics.includes('acme'), false);
  }
});

test(
  'capacity refusal exposes fixed safe-stop guidance without backend details',
  { skip: process.platform === 'win32' },
  async t => {
    const fixture = await httpsSetup(t),
      owner = await fixture.login();
    for (const code of ['HISTORY_SEGMENT_CAPACITY', 'HISTORY_MIGRATION_REQUIRED']) {
      fixture.workflow.previewArchive = () => {
        throw Object.assign(new Error('private-path-or-key-details'), { code });
      };
      const result = await owner.post('/api/maintenance/archive/preview', { taskId: 'ticket:fixture' });
      assert.equal(result.status, 409);
      assert.equal(result.json().error.code, code);
      assert.match(result.json().error.message, /Preserve all records, history, witnesses and keys/);
      assert.equal(result.text.includes('private-path-or-key-details'), false);
    }
  },
);
