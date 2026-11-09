import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { createTicketHost, approveSyntheticReview, PRIVATE_CANARY } from '../examples/providers/protected-ticket.mjs';
import { runOpenAITicketWorkflow } from '../examples/providers/openai-responses.mjs';
import { runAnthropicTicketWorkflow } from '../examples/providers/anthropic-messages.mjs';
import { toolResponse, finalResponse } from '../examples/providers/replay.mjs';

const tenantId = 'demo-company';
const publicText = 'CUSTOMER_TICKET_TEXT_MUST_NOT_ENTER_TRACES';
const read = { id: 'private_provider_read_id', name: 'tickets_read', args: { ticket_id: '123' } };
const write = {
  id: 'private_provider_write_id',
  name: 'tickets_update',
  args: { ticket_id: '123', status: 'resolved' },
};
const forbidden = { ...write, id: 'private_provider_forbidden_id', args: { ticket_id: '456', status: 'resolved' } };

for (const provider of ['openai', 'anthropic']) {
  const run = provider === 'openai' ? runOpenAITicketWorkflow : runAnthropicTicketWorkflow;
  test(`${provider}: durable ticket decisions reconstruct effects without customer payloads`, async t => {
    const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), decisionTraces: {} });
    t.after(() => executor.close());
    const host = createTicketHost({ executor, publicText });
    const responses = [
      toolResponse(provider, [read]),
      toolResponse(provider, [forbidden]),
      toolResponse(provider, [write]),
      finalResponse(provider),
    ];
    const reviews = [];
    const result = await run({
      model: 'private_model_identifier',
      host,
      review: request => {
        reviews.push(request);
        return approveSyntheticReview(request);
      },
      transport: async () => responses.shift(),
    });
    assert.deepEqual(
      result.outcomes.map(outcome => outcome.ok),
      [true, false, true],
    );
    const state = host.snapshot();
    assert.equal(state.effects.reads.length, 1);
    assert.equal(state.effects.writes.length, 1);
    assert.equal(state.tickets[1].status, 'open');
    const trace = executor.decisionTraceSnapshot({ tenantId });
    const approved = trace.events.filter(event => event.event === 'review' && event.outcome === 'APPROVED');
    assert.equal(approved.length, 1);
    const path = trace.events.filter(event => event.actionRef === approved[0].actionRef);
    assert.deepEqual(
      path.map(event => event.event),
      ['prepare', 'review', 'admit', 'settle'],
    );
    assert.equal(path.at(-1).outcome, 'SUCCEEDED');
    assert.equal(trace.events.filter(event => event.event === 'settle' && event.outcome === 'SUCCEEDED').length, 2);
    assert.equal(trace.events.filter(event => event.event === 'deny').length, 1);
    const serialized = JSON.stringify(trace);
    for (const value of [
      tenantId,
      'other-company',
      PRIVATE_CANARY,
      publicText,
      state.task.id,
      'tickets_read',
      'tickets_update',
      'private_model_identifier',
      read.id,
      write.id,
      forbidden.id,
      reviews[0].actionId,
      reviews[0].digest,
      state.effects.writes[0].operation_id,
    ]) {
      assert.equal(serialized.includes(value), false, `Unexpected trace disclosure of ${value}`);
    }
    assert.equal(executor.decisionTraceSnapshot({ tenantId: 'other-company' }).events.length, 0);
    assert.throws(() => executor.decisionTraceSnapshot({ tenantId: 'other-company', taskId: state.task.id }));
    const effectCount = state.effects.writes.length;
    const failed = await executor.exportDecisionTraces({ tenantId }, () => {
      throw new Error(PRIVATE_CANARY);
    });
    assert.equal(failed.status, 'failed');
    let exported;
    const retried = await executor.exportDecisionTraces({ tenantId }, batch => {
      exported = batch;
    });
    assert.equal(retried.status, 'exported');
    assert.deepEqual(exported.events, trace.events);
    assert.equal(JSON.stringify(exported).includes(PRIVATE_CANARY), false);
    assert.equal(executor.decisionTraceSnapshot({ tenantId }).events.length, 0);
    assert.equal(host.snapshot().effects.writes.length, effectCount);
  });

  test(`${provider}: host review refusal is traceable and has no ticket effect`, async t => {
    const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), decisionTraces: {} });
    t.after(() => executor.close());
    const host = createTicketHost({ executor });
    const responses = [toolResponse(provider, [write]), finalResponse(provider)];
    const result = await run({
      model: 'offline',
      host,
      review: () => ({ approved: false }),
      transport: async () => responses.shift(),
    });
    assert.equal(result.outcomes[0].error, 'REVIEW_DENIED');
    assert.equal(host.snapshot().effects.writes.length, 0);
    const events = executor.decisionTraceSnapshot({ tenantId }).events;
    const refusal = events.find(event => event.event === 'review' && event.outcome === 'DENIED');
    assert.ok(refusal);
    assert.equal(refusal.code, 'REVIEW_DENIED');
    assert.equal(
      events.some(event => event.event === 'admit' || event.event === 'settle'),
      false,
    );
  });
}
