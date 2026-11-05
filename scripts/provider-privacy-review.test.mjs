import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { approveSyntheticReview, createTicketHost } from '../examples/providers/protected-ticket.mjs';
import { reviewTicket } from '../examples/providers/review-ticket.mjs';
import { runTicketWorkflow } from '../examples/providers/workflow.mjs';
import { finalResponse, toolResponse } from '../examples/providers/replay.mjs';

for (const provider of ['openai', 'anthropic']) {
  test(`${provider}: schemas hide foreign IDs and provider results cannot distinguish foreign from missing tickets`, async () => {
    for (const tool of ['tickets_read', 'tickets_update']) {
      const host = createTicketHost();
      const requests = [], reviews = [];
      const calls = ['456', '789', '123'].map((ticket_id, i) => ({ id: `call${i}`, name: tool,
        args: tool === 'tickets_update' ? { ticket_id, status: 'resolved' } : { ticket_id } }));
      const result = await runTicketWorkflow({ provider, model: 'synthetic', host,
        review: request => { reviews.push(request.ticketId); return approveSyntheticReview(request); },
        transport: request => {
          const i = requests.length; requests.push(request);
          return calls[i] ? toolResponse(provider, [calls[i]]) : finalResponse(provider);
        } });
      assert.equal(JSON.stringify(requests[0].tools).includes('456'), false);
      const modelResult = i => provider === 'openai' ? requests[i].input.at(-1).output
        : requests[i].messages.at(-1).content.at(-1).content;
      assert.equal(modelResult(1), modelResult(2));
      assert.deepEqual(JSON.parse(modelResult(1)), { ok: false, error: 'RESOLUTION_FAILED' });
      assert.deepEqual(result.outcomes.map(outcome => outcome.ok), [false, false, true]);
      assert.deepEqual(reviews, tool === 'tickets_update' ? ['123'] : []);
      const snapshot = host.snapshot();
      assert.deepEqual(snapshot.effects.reads, tool === 'tickets_read' ? ['123'] : []);
      assert.deepEqual(snapshot.effects.writes.map(write => write.ticket_id), tool === 'tickets_update' ? ['123'] : []);
      assert.equal(snapshot.tickets.find(ticket => ticket.id === '456').status, 'open');
    }
  });
}

async function terminalReview(answer, isTTY = true) {
  const input = new PassThrough(), output = new PassThrough();
  input.isTTY = isTTY; output.isTTY = isTTY;
  let transcript = '', replied = false;
  output.on('data', chunk => {
    transcript += chunk.toString();
    if (!replied && transcript.includes('and press Enter:')) {
      replied = true;
      setImmediate(() => input.end(answer));
    }
  });
  try { const status = await reviewTicket({ input, output }); return { status, transcript }; }
  finally { input.destroy(); output.destroy(); }
}

test('terminal review requires the exact phrase and Enter, even if EOF flushes buffered text', { timeout: 2000 }, async () => {
  for (const answer of ['approve 123', '', '\r', 'wrong\r', '\u0003']) {
    const review = await terminalReview(answer);
    assert.equal(review.status, 0);
    assert.match(review.transcript, /No change submitted/);
    assert.doesNotMatch(review.transcript, /Confirmed:/);
  }
  const approved = await terminalReview('approve 123\r');
  assert.equal(approved.status, 0);
  assert.match(approved.transcript, /Confirmed: ticket 123 is resolved \(version 2\)/);
  const piped = await terminalReview('approve 123\n', false);
  assert.equal(piped.status, 2);
  assert.match(piped.transcript, /Nothing submitted/);
});
