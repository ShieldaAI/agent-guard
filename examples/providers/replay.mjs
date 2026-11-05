import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createTicketHost, approveSyntheticReview, PRIVATE_CANARY } from './protected-ticket.mjs';

export function isEntry(meta) {
  if (typeof meta.main === 'boolean') return meta.main;
  if (!process.argv[1]) return false;
  try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(meta.url)); }
  catch { return false; }
}

export function toolResponse(provider, calls) {
  return provider === 'openai' ? {
    status: 'completed', output: calls.map(call => ({
      type: 'function_call', id: `fc_${call.id}`, call_id: call.id,
      name: call.name, arguments: JSON.stringify(call.args), status: 'completed', caller: { type: 'direct' }, async: false,
    })),
  } : {
    role: 'assistant', stop_reason: 'tool_use', content: calls.map(call => ({
      type: 'tool_use', id: call.id, name: call.name, input: call.args, caller: { type: 'direct' },
    })),
  };
}
export function finalResponse(provider) {
  return provider === 'openai' ? { status: 'completed', output: [{
    type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Ticket 123 resolved after host approval.' }],
  }] } : { role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Ticket 123 resolved after host approval.' }] };
}

export async function runOfflineExample(provider, run) {
  const host = createTicketHost();
  const requests = [];
  const responses = [
    toolResponse(provider, [{ id: 'read_123', name: 'tickets_read', args: { ticket_id: '123' } }]),
    toolResponse(provider, [{ id: 'forbidden_456', name: 'tickets_update', args: { ticket_id: '456', status: 'resolved' } }]),
    toolResponse(provider, [{ id: 'write_123', name: 'tickets_update', args: { ticket_id: '123', status: 'resolved' } }]),
    finalResponse(provider),
  ];
  const result = await run({ model: 'offline-synthetic-model', host, review: approveSyntheticReview,
    transport: async request => { requests.push(request); return responses.shift(); } });
  const state = host.snapshot();
  assert.equal(result.outcomes[0].ok, true);
  assert.equal(result.outcomes[1].ok, false);
  assert.equal(result.outcomes[2].ok, true);
  assert.deepEqual([...state.effects.reads], ['123']);
  assert.equal(state.effects.writes.length, 1);
  assert.equal(state.effects.writes[0].ticket_id, '123');
  assert.equal(state.tickets.find(ticket => ticket.id === '456').status, 'open');
  const privateCanaryDisclosures = requests.filter(request => JSON.stringify(request).includes(PRIVATE_CANARY)).length;
  assert.equal(privateCanaryDisclosures, 0);
  console.log(JSON.stringify({ provider, mode: 'offline-synthetic-replay', reads: 1, approvedWrites: 1,
    forbiddenEffects: state.effects.writes.filter(effect => effect.ticket_id !== '123').length,
    privateCanaryDisclosures, assertions: 'passed' }));
  return result;
}
