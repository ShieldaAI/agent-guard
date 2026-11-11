import test from 'node:test';
import assert from 'node:assert/strict';
import { createQuerySession } from '../src/view-model.mjs';

function slowService() {
  const calls = [];
  let running = 0,
    peak = 0;
  const session = createQuerySession(
    (_operation, args, { signal }) =>
      new Promise((resolve, reject) => {
        running++;
        peak = Math.max(peak, running);
        calls.push({
          id: args.id,
          signal,
          finish(error) {
            running--;
            error ? reject(error) : resolve(args.id);
          },
        });
      }),
  );
  return { session, calls, peak: () => peak };
}
const turn = () => new Promise(resolve => setImmediate(resolve));

test('six slow detail reads use two slots, preserve results and release capacity after errors without retry', async () => {
  const { session, calls, peak } = slowService();
  const results = Promise.allSettled(
    Array.from({ length: 6 }, (_, id) => session.query('get_agent_inventory', { id })),
  );
  assert.equal(calls.length, 2);
  for (let id = 0; id < 6; id++) {
    calls[id].finish(id === 2 ? new Error('unavailable') : null);
    await turn();
    assert.ok(calls.length <= Math.min(6, id + 3));
  }
  assert.equal(peak(), 2);
  assert.deepEqual(
    calls.map(x => x.id),
    [0, 1, 2, 3, 4, 5],
  );
  assert.deepEqual(
    (await results).map(x => x.status),
    ['fulfilled', 'fulfilled', 'rejected', 'fulfilled', 'fulfilled', 'fulfilled'],
  );
  session.close();
});

test('navigation cancels queued old-view reads and discards started results without freeing backend slots early', async () => {
  const { session, calls, peak } = slowService(),
    view = new AbortController();
  const stale = Promise.allSettled(
    Array.from({ length: 6 }, (_, id) => session.query('get_agent_inventory', { id }, { signal: view.signal })),
  );
  view.abort();
  const current = session.query('list_owners', { id: 'current' });
  assert.deepEqual(
    calls.map(x => x.id),
    [0, 1],
  );
  assert.equal(calls[0].signal.aborted, false, 'navigation keeps started read capacity until it settles');
  calls[0].finish();
  await turn();
  assert.deepEqual(
    calls.map(x => x.id),
    [0, 1, 'current'],
  );
  calls[1].finish();
  calls[2].finish();
  assert.equal(await current, 'current');
  for (const outcome of await stale) {
    assert.equal(outcome.status, 'rejected');
    assert.equal(outcome.reason.code, 'VIEWER_REQUEST_CANCELLED');
  }
  assert.equal(peak(), 2);
  session.close();
});

test('sign-out rejects queued reads immediately, aborts started transports and never dispatches stale queued work', async () => {
  const { session, calls } = slowService();
  const pending = Array.from({ length: 6 }, (_, id) => session.query('get_agent_inventory', { id }));
  const settled = Promise.allSettled(pending);
  session.close();
  await assert.rejects(pending[5], { code: 'VIEWER_SESSION_ENDED' });
  assert.equal(calls.length, 2);
  assert.ok(calls.every(x => x.signal.aborted));
  calls[0].finish();
  calls[1].finish(new Error('old transport error'));
  for (const outcome of await settled) {
    assert.equal(outcome.status, 'rejected');
    assert.equal(outcome.reason.code, 'VIEWER_SESSION_ENDED');
  }
  assert.equal(calls.length, 2);
  await assert.rejects(session.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' });
});
