import assert from 'node:assert/strict';
import { once } from 'node:events';
import { copyFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

function message(worker, predicate) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => done(new Error('TEST_CLIENT_TIMEOUT')), 10_000);
    const receive = value => {
      if (predicate(value)) done(null, value);
    };
    const failure = error => done(error);
    const done = (error, value) => {
      clearTimeout(timer);
      worker.off('message', receive);
      worker.off('error', failure);
      error ? reject(error) : resolve(value);
    };
    worker.on('message', receive);
    worker.once('error', failure);
  });
}

async function fixture(t, handler) {
  const directory = await mkdtemp(join(tmpdir(), 'guard-admission-client-'));
  const entry = join(directory, 'client.mjs');
  // There is deliberately no packages/, node_modules/, or diagnostics module.
  // The actual worker must serve both roles without loading any of them.
  await copyFile(new URL('./benchmark-admission-client.mjs', import.meta.url), entry);
  const workers = [],
    server = createServer(handler);
  t.after(async () => {
    try {
      await Promise.all(workers.map(worker => worker.terminate()));
    } finally {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return data => {
    const worker = new Worker(pathToFileURL(entry), {
      workerData: {
        url: `http://127.0.0.1:${server.address().port}`,
        token: 'synthetic-only',
        diagnostics: false,
        ...data,
      },
    });
    workers.push(worker);
    return worker;
  };
}

test('standalone HTTP workload client preserves serial warmup/measurement requests and request failure', async t => {
  const requests = [];
  let rejectExecute = false;
  const start = await fixture(t, (request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      requests.push({
        path: request.url,
        method: request.method,
        authorization: request.headers.authorization,
        body: JSON.parse(Buffer.concat(chunks).toString()),
      });
      response.setHeader('content-type', 'application/json');
      if (request.url.endsWith('/prepare')) response.end('{"id":"synthetic-action"}');
      else if (rejectExecute) {
        response.statusCode = 503;
        response.end('{"error":"synthetic"}');
      } else response.end(JSON.stringify({ value: { enteredAtNs: process.hrtime.bigint().toString() } }));
    });
  });
  for (const fail of [false, true]) {
    rejectExecute = fail;
    requests.length = 0;
    const worker = start({ kind: 'workload', samples: 2, warmup: 1 }),
      messages = [];
    worker.on('message', value => messages.push(value));
    const result = await message(worker, value => value.kind === 'complete');
    assert.equal(result.ok, !fail);
    assert.equal(Object.hasOwn(result, 'diagnostics'), false);
    assert.deepEqual(
      messages.map(value => value.kind),
      fail ? ['warmup-sample', 'complete'] : ['warmup-sample', 'measurement-start', 'sample', 'sample', 'complete'],
    );
    assert.equal(requests.length, fail ? 2 : 6);
    for (let index = 0; index < requests.length; index++) {
      const request = requests[index];
      assert.equal(request.method, 'POST');
      assert.equal(request.authorization, 'Bearer synthetic-only');
      assert.equal(request.path, index % 2 ? '/v1/task/execute' : '/v1/task/prepare');
      assert.deepEqual(
        request.body,
        index % 2 ? { actionId: 'synthetic-action' } : { tool: 'synthetic.read-0', args: null },
      );
    }
    for (const { sample } of messages.filter(value => value.sample)) {
      assert.equal(sample.ok, !fail);
      if (fail) assert.equal(sample.error, 'ADMISSION_REQUEST_FAILED');
      else {
        assert.ok(BigInt(sample.startedNs) <= BigInt(sample.executeStartedNs));
        assert.ok(BigInt(sample.executeStartedNs) <= BigInt(sample.toolEnteredNs));
        assert.ok(BigInt(sample.toolEnteredNs) <= BigInt(sample.finishedNs));
        assert.equal(sample.admissionMs, Number(BigInt(sample.toolEnteredNs) - BigInt(sample.executeStartedNs)) / 1e6);
      }
    }
    await worker.terminate();
  }
});

test('standalone HTTP polling client retains its cold request, response validation and stop accounting', async t => {
  const requests = [];
  let valid = true,
    resolveRequest;
  const start = await fixture(t, (request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      requests.push({
        path: request.url,
        method: request.method,
        authorization: request.headers.authorization,
        body: Buffer.concat(chunks).toString(),
      });
      response.setHeader('content-type', 'application/json');
      response.end(
        JSON.stringify({ profile: valid ? 'core' : 'invalid', tasks: [{ grants: [{}, {}] }, { grants: [{}, {}] }] }),
      );
      resolveRequest();
    });
  });
  for (const accepted of [true, false]) {
    valid = accepted;
    requests.length = 0;
    const requested = new Promise(resolve => {
      resolveRequest = resolve;
    });
    const worker = start({
      kind: 'poll',
      tasks: 2,
      grants: 2,
      pollIntervalMs: 1000,
      clockOriginNs: process.hrtime.bigint().toString(),
    });
    await message(worker, value => value === 'ready');
    await requested;
    const stopped = message(worker, value => value.stats);
    worker.postMessage('stop');
    const { stats } = await stopped;
    assert.ok(stats.started >= 1);
    assert.equal(stats.started, stats.completed + stats.failed);
    assert.equal(accepted ? stats.failed : stats.completed, 0);
    assert.equal(stats.samples.length, stats.started);
    assert.ok(
      stats.samples.every(
        sample => sample.ok === accepted && sample.bytes > 0 && BigInt(sample.completedNs) >= BigInt(sample.startedNs),
      ),
    );
    assert.equal(Object.hasOwn(stats, 'diagnostics'), false);
    for (const request of requests)
      assert.deepEqual(request, {
        path: '/v1/inventory/snapshot',
        method: 'POST',
        authorization: 'Bearer synthetic-only',
        body: '{"tenantId":"synthetic-admission"}',
      });
    await worker.terminate();
  }
});

test('the owner benchmark entrypoint refuses obsolete direct worker invocation', async () => {
  const worker = new Worker(new URL('./benchmark-admission.mjs', import.meta.url), {
    workerData: { kind: 'workload' },
  });
  try {
    const [error] = await once(worker, 'error');
    assert.equal(error.message, 'ADMISSION_CLIENT_ENTRY_REQUIRED');
  } finally {
    await worker.terminate();
  }
});
