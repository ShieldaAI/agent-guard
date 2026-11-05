import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { once } from 'node:events';
import { createLiveEvaluationTransport } from './live-evaluation-transport.mjs';
import { ticketRequest } from '../examples/providers/workflow.mjs';
import { TASK_TEXT } from '../examples/providers/protected-ticket.mjs';

const key = 'synthetic-test-key';
const model = 'fixture-model-1';
const history = [{ role: 'user', content: TASK_TEXT }];
const config = provider => ({ provider, apiKey: key, model, maxOutputTokens: 1024 });
const context = () => ({ signal: new AbortController().signal });

// Intercept the final HTTPS socket constructor only. Real Request serialization, streaming,
// limits and cancellation run through the package's normal restricted HTTP client.
async function localWire(t, respond) {
  const observed = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    respond({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }, res);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const local = new URL('http://127.0.0.1:' + server.address().port);
  const stub = t.mock.method(https, 'request', (url, options, onResponse) => {
    observed.push({ url: url.href, verifyTls: options.rejectUnauthorized, lookup: options.lookup });
    return http.request(local, { method: options.method, headers: options.headers, signal: options.signal, agent: false }, onResponse);
  });
  syncBuiltinESMExports();
  t.after(async () => {
    stub.mock.restore();
    syncBuiltinESMExports();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return observed;
}

for (const provider of ['openai', 'anthropic']) {
  test(provider + ' sends the pinned client-tool request and returns provider-reported usage', async t => {
    let captured;
    const response = { model: model + '-snapshot', usage: { input_tokens: 31, output_tokens: 9 }, metadata: { score: 0.875 } };
    const observed = await localWire(t, (request, res) => {
      captured = request;
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(response));
    });
    const send = createLiveEvaluationTransport(config(provider));
    const request = ticketRequest(provider, model, history, 1024);
    assert.deepEqual(JSON.parse(JSON.stringify(await send(request, context()))), response);
    const body = JSON.parse(captured.body);
    assert.equal(body.model, model);
    assert.deepEqual(body.tools.map(tool => tool.name), ['tickets_read', 'tickets_update']);
    assert.equal(observed.length, 1);
    assert.equal(observed[0].verifyTls, true);
    assert.equal(typeof observed[0].lookup, 'function');
    assert.equal(captured.body.includes(key), false);
    if (provider === 'openai') {
      assert.equal(observed[0].url, 'https://api.openai.com/v1/responses');
      assert.equal(captured.headers.authorization, 'Bearer ' + key);
      assert.equal(captured.headers['x-api-key'], undefined);
      assert.deepEqual(body.include, ['reasoning.encrypted_content']);
      assert.equal(body.store, false);
      assert.equal(body.max_output_tokens, 1024);
    } else {
      assert.equal(observed[0].url, 'https://api.anthropic.com/v1/messages');
      assert.equal(captured.headers['x-api-key'], key);
      assert.equal(captured.headers.authorization, undefined);
      assert.equal(captured.headers['anthropic-version'], '2023-06-01');
      assert.equal(body.max_tokens, 1024);
    }
    assert.equal(body.stream, false);
  });
}

test('live evaluation transport rejects changes to pinned request controls before opening a socket', async t => {
  const observed = await localWire(t, (_, res) => res.end());
  const send = createLiveEvaluationTransport(config('openai'));
  const request = ticketRequest('openai', model, history, 1024);
  for (const change of [
    { store: true }, { model: 'other' }, { previous_response_id: 'hidden-state' },
    { max_output_tokens: 2048 }, { tools: [{ type: 'web_search' }] },
    { input: [{ role: 'user', content: 'x'.repeat(65536) }] },
  ]) {
    await assert.rejects(send({ ...request, ...change }, context()), { message: 'Live provider request failed' });
  }
  await assert.rejects(send(request, { signal: AbortSignal.abort(new Error(key)) }), { message: 'Live provider request failed' });
  assert.equal(observed.length, 0);
  for (const options of [{ provider: '__proto__' }, { model: '' }, { apiKey: key + '\n' }, { maxOutputTokens: 4100 }]) {
    assert.throws(() => createLiveEvaluationTransport({ ...config('openai'), ...options }));
  }
});

test('redirects, provider failures and malformed or oversized streamed bodies fail privately without retry', async t => {
  const replies = [
    res => { res.writeHead(307, { location: 'https://elsewhere.invalid/' }); res.end(); },
    res => { res.writeHead(429); res.end('private diagnostic ' + key); },
    res => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end('{}'); },
    res => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('broken' + key); },
    res => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"usage":{"input_tokens":90,"input_tokens":1}}'); },
    res => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(Buffer.from([0xff])); },
    res => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"large":"'); res.end('x'.repeat(65536) + '"}'); },
  ];
  const observed = await localWire(t, (_, res) => replies.shift()(res));
  const send = createLiveEvaluationTransport(config('anthropic'));
  const request = ticketRequest('anthropic', model, history, 1024);
  const count = replies.length;
  for (let n = 0; n < count; n++) {
    await assert.rejects(send(request, context()), { message: 'Live provider request failed' });
    assert.equal(observed.length, n + 1);
  }
});

test('cancelling an in-flight provider request closes the unfinished body and redacts the reason', async t => {
  const controller = new AbortController();
  let closed;
  await localWire(t, (_, res) => {
    closed = once(res, 'close');
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"unfinished":');
    controller.abort(new Error(key));
  });
  const send = createLiveEvaluationTransport(config('openai'));
  await assert.rejects(send(ticketRequest('openai', model, history, 1024), { signal: controller.signal }), {
    message: 'Live provider request failed',
  });
  await closed;
});
