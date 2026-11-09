import assert from 'node:assert/strict';
import test from 'node:test';
import { parseEvidenceJson } from '../dist/evidence-json.js';

const read = text => parseEvidenceJson(Buffer.from(text), 1024 * 1024);

test('evidence token walk preserves long escaped strings and ignores their apparent JSON tokens', () => {
  const text = '\\"{\"count\":9007199254740993}'.repeat(8192);
  const result = read(JSON.stringify({ text, count: 4, fractions: [0.125, -0.5, 1e-3] }));
  assert.equal(result.text, text);
  assert.equal(result.count, 4);
  assert.deepEqual(result.fractions, [0.125, -0.5, 1e-3]);
  assert.throws(() => read('{"text":"' + '\\\\"'.repeat(16384)));
});

test('evidence token walk rejects duplicate decoded members in their own object scope', () => {
  for (const text of ['{"key":1,"\\u006bey":2}', '{"outer":[{"key":1,"key":2}]}', '{"":1,"":2}']) {
    assert.throws(() => read(text), /Duplicate JSON member/);
  }
  assert.deepEqual(JSON.parse(JSON.stringify(read('{"key":1,"nested":{"key":2},"list":[{"key":3},{"key":4}]}'))), {
    key: 1,
    nested: { key: 2 },
    list: [{ key: 3 }, { key: 4 }],
  });
});

test('evidence token walk retains exact integer and fractional-measurement checks', () => {
  for (const token of ['9007199254740992', '-9007199254740993', '1e309', '1e-999', '1.000000000000000001']) {
    assert.throws(() => read('{"count":' + token + '}'));
  }
  assert.deepEqual(read('[0,-1,9007199254740991,1.00,1e2,0.125]'), [0, -1, 9007199254740991, 1, 100, 0.125]);
});
