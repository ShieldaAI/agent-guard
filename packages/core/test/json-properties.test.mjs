import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson, digestJson, immutableJson } from '@shieldaai/agent-guard/internal';
import { random, jsonValue, reorder } from './helpers/random.mjs';

const SEEDS = Array.from({ length: 400 }, (_, index) => 0x5eed + index);

test('canonicalJson is stable under object key order', () => {
  for (const seed of SEEDS) {
    const rng = random(seed);
    const value = jsonValue(rng);
    assert.equal(canonicalJson(reorder(rng, value)), canonicalJson(value), `seed ${seed}`);
    assert.equal(digestJson(reorder(rng, value)), digestJson(value), `seed ${seed}`);
  }
});

test('canonicalJson round-trips and digestJson is sha256 of it', () => {
  for (const seed of SEEDS) {
    const value = jsonValue(random(seed));
    const text = canonicalJson(value);
    assert.deepEqual(JSON.parse(text), JSON.parse(JSON.stringify(value)), `seed ${seed}`);
    assert.equal(digestJson(value), createHash('sha256').update(text).digest('hex'), `seed ${seed}`);
    assert.equal(canonicalJson(immutableJson(value)), text, `seed ${seed}: normalization keeps the canonical form`);
  }
});

test('canonicalJson is injective: equal encodings mean equal JSON values', () => {
  const seen = new Map();
  for (const seed of Array.from({ length: 3000 }, (_, index) => 0xc0de + index)) {
    const value = jsonValue(random(seed));
    const text = canonicalJson(value);
    const normalized = JSON.parse(JSON.stringify(value));
    if (seen.has(text)) assert.deepEqual(normalized, seen.get(text), `seed ${seed} collides with a different value`);
    else seen.set(text, normalized);
  }
});

test('values that differ only in JSON type never share a digest', () => {
  const groups = [
    [1, '1', [1], { 1: 1 }, true, 'true', null, 'null', [], {}, '', 0, '0', false],
    [{ a: [1] }, { a: '[1]' }, { a: { 0: 1 } }, [{ a: 1 }], { '{"a":1}': null }],
    [['a', 'b'], ['ab'], 'a,b', { a: 'b' }, [['a'], 'b']],
  ];
  for (const group of groups) {
    assert.equal(new Set(group.map(digestJson)).size, group.length, JSON.stringify(group));
  }
});
