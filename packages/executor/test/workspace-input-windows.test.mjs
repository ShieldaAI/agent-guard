import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { readWindowsWorkspaceInput as read } from '../dist/workspace-input-windows.js';

if (process.platform !== 'win32') {
  test('the Windows workspace reader fails closed on other systems', () => {
    assert.throws(() => read('C:\\workspace', 'selected', 10), /Workspace input/);
  });
} else {
  test('Windows workspace roots accept the operating system temporary-directory alias', t => {
    // Windows runners commonly return a RUNNER~1 ancestor here. Keep that exact
    // spelling to exercise the public caller's path instead of expanding it first.
    const root = mkdtempSync(join(tmpdir(), 'guard-win-alias-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const bytes = Buffer.from([0, 255, 10, 13, 26]);
    writeFileSync(join(root, 'selected.bin'), bytes);
    assert.deepEqual(read(root, 'selected.bin', bytes.length), bytes);
    assert.deepEqual(read(realpathSync.native(root), 'selected.bin', bytes.length), bytes);
  });

  function fixture(t) {
    const temp = realpathSync.native(mkdtempSync(join(tmpdir(), 'guard-win-input-')));
    t.after(() => rmSync(temp, { recursive: true, force: true }));
    const root = join(temp, 'workspace');
    const folder = join(root, 'Documents');
    const outside = join(temp, 'private');
    mkdirSync(folder, { recursive: true });
    mkdirSync(outside);
    const selected = Buffer.from([0, 10, 13, 255, 65, 26]);
    const leaf = 'Selected.bin';
    writeFileSync(join(folder, leaf), selected);
    writeFileSync(join(outside, leaf), 'private bytes');
    return { root, folder, outside, leaf, selected, temp };
  }

  test('Windows pinned workspace read returns exact bytes and rejects junction, hardlink, and alternate-stream inputs',
    { timeout: 120_000 }, t => {
      const { root, folder, outside, leaf, selected } = fixture(t);
      assert.deepEqual(read(root, 'Documents\\' + leaf, selected.length), selected);
      assert.throws(() => read(root, 'Documents/' + leaf, selected.length - 1), /Workspace input/);
      symlinkSync(outside, join(root, 'redirect'), 'junction');
      assert.throws(() => read(root, 'redirect/' + leaf, 64), /symlinks/);
      assert.throws(() => read(join(root, 'redirect'), leaf, 64), /symlinks/);
      assert.throws(() => read(root, 'Documents/' + leaf + ':alternate', 64), /Workspace input/);
      assert.throws(() => read(root, 'documents/' + leaf, 64), /Workspace input/);
      linkSync(join(folder, leaf), join(outside, 'also-selected'));
      assert.throws(() => read(root, 'Documents/' + leaf, 64), /Workspace input/);
    });

  test('Windows concurrent workspace junction swaps cannot return outside bytes', { timeout: 120_000 }, async t => {
    const { root, folder, outside, leaf, selected, temp } = fixture(t);
    const junction = join(root, 'spare'), parked = join(temp, 'parked');
    symlinkSync(outside, junction, 'junction');
    const shared = new SharedArrayBuffer(8);
    const state = new Int32Array(shared);
    const worker = new Worker(`
      const { renameSync } = require('node:fs');
      const { parentPort, workerData } = require('node:worker_threads');
      const { pinned, spare, parked, shared } = workerData;
      const state = new Int32Array(shared);
      const moves = [[pinned,parked],[spare,pinned],[pinned,spare],[parked,pinned]];
      let step = 0;
      while (!Atomics.load(state, 0)) {
        try {
          renameSync(...moves[step]);
          step = (step + 1) % moves.length;
          if (step === 0 && Atomics.add(state, 1, 1) === 0) parentPort.postMessage('swapping');
        } catch (err) {
          if (!['EPERM','EBUSY','EACCES'].includes(err.code)) throw err;
          Atomics.wait(state, 0, 0, 1);
        }
      }
    `, { eval: true, workerData: { pinned: folder, spare: junction, parked, shared } });
    try {
      // Keep renaming in an independent thread while the caller synchronously waits for its reader.
      await once(worker, 'message');
      for (let attempt = 0; attempt < 3; attempt++) {
        let actual;
        try { actual = read(root, 'Documents/' + leaf, 64); }
        catch (error) { assert.match(error.message, /Workspace input/); continue; }
        assert.deepEqual(actual, selected);
      }
      assert(Atomics.load(state, 1) > 1);
    } finally {
      Atomics.store(state, 0, 1);
      await worker.terminate();
    }
  });
}
