import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import os from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import { configureInventoryWorkerScheduling, currentLinuxThreadPriority } from '../../dist/inventory-scheduling.js';

if (workerData.kind === 'actual') {
  const before = currentLinuxThreadPriority();
  const evidence = configureInventoryWorkerScheduling(workerData.mode);
  parentPort.on('message', () => parentPort.postMessage(currentLinuxThreadPriority()));
  parentPort.postMessage({ before, evidence, after: currentLinuxThreadPriority() });
} else {
  // Test-local native boundary substitution, never a production injection API.
  const name = workerData.case;
  Object.defineProperty(process, 'platform', { value: name === 'nonlinux' ? 'darwin' : 'linux' });
  const tid = process.pid + 1, initialNice = name === 'negative' ? -20 : name === 'clamp' ? 18 : name === 'lowest' ? 19 : 0;
  let nice = initialNice, offset = 0, opened = 0, closed = 0, reads = 0;
  const calls = [], setCalls = []; let status = '';
  fs.openSync = (path, flags) => {
    if (path !== '/proc/thread-self/status' || flags !== (fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)) throw new Error('unexpected-open');
    opened++; offset = 0;
    if (name === 'open-failure') throw new Error('private-open-failure');
    status = `Pid:\t${tid}\nTgid:\t${process.pid}\n`;
    if (name === 'empty') status = '';
    if (name === 'missing') status = `Pid:\t${tid}\n`;
    if (name === 'duplicate') status += `Pid:\t${tid}\n`;
    if (name === 'wrong-group') status = `Pid:\t${tid}\nTgid:\t${process.pid + 1}\n`;
    if (name === 'main-tid') status = `Pid:\t${process.pid}\nTgid:\t${process.pid}\n`;
    if (name === 'zero') status = `Pid:\t0\nTgid:\t${process.pid}\n`;
    if (name === 'negative-id') status = `Pid:\t-1\nTgid:\t${process.pid}\n`;
    if (name === 'leading-zero') status = `Pid:\t0${tid}\nTgid:\t${process.pid}\n`;
    if (name === 'overflow') status = `Pid:\t2147483648\nTgid:\t${process.pid}\n`;
    if (name === 'oversize') status += 'x'.repeat(16 * 1024);
    if (name === 'changed-tid' && opened > 1) status = `Pid:\t${tid + 1}\nTgid:\t${process.pid}\n`;
    return 123;
  };
  fs.readSync = (fd, buffer, start, length, position) => {
    if (fd !== 123 || position !== null) throw new Error('unexpected-read'); reads++;
    if (name === 'read-failure') throw new Error('private-read-failure');
    const bytes = Buffer.from(status), size = Math.min(length, name === 'chunked' ? 7 : length, bytes.length - offset);
    bytes.copy(buffer, start, offset, offset + size); offset += size; return size;
  };
  fs.closeSync = fd => { if (fd !== 123) throw new Error('unexpected-close'); closed++; };
  os.getPriority = id => { calls.push(id); return name === 'bad-nice' ? 20 : name === 'nan-nice' ? NaN : nice; };
  os.setPriority = (id, value) => {
    setCalls.push({ id, value });
    if (name === 'set-failure') throw new Error('private-set-failure');
    if (name !== 'readback-failure') nice = value;
  };
  syncBuiltinESMExports();
  let evidence = null, code = null, message = null;
  try { evidence = configureInventoryWorkerScheduling(name === 'default' ? 'default' : 'linux-background'); }
  catch (error) { code = error.code; message = error.message; }
  parentPort.postMessage({ evidence, code, message, tid, initialNice, nice, opened, closed, reads, calls, setCalls });
}
