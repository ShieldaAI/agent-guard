/** Private Linux scheduling policy; no caller-selected PID, environment or native helper. */
import { openSync, readSync, closeSync, constants } from 'node:fs';
import { getPriority, setPriority } from 'node:os';
import { isMainThread } from 'node:worker_threads';
import { ExecutorError } from './store.js';

export type InventoryWorkerScheduling = 'default' | 'linux-background';
export type WorkerSchedulingEvidence = { readonly mode: 'default' } | {
  readonly mode: 'linux-background'; readonly workerTid: number; readonly beforeNice: number; readonly afterNice: number;
};
export function schedulingUnavailable(): ExecutorError { return new ExecutorError('INVENTORY_SCHEDULING_UNAVAILABLE'); }
export function schedulingMode(value: unknown): InventoryWorkerScheduling {
  if (value === undefined || value === 'default') return 'default';
  if (value === 'linux-background') return value;
  throw schedulingUnavailable();
}
function priority(tid: number): number {
  const value = getPriority(tid);
  if (!Number.isInteger(value) || value < -20 || value > 19) throw schedulingUnavailable();
  return value;
}
/** Synchronous open matters: /proc/thread-self must resolve on this JavaScript thread. */
export function currentLinuxThreadPriority(): { readonly tid: number; readonly nice: number } {
  try {
    if (process.platform !== 'linux') throw schedulingUnavailable();
    const fd = openSync('/proc/thread-self/status', constants.O_RDONLY | constants.O_NOFOLLOW);
    const buffer = Buffer.alloc(16 * 1024 + 1); let length = 0;
    try {
      while (length < buffer.length) {
        const count = readSync(fd, buffer, length, buffer.length - length, null);
        if (!count) break; length += count;
      }
    } finally { closeSync(fd); }
    if (length === 0 || length > 16 * 1024) throw schedulingUnavailable();
    const lines = buffer.subarray(0, length).toString('utf8').split('\n');
    const field = (key: string): number => {
      const selected = lines.filter(line => line.startsWith(key + ':'));
      if (selected.length !== 1) throw schedulingUnavailable();
      const value = selected[0]!.slice(key.length + 1).trim();
      if (!/^[1-9][0-9]{0,9}$/.test(value)) throw schedulingUnavailable();
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed > 2_147_483_647) throw schedulingUnavailable();
      return parsed;
    };
    const tid = field('Pid');
    if (field('Tgid') !== process.pid) throw schedulingUnavailable();
    return { tid, nice: priority(tid) };
  } catch { throw schedulingUnavailable(); }
}
export function readLinuxThreadPriority(tid: number): number {
  try {
    if (process.platform !== 'linux' || !Number.isSafeInteger(tid) || tid < 1 || tid > 2_147_483_647) throw schedulingUnavailable();
    return priority(tid);
  } catch { throw schedulingUnavailable(); }
}
export function configureInventoryWorkerScheduling(value: unknown): WorkerSchedulingEvidence {
  const mode = schedulingMode(value);
  if (mode === 'default') return Object.freeze({ mode });
  try {
    if (isMainThread) throw schedulingUnavailable();
    const before = currentLinuxThreadPriority();
    if (before.tid === process.pid) throw schedulingUnavailable();
    const afterNice = Math.min(19, before.nice + 10);
    // This can only lower this native thread's scheduling priority. Nice 19 is already lowest.
    if (afterNice !== before.nice) setPriority(before.tid, afterNice);
    const after = currentLinuxThreadPriority();
    if (after.tid !== before.tid || after.nice !== afterNice) throw schedulingUnavailable();
    return Object.freeze({ mode, workerTid: before.tid, beforeNice: before.nice, afterNice });
  } catch { throw schedulingUnavailable(); }
}
