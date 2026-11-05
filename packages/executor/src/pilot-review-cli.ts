#!/usr/bin/env node
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { parseArgs } from 'node:util';
import { parseEvidenceJson } from './evidence-json.js';
import { verifyPilotReview, type PilotReviewPolicy, type PilotReviewBundle } from './pilot-review.js';

const usage = 'agent-guard-pilot-review --policy PATH --candidate PATH --bundle PATH [--rehearsal]';
const limits = { policy: 32 * 1024, candidate: 64 * 1024 * 1024, bundle: 1024 * 1024 };
type Input = keyof typeof limits;

function policyPath(path: string): string {
  // Use the same physical path for validation and opening. Reject ambiguous traversal
  // so normalizing '..' cannot silently select a different enrollment through a link.
  if (path.split(process.platform === 'win32' ? /[\\/]/u : sep).includes('..')) throw new Error();
  const absolute = resolve(path);
  const parents: string[] = [];
  for (let parent = dirname(absolute); ; parent = dirname(parent)) {
    parents.push(parent);
    if (dirname(parent) === parent) break;
  }
  for (const parent of parents.reverse()) {
    const info = lstatSync(parent);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error();
    if (process.platform !== 'win32') {
      const trustedOwner = info.uid === 0 || info.uid === process.geteuid!();
      // A trusted sticky directory such as /tmp protects each trusted-owned child
      // against replacement. The next iteration (or policy fd check) verifies its owner.
      if (!trustedOwner || ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0)) throw new Error();
    }
  }
  return absolute;
}

function readFile(path: string, kind: Input): Buffer {
  if (kind === 'policy') path = policyPath(path);
  // Open first, then validate the descriptor that supplies the bytes. O_NOFOLLOW
  // rejects leaf links on POSIX; named identity checks also cover Windows, where
  // that flag is unavailable. O_NONBLOCK avoids waiting on a substituted FIFO.
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    const named = lstatSync(path, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.size > BigInt(limits[kind]) ||
        !named.isFile() || named.nlink !== 1n || opened.dev !== named.dev || opened.ino !== named.ino ||
        opened.size !== named.size || opened.ctimeNs !== named.ctimeNs) throw new Error();
    if (process.platform !== 'win32') {
      if (kind === 'policy' && ((opened.mode & 0o022n) !== 0n ||
          (opened.uid !== 0n && opened.uid !== BigInt(process.geteuid!())))) throw new Error();
      if (kind === 'bundle' && (opened.mode & 0o077n) !== 0n) throw new Error();
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) throw new Error();
      offset += count;
    }
    const end = fstatSync(fd, { bigint: true });
    const finalName = lstatSync(path, { bigint: true });
    if (end.size !== opened.size || end.ctimeNs !== opened.ctimeNs || end.mtimeNs !== opened.mtimeNs ||
        !finalName.isFile() || finalName.nlink !== 1n || finalName.dev !== opened.dev ||
        finalName.ino !== opened.ino || finalName.ctimeNs !== opened.ctimeNs) throw new Error();
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function inputs(args: string[]) {
  const { values, tokens } = parseArgs({ args, tokens: true, allowPositionals: false, options: {
    policy: { type: 'string' }, candidate: { type: 'string' }, bundle: { type: 'string' },
    rehearsal: { type: 'boolean' },
  } });
  const seen = new Set<string>();
  for (const token of tokens) {
    if (token.kind !== 'option' || seen.has(token.name)) throw new Error();
    seen.add(token.name);
  }
  if (!values.policy || !values.candidate || !values.bundle) throw new Error();
  return { policy: values.policy, candidate: values.candidate, bundle: values.bundle, rehearsal: values.rehearsal };
}

function main(args: string[]): void {
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write(usage + '\n');
    return;
  }
  let options;
  try {
    options = inputs(args);
  } catch {
    process.stderr.write(usage + '\n');
    process.exitCode = 1;
    return;
  }

  let policy, candidate, bundle;
  try {
    policy = parseEvidenceJson(readFile(options.policy, 'policy'), limits.policy) as unknown as PilotReviewPolicy;
    candidate = readFile(options.candidate, 'candidate');
    bundle = parseEvidenceJson(readFile(options.bundle, 'bundle'), limits.bundle) as unknown as PilotReviewBundle;
  } catch {
    process.stderr.write('Could not read pilot inputs. Check file types, permissions, sizes and JSON.\n');
    process.exitCode = 1;
    return;
  }
  try {
    const expected = options.rehearsal ? 'rehearsal' : 'company-pilot';
    if (policy?.mode && policy.mode !== expected) {
      process.stderr.write('The enrolled mode differs from the requested pilot mode.\n');
      process.exitCode = 1;
      return;
    }
    const result = verifyPilotReview(policy, candidate, bundle, expected);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch {
    process.stderr.write('Pilot review verification failed.\n');
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
