import { createCipheriv, createDecipheriv, createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { canonicalJson } from '@shieldaai/agent-guard/internal';
import { historyFailure, validHistoryHead } from './history-state.mjs';

export const MAX_HISTORY_PLAIN = 16 * 1024 * 1024;
const MAX_HISTORY_FILE = 24 * 1024 * 1024;
export const historyHash = value => createHash('sha256').update(value).digest('hex');
export const historyJson = value => canonicalJson(value);
export const tenantHistoryDigest = tenantId => historyHash(`agent-ops-company-history-v1\0${tenantId}`);
function privateDirectory(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || realpathSync(path) !== path) historyFailure('HISTORY_DIRECTORY_REQUIRED');
  for (let current = path; ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.uid !== 0 && stat.uid !== process.geteuid()) ||
        ((stat.mode & 0o022) && !(stat.mode & 0o1000)) ||
        (current === path && (stat.uid !== process.geteuid() || stat.mode & 0o077))) historyFailure('HISTORY_DIRECTORY_UNSAFE');
    if (current === dirname(current)) break;
  }
  return path;
}
function containsDirectory(parent, child) {
  if (parent === child || child.startsWith(`${parent}/`)) return true;
  let parentStat;
  try { parentStat = lstatSync(parent); } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  for (let current = child; ; current = dirname(current)) {
    try { if (same(parentStat, lstatSync(current))) return true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (current === dirname(current)) return false;
  }
}
function independent(left, right) {
  if (containsDirectory(left, right) || containsDirectory(right, left)) historyFailure('HISTORY_DIRECTORY_UNSAFE');
}
export function privateHistoryDirectory(config) {
  const path = privateDirectory(config.historyDirectory);
  for (const file of [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness, config.keyringFile]) independent(path, dirname(file));
  if (config.historyMirrorDirectory) independent(path, config.historyMirrorDirectory);
  return path;
}
/** The recovery copy lives under independent witness custody, never the primary volume. */
export function privateHistoryMirrorDirectory(config) {
  const path = privateDirectory(config.historyMirrorDirectory), witness = privateDirectory(dirname(config.backendWitness));
  if (dirname(path) !== witness) historyFailure('HISTORY_MIRROR_CUSTODY_REQUIRED');
  for (const other of [dirname(config.ledgerDatabase), dirname(config.backendDatabase), dirname(config.keyringFile), config.historyDirectory]) {
    if (typeof other !== 'string') historyFailure('HISTORY_DIRECTORY_REQUIRED');
    independent(path, other);
  }
  return path;
}
export function historyFilename(backendId, tenantId, head) {
  if (!/^[a-f0-9-]{36}$/.test(backendId) || !validHistoryHead(head) || head === null) historyFailure('HISTORY_STATE_INVALID');
  return `b-${backendId}-t-${tenantHistoryDigest(tenantId)}-${String(head.index).padStart(16, '0')}-${head.hash}.agh`;
}
const aad = (backendId, tenantId, index) => Buffer.from(historyJson(['agent-ops-history-v1', backendId, tenantHistoryDigest(tenantId), index]));
export function encryptHistorySegment(backendId, tenantId, pending, payload) {
  const plain = Buffer.from(historyJson(payload));
  if (plain.length > MAX_HISTORY_PLAIN) historyFailure('HISTORY_BATCH_TOO_LARGE');
  const key = Buffer.from(pending.keyBase64, 'base64');
  try {
    const cipher = createCipheriv('aes-256-gcm', key, Buffer.from(pending.ivBase64, 'base64'));
    cipher.setAAD(aad(backendId, tenantId, pending.index));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.from(historyJson({ version: 1, iv: pending.ivBase64, tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }));
  } finally { key.fill(0); plain.fill(0); }
}
export function decryptHistorySegment(bytes, backendId, tenantId, head) {
  if (!validHistoryHead(head) || !head || bytes.length > MAX_HISTORY_FILE || historyHash(bytes) !== head.hash) historyFailure('HISTORY_EVIDENCE_INVALID');
  const key = Buffer.from(head.keyBase64, 'base64'); let plain;
  try {
    const envelope = JSON.parse(bytes.toString('utf8'));
    if (envelope.version !== 1 || typeof envelope.iv !== 'string' || typeof envelope.tag !== 'string' || typeof envelope.ciphertext !== 'string') historyFailure('HISTORY_EVIDENCE_INVALID');
    const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    cipher.setAAD(aad(backendId, tenantId, head.index)); cipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    plain = Buffer.concat([cipher.update(Buffer.from(envelope.ciphertext, 'base64')), cipher.final()]);
    if (plain.length > MAX_HISTORY_PLAIN) historyFailure('HISTORY_EVIDENCE_INVALID');
    const payload = JSON.parse(plain.toString('utf8'));
    if (payload.version !== 1 || payload.backendInstanceId !== backendId || payload.tenantId !== tenantId || payload.index !== head.index ||
        !validHistoryHead(payload.previous) || (payload.previous === null ? head.index !== 1 : payload.previous.index !== head.index - 1)) historyFailure('HISTORY_EVIDENCE_INVALID');
    return payload;
  } catch { historyFailure('HISTORY_EVIDENCE_INVALID'); }
  finally { key.fill(0); plain?.fill(0); }
}
function same(left, right) { return left.dev === right.dev && left.ino === right.ino; }
export function readHistoryFile(directory, filename) {
  if (!/^[a-zA-Z0-9.-]+$/.test(filename) || filename.includes('..')) historyFailure('HISTORY_EVIDENCE_INVALID');
  const path = join(directory, filename); let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd), named = lstatSync(path);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== process.geteuid() || before.mode & 0o077 ||
        before.size > MAX_HISTORY_FILE || !same(before, named)) historyFailure('HISTORY_EVIDENCE_INVALID');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) { const n = readSync(fd, bytes, length, bytes.length - length, length); if (!n) break; length += n; }
    const after = fstatSync(fd);
    if (length !== before.size || before.ctimeMs !== after.ctimeMs || before.mtimeMs !== after.mtimeMs || !same(after, lstatSync(path))) historyFailure('HISTORY_EVIDENCE_INVALID');
    return bytes.subarray(0, length);
  } catch { historyFailure('HISTORY_EVIDENCE_UNAVAILABLE'); }
  finally { if (fd !== undefined) closeSync(fd); }
}
function inspect(path) { try { return lstatSync(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } }
function syncDirectory(path) { const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); try { fsyncSync(fd); } finally { closeSync(fd); } }
/** Immutable final link; a crash may leave only this operation's private temporary ciphertext. */
export function publishHistoryFile(directory, filename, operationId, bytes) {
  if (!/^[a-f0-9-]{36}$/.test(operationId) || bytes.length > MAX_HISTORY_FILE) historyFailure('HISTORY_EVIDENCE_INVALID');
  const path = join(directory, filename), temp = join(directory, `.pending-${operationId}`);
  let staged = inspect(temp), final = inspect(path);
  if (staged) {
    if (!staged.isFile() || staged.isSymbolicLink() || staged.uid !== process.geteuid() || staged.mode & 0o077 ||
        !(staged.nlink === 1 || staged.nlink === 2 && final && same(staged, final))) historyFailure('HISTORY_EVIDENCE_INVALID');
    unlinkSync(temp); syncDirectory(directory);
  }
  if (final) {
    const existing = readHistoryFile(directory, filename);
    if (!existing.equals(bytes)) historyFailure('HISTORY_EVIDENCE_INVALID');
    return;
  }
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  linkSync(temp, path); syncDirectory(directory);
  unlinkSync(temp); syncDirectory(directory);
  if (!readHistoryFile(directory, filename).equals(bytes)) historyFailure('HISTORY_EVIDENCE_INVALID');
}
