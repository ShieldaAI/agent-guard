import { DatabaseSync } from 'node:sqlite';
import { createDecipheriv, createHash } from 'node:crypto';
import { closeSync, constants, openSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Ledger } from './store.js';
import { checkPrivate, custodyFail, privateDirectory } from './custody-files.js';

/** Reads immutable encrypted snapshots against an independently authenticated commitment. */
export class CustodySnapshot {
  readonly #db: DatabaseSync;
  readonly #key: Buffer;
  readonly #ownsDatabase: boolean;
  constructor(path: string, key: Uint8Array, readonly commitment: string, options: {database?:DatabaseSync} = {}) {
    privateDirectory(dirname(path));
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try { checkPrivate(fd, path); } finally { closeSync(fd); }
    this.#key = Buffer.from(key);
    this.#ownsDatabase = options.database === undefined;
    this.#db = options.database ?? new DatabaseSync(path, { readOnly: true });
    try { if (this.#ownsDatabase) this.#db.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON'); this.read(); }
    catch { this.close(); custodyFail('CUSTODY_SNAPSHOT_INVALID'); }
  }
  read(): Ledger {
    let plain: Buffer | undefined;
    try {
      const payload = this.#db.prepare("SELECT payload FROM ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(128 * 1024 * 1024 + 512)?.payload;
      if (typeof payload !== 'string' || createHash('sha256').update(payload).digest('hex') !== this.commitment) custodyFail('CUSTODY_SNAPSHOT_INVALID');
      const parts: unknown = JSON.parse(payload);
      if (!Array.isArray(parts) || parts.length !== 3 || parts.some(p => typeof p !== 'string')) custodyFail('CUSTODY_SNAPSHOT_INVALID');
      const [iv, tag, ciphertext] = (parts as string[]).map(p => Buffer.from(p, 'base64'));
      if (iv!.length !== 12 || tag!.length !== 16 || ciphertext!.length > 64 * 1024 * 1024) custodyFail('CUSTODY_SNAPSHOT_INVALID');
      const decipher = createDecipheriv('aes-256-gcm', this.#key, iv!);
      decipher.setAAD(Buffer.from('agent-guard-witnessed-ledger-v1')); decipher.setAuthTag(tag!);
      plain = Buffer.concat([decipher.update(ciphertext!), decipher.final()]);
      const state = JSON.parse(plain.toString('utf8'), (_k, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.assign(Object.create(null), v) : v) as Ledger;
      if (![1, 2, 3].includes(state.schema) || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions || typeof state.inventoryInstanceId !== 'string') custodyFail('CUSTODY_SNAPSHOT_INVALID');
      return state;
    } catch { return custodyFail('CUSTODY_SNAPSHOT_INVALID'); }
    finally { plain?.fill(0); }
  }
  readArchive(id: string): string {
    const payload = this.#db.prepare("SELECT payload FROM authority_archives WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(id, 32 * 1024 * 1024)?.payload;
    if (typeof payload !== 'string') custodyFail('CUSTODY_SNAPSHOT_INVALID');
    return payload;
  }
  /** Bounded ciphertext inventory, including rows outside a host catalog. */
  auxiliaryDigest(table: 'authority_archives' | 'custody_catalog'): string {
    const digest=createHash('sha256').update(`guard-snapshot-${table}-v1\0`);
    if(!this.#db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name=?").get(table))return digest.digest('hex');
    const cap=table==='authority_archives'?32*1024*1024:131072;let count=0,bytes=0;
    for(const row of this.#db.prepare(`SELECT CASE WHEN typeof(id)='text' AND length(id)<=128 THEN id END AS id, CASE WHEN typeof(payload)='text' AND length(CAST(payload AS BLOB))<=? THEN payload END AS payload FROM ${table} ORDER BY id`).iterate(cap)){
      if(typeof row.id!=='string'||typeof row.payload!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(row.id))custodyFail('CUSTODY_SNAPSHOT_INVALID');
      if(++count>(table==='authority_archives'?4096:100000)||(bytes+=Buffer.byteLength(row.payload))>256*1024*1024)custodyFail('CUSTODY_SNAPSHOT_INVALID');
      digest.update(row.id).update('\0').update(row.payload).update('\0');
    }
    return digest.digest('hex');
  }
  close(): void { if (this.#ownsDatabase) this.#db.close(); this.#key.fill(0); }
}
