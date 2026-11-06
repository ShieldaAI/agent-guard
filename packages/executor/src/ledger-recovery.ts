import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdtempSync, openSync, renameSync, rmdirSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { LedgerStore, type Ledger } from './store.js';
import { withLedgerKeyringState, type LedgerKey, type ParsedKeyring } from './ledger-maintenance.js';
import { CustodySnapshot } from './custody-snapshot.js';
import { verifyAllArchiveStorage } from './lifecycle.js';
import { checkPrivate, copyPrivate, custodyFail as fail, independentDirectories, privateDirectory, syncDirectory } from './custody-files.js';
import type { CustodyStore, CustodyHistoryAdapter } from './ledger-custody.js';

export interface LedgerRecoveryOptions {
  readonly keyringFile: string;
  readonly stores: readonly CustodyStore[];
  readonly history?: CustodyHistoryAdapter & {readonly recoveryDirectory:string};
}
export interface LedgerRecoveryResult {
  readonly operation:'enroll'|'repair'; readonly applied:boolean; readonly digest:string;
  readonly stores:number; readonly alreadyMirrored:number; readonly historyFiles:number;
  readonly historyReenrollmentRequired:boolean;
}
const maximum=64*1024*1024, hashPattern=/^[a-f0-9]{64}$/;
const sha=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex');
const stable=(value:unknown)=>JSON.stringify(value,(_key,item:unknown)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.entries(item).sort(([a],[b])=>a<b?-1:a>b?1:0)):item);
type Reader=Pick<LedgerStore,'read'|'readArchive'>;
function validate(options:LedgerRecoveryOptions):void {
  if (!['linux','darwin'].includes(process.platform)||!Array.isArray(options.stores)||!options.stores.length||options.stores.length>16||
      options.stores.some(s=>!s||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(s.id))||new Set(options.stores.map(s=>s.id)).size!==options.stores.length) fail('RECOVERY_CONFIG_INVALID');
  const paths=[options.keyringFile,...options.stores.flatMap(s=>[s.database,s.witnessPath])];
  if(new Set(paths).size!==paths.length)fail('RECOVERY_CONFIG_INVALID');
  paths.forEach(path=>{if(typeof path!=='string'||path.length>512)fail('RECOVERY_CONFIG_INVALID');privateDirectory(dirname(path));});
  const data=[...new Set(options.stores.map(s=>dirname(s.database)))],witness=[...new Set(options.stores.map(s=>dirname(s.witnessPath)))];
  independentDirectories([...data,...witness,dirname(options.keyringFile)]);
  if(options.history){
    // The history mirror may be a private child of witness custody, but must be
    // independent from all primary data, primary history and active-key roots.
    independentDirectories([options.history.directory,...data,...witness,dirname(options.keyringFile)]);
    independentDirectories([options.history.recoveryDirectory,options.history.directory,...data,dirname(options.keyringFile)]);
  }
}
function scope(ring:ParsedKeyring,source:CustodyStore,state:Ledger):void {
  const custody=(state as Ledger&{keyCustody?:string}).keyCustody;
  if(ring.managed){
    const member=ring.managed.stores.find(m=>m.database===source.database&&m.witnessPath===source.witnessPath);
    if(!member||member.inventoryInstanceId!==state.inventoryInstanceId||custody!==ring.managed.id)fail('RECOVERY_SCOPE_MISMATCH');
  }else if(custody!==undefined)fail('RECOVERY_SCOPE_MISMATCH');
}
function closure(options:LedgerRecoveryOptions,readers:Map<string,Reader>):readonly{name:string;sha256:string}[]{
  let external=0;for(const reader of readers.values())external+=verifyAllArchiveStorage(reader).externalHistories;
  if(external&&!options.history)fail('RECOVERY_HISTORY_REQUIRED');
  const files=options.history?.verify(readers,options.history.recoveryDirectory)??[];
  if(files.length>20000)fail('RECOVERY_HISTORY_CAPACITY');
  const names=new Set<string>();
  for(const file of files){
    if(!/^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,240}$/.test(file.name)||!hashPattern.test(file.sha256)||names.has(file.name))fail('RECOVERY_HISTORY_INVALID');
    names.add(file.name);copyPrivate(join(options.history!.recoveryDirectory,file.name),undefined,file.sha256);
  }
  return files;
}
class Mirror {
  readonly db:DatabaseSync; readonly reader:CustodySnapshot; readonly commitment:string; readonly key:LedgerKey;
  constructor(path:string,keys:readonly LedgerKey[]){
    const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try{checkPrivate(fd,path);}finally{closeSync(fd);}
    // Open the surviving witness through SQLite first. Its hot journal and
    // super-journal are resolved before any bytes are treated as current.
    this.db=new DatabaseSync(path);let reader:CustodySnapshot|undefined,key:LedgerKey|undefined;
    try{
      this.db.exec('PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE');
      const value=this.db.prepare('SELECT digest FROM commitment WHERE id=1').get()?.digest;
      if(typeof value!=='string'||!hashPattern.test(value))fail('RECOVERY_MIRROR_UNAVAILABLE');this.commitment=value;
      for(const candidate of keys){try{reader=new CustodySnapshot(path,candidate.key,value,{database:this.db});key=candidate;break;}catch{/* No authority changes while selecting a retained key. */}}
      if(!reader||!key)fail('RECOVERY_KEY_UNAVAILABLE');
      const state=reader.read() as Ledger&{recoveryMirror?:unknown;custody?:{catalogDigest?:unknown}};
      if(state.schema!==3||state.recoveryMirror!==1)fail('RECOVERY_NOT_ENROLLED');
      verifyAllArchiveStorage(reader);
      // Custody catalogs are ciphertext authenticated by their encrypted head.
      if(state.custody){const digest=createHash('sha256').update('agent-guard-custody-catalog-v1\0');let count=0;
        for(const row of this.rows('custody_catalog',131072)){if(++count>100000)fail('RECOVERY_CAPACITY');digest.update(row.id).update('\0').update(row.payload).update('\0');}
        if(digest.digest('hex')!==state.custody.catalogDigest)fail('RECOVERY_MIRROR_CORRUPT');
      }
      this.db.exec('COMMIT');this.reader=reader;this.key=key;
    }catch(error){reader?.close();this.db.close();throw error;}
  }
  *rows(table:'authority_archives'|'custody_catalog',cap:number):Iterable<{id:string;payload:string}>{
    const statement=this.db.prepare(`SELECT CASE WHEN typeof(id)='text' AND length(id)<=128 THEN id END AS id, CASE WHEN typeof(payload)='text' AND length(CAST(payload AS BLOB))<=? THEN payload END AS payload FROM ${table} ORDER BY id`);
    for(const row of statement.iterate(cap)){if(typeof row.id!=='string'||typeof row.payload!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(row.id))fail('RECOVERY_MIRROR_CORRUPT');yield{id:row.id,payload:row.payload};}
  }
  snapshot(path:string):void{
    const fd=openSync(path,constants.O_CREAT|constants.O_EXCL|constants.O_RDWR|constants.O_NOFOLLOW,0o600);closeSync(fd);
    const output=new DatabaseSync(path);
    try{
      output.exec('PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; BEGIN IMMEDIATE; CREATE TABLE ledger(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL); CREATE TABLE authority_archives(id TEXT PRIMARY KEY,payload TEXT NOT NULL); CREATE TABLE custody_catalog(id TEXT PRIMARY KEY,payload TEXT NOT NULL)');
      const payload=this.db.prepare("SELECT payload FROM ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(maximum*2+512)?.payload;
      if(typeof payload!=='string'||sha(payload)!==this.commitment)fail('RECOVERY_MIRROR_CORRUPT');output.prepare('INSERT INTO ledger(id,payload) VALUES(1,?)').run(payload);
      for(const table of ['authority_archives','custody_catalog'] as const){const insert=output.prepare(`INSERT INTO ${table}(id,payload) VALUES(?,?)`);let count=0,bytes=0;
        for(const row of this.rows(table,table==='authority_archives'?32*1024*1024:131072)){count++;bytes+=Buffer.byteLength(row.payload);
          if((table==='authority_archives'&&(count>4096||bytes>256*1024*1024))||(table==='custody_catalog'&&(count>100000||bytes>256*1024*1024)))fail('RECOVERY_CAPACITY');insert.run(row.id,row.payload);}}
      output.exec('COMMIT');
    }finally{output.close();}
    const synced=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);try{fsyncSync(synced);}finally{closeSync(synced);}syncDirectory(dirname(path));
    this.verifySnapshot(path);
  }
  verifySnapshot(path:string):void{
    const expected=new Map((['authority_archives','custody_catalog'] as const).map(table=>[table,this.reader.auxiliaryDigest(table)]));
    const verified=new CustodySnapshot(path,this.key.key,this.commitment);try{verifyAllArchiveStorage(verified);for(const [table,digest]of expected)if(verified.auxiliaryDigest(table)!==digest)fail('RECOVERY_MIRROR_CORRUPT');}finally{verified.close();}
  }
  close():void{this.reader.close();this.db.close();}
}
function preserve(path:string,name:string):void{
  // Capture the directory entry atomically, without an existence check or any
  // attempt to follow/read a possibly damaged original. A fresh private directory
  // prevents overwriting another retained original. Even dangling symlinks and
  // interrupted publication hard links remain opaque preserved evidence.
  const parent=dirname(path),retained=mkdtempSync(join(parent,`${name}-`));
  syncDirectory(retained);syncDirectory(parent);
  try{renameSync(path,join(retained,'original'));}
  catch(error){
    if((error as NodeJS.ErrnoException).code==='ENOENT'){rmdirSync(retained);syncDirectory(parent);return;}
    throw error;
  }
  syncDirectory(retained);syncDirectory(parent);
}
function publish(staged:string,target:string,verify:(path:string)=>void):void{
  const source=openSync(staged,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const original=checkPrivate(source,staged);
    // Exclusive link creation cannot overwrite an entry that appeared after
    // preservation. Both names are in the same private filesystem directory.
    try{linkSync(staged,target);}
    catch(error){if((error as NodeJS.ErrnoException).code==='EEXIST')fail('RECOVERY_PUBLICATION_CHANGED');throw error;}
    const output=openSync(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try{
      const linked=fstatSync(output);
      if(linked.dev!==original.dev||linked.ino!==original.ino||linked.size!==original.size||linked.mtimeMs!==original.mtimeMs||linked.nlink!==2)fail('RECOVERY_PUBLICATION_CHANGED');
      fsyncSync(output);syncDirectory(dirname(target));
      unlinkSync(staged);syncDirectory(dirname(target));
      const published=checkPrivate(output,target);
      if(published.size!==original.size||published.mtimeMs!==original.mtimeMs)fail('RECOVERY_PUBLICATION_CHANGED');
      verify(target);
    }finally{closeSync(output);}
  }finally{closeSync(source);}
}
/** Exact current-state repair. No witness, task identity, quota or epoch is reset. */
export function manageLedgerRecovery(options:LedgerRecoveryOptions,request:{readonly operation:'enroll'|'repair'},apply?:{readonly expectedDigest:string}):LedgerRecoveryResult{
  validate(options);if(!['enroll','repair'].includes(request.operation)||(apply&&!hashPattern.test(apply.expectedDigest)))fail('RECOVERY_REQUEST_INVALID');
  return withLedgerKeyringState(options.keyringFile,ring=>{
    if(ring.managed&&(ring.managed.stores.length!==options.stores.length||ring.managed.stores.some(member=>!options.stores.some(source=>source.database===member.database&&source.witnessPath===member.witnessPath))))fail('RECOVERY_SCOPE_MISMATCH');
    const stores=new Map<string,LedgerStore>(),mirrors=new Map<string,Mirror>(),readers=new Map<string,Reader>();
    try{
      for(const source of options.stores){
        if(request.operation==='repair'){const mirror=new Mirror(source.witnessPath,ring.keys);mirrors.set(source.id,mirror);scope(ring,source,mirror.reader.read());readers.set(source.id,mirror.reader);}
        else{let opened:LedgerStore|undefined;for(const key of ring.keys){try{opened=new LedgerStore(source.database,key.key,maximum,{path:source.witnessPath,mode:'resume'},{existingOnly:true});break;}catch{}}
          if(!opened)fail('RECOVERY_STORE_UNAVAILABLE');stores.set(source.id,opened);scope(ring,source,opened.read());readers.set(source.id,opened);}
      }
      const files=closure(options,readers),alreadyMirrored=[...readers.values()].filter(r=>(r.read() as Ledger&{recoveryMirror?:unknown}).recoveryMirror===1).length;
      const digest=sha(stable({operation:request.operation,keyringFile:options.keyringFile,keys:ring.keys.map(k=>[k.keyId,sha(k.key)]),stores:options.stores.map(source=>({ ...source,
        directory:(()=>{const stat=lstatSync(dirname(source.database));return{dev:String(stat.dev),ino:String(stat.ino)};})(),
        commitment:mirrors.get(source.id)?.commitment??stores.get(source.id)!.snapshotCommitment()})),history:options.history?{directory:options.history.directory,recoveryDirectory:options.history.recoveryDirectory,files}:null}));
      const result:LedgerRecoveryResult={operation:request.operation,applied:!!apply,digest,stores:options.stores.length,alreadyMirrored,historyFiles:files.length,historyReenrollmentRequired:request.operation==='repair'&&!!options.history};
      if(!apply)return result;if(apply.expectedDigest!==digest)fail('RECOVERY_PREVIEW_CHANGED');
      if(request.operation==='enroll'){for(const store of stores.values())store.enableRecoveryMirror();return{...result,alreadyMirrored:stores.size};}
      const id=randomUUID(),staged=new Map<string,string>();
      // Validate every staged current store before changing any primary path.
      for(let index=0;index<options.stores.length;index++){const source=options.stores[index]!,path=join(dirname(source.database),`.guard-repair-${id}-${index}`);mirrors.get(source.id)!.snapshot(path);staged.set(source.id,path);}
      const historyStages=new Map<string,string>();
      for(const file of files){const path=join(options.history!.directory,`.guard-history-repair-${id}-${sha(file.name)}`);copyPrivate(join(options.history!.recoveryDirectory,file.name),path,file.sha256);historyStages.set(file.name,path);}
      for(let index=0;index<options.stores.length;index++){const source=options.stores[index]!;
        for(const suffix of ['', '-journal','-wal','-shm'])preserve(source.database+suffix,`.guard-original-${id}-${index}${suffix||'.sqlite'}`);
        publish(staged.get(source.id)!,source.database,path=>mirrors.get(source.id)!.verifySnapshot(path));
      }
      for(const file of files){const target=join(options.history!.directory,file.name);preserve(target,`.guard-history-original-${id}-${sha(file.name)}`);publish(historyStages.get(file.name)!,target,path=>{copyPrivate(path,undefined,file.sha256);});}
      return result;
    }finally{for(const store of stores.values())store.close();for(const mirror of mirrors.values())mirror.close();}
  });
}
