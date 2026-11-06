import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { LedgerStore } from '../dist/store.js';
import { LedgerStore as Schema2Store } from './fixtures/schema2-store.mjs';
import { manageLedgerRecovery } from '../dist/ledger-recovery.js';
import { createLedgerKeyring,readLedgerKeyring,loadLedgerKey,rotateLedgerKeyring } from '../dist/ledger-maintenance.js';
const test=(name,fn)=>nodeTest(name,{skip:process.platform==='win32'},fn);
const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(t,mirror=true){
 const root=fs.realpathSync(fs.mkdtempSync(join(tmpdir(),'guard-current-recovery-')));for(const dir of ['data','witness','keys'])fs.mkdirSync(join(root,dir),{mode:0o700});t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const options={keyringFile:join(root,'keys','ring.json'),stores:['a','b'].map(id=>({id,database:join(root,'data',id+'.sqlite'),witnessPath:join(root,'witness',id+'.sqlite')}))};
 createLedgerKeyring({keyringFile:options.keyringFile,keyId:'initial'});const keys=readLedgerKeyring(options);const key=keys[0].key;t.after(()=>key.fill(0));
 for(const source of options.stores){const store=new LedgerStore(source.database,key,64*1024*1024,{path:source.witnessPath,mode:'create',...(mirror?{recovery:'mirror'}:{})});store.transaction(s=>{if(s.schema===1)s.schema=2;s.audit.push({time:1,event:'previous acknowledged authority'});});store.close();}
 const open=(index=0)=>{const source=options.stores[index],selected=loadLedgerKey({...source,keyringFile:options.keyringFile,maxBytes:64*1024*1024});try{return new LedgerStore(source.database,selected.key,64*1024*1024,{path:source.witnessPath,mode:'resume'},{existingOnly:true});}finally{selected.key.fill(0);}};
 const apply=operation=>{const preview=manageLedgerRecovery(options,{operation});return manageLedgerRecovery(options,{operation},{expectedDigest:preview.digest});};return{root,options,key,open,apply};
}
test('new mirrored stores atomically preserve current payload, archives and catalog through rotation and primary loss',t=>{
 const f=fixture(t);let s=f.open();s.transaction((state,archive)=>{state.epoch=7;state.audit.push({time:2,event:'new acknowledged authority'});archive.putArchive('retained','encrypted-retained-value');archive.putCustodyRecord('record','encrypted-catalog-value');});s.close();
 for(const source of f.options.stores)rotateLedgerKeyring({...source,keyringFile:f.options.keyringFile,nextKeyId:'second',maxBytes:64*1024*1024});
 const before=f.options.stores.map(source=>fs.readFileSync(source.witnessPath));fs.rmSync(join(f.root,'data'),{recursive:true});fs.mkdirSync(join(f.root,'data'),{mode:0o700});
 assert.equal(f.apply('repair').alreadyMirrored,2);s=f.open();assert.equal(s.read().schema,3);assert.equal(s.read().epoch,7);assert.equal(s.read().audit.at(-1).event,'new acknowledged authority');assert.equal(s.readArchive('retained'),'encrypted-retained-value');assert.deepEqual([...s.custodyRecords()],[{id:'record',ciphertext:'encrypted-catalog-value'}]);s.close();
 f.options.stores.forEach((source,index)=>assert.deepEqual(fs.readFileSync(source.witnessPath),before[index]));
});
test('explicit legacy enrollment fences the actual schema2 reader without resetting authority',t=>{
 const f=fixture(t,false),source=f.options.stores[0];const old=new Schema2Store(source.database,f.key,undefined,{path:source.witnessPath,mode:'resume'},{existingOnly:true});assert.equal(old.read().schema,2);old.close();
 const preview=manageLedgerRecovery(f.options,{operation:'enroll'});assert.equal(preview.alreadyMirrored,0);f.apply('enroll');
 const data=fs.readFileSync(source.database),witness=fs.readFileSync(source.witnessPath);assert.throws(()=>new Schema2Store(source.database,f.key,undefined,{path:source.witnessPath,mode:'resume'},{existingOnly:true}));
 assert.deepEqual(fs.readFileSync(source.database),data);assert.deepEqual(fs.readFileSync(source.witnessPath),witness);const current=f.open();assert.equal(current.read().audit[0].event,'previous acknowledged authority');current.close();
});
test('mirrored mode cannot be disabled and mirror write failure rolls back current authority',t=>{
 const f=fixture(t),source=f.options.stores[0];let s=f.open();assert.throws(()=>s.transaction(state=>{delete state.recoveryMirror;}),{code:'STORE_RECOVERY_MODE_CHANGED'});assert.throws(()=>s.transaction(state=>{state.schema=2;}),{code:'STORE_RECOVERY_MODE_CHANGED'});s.close();
 const db=new DatabaseSync(source.witnessPath);db.exec("CREATE TRIGGER fail_mirror BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT,'mirror failure'); END");db.close();s=f.open();const before=s.read();assert.throws(()=>s.transaction(state=>{state.epoch=99;}));assert.deepEqual(s.read(),before);s.close();
});
test('archive deletion and mirror corruption cannot produce an accepted partial recovery',t=>{
 const f=fixture(t),source=f.options.stores[0];let s=f.open();s.transaction((_state,a)=>a.putArchive('item','cipher'));assert.throws(()=>s.transaction((_state,a)=>{a.deleteArchive('item',sha('cipher'));throw Error('abort');}));assert.equal(s.readArchive('item'),'cipher');s.transaction((_state,a)=>a.deleteArchive('item',sha('cipher')));s.close();
 let db=new DatabaseSync(source.witnessPath);assert.equal(db.prepare('SELECT count(*) AS n FROM authority_archives').get().n,0);db.prepare('UPDATE ledger SET payload=? WHERE id=1').run('changed');db.close();
 const before=fs.readFileSync(source.database);assert.throws(()=>manageLedgerRecovery(f.options,{operation:'repair'}));assert.deepEqual(fs.readFileSync(source.database),before);assert.throws(()=>f.open());
});
test('repair refuses active owners and stale reviewed commitments',t=>{
 const f=fixture(t);let s=f.open();assert.throws(()=>manageLedgerRecovery(f.options,{operation:'repair'}));s.close();
 const preview=manageLedgerRecovery(f.options,{operation:'repair'});s=f.open();s.transaction(state=>{state.epoch++;});s.close();assert.throws(()=>manageLedgerRecovery(f.options,{operation:'repair'},{expectedDigest:preview.digest}),{code:'RECOVERY_PREVIEW_CHANGED'});
});
for(const point of ['before-commit','after-commit'])test(`process loss ${point} with entire primary directory removed preserves acknowledged mirror`,t=>{
 const f=fixture(t),source=f.options.stores[0];const script=`import {DatabaseSync} from 'node:sqlite';import fs from 'node:fs';import {LedgerStore} from ${JSON.stringify(new URL('../dist/store.js',import.meta.url).href)};const store=new LedgerStore(${JSON.stringify(source.database)},Buffer.from(${JSON.stringify(f.key.toString('base64'))},'base64'),undefined,{path:${JSON.stringify(source.witnessPath)},mode:'resume'},{existingOnly:true});const exec=DatabaseSync.prototype.exec;DatabaseSync.prototype.exec=function(sql){if(sql==='COMMIT'){${point==='after-commit'?'exec.call(this,sql);':''}fs.rmSync(${JSON.stringify(join(f.root,'data'))},{recursive:true});process.kill(process.pid,'SIGKILL');}return exec.call(this,sql);};store.transaction(state=>{state.epoch=42;state.audit.push({time:2,event:'new transaction'});});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8'});assert.equal(child.signal,'SIGKILL',child.stderr);fs.mkdirSync(join(f.root,'data'),{mode:0o700});
 f.apply('repair');const recovered=f.open();assert.equal(recovered.read().epoch,point==='after-commit'?42:0);assert.equal(recovered.read().audit[0].event,'previous acknowledged authority');recovered.close();
});
test('primary domain loss after native super-journal publication preserves latest acknowledged authority',async t=>{
 const f=fixture(t),source=f.options.stores[0];const s=f.open();s.transaction(state=>{state.largeFixture='A'.repeat(24*1024*1024);});s.close();
 const script=`import {LedgerStore} from ${JSON.stringify(new URL('../dist/store.js',import.meta.url).href)};const store=new LedgerStore(${JSON.stringify(source.database)},Buffer.from(${JSON.stringify(f.key.toString('base64'))},'base64'),64*1024*1024,{path:${JSON.stringify(source.witnessPath)},mode:'resume'},{existingOnly:true});store.transaction(state=>{state.largeFixture='B'.repeat(24*1024*1024);state.epoch=99;});process.stdout.write('ACKNOWLEDGED\\n');store.close();`;
 let observed=false,child;const watcher=fs.watch(join(f.root,'witness'),(_event,name)=>{if(String(name).includes('-mj')&&fs.existsSync(join(f.root,'witness',String(name)))&&!observed){observed=true;child.kill('SIGKILL');}});
 try{child=spawn(process.execPath,['--input-type=module','-e',script],{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);const exit=await new Promise(resolve=>child.on('exit',(code,signal)=>resolve({code,signal})));
  assert.equal(observed,true,`No surviving-witness super-journal observed: ${err}`);assert.equal(exit.signal,'SIGKILL');fs.rmSync(join(f.root,'data'),{recursive:true});fs.mkdirSync(join(f.root,'data'),{mode:0o700});
  f.apply('repair');const recovered=f.open(),state=recovered.read();assert.equal(state.audit[0].event,'previous acknowledged authority');assert.ok([0,99].includes(state.epoch));if(out.includes('ACKNOWLEDGED'))assert.equal(state.epoch,99);assert.equal(state.largeFixture[0],state.epoch===99?'B':'A');recovered.close();
  t.diagnostic('Observed native super-journal in surviving witness domain, killed writer, removed complete primary directory including journals, and repaired authenticated current state; process/storage-loss simulation, not physical power loss.');
 }finally{watcher.close();child?.kill('SIGKILL');}
});

test('interrupted multi-store promotion re-previews current mirrors and preserves original files',t=>{
 const f=fixture(t),before=f.options.stores.map(source=>fs.readFileSync(source.witnessPath));
 const script=`import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {manageLedgerRecovery} from ${JSON.stringify(new URL('../dist/ledger-recovery.js',import.meta.url).href)};const options=${JSON.stringify(f.options)};const preview=manageLedgerRecovery(options,{operation:'repair'}),rename=fs.renameSync;fs.renameSync=function(from,to){const result=rename.call(this,from,to);if(to===options.stores[0].database)process.kill(process.pid,'SIGKILL');return result;};syncBuiltinESMExports();manageLedgerRecovery(options,{operation:'repair'},{expectedDigest:preview.digest});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8'});assert.equal(child.signal,'SIGKILL',child.stderr);f.apply('repair');
 assert.ok(fs.readdirSync(join(f.root,'data')).some(name=>name.startsWith('.guard-original-')));
 f.options.stores.forEach((source,index)=>assert.deepEqual(fs.readFileSync(source.witnessPath),before[index]));
 for(let i=0;i<2;i++){const s=f.open(i);assert.equal(s.read().audit[0].event,'previous acknowledged authority');s.close();}
});

test('generic recovery CLI requires exact preview and returns only safe metadata',t=>{
 const f=fixture(t),config=join(f.root,'keys','recovery.json');fs.writeFileSync(config,JSON.stringify({version:1,...f.options}),{mode:0o600});
 const cli=new URL('../dist/ledger-maintenance-cli.js',import.meta.url).pathname,preview=spawnSync(process.execPath,[cli,'recovery','repair','--config',config],{encoding:'utf8'});assert.equal(preview.status,0,preview.stderr);
 const value=JSON.parse(preview.stdout);assert.equal(value.stores,2);const applied=spawnSync(process.execPath,[cli,'recovery','repair','--config',config,'--apply','--digest',value.digest],{encoding:'utf8'});assert.equal(applied.status,0,applied.stderr);assert.equal(JSON.parse(applied.stdout).applied,true);assert.equal(applied.stdout.includes(f.key.toString('base64')),false);
});
