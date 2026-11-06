import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import * as publicApi from '../dist/index.js';
import { projectCoreInventoryObservation as candidate } from '../dist/inventory.js';
import { projectInventory, projectInventoryJson } from '../dist/inventory.js';
import { decodeCoreInventoryObservation, decodeLedgerObservation } from '../dist/store.js';
import { composeInventorySnapshot } from '../dist/inventory-manifest.js';
import { projectCapturedMcp, finishCapturedMcp } from '../dist/inventory-mcp-capture.js';
import { fixture, uniqueFixture, now } from './fixtures/inventory-late-ledger.mjs';
const key=Buffer.alloc(32,7), maximum=16*1024*1024;
const source={companyId:'synthetic-company',sourceId:'synthetic-source',enrollmentGeneration:'synthetic-generation'};
const scope={tenantId:'synthetic-admission'};
const live=new Map(Array.from({length:10},(_,i)=>[`synthetic.read-${i}`,{fingerprint:'a'.repeat(64),revision:1,definition:{maxCost:0,requiresApproval:false,controlPlane:false}}]));
function seal(text,witnessed=true) { const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key,iv);c.setAAD(Buffer.from(witnessed?'agent-guard-witnessed-ledger-v1':'agent-guard-ledger-v1'));const bytes=Buffer.concat([c.update(text),c.final()]);return JSON.stringify([iv.toString('base64'),c.getAuthTag().toString('base64'),bytes.toString('base64')]); }
const capture=(text,overrides={})=>({payload:seal(text,overrides.witnessed??true),key,maxBytes:maximum,witnessed:true,mirror:false,...overrides});
const normalized=json=>json.replace(/"snapshotId":"[a-f0-9-]+"/,'"snapshotId":"normalized"');
// Oracle: the existing descriptor-only projection plus exact worker capture and
// mirror checks used before the sealed entry. It never selects the fast reader.
function baseline(ledger,registrations,enrollment,selected,time,referenceKey) {
 if(!(ledger.key instanceof Uint8Array)||ledger.key.byteLength!==32||typeof ledger.payload!=='string'||ledger.payload.length>ledger.maxBytes*2+512)throw Error();
 const state=decodeCoreInventoryObservation(ledger.payload,ledger.key,ledger.maxBytes,ledger.witnessed),mode=state.recoveryMirror;
 if((mode!==undefined||state.schema===3||ledger.mirror)&&(!ledger.witnessed||!ledger.mirror||mode!==1||state.schema!==3))throw Error();
 return projectInventoryJson(state,registrations,enrollment,selected,time,referenceKey);
}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const outcome=fn=>{try{const v=fn();return{ok:true,json:normalized(v.json),bytes:v.bytes,profile:v.profile,source:v.source};}catch(e){return{ok:false,name:e.name,code:e.code??null};}};
function compare(text,options={}) {
 const c=capture(text,options.capture);const args=[c,options.live??live,options.source??source,options.scope??scope,options.time??now];
 for(const ref of options.rawOnly?[undefined]:[undefined,Buffer.alloc(32,9)]) {
  const a=outcome(()=>baseline(...args,ref)),b=outcome(()=>candidate(...args,ref));assert.deepEqual(b,a);
  if(b.ok) {assert.equal(b.bytes,Buffer.byteLength(candidate(...args,ref).json));const state=decodeCoreInventoryObservation(c.payload,c.key,c.maxBytes,c.witnessed);assert.equal(b.json,normalized(projectInventoryJson(state,args[1],args[2],args[3],args[4],ref).json));}
 }
}
function wipeProbe(fn) {
 const original=crypto.createDecipheriv,updates=[],events=[];
 crypto.createDecipheriv=function(...args){const c=Reflect.apply(original,this,args),u=c.update,f=c.final;c.update=function(...a){events.push('update');const b=Reflect.apply(u,this,a);updates.push(b);return b;};c.final=function(...a){events.push('final');return Reflect.apply(f,this,a);};return c;};syncBuiltinESMExports();
 try {fn({updates,events});}finally{crypto.createDecipheriv=original;syncBuiltinESMExports();}
}
const assertWiped=updates=>{assert.ok(updates.length>0);for(const b of updates)assert.ok(b.every(x=>x===0));};

test('sealed entry has no parsed-state or callback API and exact426660-byte baseline remains bound',()=>{
 assert.equal(Object.hasOwn(publicApi,'projectCoreInventoryObservation'),false);const text=JSON.stringify(fixture());assert.equal(Buffer.byteLength(text),426660);assert.equal(sha(text),'44dfe5b52d6352f86ec2481f84a5a48d65ffe9c3893abb3f062dcd9bf29efe9f');
 compare(text);compare(JSON.stringify(uniqueFixture()));assert.throws(()=>candidate(fixture(),live,source,scope,now));
 const one=candidate(capture(text),live,source,scope,now);assert.ok(Object.isFrozen(one));assert.ok(Object.isFrozen(one.source));
 assert.deepEqual(Object.keys(one).sort(),['bytes','json','profile','source']);assert.equal(one.json.includes('tokenHash'),false);assert.equal(one.json.includes('ACTION_SUCCEEDED'),false);
 const mutated=JSON.parse(one.json);mutated.tasks[0].usage.calls=999;assert.equal(JSON.parse(candidate(capture(text),live,source,scope,now).json).tasks[0].usage.calls,300);
});

test('own dangerous names, duplicate JSON fields, Unicode/escaped identifiers and negativezero preserve exact wire',()=>{
 const s=fixture();s.tasks=Object.create(null);s.families=Object.create(null);s.tools=Object.create(null);
 for(const [i,id] of ['__proto__','constructor','prototype','toString','toJSON','hasOwnProperty','then','雪😀'].entries()) {
  const t=fixture().tasks['synthetic-task-0'];t.options.id=id;t.options.principalId=id;t.family=id;t.options.grants=[{tool:id,resources:[id,'雪😀\\"']}];t.calls=i;t.options.allowedRecipients=[id];s.tasks[id]=t;s.families[id]={sensitive:false};s.tools[id]={fingerprint:'a'.repeat(64),revision:1,approved:true};
 }
 s.actions=JSON.parse('{"__proto__":{"private":true},"constructor":{"prototype":{"polluted":true}},"toJSON":[{"unused":"sensitive"}]}');
 const text=JSON.stringify(s).replace('"spent":0','"spent":-0').slice(0,-1)+',"revision":1310}';compare(text);assert.equal(Object.hasOwn(Object.prototype,'polluted'),false);
 for(const value of ['x'.repeat(4096),'雪'.repeat(4096),'😀'.repeat(4096),'a'+'😀'.repeat(4095), 'x'.repeat(4097),'\ud800','a\0b','  \t']){const s=fixture();s.tasks['synthetic-task-0'].options.principalId=value;compare(JSON.stringify(s));}
});

test('tenant isolation, exact relationships, counts and malformed JSON-state values preserve denials',()=>{
 const s=fixture();s.tasks['synthetic-task-99'].options.tenantId='foreign';s.tasks['synthetic-task-99'].options.principalId={private:'notprojected'};compare(JSON.stringify(s));compare(JSON.stringify(fixture()),{scope:{tenantId:'empty'}});
 const mutations=[s=>delete s.tasks['synthetic-task-0'].options.tenantId,s=>s.tasks['synthetic-task-0'].options=[],s=>s.tasks['synthetic-task-0'].parent='missing',s=>s.tasks['synthetic-task-0'].parent='synthetic-task-0',s=>delete s.families['synthetic-family-0'].sensitive,s=>s.tasks['synthetic-task-0'].options.budget.maxCalls=1.5,s=>s.tools['synthetic.read-0'].fingerprint='invalid',s=>s.tasks=[],s=>s.families=null,s=>s.tasks['synthetic-task-0'].options.grants[0].resources=Array.from({length:1025},(_,i)=>'r'+i),s=>s.tasks['synthetic-task-0'].options.grants=Array.from({length:2049},(_,i)=>({tool:'t'+i,resources:[]})),s=>s.tools['synthetic.read-0']=true,s=>s.tasks['synthetic-task-0'].options.budget='text'];
 for(const mutate of mutations){const s=fixture();mutate(s);compare(JSON.stringify(s));}
});

test('inherited accessor canaries cannot supply missing root or nested fields',()=>{
 for(const [field,remove] of [['sensitive',s=>delete s.families['synthetic-family-0'].sensitive],['grants',s=>delete s.tasks['synthetic-task-0'].options.grants],['family',s=>delete s.tasks['synthetic-task-0'].family],['recoveryMirror',()=>{}]]) {
  const s=fixture();remove(s);const text=JSON.stringify(s);let called=0;assert.equal(Object.hasOwn(Object.prototype,field),false);
  Object.defineProperty(Object.prototype,field,{configurable:true,get(){called++;throw Error('private-canary');}});
  try{compare(text);assert.equal(called,0);}finally{delete Object.prototype[field];}
 }
});

test('configuration,scope,live registration and definition accessors retain original descriptor-only handling',()=>{
 const text=JSON.stringify(fixture());let called=0;const accessor=()=>{called++;throw Error('private-metadata');};
 for(const context of [
  {source:Object.defineProperty({...source},'companyId',{get:accessor})},
  {scope:Object.defineProperty({...scope},'tenantId',{get:accessor})},
  {live:new Map([...live].map(([k,v],i)=>[k,i===0?Object.defineProperty({...v},'fingerprint',{get:accessor}):v]))},
  {live:new Map([...live].map(([k,v],i)=>[k,i===0?{...v,definition:Object.defineProperty({...v.definition},'maxCost',{get:accessor})}:v]))}
 ]) {compare(text,context);assert.equal(called,0);}
 for(const bad of [{source:{...source,extra:true}},{scope:{tenantId:''}},{scope:{tenantId:'x'.repeat(4097)}},{source:{...source,companyId:null}},{time:NaN}])compare(text,bad);
});

test('fresh authentication, size bounds, schema checks and plaintext wiping are unchanged',()=>{
 const text=JSON.stringify(fixture()),c=capture(text),parts=JSON.parse(c.payload),tampered=[];
 for(const i of [0,1,2]){const p=[...parts],b=Buffer.from(p[i],'base64');b[0]^=1;p[i]=b.toString('base64');tampered.push({...c,payload:JSON.stringify(p)});}
 tampered.push({...c,key:Buffer.alloc(32,8)},{...c,witnessed:false});
 for(const fn of [baseline,candidate]) {
  for(const v of [c,{...c,maxBytes:Buffer.byteLength(text)-1},...tampered])wipeProbe(({updates,events})=>{const result=outcome(()=>fn(v,live,source,scope,now));assert.equal(result.ok,v===c);assert.deepEqual(events,['update','final']);assertWiped(updates);});
  for(const raw of ['{"schema":1,','null','[]','true','42','"text"',JSON.stringify({...fixture(),schema:4}),JSON.stringify({...fixture(),revision:.25}),JSON.stringify({...fixture(),inventoryInstanceId:'invalid'}),JSON.stringify({...fixture(),actions:null})])wipeProbe(({updates,events})=>{assert.throws(()=>fn(capture(raw),live,source,scope,now));assert.deepEqual(events,['update','final']);assertWiped(updates);});
  wipeProbe(({updates,events})=>{assert.throws(()=>fn({...c,payload:'x'.repeat(2561),maxBytes:1024},live,source,scope,now));assert.equal(updates.length,0);assert.equal(events.length,0);});
 }
});

test('exact reserved outputbyte boundary and onebyte overflow reject identically',()=>{
 const s=fixture();s.tasks={'synthetic-task-0':s.tasks['synthetic-task-0'],'synthetic-task-1':s.tasks['synthetic-task-1']};s.actions={};s.audit=[];
 const resources=Array.from({length:1024},(_,i)=>`${i}:`+'x'.repeat(4000));
 for(const task of Object.values(s.tasks)){task.options.grants=[{tool:'synthetic.read-0',resources}];task.options.budget.deadline=1e-7;}
 const max=8*1024*1024-16*2;let remaining=max-baseline(capture(JSON.stringify(s)),live,source,scope,now).bytes;
 for(let i=0;i<resources.length&&remaining>1;i++){const count=Math.min(4096-resources[i].length,Math.floor(remaining/2));resources[i]+='x'.repeat(count);remaining-=count*2;}
 assert.ok(remaining===0||remaining===1);s.tasks['synthetic-task-0'].options.principalId+='x'.repeat(remaining);
 const c=capture(JSON.stringify(s));for(const fn of [baseline,candidate])assert.equal(fn(c,live,source,scope,now).bytes,max);
 compare(JSON.stringify(s),{rawOnly:true});s.tasks['synthetic-task-0'].options.principalId+='x';
 for(const fn of [baseline,candidate])assert.throws(()=>fn(capture(JSON.stringify(s)),live,source,scope,now),{code:'INVENTORY_LIMIT_EXCEEDED'});
});

async function worker(t,url) {const w=new Worker(url,{execArgv:[],env:{},stdout:true,stderr:true,workerData:{scheduling:'default'},resourceLimits:{maxOldGenerationSizeMb:640,maxYoungGenerationSizeMb:32,stackSizeMb:4}});w.stdout.resume();w.stderr.resume();t.after(()=>w.terminate());const [ready]=await once(w,'message');assert.equal(ready.type,'ready');return w;}
let sequence=0;
async function observe(w,state,profile='core',extra={},after=[],flags={}) {const id=++sequence;const message={type:'snapshot',id,ledger:capture(JSON.stringify(state),flags),metadata:{source,registrations:[...live],referenceKey:new Uint8Array(32).fill(9)},scope,generatedAt:now,profile,...extra};const p=once(w,'message');w.postMessage(message);let [r]=await p;if(r.type==='mcp-after'){const p=once(w,'message');w.postMessage({type:'mcp-after',id,after});[r]=await p;}return r;}
const normalAll=json=>{const s=JSON.parse(json);s.snapshotId='normalized';if(s.profile!=='core')s.generatedAt='normalized';if(s.mcp){s.mcp.observedAt='normalized';s.coverage.mcp.observedAt='normalized';}return JSON.stringify(s);};
test('actual worker core output and unchanged host/MCP pipeline preserve descriptor oracle bytes',async t=>{
 const w=await worker(t,new URL('../dist/inventory-worker.js',import.meta.url)),state=fixture();
 const core=JSON.parse(candidate(capture(JSON.stringify(state)),live,source,scope,now).json);
 const manifest={schemaVersion:1,evidenceKind:'host_asserted',source:core.source,manifestId:'catalog',revision:1,observedAt:'2026-11-06T00:00:00Z',agents:[{id:'agent',name:'Agent',ownerId:null,teamId:'team'}],deployments:[{id:'deployment',agentId:'agent',environment:'test'}],taskBindings:[{taskId:'synthetic-task-0',deploymentId:'deployment'}],executionBindings:[{id:'binding',deploymentId:'deployment',tool:'synthetic.read-0',connectionId:'documents',identitySelection:'unknown',identity:null}],resourceBindings:[]};
 const inventory={schemaVersion:1,identity:{serverId:'documents',transportRef:`opaque:${'a'.repeat(64)}`,principalId:'operator',tenantId:scope.tenantId},sessionId:'session',revision:2,authorizationEpoch:1,metadataRevision:1,state:'ready',metadataState:'current',observedAt:'2026-11-06T00:00:00Z',operations:[{name:'synthetic.read-0',kind:'tool',fingerprint:'a'.repeat(64)}]};
 const mcpBefore=[{tenantId:scope.tenantId,connectionId:'documents',inventory,digest:'b'.repeat(64)}];
 for(const [profile,changed] of [['core',false],['host',false],['host-mcp',false],['host-mcp',true]]) {
  const extra=profile==='core'?{}:{manifest,mcpBefore},after=[{tenantId:scope.tenantId,connectionId:'documents',digest:(changed?'c':'b').repeat(64)}];
  const c=capture(JSON.stringify(state)),decoded=decodeLedgerObservation(c.payload,c.key,c.maxBytes,c.witnessed);
  let expected=projectInventory(decoded,live,source,scope,now,Buffer.alloc(32,9));
  if(profile!=='core')expected=composeInventorySnapshot(expected,manifest);
  if(profile==='host-mcp')expected=finishCapturedMcp(projectCapturedMcp(expected,mcpBefore),mcpBefore,after);
  const actual=await observe(w,state,profile,extra,after);assert.equal(actual.type,'result');assert.equal(normalAll(actual.json),normalAll(JSON.stringify(expected)));
  assert.equal(actual.bytes,Buffer.byteLength(actual.json));assert.equal(actual.sha256,sha(actual.json));if(changed)assert.equal(JSON.parse(actual.json).mcp.connections[0].reason,'changed');
 }
});

test('sealed actualworker preserves all48 schema/witness/mirror acceptance and refusal combinations',async t=>{
 const w=await worker(t,new URL('../dist/inventory-worker.js',import.meta.url));
 for(const schema of [1,2,3])for(const mode of [undefined,1,2,null])for(const witnessed of [false,true])for(const mirror of [false,true]) {
  const s=fixture();s.schema=schema;if(mode!==undefined)s.recoveryMirror=mode;
  const accepted=(mode===undefined&&schema!==3&&!mirror)||(witnessed&&mirror&&mode===1&&schema===3);
  const actual=await observe(w,s,'core',{},[],{witnessed,mirror});
  assert.equal(actual.type,accepted?'result':'error');
  if(accepted)assert.equal(normalized(actual.json),normalized(baseline(capture(JSON.stringify(s),{witnessed,mirror}),live,source,scope,now,Buffer.alloc(32,9)).json));
  else {assert.equal(actual.code,'INVENTORY_UNAVAILABLE');assert.throws(()=>candidate(capture(JSON.stringify(s),{witnessed,mirror}),live,source,scope,now));}
 }
});

test('shared constructor preserves mutable synchronous caller isolation and authority null prototypes',()=>{
 const c=capture(JSON.stringify(fixture())),state=decodeLedgerObservation(c.payload,c.key,c.maxBytes,c.witnessed);
 assert.equal(Object.getPrototypeOf(state.tasks),null);assert.equal(Object.getPrototypeOf(state.tasks['synthetic-task-0'].options),null);
 const first=projectInventory(state,live,source,scope,now);state.tasks['synthetic-task-0'].calls=999;
 assert.equal(first.tasks[0].usage.calls,300);assert.equal(projectInventory(state,live,source,scope,now).tasks[0].usage.calls,999);
 let called=0;Object.defineProperty(state.tasks['synthetic-task-0'],'calls',{get(){called++;throw Error('must not call');}});
 assert.throws(()=>projectInventoryJson(state,live,source,scope,now),{code:'INVENTORY_STATE_INVALID'});assert.equal(called,0);
 assert.equal(JSON.parse(candidate(c,live,source,scope,now).json).tasks[0].usage.calls,300);
});
