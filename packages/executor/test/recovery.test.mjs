import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, readFileSync, existsSync, rmSync, writeFileSync, chmodSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { DurableExecutor } from '../dist/index.js';

for (const point of ['before-admission-commit', 'after-admission-commit', 'after-settlement-commit']) {
  test(`fault injection ${point} preserves atomic authority and does not replay effects`, async t => {
    const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-fault-')));
    let executor;
    t.after(() => { executor?.close(); rmSync(directory, { recursive: true, force: true }); });
    const database = join(directory, 'state.sqlite'), effect = join(directory, 'effect');
    const module = new URL('../dist/index.js', import.meta.url).href;
    const store = new URL('../dist/store.js', import.meta.url).href;
    const script = `import {DurableExecutor} from ${JSON.stringify(module)};
      import {LedgerStore} from ${JSON.stringify(store)};
      import {writeFileSync} from 'node:fs';
      let armed=false;
      const original=LedgerStore.prototype.transaction;
      LedgerStore.prototype.transaction=function(operation){
        let observed;
        const result=original.call(this,state=>{
          const result=operation(state);observed=Object.values(state.actions)[0]?.status;
          if(armed&&process.argv[3]==='before-admission-commit'&&observed==='ADMITTED')process.exit(17);
          return result;
        });
        if(armed&&((process.argv[3]==='after-admission-commit'&&observed==='ADMITTED')||(process.argv[3]==='after-settlement-commit'&&observed==='SUCCEEDED')))process.exit(17);
        return result;
      };
      const e=new DurableExecutor({database:process.argv[1],encryptionKey:Buffer.alloc(32,7),clock:()=>1000});
      const fp=e.registerTool({name:'effect',description:'effect',requiresApproval:true,maxCost:5,resolve:()=>({resourceId:'item',tenantId:'tenant'}),execute:()=>{writeFileSync(process.argv[2],'one effect');return{value:true,actualCost:2}}});
      e.approveTool('effect',fp);
      e.createTask({id:'task',principalId:'host',tenantId:'tenant',grants:[{tool:'effect',resources:['item']}],budget:{maxCalls:5,maxConcurrent:2,maxCost:20,deadline:100000}});
      const action=await e.prepare('task',{tool:'effect',args:null});
      const approvalId=e.approve(action.id,{approverId:'reviewer',expiresAt:5000});
      process.stdout.write(action.id+'\\n');armed=true;
      await e.execute('task',action.id,{approvalId});`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, database, effect, point], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(child.status, 17, child.stderr);
    executor = new DurableExecutor({ database, encryptionKey: Buffer.alloc(32, 7), clock: () => 1000 });
    const status = executor.execution('task', child.stdout.trim()).status;
    const counters = executor.snapshot('task');
    if (point === 'before-admission-commit') {
      assert.equal(status, 'PREPARED'); assert.equal(counters.calls, 0); assert.equal(counters.reserved, 0); assert.equal(existsSync(effect), false);
    } else if (point === 'after-admission-commit') {
      assert.equal(status, 'UNKNOWN'); assert.equal(counters.calls, 1); assert.equal(counters.reserved, 5); assert.equal(counters.concurrent, 1); assert.equal(existsSync(effect), false);
    } else {
      assert.equal(status, 'SUCCEEDED'); assert.equal(counters.calls, 1); assert.equal(counters.spent, 2); assert.equal(counters.reserved, 0); assert.equal(readFileSync(effect, 'utf8'), 'one effect');
    }
    await assert.rejects(executor.execute('task', child.stdout.trim()), { code: point === 'before-admission-commit' ? 'POLICY_CHANGED' : 'ACTION_USED' });
  });
}

test('unsafe POSIX state paths and corrupt encrypted state fail before authority is available', { skip: process.platform === 'win32' }, t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-path-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'state.sqlite');
  const options = { database, encryptionKey: Buffer.alloc(32), clock: () => 1000 };
  chmodSync(directory, 0o755);
  assert.throws(() => new DurableExecutor(options), { code: 'STORE_DIRECTORY_UNSAFE' });
  chmodSync(directory, 0o700);
  const target = join(directory, 'target'); writeFileSync(target, '', { mode: 0o600 });
  symlinkSync(target, database); assert.throws(() => new DurableExecutor(options)); rmSync(database);
  linkSync(target, database); assert.throws(() => new DurableExecutor(options), { code: 'STORE_FILE_UNSAFE' }); rmSync(database);
  const executor = new DurableExecutor(options); executor.close();
  writeFileSync(database, Buffer.alloc(512, 0xaa)); assert.throws(() => new DurableExecutor(options));
});
