# Detect a restored old ledger

The executor keeps its state in an encrypted file, the ledger. Encryption proves the file
was written by someone who holds the key. It does not prove the file is the latest one. If
an old backup is restored, a task token that was revoked after that backup works again.
The rollback witness is a second small file that records which ledger state is current,
so the executor can refuse to start on an older one.

## What you will achieve

- An executor that writes a witness file next to its ledger.
- A refusal to start (`STORE_WITNESS_UNAVAILABLE`) when the ledger is older than the
  witness, or when either file is missing or replaced.
- A recovery procedure that does not bring revoked tasks back.

## Prerequisites

- Linux or macOS. The witness is not available on Windows.
- Node.js 22.13 or later, and this repository built (`npm ci --ignore-scripts`, then
  `npm run build`).
- Two directories that only the host's user can access (mode `0700`), neither inside the
  other, on local filesystems.
- Backups arranged so that the two directories are **not** saved and restored together.
  If one snapshot rewinds both, the witness cannot help.
- The encryption key and configuration stored where agent workloads cannot read them.

## Steps

### 1. Create the two directories

```sh
sudo install -d -o "$USER" -m 0700 /srv/agent-guard/state
sudo install -d -o "$USER" -m 0700 /srv/agent-guard-control/witness
```

Use the user the host runs as in place of `$USER`.

### 2. Turn the witness on

```js
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({
  database: '/srv/agent-guard/state/ledger.sqlite',
  encryptionKey: keyFromHostSecretStore, // 32 bytes from your secret store
  rollbackWitness: {
    path: '/srv/agent-guard-control/witness/latest.sqlite',
    mode: 'create', // first start only; use 'resume' on every later start
  },
});
```

Both paths must be absolute. With `create`, neither file may exist yet. With `resume`,
both must exist and match. A ledger created with a witness cannot be opened without the
`rollbackWitness` option.

### 3. See the refusal for yourself

Save this as `witness-demo.mjs` in the repository root and run `node witness-demo.mjs`. It
creates a ledger in a temporary directory, backs it up, revokes a task, restores the
backup and tries to start.

```js
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const root = realpathSync(mkdtempSync(join(tmpdir(), 'witness-demo-')));
for (const name of ['state', 'witness']) mkdirSync(join(root, name), { mode: 0o700 });
const database = join(root, 'state', 'ledger.sqlite');
const witness = join(root, 'witness', 'latest.sqlite');
const encryptionKey = randomBytes(32);
const open = mode => new DurableExecutor({ database, encryptionKey, rollbackWitness: { path: witness, mode } });

// First start: create both files.
let executor = open('create');
executor.createTask({
  id: 'demo-task',
  principalId: 'demo',
  tenantId: 'demo',
  grants: [],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
executor.close();

// Take a backup of the ledger, then change the state by revoking the task.
copyFileSync(database, `${database}.backup`);
executor = open('resume');
executor.revokeTask('demo-task');
executor.close();

// Restore the older ledger. The witness still describes the newer state.
copyFileSync(`${database}.backup`, database);
try {
  open('resume');
  console.log('opened: the stale restore was NOT detected');
} catch (error) {
  console.log('refused:', error.code);
}
```

### 4. Back up and restore safely

1. Stop sending work and close the executor before you copy or restore the ledger.
2. Back up the ledger file on its own. Keep the witness in its separate backup domain.
3. To restore, put back the closed ledger file only. Do not mix it with SQLite journal
   files from another time.
4. Start with `mode: 'resume'`. A ledger that matches the witness opens. An older one is
   refused.

### 5. Measure the cost

With the witness on, every state change waits for both files to reach the disk. Calls get
much slower, often by ten times or more. Before you set a latency budget, run the
[benchmark](../../scripts/benchmark-rollback-witness.mjs) on the storage you will use:

```sh
node scripts/benchmark-rollback-witness.mjs
```

Compare `default.p95Ms` (without the witness) with `witnessed.p95Ms` in its output.

## What you should see

Step 3 prints:

```text
refused: STORE_WITNESS_UNAVAILABLE
```

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `STORE_CONFIG_INVALID` | A path is relative, one directory is inside the other, `mode` is not `create` or `resume`, or the host runs on Windows. | Use two absolute paths in separate directories on Linux or macOS. |
| `STORE_WITNESS_UNAVAILABLE` on first start | One of the files already exists, or a directory is not owner-only. | Use new file names in `0700` directories owned by the host's user. |
| `STORE_WITNESS_UNAVAILABLE` on a later start | A file is missing, the ledger is older than the witness, the witness was replaced, or the key is wrong. | Stop. Follow the recovery steps below. |
| `STORE_UNAVAILABLE` | A ledger that was created with a witness was opened without the `rollbackWitness` option. | Add the option with `mode: 'resume'`. |
| Calls became much slower | Expected with the witness on. | Measure with the benchmark. Do not lower SQLite's sync settings; that removes the protection. |

**When a later start is refused:**

1. Stop and keep every file as it is.
2. Check file ownership, the paths, the key, and which backup matches the witness.
3. Restore the ledger backup that matches the witness, if you have it.
4. If no matching ledger exists, treat the old state as lost: check your backends for
   actions that ran, revoke the old credentials, and set up a new deployment with new
   files. Do not resume the old tasks.

Do not delete or recreate the witness, switch to `mode: 'create'`, or restore an old
ledger and witness together to make the error go away. Each of those brings revoked
authority back.

## What the witness does not cover

- A machine or volume snapshot that rewinds both files together.
- A person or process with the host's own file access and key.
- Adding a witness to a ledger that was created without one.
- Automatic recovery when the witness itself is lost.

For general limits, see [Support and limits](../support-and-limits.md).
