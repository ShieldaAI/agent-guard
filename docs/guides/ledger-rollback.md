# Detect a stale restore before it can revive authority

A valid AES-GCM payload proves the state was written by a holder of the key.
It cannot tell you that it is the **latest** state. In a disposable reproduction,
restoring an earlier encrypted database caused an otherwise valid, revoked task
token to authenticate again. The single-owner witness profile detects this
restore before exposing task or approval APIs.

**Provision once.** On a POSIX host, prepare two canonical, owner-only directories
(0700), with neither directory inside the other. Keep the ledger and its
independently protected witness in **different restore domains**, on local
filesystems supporting SQLite locking, durable sync and rollback journals.
Both filenames must be new. Keep the config and encryption key outside workloads.

```ts
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({
  database: '/srv/agent-guard/state/ledger.sqlite',
  encryptionKey: keyFromHostSecretStore,
  rollbackWitness: {
    path: '/srv/agent-guard-control/witness/latest.sqlite',
    mode: 'create', // first initialization only
  },
});
```

On **every subsequent start**, use the same paths and key, with `mode: 'resume'`.
Resume requires both files to exist and match. The witness stores a SHA-256
commitment to the encrypted bytes. The store updates both databases in one
transaction using [SQLite's attached-database atomic commit](https://sqlite.org/lang_attach.html),
on-disk databases, DELETE rollback journals and [EXTRA synchronous writes](https://sqlite.org/pragma.html#pragma_synchronous)
on both files. In a [disposable Linux VM](../validation/witness-vm-power-cut-2026-11-05-a7957d91a4dfc4e2f523675804b58b5b5dc994e4e9ed2ef51d973b9aa38f54f9.json),
three abrupt guest shutdowns exercised two points during commit and one after
revocation returned. The acknowledged revocation survived reboot. The host
and disk controller stayed powered. Validate physical durability and restoration
on the enrolled deployment's storage and backup system.
Witnessed ciphertext uses a distinct authentication domain: removing the option
does not make a witnessed ledger usable as an ordinary ledger.

**Recovery.** Stop dispatch and close the executor before taking or restoring a
database backup. Preserve the current witness independently. Restore the closed
ledger file only; do not mix backups with live or historic SQLite journal files.
A matching pair can resume; an earlier ledger, substituted witness, missing file
or mismatched key fails closed. On `STORE_WITNESS_UNAVAILABLE`, stop and retain
the files. Check ownership, provisioning, the key, and which backup actually
matches the independent witness. Do **not** delete/recreate the witness, try
`create`, restore an old pair, or create fresh authority to clear the error.
If the matching state is lost, investigate and reconcile backend effects, revoke
old credentials, and explicitly enroll a new deployment rather than resuming
old tasks. Interrupted initial provisioning may leave unused files; determine
that no deployment was activated before provisioning a different pair.

**Cost.** On the reviewer's macOS arm64 filesystem, the 95th percentile for
one complete prepare, approve and execute cycle was **251.5 ms** with the
witness and **7.2 ms** with the ordinary ledger (100 measured cycles per
mode, with both directories on the same disk). Use the [benchmark](../validation/benchmark-rollback-witness.mjs)
and [recorded samples](../validation/protection-96-witness-timing-2026-11-05.json)
to compare results on the intended storage before setting a latency budget.
Reducing the sync settings invalidates the tested durability profile.

**Limits.** This does not protect a machine snapshot that rewinds *both* files,
a malicious host owner, an untrusted filesystem, or an old deployment with a
separate authorization route. Separate directory names alone cannot establish
independent backups. No in-place enrollment of unverified legacy history,
Windows ACL profile, cross-host quorum, or automatic recovery from a lost
witness is claimed. Privately validate the restore policy against the actual
backup system. The [regressions](../../packages/executor/test/rollback-witness.test.mjs)
exercise stale-token resurrection, a confirmed backend write, and child-process
termination immediately before and after the paired commit.
