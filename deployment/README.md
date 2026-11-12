# Isolated execution profile

`@shieldaai/agent-guard-executor` includes a Docker-backed local execution API for
explicitly selected files. It requires a **local Linux Docker daemon** and an
already-installed, reviewed image pinned with `repository@sha256:digest`. It never
pulls an image or mounts the host project, home directory, Docker socket, credential
store or other management socket. The only host bind mount is a newly created,
read-only directory containing copies of the selected regular files.

| Host | Runtime requirement | Status |
| --- | --- | --- |
| Linux | Local Linux Docker Engine with cgroup resource limits | Checked in CI on every change. |
| macOS | A local Linux VM (Docker Desktop or Colima) sharing the private staging directory | Works through the VM. Run the platform check on your host before relying on it. |
| Windows | Local Linux Docker VM or WSL2 with a local named-pipe endpoint and staging-directory file sharing | Not verified. Run the platform check on native Windows before use. |

Remote TCP/SSH daemons and non-Linux daemons fail closed. The daemon must report support for memory/swap, process and CPU limits, default seccomp and cgroup namespaces. Docker must be configured
and available to the trusted host process. Docker management access is powerful;
keep the executor and its credentials outside the agent workload. A digest identifies
image bytes, but does not establish that an image is trustworthy or vulnerability-free.

## Enforced boundary

The workload always runs as UID/GID 1000 with a read-only image filesystem, all
Linux capabilities dropped, `no-new-privileges`, private IPC/cgroup namespaces,
Docker's default seccomp filtering, no published ports and `network=none`. There is
no option for host networking, privileged execution, host devices, arbitrary binds,
capability additions or weakening these settings. Images declaring implicit volumes
are rejected. Image healthchecks and log persistence are disabled.

Only `/workspace` and `/tmp` are writable tmpfs mounts. `/tmp` is also `noexec`;
`/workspace` permits building and running selected project code. Defaults are one
CPU, 256 MiB memory with no additional swap allowance, 64 processes, a 64 MiB
workspace, 30 seconds per workload, 16 MiB selected inputs, 1 MiB combined stdout/
stderr, and 16 MiB selected exports. Profiles can set bounded limits. Timeout,
cancellation and oversized output trigger container removal, which also terminates
background processes. Cleanup failure is an error containing the container name.

The pinned image must provide `/bin/sh`, `cp`, `chmod`, `sleep` and `/bin/tar`.
A Node/Python/compiler image can run those tools inside the same boundary. No host
environment variables or model credentials are passed to the workload. The image's
own contents and baked environment remain part of the trusted image selection.

## API and review flow

```js
import {
  runDockerSandbox,
  writeReviewedExports,
} from "@shieldaai/agent-guard-executor/sandbox";

const result = await runDockerSandbox({
  profile: { image: process.env.REVIEWED_IMAGE_DIGEST, timeoutMs: 30_000 },
  workspace: "/absolute/path/to/project",
  inputFiles: ["src/main.js", "package.json"],
  command: ["/bin/sh", "-c", "node src/main.js > result.txt"],
  exportFiles: ["result.txt"],
});

// Present result.exports paths, sizes, hashes and decoded content for host-side review.
// After that review, pass only the explicitly approved paths AND exact SHA-256 hashes.
const approved = [{ path: "result.txt", sha256: "reviewed-output-sha256" }];
writeReviewedExports(result, approved, "/absolute/path/to/new-reviewed-output");
```

`runDockerSandbox` returns untrusted stdout/stderr and in-memory output artifacts;
it never copies generated files back into the project. The trusted caller must keep
review/approval outside agent control. `writeReviewedExports` validates approved
hashes, writes only selected regular files into a **new** private directory and
refuses an existing destination. It never overwrites project files or executes output.
An agent-generated list of hashes is not a human approval or policy authorization.

Input and export paths must be explicit portable relative filenames: at most 240 UTF-8
bytes each, at most 256 paths, in normalized (NFC) form. Input symlinks, hardlinks,
sockets, devices, traversal and case-colliding selections are rejected. The same rule
applies to artifact receipts and build policies. A private
parent under the host home directory protects staging files from other local users;
only its dedicated input child is mounted. This location supports VM file sharing
without mounting the home directory itself.

Linux opens each component through a retained directory descriptor under
`/proc/self/fd`. macOS asks the kernel to reject symbolic links throughout the
path during the open. Windows file selection requires a local fixed drive
and the system Windows PowerShell compiler. The helper retains Windows file
handles while it checks for reparse points and copies the selected bytes.
Keep the host account, its temporary directory and the Docker daemon private.

Exports use a bounded tar stream from `/workspace` because Docker's copy API does
not reliably copy tmpfs contents. The host parser reads regular-file bytes into
memory and **never extracts an archive**. Links, devices, traversal,
duplicate/case-colliding paths, invalid checksums and missing selected outputs fail the
export. A link anywhere in the workspace blocks export. Long file names are read from
the archive's long-name and `path` records; other extended tar features are refused. A
command that exits unsuccessfully returns its exit code and output without an export.
The workspace is discarded afterwards.

Public utilities are `validateSandboxProfile`, `buildDockerCreateArgs`,
`readSandboxArchive` and `writeReviewedExports`, alongside `runDockerSandbox`.
Types are `SandboxProfile`, `ValidatedSandboxProfile`, `SandboxExport` and
`SandboxResult`.

## Verification and CI

Unit tests run with the executor suite. Real Docker tests require an explicit pinned
Linux image already present locally; they do not relax the profile:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' \
  node --test packages/executor/test/sandbox.test.mjs
```

That digest is a reproducible smoke-test
fixture, not a production image recommendation. Tests inspect UID, capabilities,
no-new-privileges, network interfaces and actual cgroup memory/process limits, verify
read-only host input/root filesystems, reject malicious exports, exercise timeout/
output bounds, and check container cleanup. Without the environment variable, the
three real-Docker tests are explicitly skipped.

Installed CI workflows:

- The ordinary CI runs unit/build/package checks on Linux, macOS and Windows; the
  Node 22/24/26 compatibility matrix also runs on Linux.
- The manually dispatched `Platform isolation gate` workflow runs this unchanged real-Docker
  suite on dedicated runners labeled `agent-guard-isolation` plus `Linux`, `macOS`
  or `Windows`. These runners must provide the corresponding Linux daemon/VM.
- Provision the same reviewed digest beforehand, confirm local endpoint/LINUX mode,
  and archive host OS, Docker/VM versions and unskipped test results. A skipped
  integration suite must not count as platform isolation certification. The
  `scripts/verify-platform.mjs` check requires the image input and writes
  `artifacts/platform-evidence.json`. Do not run untrusted pull requests on a
  persistent runner with Docker-management privileges.

### Windows preflight and failure handling

Run the Windows check from native Windows Node under the dedicated host account.
A Node process running inside WSL exercises the Linux profile. Use Node 22.13.0 or
later, a fixed local drive, and a canonical workspace path. Selected file names
must match their on-disk spelling. Network shares, junctions, symbolic links,
hard links, alternate streams and short-name aliases in selected relative paths
are outside the input profile. OS-supplied short-name ancestors in the workspace
root are resolved from retained directory handles.

The account needs Windows PowerShell at
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, permission to run
`Add-Type` and its C# compiler, and a private writable
`%USERPROFILE%\AppData\Local\Temp` directory. The helper uses the OS account's
profile, ignores caller-supplied temporary/search paths, and runs without a user
PowerShell profile. Configure the Docker Linux VM to share the account's private
`.agent-guard-stage-*` directories. Provision the account's filesystem ACLs outside
the library. The POSIX rollback-witness profile is unavailable on Windows.

After building, first run the two native file-reader tests, then
the complete platform check with locally installed reviewed image digests. In
PowerShell, replace both image placeholders before running these commands.

```powershell
node -p process.platform # Must report win32.
node --test packages/executor/test/workspace-input-windows.test.mjs
$env:AGENT_GUARD_EXPECTED_HOST = 'Windows'
$env:AGENT_GUARD_SANDBOX_IMAGE = 'REVIEWED_SHELL_IMAGE@sha256:REVIEWED_DIGEST'
$env:AGENT_GUARD_MCP_ISOLATION_IMAGE = 'REVIEWED_NODE_IMAGE@sha256:REVIEWED_DIGEST'
node scripts/verify-platform.mjs
```

Keep a passing `artifacts/platform-evidence.json` with zero skipped checks
before enabling this profile. A file-reader failure calls for checking the path,
links, account permissions, available PowerShell compiler and private temporary
directory. A Docker failure calls for checking Linux mode, the local named-pipe
endpoint, reviewed image availability and staging-directory sharing. If cleanup
fails, remove the container named in the host error with
`docker rm --force --volumes <name>` before continuing. A governed call can retain
an `UNKNOWN` receipt after a failure. Inspect the host receipt and reconcile any
uncertain effect before preparing another execution.

This implements bounded isolated command execution. It does not yet integrate a
complete coding-agent client, credential injection, an approved tool broker network,
provider egress, checkpoint recovery or a full end-to-end agent session. Networking
remains disabled. A compromised host administrator, Docker daemon, VM or kernel is
outside this boundary; container isolation is not a guarantee against kernel exploits.

References: [Docker runtime controls](https://docs.docker.com/engine/containers/run/)
and [Docker copy/tar behavior](https://docs.docker.com/reference/cli/docker/container/cp/).

## Signed sandbox input and output provenance

`ArtifactBroker` and `runGovernedSandbox(executor, taskId, { broker, ...options })`
are host administration APIs. Use them around the raw Docker launcher whenever
sandbox files or terminal output may feed another task. The broker needs a stable
random 32-byte HMAC key and key ID stored by the host, outside agent environments,
workspaces, logs and model arguments. Keep that key across host restarts if old
receipts must remain verifiable. Rotating the key invalidates old receipts; no
key distribution service is required.

For files from external builds, enroll the release digest and builder signing
policy on the host and admit a DSSE-signed build statement through the broker.
The configured broker requires policy-bound receipts for every selected file
and preserves the policy digest on derived outputs. See the
[build artifact admission guide](../docs/guides/build-artifact-admission.md).

The wrapper snapshots only selected regular input files into a private host
directory, validates any supplied receipts against the exact bytes, and persists
family sensitivity before launching the shell. Raw inputs **and the command**
default to sensitive. A trusted host can explicitly classify the whole run as
public with `inputClassification: 'public'`; never allow the model to choose this
setting. Existing family taint and signed sensitive inputs always override public
classification. `classifyArtifact` admits host-uploaded bytes and also defaults to
sensitive. All content remains untrusted as instructions, including public files.

Returned `inputs`, `artifacts`, `stdout` and `stderr` are signed envelopes binding
SHA-256, byte size, tenant, sensitivity, origin, opaque artifact ID, derivation
version and task/artifact lineage. Stdout and stderr remain in host memory with
these receipts; do not log, forward or re-import them as unlabeled public text.
No export is automatically copied into a project directory. A host must review
exact file paths and hashes, then call `writeReviewedArtifacts`. This creates a
fresh private destination and a `.agent-guard-provenance.json` sidecar. Review does
not declassify sensitive data or authorize sending it to an external recipient.

For a new root, pass the envelope and exact bytes to
`broker.createTaskFromArtifacts(executor, taskOptions, inputs)`. The host chooses
its grants and recipients; the importer verifies every receipt before creating
the task. It binds the producing task through durable `sourceTaskId` provenance,
shares its monotonic family sensitivity, and rechecks all source ancestry for
revocation. Import stdout/stderr by supplying their UTF-8 bytes with their own
envelopes. Inputs from multiple producing tasks fail closed; use an explicitly
reviewed host consolidation workflow rather than dropping source lineage. Signed
input receipts for sandbox runs must already belong to the destination task's
durable source ancestry, so import them before running. Later runs retain source
revocation even after broker restart and without repeating the original inputs.

These receipts authenticate this host's classifications; they are not third-party
publisher signatures or an assertion that content is safe. Derivation versions
are signed metadata, not a global latest-version registry. A malicious trusted
host can bypass this wrapper, call the raw launcher, lose labels, expose its HMAC
key or falsely classify secret bytes as public. The protected deployment must
keep those administration decisions outside model-controlled tools. A process
with the host account's privileges can modify private staging or use the signing
key directly. Run hostile code inside the guest under a separate identity.

The platform check requires `AGENT_GUARD_EXPECTED_HOST` (`Linux`, `macOS` or
`Windows`) to match the actual host, zero skipped/cancelled/todo tests, all three
real isolation cases, the signed artifact import case and the durable shell
approval/budget/cancellation case. A successful
ordinary unit run with Docker tests skipped does not check the platform.


## Registering shell execution with the durable executor

Use `createSandboxTool` for model-requested shell work. Its host configuration
fixes the executor, broker, image and limits, workspace, selected input/output
paths, tenant, resource, origin, classification and input receipts. The model can
supply only a bounded `command` argument array. Register the returned definition,
approve its fingerprint, and grant only its exact resource to a task. Each call
then uses the ordinary `prepare` / host approval / `execute` flow. Approval is
required by default; task budgets and cancellation apply to actual execution.
There is no host-shell execution path.

Preparation binds exact selected input bytes using a per-instance keyed HMAC
version. It does not reveal an input content hash that could permit offline
guessing before approval. Before Docker starts, the broker checks the version
against the private buffers it will copy into the guest. A changed file requires
fresh approval.
The tool fingerprint binds the host configuration and supplied receipt digests.

A required `onResult` host callback receives the complete signed result and task
ID and returns an opaque result ID. Retain that result in host-controlled storage
with its envelopes. The model receives the result ID, exit status, sensitivity,
output artifact IDs and at most 16 KiB from each stdout/stderr stream, with an
explicit truncation flag and the signed full-stream hash. Returning output to the
originating task preserves its family taint. Future tasks must use the signed
importer. Host result storage is not a new external upload capability.

The real integration test verifies approval and grant rejection, stale input
rejection, a successful approved run charged against the call budget, bounded
model logs, and cancellation after a real guest process starts. It also verifies
that cancellation removes the container and retains the executor's unresolved
reservation for host reconciliation. This is a governed shell tool, not a full
networked coding client, an isolated MCP-server manager or VM restart/reconnect
orchestration.
