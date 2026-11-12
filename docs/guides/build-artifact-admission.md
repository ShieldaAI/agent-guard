# Admit signed build files into a sandbox task

Read this if you use the executor's Docker sandbox and want a task to accept only release files that your build system signed. Everyone else can skip it.

## What you will achieve

You will configure an `ArtifactBroker` so that a file from an outside build system is accepted only when all of these hold:

- its bytes match the SHA-256 you wrote down in advance;
- the build system's signature verifies against the public key you wrote down;
- the signed statement names the builder, build type and source you expect.

The broker then issues a signed receipt for the file. Every later use of the file is checked against that receipt, and a file without a receipt is refused.

The signature shows what the builder reported. Whether that builder is trustworthy is for you to assess.

## Prerequisites

- Node.js 22.13 or newer and the executor package: `npm install @shieldaai/agent-guard-executor`.
- A build system that signs each release file with an Ed25519 key and produces the attestation described in [The attestation the broker accepts](#the-attestation-the-broker-accepts).
- The builder's public key in PEM format and the file's SHA-256, both confirmed through a channel other than the files you are about to admit.
- A random 32-byte secret for signing receipts. It stays in the host and is unrelated to the builder's key.
- Docker, only when you run the sandbox itself (steps 3 and 5).

## Steps

### 1. Write a rule for each file

A rule is a `BuildArtifactRule` object. Load the rules from host configuration that the agent cannot change. A policy holds up to 128 rules, and no two rules may share a tenant and path.

| Field | Value |
| --- | --- |
| `tenantId` | The tenant that may receive the file |
| `path` | The relative path where the file may be placed, such as `dist/app.tar` |
| `sha256` | SHA-256 of the file, 64 lowercase hex characters |
| `subjectName` | The file's name as it appears in the attestation |
| `builderId`, `buildType` | The builder and build type URIs the attestation must report |
| `sourceUri`, `sourceDigest` | The source repository URI and its revision, as `{ "algorithm": "sha1" or "sha256", "value": "<lowercase hex>" }` |
| `signerPublicKeyPem` | The builder's Ed25519 public key in PEM format |

### 2. Create the broker and admit the file

This script runs as written from the root of a clone of this repository (after `npm ci` and `npm run build`). It uses a test rule and attestation from the repository. Save it as `admit-build.mjs` and run `node admit-build.mjs`.

```js
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { ArtifactBroker } from '@shieldaai/agent-guard-executor/sandbox';

// Test data from this repository: one rule, and the builder's attestation for a file containing "fixture".
const { rule, attestation } = JSON.parse(
  readFileSync('packages/executor/test/fixtures/packed-build-attestation.json', 'utf8'),
);
const bytes = Buffer.from('fixture');

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
const broker = new ArtifactBroker({
  keyId: 'build-receipts',
  key: randomBytes(32), // in production: a stable 32-byte secret that stays in the host
  buildPolicy: { artifacts: [rule] },
});

// Throws unless the bytes, tenant, path, signature and signed claims all match the rule.
const receipt = broker.admitBuildArtifact({
  content: bytes,
  path: rule.path,
  tenantId: rule.tenantId,
  attestation,
});

// The host still decides what the task may do. The file grants nothing by itself.
const credential = broker.createTaskFromArtifacts(
  executor,
  {
    id: 'release-check',
    tenantId: rule.tenantId,
    principalId: 'release-operator',
    grants: [{ tool: 'shell', resources: ['workspace'] }],
    budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  },
  [{ envelope: receipt, contentBase64: bytes.toString('base64') }],
);

console.log(receipt.payload.origin, receipt.payload.sensitivity, receipt.payload.trust);
console.log(receipt.payload.buildProvenance);
console.log(credential.taskId);

broker.close();
executor.close();
```

Keep the broker, the receipt key, the rules and the task credential in the host. Never hand them to the agent.

### 3. Pass the receipt when the file is used

A broker with a `buildPolicy` refuses any file that has no receipt. Pass the receipts as `inputReceipts` when you register the sandbox tool or call `runGovernedSandbox`. This fragment continues the script above; replace the image and the workspace with your own.

```js
import { createSandboxTool } from '@shieldaai/agent-guard-executor/sandbox';

const tool = createSandboxTool({
  name: 'shell',
  executor,
  broker,
  profile: { image: 'alpine@sha256:YOUR_REVIEWED_DIGEST' },
  tenantId: rule.tenantId,
  resourceId: 'workspace',
  origin: 'host:release-check',
  workspace: '/srv/release-workspace', // contains the file at rule.path
  inputFiles: [rule.path],
  inputReceipts: [receipt],
  onResult(output) {
    return 'stored'; // keep the output in the host and return an opaque ID
  },
});
executor.approveTool('shell', executor.registerTool(tool));
```

The tool checks the files when a call is prepared and ties their versions to the approval. The broker checks the bytes again just before it starts Docker.

### 4. Change the rules

Close the old broker, create a new one with the new rules and register its tools again.

- Closing a broker stops new preparations and launches at once. Work that Docker has already started keeps running; cancel it through the executor.
- The new broker rejects every receipt issued under different rules, including receipts for files the sandbox produced.
- Running tasks keep their grants. Revoke the ones that must stop.
- If you later return to an earlier set of rules, its old receipts become valid again. To prevent that, change the receipt key too.

### 5. Test on your Docker host

```sh
npm run build
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:YOUR_REVIEWED_DIGEST' \
  node --test packages/executor/test/build-artifact-import.test.mjs \
  packages/executor/test/build-provenance.test.mjs
```

Use the digest of an image that you have reviewed and already pulled. With the variable set, one test places a signed file in a real container, runs an approved command, imports the output, and confirms that the output is rejected after the rules change. Without the variable that test is skipped.

## What you should see

The script in step 2 prints:

```text
verified-build sensitive untrusted
[Object: null prototype] {
  policySha256: '07e58e4cb1a5ecde01e3d8ed1604f9ca01fed06169c7137f4785a038da74c151',
  signerSha256: '8cefd1a8c88da7112905d8e9ef1e11e70917ad51a5f56ae4ec8528782177990f',
  statementSha256: '7089798fbe22c3b3ee8004e4716687322b319b786f324765bb317928d1558a36'
}
release-check
```

The first line is how the receipt labels the file: it came from a verified build, it is sensitive, and it is still outside content (`trust: 'untrusted'`). A valid signature says where a file came from. It does not make instructions inside the file safe to follow.

`buildProvenance` holds the digest of your rules, the fingerprint of the signing key and the digest of the signed statement. Keep the signed statement so that you can match it to `statementSha256` later.

## The attestation the broker accepts

The attestation is a [DSSE envelope](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md):

| Field | Value |
| --- | --- |
| `payloadType` | `application/vnd.in-toto+json` |
| `payload` | Base64 of the signed statement, at most 128 KiB decoded |
| `signatures` | Exactly one entry. `keyid` is the lowercase SHA-256 of the builder's public key in DER (SubjectPublicKeyInfo) form. `sig` is the base64 Ed25519 signature. |

The payload is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with predicate type `https://slsa.dev/provenance/v1` ([SLSA provenance](https://slsa.dev/spec/v1.2/build-provenance)). The broker compares these values with the rule:

| In the statement | Must equal |
| --- | --- |
| The single `subject`: `name` and `digest.sha256` | `subjectName` and `sha256` |
| `predicate.runDetails.builder.id` | `builderId` |
| `predicate.buildDefinition.buildType` | `buildType` |
| The single entry in `predicate.buildDefinition.resolvedDependencies`: `uri` and `digest` | `sourceUri` and `sourceDigest` |

`externalParameters` and `internalParameters` may be absent, null or empty. `runDetails.builder.version` and `runDetails.metadata` (`invocationId`, `startedOn`, `finishedOn`) are allowed. Any other field, a second subject, dependency or signature, or a duplicate JSON key fails verification.

## What can go wrong

Each error has a `code`. The codes for a rejected file or receipt are the same for every cause, so that an error cannot reveal what was in the file.

| Error `code` | Cause | Fix |
| --- | --- | --- |
| `BUILD_PROVENANCE_INVALID` from `admitBuildArtifact` | The bytes, tenant or path match no rule; the signature does not verify; `keyid` is not the fingerprint of the key in the rule; or a signed value differs from the rule. | Recompute the file's SHA-256, then compare the statement with the rule field by field. |
| `BUILD_PROVENANCE_INVALID` when creating the broker | A rule has a missing or extra field, an absolute path or one containing `..`, a digest that is not lowercase hex, or the same tenant and path as another rule. | Correct the rule. |
| `ARTIFACT_ATTESTATION_REQUIRED` | A file without a receipt reached a broker that has a `buildPolicy`, or `admitBuildArtifact` was called on a broker that has none. | Admit the file first and pass its receipt in `inputReceipts`. |
| `ARTIFACT_INVALID` | A receipt was altered, belongs to different bytes or another tenant, or was issued under different rules or another receipt key. | Admit the file again with the current broker. |
| `ARTIFACT_BROKER_CLOSED` | The broker was closed, for example while changing the rules. | Use the new broker and register its tools again. |
| `TOOL_CHANGED` when an approved call runs | An input file changed between approval and launch. | Prepare the call again and have it approved again. |
| The call ends as `UNKNOWN` | The executor accepted the call and it then failed, so the executor cannot tell whether anything ran. | Check what the sandbox did, then settle the call with `executor.reconcile`. |

A file can be up to 64 MiB. The container image is controlled separately, by the pinned digest in the sandbox profile. For general limits see [Support and limits](../support-and-limits.md).
