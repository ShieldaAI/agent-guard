# Verify a signed pilot review

Read this if your company is piloting one deployment of the read-only inventory service and an independent reviewer must sign off on its test results before rollout. Library users can skip it.

## What you will achieve

You will run one command that checks, on your own machine, that a pilot was tested and approved as agreed:

- the build file is the one named in the policy and was signed by the expected builder;
- the deployment that was tested is the one described in the policy;
- the person who ran the tests signed the results, and the results meet fixed rules for access, recovery and load;
- a second person, with a different name and key, signed an approval of exactly those results.

The review covers one build file, one deployment, one tenant and one read-only tool, for at most 31 days. The command only checks. The decision to roll out stays with the deployment owner.

## Prerequisites

- Node.js 22.13 or newer and the executor package: `npm install @shieldaai/agent-guard-executor`.
- Three roles, each with its own Ed25519 key pair: the **builder** signs the [build attestation](build-artifact-admission.md#the-attestation-the-broker-accepts), the **observer** runs the tests and signs the results, and the **reviewer**, who is independent of the observer, signs the approval.
- The build file and its build attestation.
- Test results from the deployment. The [deployment runbook](../../deployment/cartography/RUNBOOK.md) describes how to collect them.

## Steps

### 1. Try it with test data

In a clone of this repository (after `npm ci` and `npm run build`), save this as `rehearsal.mjs` in the repository root and run `node rehearsal.mjs`. It creates a signed practice review with throwaway keys and verifies it.

```js
import { verifyPilotReview } from '@shieldaai/agent-guard-executor/pilot';
import { createPilotReviewFixture } from './packages/executor/test/fixtures/pilot-review.mjs';

const { policy, candidateBytes, bundle } = createPilotReviewFixture();
console.log(verifyPilotReview(policy, candidateBytes, bundle, 'rehearsal'));
```

[The fixture](../../packages/executor/test/fixtures/pilot-review.mjs) is a complete worked example of every file described below.

### 2. Write the policy

The policy fixes what will be reviewed before any test runs. It is a JSON file with exactly these fields. Store it where the people being reviewed cannot change it.

| Field | Value |
| --- | --- |
| `version` | `1` |
| `mode` | `company-pilot`, or `rehearsal` for a practice run |
| `companyId`, `deploymentId` | Stable identifiers for the company and the deployment |
| `runId` | 64 lowercase hex characters, generated at random for this run |
| `candidate` | The build file: one [`BuildArtifactRule`](build-artifact-admission.md#1-write-a-rule-for-each-file) |
| `boundarySha256` | SHA-256 of the deployment description from step 3 |
| `observer`, `reviewer` | Each `{ "subject": "<name>", "publicKeyPem": "<Ed25519 public key in PEM>" }` |
| `notBefore`, `expiresAt` | The review window in Unix milliseconds, at most 31 days long |
| `minLoadSamples` | 20 to 2,048: the fewest timed requests you will accept |
| `maxLatencyP95Ms` | The slowest acceptable 95th-percentile latency, in whole milliseconds |

### 3. Describe the deployment

Write a JSON file with exactly these fields. The SHA-256 of its exact bytes is the policy's `boundarySha256`.

| Field | Value |
| --- | --- |
| `version` | `1` |
| `companyId`, `deploymentId` | The same values as in the policy |
| `tenantId`, `candidateSha256` | The `tenantId` and `sha256` of the policy's `candidate` |
| `oidcIssuer`, `oidcAudience` | The HTTPS URL of your sign-in issuer, and the audience your service expects |
| `httpsOrigin` | The HTTPS origin of the service, with no path |
| `awsRoleArn`, `expectedBucketOwner` | The IAM role the collector uses, and the 12-digit account ID in that role |
| `awsAction`, `awsResourceArn` | `s3:GetBucketLocation` and the ARN of one S3 bucket. See the [AWS guide](../../deployment/cartography/AWS.md). |
| `protectedTool` | The one tool under review |
| `excludedSurfaces` | Up to 32 distinct names of things the review does not cover |

### 4. Write the three result files

Every file below refers to the policy digest: the SHA-256 of the policy as JSON with keys sorted at every depth and no whitespace. These helpers compute it and build the signed envelopes used in steps 5 and 6.

```js
import { createHash, sign } from 'node:crypto';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}
const policyDigest = policy => sha256(canonical(policy));

// A DSSE envelope with one Ed25519 signature over the exact payload bytes.
function envelope(payloadType, payloadBytes, privateKey, publicKey) {
  const header = Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payloadBytes.length} `);
  return {
    payloadType,
    payload: payloadBytes.toString('base64'),
    signatures: [
      {
        keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })),
        sig: sign(null, Buffer.concat([header, payloadBytes]), privateKey).toString('base64'),
      },
    ],
  };
}
```

Every other digest in this guide is a plain SHA-256 of a file's exact bytes.

Each result file is a JSON object with `kind`, `policySha256`, `collectedAt` (Unix milliseconds, within the test run), `sourceReport` (base64 of up to 64 KiB of the original report, with credentials removed) and the fields below. All counts and times are whole numbers.

| `kind` | Extra fields | Rule |
| --- | --- | --- |
| `access` | `probes`: nine entries of `{name, outcome, backendReads, backendWrites}` | `oidc-read`, `rotated-tls-read`, `rotated-key-read` and `aws-read` are `allowed` with one read and no writes. `foreign-tenant-read`, `revoked-session-read`, `retired-tls-read`, `retired-key-read` and `aws-write` are `denied` with no reads and no writes. |
| `recovery` | `before` and `restored`: `{logicalStateSha256, records}`. `incident`: `{initialStatus, finalStatus, receiptSha256, effectsBefore, effectsAfter}` | The state digest and record count are equal before and after the restore. The incident goes from `UNKNOWN` to `SUCCEEDED` with both effect counts at 1. |
| `load` | `latenciesMs`, `totalAttempts`, `failedAttempts` | One latency per request, from `minLoadSamples` to 2,048 of them. `totalAttempts` equals their number, `failedAttempts` is 0, and the 95th percentile is at most `maxLatencyP95Ms`. |

The verifier checks the numbers and the digests. It cannot check that a `sourceReport` came from the deployment; the observer and the reviewer vouch for that by signing.

### 5. Sign the results and the approval

The observer saves this object as a file and signs its exact bytes with payload type `application/vnd.agent-guard.pilot-observations.v1+json`.

```js
const observations = {
  policySha256, mode: policy.mode, runId: policy.runId,
  candidateSha256,       // SHA-256 of the build file
  buildStatementSha256,  // SHA-256 of the decoded payload of the build attestation
  startedAt, finishedAt, // Unix milliseconds
  evidence: { access: accessSha256, recovery: recoverySha256, load: loadSha256 },
};
```

The reviewer checks the build, the deployment description, each source report and the load figures, then signs this object with payload type `application/vnd.agent-guard.pilot-review.v1+json`. Any other decision, or a non-empty `openExceptions`, fails verification.

```js
const review = {
  policySha256, mode: policy.mode, runId: policy.runId,
  observationSha256,     // SHA-256 of the exact bytes the observer signed
  decision: 'approve', reviewedAt, openExceptions: [],
};
```

### 6. Assemble the bundle and verify

The bundle is one JSON file. Make it readable by its owner only (`chmod 600`).

```js
const bundle = {
  version: 1,
  boundary,          // base64 of the deployment description file
  buildAttestation,  // the builder's envelope, as an object
  observations,      // the observer's envelope
  review,            // the reviewer's envelope
  evidence: { access, recovery, load }, // base64 of each result file
};
```

```sh
npx agent-guard-pilot-review --policy ./policy.json \
  --candidate ./build.bin --bundle ./bundle.json
```

Add `--rehearsal` when the policy's `mode` is `rehearsal`. Inside a clone of this repository, call `node packages/executor/dist/pilot-review-cli.js` with the same options. A host can run the same check in code with `verifyPilotReview(policy, buildBytes, bundle)` from `@shieldaai/agent-guard-executor/pilot`.

Verification changes nothing, so run it again on the day you decide to roll out. To withdraw an approval, retire the policy or give it a new `runId`.

## What you should see

Exit code `0` and one line of JSON:

```json
{"version":1,"status":"verified","mode":"company-pilot","policySha256":"...","candidateSha256":"...","boundarySha256":"...","expiresAt":1794408782792,"buildStatementSha256":"...","observationSha256":"...","reviewSha256":"...","loadSamples":100,"latencyP95Ms":95}
```

Keep this summary with the exact policy, bundle and build file that produced it.

A failure exits with code `1` and writes two lines to standard error: an error code, then one sentence. In code, `verifyPilotReview` throws an error with `code` `PILOT_REVIEW_INVALID` and the failed check in `detail`.

```text
PILOT_REVIEW_INVALID
Failed check MODE: the policy mode differs from the requested mode (--rehearsal selects a rehearsal policy).
```

## What can go wrong

The messages never quote your files.

| First line | Cause | Fix |
| --- | --- | --- |
| `PILOT_ARGUMENT_INVALID` | A missing, repeated or unknown option. | Pass `--policy`, `--candidate` and `--bundle` once each. |
| `PILOT_INPUT_UNAVAILABLE` | A file or its directory is missing or cannot be opened. A symbolic link is refused. | Check the path and your read permission. |
| `PILOT_INPUT_UNSAFE` | A file is not an ordinary file with one hard link. On Linux and macOS: the policy or a directory above it is a link, is owned by another user, or is writable by group or others; the policy path contains `..`; or the bundle is accessible to group or others. | `chmod go-w` on the policy and its directories, `chmod 600` on the bundle, and give the policy by its real path. |
| `PILOT_INPUT_TOO_LARGE` | The policy exceeds 32 KiB, the bundle 1 MiB or the build file 64 MiB. | Reduce the file. |
| `PILOT_INPUT_CHANGED` | A file changed while it was being read. | Run again when nothing is writing to it. |
| `PILOT_INPUT_INVALID` | The policy or bundle is not UTF-8 JSON, or has duplicate keys. | Correct the file. |
| `PILOT_REVIEW_INVALID` | A check failed. The second line names it. | See the next table. |

| Failed check | Cause | Fix |
| --- | --- | --- |
| `POLICY`, `BUNDLE` | A missing, extra or out-of-range field. For the policy also: the observer and reviewer share a name or key. | Compare the file with step 2 or step 6. |
| `CANDIDATE` | In code only: the build file was not passed as a `Uint8Array`. | Pass the file's bytes. |
| `MODE` | The policy says `rehearsal` and you omitted `--rehearsal`, or the reverse. | Match the option to the policy. |
| `BOUNDARY` | The deployment description does not match `boundarySha256`, or its company, deployment, tenant or build digest differs from the policy. | Recompute the digest from the exact bytes and compare the fields with step 3. |
| `BUILD_ATTESTATION` | The build file or its attestation does not match the policy's `candidate`, or the builder's key is also the observer's or reviewer's. | Check the file's SHA-256 and the attestation. |
| `OBSERVATIONS`, `REVIEW` | A signature does not verify, a digest in the signed object is wrong, the decision is not `approve`, or the times are not in the order `notBefore`, `startedAt`, `finishedAt`, `reviewedAt`, `expiresAt`. | Recompute the digests and sign the final bytes. |
| `ACCESS_EVIDENCE`, `RECOVERY_EVIDENCE`, `LOAD_EVIDENCE` | A result file does not match the digest the observer signed, breaks a rule in step 4, exceeds 128 KiB, or has a `collectedAt` outside the run. For load: a latency is longer than the time from `startedAt` to `collectedAt`. | Correct the file, then repeat step 5. |
| `VALIDITY_WINDOW` | The current time is before `reviewedAt` or not before `expiresAt`. | Check the clock. After expiry, repeat the review under a new policy. |
