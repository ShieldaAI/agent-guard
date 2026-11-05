# Verify an independently reviewed company pilot

Use this verifier for a time-limited review of **one build artifact, deployment, tenant and read-only tool path**. It reads the candidate, operational evidence and independent review locally. Keep the exact policy, bundle, candidate and resulting receipt together in the private review archive.

```sh
agent-guard-pilot-review --policy ./enrolled-policy.json \
  --candidate ./candidate.bin --bundle ./pilot-evidence.json
```

The executable comes with `@shieldaai/agent-guard-executor`. A successful company review exits zero and prints a bounded JSON receipt. For a disposable rehearsal, enroll `mode: "rehearsal"` and pass `--rehearsal`. Both the verifier and CLI require a match with the signed mode. Only the deployment owner decides whether to roll out. Approval covers exactly the enrolled scope while its policy is valid. Run verification again with the current trusted policy and clock when making that decision. Retire the policy or rotate its run ID to withdraw a previous approval.

## 1. Enroll the candidate and boundary

Publish the policy to a separately controlled, authenticated host configuration path. The CLI checks the complete policy path from the filesystem root. Use physical directory names without parent links or `..` traversal. On POSIX the effective user or root must own the policy and every ancestor. Group or other write permission is refused on the policy. The same rule applies to directories except that a trusted sticky temporary directory protects its trusted-owned child. On Windows the operator must verify the equivalent ownership and access controls. All inputs must be local regular single-link files and the evidence bundle must be private.

The version-1 policy contains these exact fields.

| Field | Enrollment |
| --- | --- |
| `version`, `mode` | `1` and either `company-pilot` or `rehearsal` |
| `companyId`, `deploymentId`, `runId` | Stable opaque company and deployment identifiers and a fresh 32-byte cryptographically random nonce encoded as lowercase hex |
| `candidate` | One [BuildArtifactRule](build-artifact-admission.md) with the tenant, builder key, build type, source dependency, artifact path and SHA-256 |
| `boundarySha256` | Lowercase SHA-256 over the exact UTF-8 deployment manifest bytes |
| `observer`, `reviewer` | Each has an independently enrolled `subject` and `publicKeyPem` (Ed25519 SPKI). Enroll the operator capturing the evidence and the independent reviewer under distinct stable identities and keys. Keep the builder signing key separate from both. |
| `notBefore`, `expiresAt` | UTC Unix epoch milliseconds, inclusive start and exclusive end, at most 31 days apart |
| `minLoadSamples`, `maxLatencyP95Ms` | Agree on the workload and thresholds before collecting data. Enroll 20–2,048 observations and a positive integer p95 ceiling in milliseconds. |

The manifest fixes the deployment that the reviewer is being asked to approve. Its fields are `version: 1`, `companyId`, `deploymentId`, `tenantId`, `candidateSha256`, `oidcIssuer`, `oidcAudience`, `httpsOrigin`, `awsRoleArn`, `expectedBucketOwner`, `awsAction`, `awsResourceArn`, `protectedTool` and `excludedSurfaces` (up to 32 distinct scope identifiers). The issuer accepts a canonical HTTPS URL with an optional path. The service origin accepts an HTTPS origin without a path. The AWS profile covers the existing commercial-account metadata read. Specify `s3:GetBucketLocation`, one exact S3 bucket ARN and the 12-digit owner of the specified IAM role. The collector must actually send that account as `ExpectedBucketOwner`. This check needs no access to object contents. [Collector boundary](../../deployment/cartography/AWS.md)

Store the actual artifact bytes for verification and the exact [build attestation](build-artifact-admission.md#the-accepted-attestation) from its producer. Keep all signing keys outside the candidate and its evidence. A copied public key under a second subject will be rejected. Establish the two people's organizational independence and authority through enrollment.

## 2. Collect and sign the run

Compute `policySha256` with `digestJson(immutableJson(policy))` from `@shieldaai/agent-guard`. This covers the complete policy, including threshold, mode, pins, window and nonce. The boundary, section, statement and observation file digests use SHA-256 over **original bytes**, including whitespace.

Create three UTF-8 JSON evidence sections. Every section contains `kind` (its section name), `policySha256`, `collectedAt` (epoch milliseconds in the observed run) and `sourceReport` (standard padded base64 of up to 64 KiB of original redacted operator evidence). The following are the additional fields.

| Section | Required observations |
| --- | --- |
| `access` | `probes` has exactly one `{name,outcome,backendReads,backendWrites}` per named check. `oidc-read`, `rotated-tls-read`, `rotated-key-read` and `aws-read` each require `allowed`, one successful protected read and zero writes. `foreign-tenant-read`, `revoked-session-read`, `retired-tls-read`, `retired-key-read` and `aws-write` each require `denied`, zero reads and zero writes. Count protected backend effects for the individual probe. Exercise the write as a denied request through the mediator using the existing read-only enrollment. |
| `recovery` | `before` and `restored` each contain `logicalStateSha256` and a positive `records` count. Use the same canonical logical state projection and compare both observations. `incident` contains `initialStatus: "UNKNOWN"`, `finalStatus: "SUCCEEDED"`, a `receiptSha256` for the retained trusted backend receipt and `effectsBefore: 1`, `effectsAfter: 1` for the reconciled action. Use an isolated approved effect and establish that reconciliation kept its count at one. |
| `load` | `latenciesMs` contains every timed observation for the enrolled workload (whole milliseconds, 0–86,400,000). `totalAttempts` equals its length and `failedAttempts` is zero. The gate computes nearest-rank p95, enforces the minimum population and accepts p95 at or below the agreed ceiling. |

Use the existing [pilot, benchmark and recovery runbook](../../deployment/cartography/RUNBOOK.md) to collect the underlying receipts. Redact credential material before encoding evidence. Base64 only transports bytes. Preserve original logs and the probe-to-receipt mapping under operator access controls. The verifier checks the normalized measurements and byte digests. Source reports are opaque attachments. The observer and independent reviewer establish that each report came from the enrolled deployment and supports its normalized rows. Repository synthetic reports belong in rehearsal runs.

Record counts and timing measurements as exact safe integers. The verifier rejects fractional JSON numbers even when floating-point rounding would turn them into a valid count. Each latency must fit between the run start and load collection time, including samples above p95. Include the digests of all three evidence sections in the observer statement.

```js
const observations = {
  policySha256, mode: policy.mode, runId: policy.runId,
  candidateSha256, buildStatementSha256, startedAt, finishedAt,
  evidence: { access: accessSha256, recovery: recoverySha256, load: loadSha256 },
};
```

Hash each exact JSON section file. The build statement digest covers the decoded bytes of the producer's signed payload. The observer signs the original observation JSON bytes in a single-signature DSSE envelope with payload type `application/vnd.agent-guard.pilot-observations.v1+json`. All envelopes use canonical padded base64. The untrusted key ID must match the enrolled SPKI DER SHA-256. The Ed25519 signature covers the standard DSSE pre-authentication encoding of the media type and payload.

## 3. Review, sign and verify

Verify the candidate's build and deployment pins, inspect each source report, review its recorded time, compare backend effects and confirm the workload and exclusions. The independent reviewer signs the approval below using the payload type `application/vnd.agent-guard.pilot-review.v1+json`.

```js
const review = {
  policySha256, mode: policy.mode, runId: policy.runId,
  observationSha256, decision: 'approve', reviewedAt, openExceptions: [],
};
```

`observationSha256` binds the exact decoded observer payload. An open exception or rejection leaves the scope unapproved. The run must fall within the policy window, each section must fall within the run, and review must occur after collection and no later than verification. The signature scope includes the run nonce and counters. Repeat verification is read-only and idempotent while the enrolled window is valid.

The final bundle has `{version:1,boundary,buildAttestation,observations,review,evidence:{access,recovery,load}}`. Supply the three signed envelopes as objects and the boundary and three section files as canonical base64 strings. Maximum input sizes are 32 KiB for the policy, 64 MiB for the artifact and 1 MiB for the bundle. Each decoded section is bounded to 128 KiB. The boundary and both operational statements are each bounded to 16 KiB. The receipt reports digests, expiry, mode, sample count and p95. It omits source reports, keys, internal identifiers and endpoints.

Hosts call `verifyPilotReview(policy, candidateBytes, bundle)` for a company pilot. A rehearsal requires an explicit fourth argument, `'rehearsal'`. Choose that argument from the intended operation before processing the evidence. Pass the same privately held candidate bytes that the deployment will select by digest. The verifier rejects concurrently mutable shared memory. The [disposable fixture](../../packages/executor/test/fixtures/pilot-review.mjs) demonstrates exact serialization, hashing and role-separated signing. [Regression tests](../../packages/executor/test/pilot-review.test.mjs) exercise real signatures, malformed input, scope changes, unsuccessful operations, clock windows and resource bounds.
