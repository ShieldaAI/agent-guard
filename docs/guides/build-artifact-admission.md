# Admit externally built files to a protected task

Configure an `ArtifactBroker` with a build policy when a task will consume a release artifact from an external build system. The host enrolls the expected bytes, tenant, path, signing key and build identity. The broker verifies the external signature, compares the signed claims with that enrollment, and issues a sensitive local receipt. Each subsequent import checks the bytes again.

## Enroll the build

For each permitted file, the deployment owner records:

- The exact `tenantId` and portable relative `path` where the file may be admitted.
- The release manifest's expected file `sha256` and the attestation's enrolled `subjectName`.
- The expected `builderId`, `buildType`, `sourceUri` and `sourceDigest`. Use a lowercase hex `sha256` or `sha1` under the corresponding algorithm name for the source identifier. The file digest always uses SHA-256.
- The builder's Ed25519 public key in PEM SubjectPublicKeyInfo format as `signerPublicKeyPem`.

Provision this enrollment through an authenticated host configuration channel. Confirm the builder's key fingerprint and release digest independently of the candidate files. The host's 32-byte receipt HMAC key serves a separate purpose and stays with the broker.

```ts
import type { TaskOptions } from '@shieldaai/agent-guard';
import { ArtifactBroker, type BuildArtifactRule, type BuildAttestationEnvelope } from '@shieldaai/agent-guard-executor/sandbox';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

export function importBuild(
  executor: DurableExecutor, receiptKey: Uint8Array, enrolled: BuildArtifactRule,
  task: TaskOptions, candidateBytes: Uint8Array, attestation: BuildAttestationEnvelope,
) {
  const broker = new ArtifactBroker({
    keyId: 'pilot-receipts', key: receiptKey, buildPolicy: { artifacts: [enrolled] },
  });
  try {
    const bytes = Buffer.from(candidateBytes);
    const receipt = broker.admitBuildArtifact({
      content: bytes, path: enrolled.path, tenantId: enrolled.tenantId, attestation,
    });
    const credential = broker.createTaskFromArtifacts(executor, task, [
      { envelope: receipt, contentBase64: bytes.toString('base64') },
    ]);
    return { broker, receipt, credential }; // The host closes the broker after use.
  } catch (error) {
    broker.close();
    throw error;
  }
}
```

The task still needs host-issued grants, resource checks and approval for every governed effect that requires it. The receipt marks the bytes sensitive and their content untrusted. Keep the broker, task credentials and enrollment in the host process.

## The accepted attestation

The envelope has `payloadType: "application/vnd.in-toto+json"`, a base64 `payload`, and one signature containing `keyid` and base64 `sig`. The key ID must equal the lowercase SHA-256 of the enrolled public key's SPKI DER bytes. The broker verifies Ed25519 over the DSSE pre-authentication encoding of the original payload bytes and media type. [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)

The signed payload is an in-toto Statement v1 with predicate type `https://slsa.dev/provenance/v1`. This implementation accepts one subject containing the expected name and SHA-256 digest. It checks `predicate.runDetails.builder.id`, `predicate.buildDefinition.buildType`, and a single reported `resolvedDependencies` entry with the enrolled URI and source digest. The signature authenticates what the enrolled builder reported. The deployment owner assesses the builder and the completeness of its dependency reporting. [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) · [SLSA Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)

The supported profile accepts omitted, null or empty external/internal build parameters. It permits optional descriptive builder version strings and run metadata for invocation ID, start and finish. Other fields and relationship shapes fail validation. It rejects duplicate JSON members, malformed UTF-8, unrecognized keys, multiple subjects/signatures and ambiguous tenant/path rules. The classifier accepts up to 128 policy rules, 1 MiB of policy JSON and 128 KiB of decoded statement bytes. The existing broker limit applies to candidate file bytes (64 MiB).

## Enforce the receipt at use

With `buildPolicy` configured, `classifyArtifact` rejects raw uploads. Pass the returned receipt alongside its file in `inputReceipts` when calling `runGovernedSandbox` or registering `createSandboxTool`. Every selected input requires a matching receipt. The governed tool includes the policy digest in its configuration, checks the inputs during preparation and binds the file versions to the approval. The broker checks the final staged bytes before launching Docker. A changed file fails with `TOOL_CHANGED` at dispatch. The durable executor conservatively retains an admitted failure as `UNKNOWN` pending operator reconciliation.

The broker signs every receipt under the configured policy using schema version 2. Each receipt includes `buildPolicySha256`. External root receipts additionally include `buildProvenance` with the policy digest, the signed statement digest and the verified signer fingerprint. Derived files, stdout and stderr carry the policy digest and local lineage. The external build attestation pertains to the original root bytes. Keep the signed statement with the deployment evidence to resolve its digest during review.

To rotate the policy, close the old broker, replace the host's enrolled rules, instantiate a new broker and re-register its governed tools. Closing the broker blocks new preparations and launches, including commands with zero selected inputs. Cancel any already launched work through the executor and reconcile uncertain effects using trusted backend evidence. The new broker rejects both roots and derived receipts issued under a different policy digest, even when the host receipt key is shared. Explicitly revoke any running tasks that must lose authority. To permanently invalidate old receipts when reinstating an earlier policy, rotate the host receipt key too. A broker opened without a build policy continues to use the original version-1 receipt protocol.

## Verify a deployment

```sh
npm run build
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:YOUR_REVIEWED_DIGEST' \
  node --test packages/executor/test/build-artifact-import.test.mjs \
  packages/executor/test/build-provenance.test.mjs
```

Use a reviewed digest already installed on the local Docker host. The integration test stages real signed bytes, runs an approved shell command, imports its output, and rejects that output after signer rotation. Adversarial tests cover forged signatures or claims, file substitution, mixed and sparse batches, tenant switching and unreceipted inputs. The fixture keys are disposable.

This milestone covers host-selected files entering the configured broker. Container image admission still uses the separate pinned-image profile. Production rollout requires enrollment of the actual builder and release manifest, operator custody of the policy and keys, and an independent review of which import and execution entry points the deployment exposes.
