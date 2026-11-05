# Run an operator usability acceptance session

**Current evidence: unmeasured.** The repository contains a blank study packet and executable scoring rules. A UX owner can use them to decide whether operators can safely use a particular build and deployment. The checked-in tests use generated fixtures. No participant identities, observations, signatures or acceptance receipts are supplied.

Give the [participant brief](operator-study/participant-brief.md) to operators. Keep the following setup and scoring instructions with the facilitator and backend evidence owner. The [scorer](../../scripts/score-operator-study.mjs) runs offline against a local build of the executor package, on POSIX, using Node.js 22.13 or newer. Run `npm run build` from the repository root if the package has not been built.

## Freeze the study before the first task

1. The UX owner enrolls **5–40 different representative operators** who did not build the workflow. Include a habitual keyboard-only user and a separate assistive-technology user. Verify the real participants and their usual access methods privately. Use unique aliases in the worksheet. A simulated participant or an engineer role-playing a disability cannot fill either seat.
2. Use synthetic records in a private disposable tenant on the proposed deployment, with its actual approval interface, company sign-in, evidence viewer and receipt lookup. Pin the source/build digest and a digest of the reviewed deployment boundary. Verify identity, rollback and receipt access before inviting anyone. The local terminal demonstration alone cannot test this integration.
3. The facilitator freezes the exact private task script, including the five tasks, the assignment on each card and counterbalanced review order. Make a read-only copy. Start from [enrollment.blank.json](operator-study/enrollment.blank.json). Set `briefSha256` to the SHA-256 of the exact script bytes, `buildSha256` and `deploymentSha256` to the reviewed digests, `studyId` to a unique alias, and `start` and `end` to UTC timestamps with milliseconds (at most 31 days apart). Add `{"alias":"<alias>","method":"<method>"}` for every participant using `standard`, `keyboard-only` or `assistive-technology`.
4. Enroll **different Ed25519 public keys** under `facilitatorKey` and `backendKey`. The facilitator observes human decisions. A separate backend evidence owner checks the complete action, identity and receipt logs for the enrolled tenant. Provision these keys privately under their respective owners. Each key field is canonical base64 of its public SPKI DER bytes. For example, an owner can export an existing Ed25519 public key using `openssl pkey -pubin -in public.pem -outform DER | openssl base64 -A`.
5. The release owner runs the commands below before the enrollment starts. Preserve the printed digest in a dated, access-controlled release record outside the scoring bundle. The scorer cannot establish advance enrollment from an editable file and a digest supplied by the same submitter.

```sh
node scripts/score-operator-study.mjs enroll enrollment.json private-task-script.md
node scripts/score-operator-study.mjs worksheet enrollment.json facilitator > facilitator.json
node scripts/score-operator-study.mjs worksheet enrollment.json backend > backend.json
```

Both worksheets contain every planned participant/task pair. Placeholder nulls are intentional. Do not supply a blank worksheet as an observation. A changed build, task script, access method, participant list or deployment needs fresh enrollment. Preserve failed and abandoned rounds.

## Observe the five tasks

Give each person one card at a time. Do not suggest the intended decision. Ask what happened and why after each task. Any instruction during the task earns `prompted` rather than `none`. Record `abandoned` when someone stops. Code a safe unfinished or misunderstood task as `incomplete` and an unsafe decision as `unsafe`. The success answers below require both the observed human action and the operator’s own accurate account.

| Case | Only successful answer | Minimum setup and complete backend event sequence for success, in order |
| --- | --- | --- |
| `approve` | `explained-confirmed-change`: approved the assigned tenant, ticket, change and version, then correctly described the confirmed outcome. | `exact-review-presented` → `review-approved` → `write-dispatched` → `write-committed`. One correlated write to the exact assigned target. An operator who safely refuses may have `exact-review-presented` → `operator-refused` and no write. |
| `lookalike` | `refused-and-identified-mismatch`: the person refused and identified the substituted tenant or target. A backend block alone earns no credit. | `wrong-target-presented` → `operator-refused`. Record an attempted unsafe approval even if the backend denied it. |
| `session` | `reauthenticated-and-explained-expiry`: observed protected results clearing, used the intended sign-in and understood the inventory still existed. | `scoped-evidence-served` → `session-revoked` → `old-session-denied` → `new-session-authenticated` → `scoped-evidence-served`. The enrolled exercise must record the first two events. |
| `relationship` | `identified-unknown-and-required-check`: recognized the stale, missing or conditional relationship as inconclusive and identified the missing live check. | `unknown-relationship-served` from the scoped viewer query. |
| `recovery` | `checked-receipt-and-avoided-retry`: found the original receipt, checked termination, reconciled, and avoided submitting again. | `write-dispatched` → `write-committed` → `response-lost` → `receipt-read` → `execution-reconciled`. Seed and capture the first three events before the user investigates. |

The facilitator fills each pre-generated row with the actually used `method`, `assistance`, `answer`, and explicit booleans for `unsafeDecision`, `disclosure` and `criticalBlocker`. Record unsafe behavior independently of whether it caused harm. A critical blocker prevents safe use of an essential task with the enrolled access method. Agree a fresh opaque `runRef` with the backend owner per attempt (64 lowercase hex digits). After witnessing and verifying the private roster, the facilitator may set `witnessedIndependentRepresentativeHumans` to true.

## Collect and sign the evidence

For each attempt, the independent backend owner exports a **complete**, minimized chronological projection of the enrolled audit window. Use [receipt.blank.json](operator-study/receipt.blank.json). Bind the enrollment digest, alias, scenario, run reference and the actual capture timestamp. Set `complete` only after checking all relevant streams, including refused and retried operations. Missing logs leave the gate unverified. Store the original backend records privately for independent inspection.

Each event has exactly `type` and `ref`. Use the vocabulary in the table and record `wrong-target-approved`, `write-retried`, `foreign-write` or `foreign-disclosure` when observed. Preserve actual dispatches and commits, including duplicates. For a safely unfinished task the export may end after a prefix of the sequence, provided it covers the entire observation window and includes the required setup. The event reference is a pseudonymous, collision-resistant 64-hex digest of the actual audited operation, prepared review, query, or session identifier as appropriate. Use the **same** operation reference for a write and its receipt, including recovery. For session renewal, bind the first three events to the old session and the last two to the same new one. Use fresh subjects for every attempt. Do not use one shared ticket number or a fabricated reference for unrelated events.

Hash each receipt file's exact bytes and store it privately as `receipts/<sha256>.json`. Enter that digest in the matching row of `backend.json`. Counters, screenshots, a task outcome ticked by a facilitator, and a generic backend denial cannot replace these records. The observer must compare the normalized evidence to the original deployment records. Cryptography authenticates the enrolled signers and detects substitutions; it cannot establish that people attended, that the environment was representative, or that a dishonest signer reported every event.

The owners separately sign the final exact JSON bytes with their enrolled keys. For OpenSSL 3 and a privately managed local test key, the signing command is:

```sh
openssl pkeyutl -sign -rawin -inkey facilitator-private.pem -in facilitator.json -out facilitator.sig
openssl pkeyutl -sign -rawin -inkey backend-private.pem -in backend.json -out backend.sig
```

Do not transfer private keys to the release owner. The release owner retrieves the original enrollment digest from the dated record and checks the build and deployment before running:

```sh
node scripts/score-operator-study.mjs score enrollment.json "$ENROLLED_SHA256" \
  facilitator.json facilitator.sig backend.json backend.sig receipts
```

## Read the decision

The report includes successful/planned counts per scenario, access method and overall. Every planned attempt counts. A malformed, missing, duplicated, misbound, unsigned or incomplete study cannot pass. A wrong target, unsafe retry or disclosure, critical accessibility blocker, unsupported claim of success, or failure to complete either lookalike refusal or recovery independently disqualifies the round.

- `stretch-met` (exit 0) requires at least **96% unassisted safe completion overall**, at least **80% in every scenario and access method**, and every hard gate. With five operators the overall requirement is 24/25.
- `pilot-only` (exit 1) meets the original 90% pilot threshold (23/25 for five operators) with every hard gate, but misses a stretch threshold. `failed` (also exit 1) falls short of the pilot.
- `unverified` (exit 2) means the required evidence could not be verified. `enroll` alone prints `unmeasured`. Neither result earns a human UX score.

A stretch result supports the named build and cohort. The 96% threshold is a task-completion criterion; five operators do not establish a population-wide UX rating or general accessibility conformance. Retest with a fresh cohort and enrollment after a critical fix. To exercise the verifier with test fixtures, run `node --test scripts/score-operator-study.test.mjs`.
