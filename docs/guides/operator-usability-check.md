# Test the approval screen with real operators

Read this if you must decide whether the people who approve agent actions can use your deployment's review screen safely, and you can recruit at least five of them for a study. Library users can skip it.

## What you will achieve

You will run a small study and get a score. Between 5 and 40 operators each attempt five tasks on a test copy of your deployment. One person watches the operators and records what they did. A second person records what the backend logs show for the same attempts. A script compares the two records and prints the result.

The repository supplies the handout for operators, two blank forms and the scoring script. You collect the results.

## Prerequisites

- Linux or macOS, Node.js 22.13 or newer, and a clone of this repository with `npm ci` and `npm run build` done. The script works offline.
- OpenSSL 3 or newer for signing. The `openssl` that ships with macOS is LibreSSL and does not support the signing command below.
- A private test tenant on the deployment you want to assess, filled with made-up records, with its real approval screen, company sign-in, evidence viewer and receipt lookup.
- These people:

  | Role | Who | Does what |
  | --- | --- | --- |
  | Operators | 5 to 40 people who will do this work and did not build the workflow. At least one routinely works by keyboard only and at least one other uses assistive technology. An engineer playing the part does not count. | Attempt the five tasks |
  | Facilitator | One person who sits with the operators | Records what each operator did and said, and signs that record |
  | Backend owner | A different person, with access to the backend logs | Records what the logs show for each attempt, and signs that record |
  | Study owner | Whoever makes the decision | Keeps the study digest from step 3 and runs the scoring |

- An Ed25519 key each for the facilitator and the backend owner. Private keys stay with their owners. To create a key and print the public part in the form the study file expects:

  ```sh
  openssl genpkey -algorithm ed25519 -out facilitator-private.pem
  openssl pkey -in facilitator-private.pem -pubout -out facilitator-public.pem
  openssl pkey -pubin -in facilitator-public.pem -outform DER | openssl base64 -A
  ```

## Steps

### 1. Write the task script

The facilitator writes a private file, here `private-task-script.md`, with the five tasks, the team, environment and target printed on each operator's task card, and the order in which each operator gets the tasks. Vary the order between operators. Operators receive only the [participant brief](operator-study/participant-brief.md) and their cards.

### 2. Fill in the study file

Copy [enrollment.blank.json](operator-study/enrollment.blank.json) to `enrollment.json` and fill in every field.

| Field | Value |
| --- | --- |
| `kind` | Leave as `operator-study-enrollment-v1` |
| `studyId` | A short name: letters, digits, `_` and `-`, at most 48 characters |
| `buildSha256`, `deploymentSha256` | SHA-256 digests that identify the build and the deployment configuration under test |
| `briefSha256` | SHA-256 of the task script: `shasum -a 256 private-task-script.md` |
| `start`, `end` | UTC times with milliseconds, such as `2026-11-20T09:00:00.000Z`. At most 31 days apart. |
| `facilitatorKey`, `backendKey` | The two public keys, as printed by the last command above. They must differ. |
| `participants` | One `{"alias": "<alias>", "method": "<method>"}` per operator. The method is `standard`, `keyboard-only` or `assistive-technology`. Use aliases, not names. |

### 3. Lock the study before it starts

Run this before the `start` time. It checks the file and prints its digest.

```sh
node scripts/score-operator-study.mjs enroll enrollment.json private-task-script.md
```

```json
{
  "status": "unmeasured",
  "enrollmentSha256": "0e811ee039bad52f868cd3bf76d5e8bf36797c9a295606225e1f771eef4bbe66"
}
```

The study owner stores that digest where neither signer can edit it. Scoring later fails if `enrollment.json` no longer has this digest. If the build, the task script, the operator list or the deployment changes, start again from step 2.

### 4. Create the two worksheets

```sh
node scripts/score-operator-study.mjs worksheet enrollment.json facilitator > facilitator.json
node scripts/score-operator-study.mjs worksheet enrollment.json backend > backend.json
```

Each worksheet has one row for every operator and task, with `null` where a value is needed.

### 5. Run the sessions

Give each operator one card at a time. Do not hint at the expected decision. After each task, ask what happened and how they know.

The five tasks (`scenario` in the worksheets):

| Task | The operator succeeds by | `answer` on success | Backend events for a success, in order |
| --- | --- | --- | --- |
| `approve` | Approving the assigned change and correctly describing the confirmed result | `explained-confirmed-change` | `exact-review-presented`, `review-approved`, `write-dispatched`, `write-committed` |
| `lookalike` | Refusing a request for the wrong tenant or target, and saying what was wrong with it. A backend block alone does not count. | `refused-and-identified-mismatch` | `wrong-target-presented`, `operator-refused` |
| `session` | Signing in again after the session ends, and understanding that the inventory still exists | `reauthenticated-and-explained-expiry` | `scoped-evidence-served`, `session-revoked`, `old-session-denied`, `new-session-authenticated`, `scoped-evidence-served` |
| `relationship` | Recognizing that a stale, missing or conditional relationship proves nothing, and naming the live check that is needed | `identified-unknown-and-required-check` | `unknown-relationship-served` |
| `recovery` | Finding the original receipt for an update whose response was lost, and not submitting it again | `checked-receipt-and-avoided-retry` | `write-dispatched`, `write-committed`, `response-lost`, `receipt-read`, `execution-reconciled` |

For `session`, set up the first two events before the operator starts. For `recovery`, set up the first three.

For each attempt the facilitator and the backend owner agree a fresh `runRef` (`openssl rand -hex 32`), and the facilitator fills in the row:

| Field | Value |
| --- | --- |
| `runRef` | The agreed value. Never reuse one. |
| `method` | The access method the operator actually used. It must match the study file. |
| `assistance` | `none`, `prompted` (any instruction during the task) or `abandoned` (the operator stopped) |
| `answer` | The success answer from the table above, `incomplete` (unfinished or misunderstood, but safe) or `unsafe` |
| `unsafeDecision`, `disclosure` | `true` if the operator made an unsafe decision or exposed another tenant's data, whether or not harm followed |
| `criticalBlocker` | `true` if the operator could not safely do an essential task with their access method |

When all sessions are done and the facilitator has confirmed that every participant was a real, independent operator, the facilitator sets `witnessedIndependentRepresentativeHumans` to `true`.

### 6. Record what the backend shows

For every attempt the backend owner copies [receipt.blank.json](operator-study/receipt.blank.json), fills it in from the audit log, and saves it.

| Field | Value |
| --- | --- |
| `enrollmentSha256` | The digest from step 3 |
| `alias`, `scenario`, `runRef` | The same values as the facilitator's row |
| `capturedAt` | When the log was read: UTC with milliseconds, between `start` and `end` |
| `complete` | `true` only after checking every relevant log, including refused and retried operations |
| `events` | 1 to 32 entries of `{"type": "<event>", "ref": "<64 hex characters>"}` in the order they happened |

Rules for `events`:

- Record what actually happened, including duplicates. Use the event names from the table in step 5, plus `wrong-target-approved`, `write-retried`, `foreign-write` and `foreign-disclosure` when you see them. An operator who safely declines the `approve` task leaves `exact-review-presented`, `operator-refused`.
- `ref` is a SHA-256 digest of the real identifier of the operation, review, query or session in your logs, so that the receipt carries no private identifier.
- All events in one receipt share one `ref`. The exception is `session`: the first three events share the old session's `ref`, and the last two share the new session's.
- Never reuse a `ref` in another receipt.

Save each receipt in a `receipts` directory under the name of its own digest, and enter that digest as `receiptSha256` in the matching row of `backend.json`:

```sh
mkdir -p receipts
digest=$(shasum -a 256 receipt.json | cut -d' ' -f1)
mv receipt.json "receipts/$digest.json"
echo "$digest"
```


### 7. Sign the worksheets

Each owner signs the final bytes of their own worksheet with their own key.

```sh
openssl pkeyutl -sign -rawin -inkey facilitator-private.pem -in facilitator.json -out facilitator.sig
openssl pkeyutl -sign -rawin -inkey backend-private.pem -in backend.json -out backend.sig
```

### 8. Score

The study owner runs the scoring with the digest stored in step 3.

```sh
node scripts/score-operator-study.mjs score enrollment.json "$ENROLLED_SHA256" \
  facilitator.json facilitator.sig backend.json backend.sig receipts
```

## What you should see

```json
{
  "status": "stretch-met",
  "enrollmentSha256": "0e811ee039bad52f868cd3bf76d5e8bf36797c9a295606225e1f771eef4bbe66",
  "participants": 5,
  "pilot": true,
  "stretch": true,
  "failures": [],
  "missedThresholds": [],
  "overall": { "successful": 24, "planned": 25 },
  "byScenario": { "approve": { "successful": 4, "planned": 5 }, "...": {} },
  "byMethod": { "standard": { "successful": 14, "planned": 15 }, "...": {} }
}
```

An attempt counts as successful only when the operator needed no help, gave the success answer, did nothing unsafe, hit no critical blocker, and the backend receipt shows the complete event sequence. Every planned attempt is in the denominator.

| `status` | Exit code | Meaning |
| --- | --- | --- |
| `stretch-met` | `0` | At least 96% of all attempts succeeded, at least 80% in every task and for every access method, and nothing in `failures`. With five operators that is 24 of 25. |
| `pilot-only` | `1` | At least 90% of all attempts succeeded (23 of 25 with five operators) and nothing in `failures`, but a higher threshold was missed. `missedThresholds` says which. |
| `failed` | `1` | Fewer than 90% succeeded, or `failures` is not empty. |
| `unverified` | `2` | The files could not be checked. `reason` says why. No score is given. |

Any of these puts an entry in `failures` and fails the study, whatever the percentages:

| `failures` entry | Cause |
| --- | --- |
| `UNSAFE_OR_DISCLOSED` | An operator made an unsafe decision or exposed data, or the backend shows a wrong target approved, a retried write, a duplicate write or an effect on another tenant. |
| `CRITICAL_ACCESSIBILITY_BLOCKER` | A row has `criticalBlocker: true`. |
| `CRITICAL_TASK_FAILED` | Any operator did not succeed, unaided, at `lookalike` or `recovery`. |
| `UNSUPPORTED_OBSERVATION` | The facilitator recorded a success that the backend events do not support, or the events are out of order or carry the wrong `ref`. |

A good result describes this build, this deployment and these operators. After fixing a serious problem, run a new study with different operators.

## What can go wrong

Every problem with the files prints `{"status":"unverified","reason":"..."}` and exits with code `2`.

| `reason` | Cause | Fix |
| --- | --- | --- |
| `ENROLL_BEFORE_STUDY` | `enroll` was run after the `start` time. | Choose a later `start` and run `enroll` first. |
| `BRIEF_CHANGED`, `ENROLLMENT_CHANGED` | The task script or `enrollment.json` no longer matches its recorded digest. | Restore the original file. A changed study starts again at step 2. |
| `OPERATOR_COUNT`, `MISSING_ACCESS_METHOD` | Fewer than 5 or more than 40 operators, or no keyboard-only or no assistive-technology operator. | Recruit the missing operators before the study. |
| `INVALID_PUBLIC_KEY`, `SAME_SIGNER` | A key is not in the form printed by the command under Prerequisites, or both roles use the same key. | Export each owner's key again. |
| `INVALID_TIME`, `INVALID_WINDOW` | A time is not written like `2026-11-20T09:00:00.000Z`, or `end` is not after `start` and within 31 days of it. | Correct the times. |
| `INVALID_SIGNATURE` | A worksheet was edited after signing, or signed with the wrong key. | The owner signs the final file again. |
| `HUMAN_WITNESS_REQUIRED` | `witnessedIndependentRepresentativeHumans` is not `true`. | The facilitator sets it, if it is true, and signs again. |
| `INCOMPLETE_MATRIX`, `INCOMPLETE_OBSERVATION` | A row is missing, or still holds `null` or a value outside the lists in step 5. | Fill in every row. Record an attempt that did not happen as `abandoned` and `incomplete`. |
| `REUSED_OR_MISSING_RUN`, `REUSED_OR_MISSING_RECEIPT`, `REUSED_EVENT_IDENTITY` | A `runRef`, receipt or event `ref` is missing or used twice. | Use fresh values for every attempt. |
| `RECEIPT_CHANGED`, `RECEIPT_BINDING`, `RECEIPT_TIME`, `INSUFFICIENT_BACKEND_EVIDENCE` | A receipt does not match its digest or its worksheet row, has `complete` other than `true`, has a `capturedAt` outside the study or in the future, or does not start with the task's setup events. | Correct the receipt, save it under its new digest and update `backend.json`. |
| `INVALID_OR_UNREADABLE_INPUT` | A file is missing, is a symbolic link, is too large or is not valid JSON, or the command has the wrong number of arguments. | Check the paths and the argument order in step 8. |

The signatures show that the two named people produced the two records and that nothing was swapped afterwards. They cannot show that the operators were who you intended, or that a signer reported everything.
