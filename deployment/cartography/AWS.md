# Single-account AWS inventory and policy evidence

This optional collector fills the provider inventory used by Agent Guard's
existing cloud joins. It captures IAM role/user identifiers and general-purpose
S3 bucket metadata for one explicitly enrolled commercial AWS account. It writes
the pinned Cartography `AWSRole`, `AWSUser` and `AWSS3Bucket` shapes, with an
account ownership edge and an independent complete-capture membership record.
Cloud associations remain observations with `assessment: unknown`.
An additional enrollment flag enables bounded IAM identity-policy collection
and S3 candidate permission edges. It is off by default.

The collector runs inside the existing observer worker's ingestion lock.
It is disabled unless `--aws-enrollment` is supplied. Installing the package,
running the synthetic pilot, or starting ordinary observer polling does not
discover AWS accounts, read AWS credential profiles or install a schedule.

## Scope and required reads

The default metadata capture uses these five API operations:

| API operation | Purpose and retained evidence |
| --- | --- |
| [STS GetCallerIdentity](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/get_caller_identity.html) | Verify the exact account ID and caller ARN before inventory reads. Caller details are not printed. |
| [IAM ListRoles](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_roles.html) | Paginate role ARN, ID, name, path and creation time. Discard trust policy documents and other returned fields. |
| [IAM ListUsers](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html) | Paginate user ARN, ID, name, path and creation time. Password-use observations are not collected or overwritten. |
| [S3 ListBuckets](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/list_buckets.html) | Paginate the caller account's general-purpose bucket names and creation times. |
| [S3 GetBucketLocation](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_location.html) | Read each bucket's region with `ExpectedBucketOwner` fixed to the enrolled account. |

Review the collection role for `iam:ListRoles`, `iam:ListUsers`,
`s3:ListAllMyBuckets` and `s3:GetBucketLocation`, with your account's intended
resource and organizational controls. STS identity lookup itself does not require
an allow grant, so a successful identity check does not prove the remaining
inventory reads are permitted. Permission creation and role assumption are host
administration steps; this launcher performs neither.

The default capture excludes IAM policy collection. Both modes exclude role trust
evaluation, AWS Organizations discovery, service-last-accessed reporting jobs,
access-key enumeration, S3 objects, ACLs, bucket policies and directory buckets.
It does not call the full upstream IAM/S3 orchestration stages or their cleanup
jobs. Bucket identity and region alone cannot establish effective object or
prefix permissions.

## Opt in to IAM policy evidence

Set `includeIamPolicyEvidence: true` in the private AWS enrollment file to add
[IAM GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html).
The collection role needs `iam:GetAccountAuthorizationDetails`. This read returns
account-wide IAM policy data, including documents; enable it only for the intended
account and collector. The request uses all five entity filters (`User`, `Role`,
`Group`, `LocalManagedPolicy`, `AWSManagedPolicy`) and pages of up to 100 entities.
There are no per-policy fallback calls. The default mode refuses this operation
at the HTTP transport boundary even if its credential could call it.

The collector checks that role/user ARNs and stable identities agree with the
metadata census. User group memberships, attached managed policies, default
versions and permission-boundary references must resolve in the complete IAM
capture. Missing references, duplicate identities, inconsistent pagination or
quota failures reject the whole AWS capture. AWS pagination is not transactional;
these consistency checks detect some concurrent changes, not every possible race.

Direct and group identity policies are combined before computing candidates.
The pinned Cartography mapper evaluates only the packaged mappings:

| Mapping | Action | Retained scope |
| --- | --- | --- |
| `CAN_READ` | `s3:GetObject` | Bucket summary, including possible object/prefix restrictions |
| `CAN_WRITE` | `s3:PutObject` | Bucket summary, including possible object/prefix restrictions |
| `CAN_LIST` | `s3:ListBucket` | Bucket summary |

Every candidate has `assessment: unknown` and `resourceScope: bucket_summary`.
Conditions are unresolved; the graph retains only their key names and a condition
flag. Conditional denies can suppress candidates in the upstream mapper. Missing
candidates never establish denial, and object/prefix evidence never establishes
access to every object. Principals with a permissions boundary are marked
`boundary_unresolved`; unsupported expressions mark a principal `unsupported`.
Both statuses suppress that principal's candidates. Session policies, resource
policies, SCPs, trust policies and request-time context are not evaluated.

The supported selector subset escapes literal characters and implements `?` as
one character, with at most one `*` per selector. Resource matching preserves
case, including object-to-bucket summaries; action matching is case-insensitive.
`NotAction`, `NotResource`,
policy variables, multiple `*` wildcards and unrecognized statement forms mark
the affected principal unsupported. Policy documents are limited to 128 KiB,
16 nested levels and 20,000 structural nodes. Conditions have at most 32
operators, 128 distinct keys and 128 values per key; key names are at most 256
UTF-8 bytes. These deliberately narrow bounds can reject large legitimate
policies; a failed or unsupported result is not evidence of denial.

Policy documents, statements, condition values, trust documents, tags and policy
names stay inside the bounded capture worker. Its output contains a policy census
digest, counts, per-principal status and minimized candidate edges. The digest
detects policy changes even when the candidate graph stays the same; it is not an
authorization signature or a secret. The worker does not archive raw documents.

Publication creates `G_AWS_POLICY_CANDIDATE` relationships between the current
collection's observed provider principals and buckets. Their `relationship`
property records the mapping above; `collection_id`, `capture_hash` and
`captured_at` identify ownership and observation time. It never changes shared
Cartography `CAN_*` relationships or `AWSPolicy` nodes. `GuardAwsCollection` and
its principal membership relationships record policy coverage, including complete
empty results, unresolved principals and disabled collection.

Only this collection's candidate relationships are replaced, in the same atomic
transaction as its metadata. A failed policy read or publication preserves the
last complete capture with its original timestamp. To stop policy collection,
set the flag to `false`, restart the worker, and complete a newer metadata capture;
that successful capture removes its owned candidates and marks policy collection
disabled. Merely stopping collection does not delete old evidence. Another
collection's candidates and shared provider data are preserved.

The resource-case correction does not rewrite existing candidate evidence on
upgrade. Complete a newer successful AWS capture and then a fresh Guard
collection to replace affected candidates and refresh their joins. The graph
does not retain the raw policies needed to recompute old captures offline.

The Agent Map [reference API/viewer](../../packages/agent-map/README.md#current-iam-policy-evidence)
exposes this layer only through visible task, execution and resource bindings.
It verifies collection ownership, capture hashes/times, provider consistency and
independent freshness, then rechecks the observations before returning. It exposes
no account-wide policy digest or candidate counts. Unsupported or stale evidence
has an explicit reason; empty results never establish denial. A newer AWS capture
requires a fresh Guard collection before those provider joins support candidates.
Historical snapshot comparisons do not claim policy history. Never use these
relationships for executor admission.

## Prepare explicit enrollment

Use Python 3.13 and the locked integration environment on a POSIX host. The
private worker uses process groups and POSIX file checks; native Windows is not
supported. The observer, host manifest and cloud scope should already identify
the intended company and tenant. From the repository root:

```sh
install -d -m 700 "$HOME/.config/agent-guard-cartography"
install -m 600 integrations/cartography/examples/observer-enrollment.json "$HOME/.config/agent-guard-cartography/observer.json"
install -m 600 integrations/cartography/examples/cloud-scope.json "$HOME/.config/agent-guard-cartography/cloud-scope.json"
install -m 600 integrations/cartography/examples/aws-enrollment.json "$HOME/.config/agent-guard-cartography/aws.json"
```

Edit all three private copies. Replace the observer's enrollment generation,
ledger instance, endpoint and profile with the trusted executor configuration.
The AWS file's `companyId` and `tenantId` must match an enrolled observer and its
explicit cloud scope. The cloud scope must include the exact `partition` and
`accountId`. The supplied examples agree on `example-company`, `alpha` and
`111122223333`; these are placeholders, not a discovered account.

Only partition `aws` is supported. Set an explicit commercial AWS `region` for
STS and the initial S3 listing. The paginated `ListBuckets` response must supply
each bucket's `BucketRegion`. Location reads select only that region's canonical
`s3.<region>.amazonaws.com` endpoint, send the expected account owner, and require
the returned location to agree. At most 64 regional S3 clients are retained for
one capture. IAM uses its global commercial endpoint and signing region.
China, GovCloud, sovereign partitions, custom service endpoints, proxy
configuration and private endpoint overrides are outside this implementation.
Requests use verified HTTPS with TLS 1.2 or newer. The transport refuses
redirects instead of forwarding credentials to an unselected destination.
Offline signed-request tests cover regional endpoint selection; a live deployment
must still validate its selected region and expected buckets. Synthetic tests
are not a cross-region connectivity certification.

`expectedCallerArn` must exactly equal the ARN returned for the intended
credentials. The example expects an assumed-role session named
`agent-map-collector`; it is not the IAM role ARN. Wildcards, root identities and
another account's identity are rejected. An explicitly enrolled IAM user ARN is
also supported with temporary session credentials. Obtain and confirm this
identity through your trusted AWS administration process.

Provide all three named credentials through the host's protected process
environment:

- `AGENT_MAP_AWS_ACCESS_KEY_ID`
- `AGENT_MAP_AWS_SECRET_ACCESS_KEY`
- `AGENT_MAP_AWS_SESSION_TOKEN`

The configuration stores environment variable names, never credential values.
Values are frozen for one capture and sent to its child process over a private
pipe, not command-line arguments. The worker does not discover profiles, IMDS,
web identity, credential processes or refresh providers. Missing credentials fail
closed; they do not trigger a fallback provider. Provision the independent
observer token and Neo4j password through their configured environment names too.

The AWS enrollment file must be current-user-owned, regular, mode `0600` or
stricter, and at most 32 KiB. Symbolic links, multiple hard links, FIFOs, devices,
duplicate keys and unknown settings are rejected. Protect its parent directories
as well. The example is public metadata and has to be copied to a protected file
before the launcher accepts it.

## Run a reviewed capture and coordinate polling

After preparing the private files and credentials, use one process for AWS and
Agent Guard collection. From `integrations/cartography`:

```sh
uv sync --locked
uv run agent-guard-cartography \
  --enrollment "$HOME/.config/agent-guard-cartography/observer.json" \
  --cloud-scope "$HOME/.config/agent-guard-cartography/cloud-scope.json" \
  --aws-enrollment "$HOME/.config/agent-guard-cartography/aws.json" \
  --archive-dir "$HOME/.config/agent-guard-cartography/archive" \
  --lock-file "$HOME/.config/agent-guard-cartography/ingestion.lock" \
  --neo4j-uri bolt://127.0.0.1:7687 \
  --neo4j-user neo4j \
  --neo4j-password-env-var NEO4J_PASSWORD
```

This is an opt-in live command: it calls the configured account after identity
verification and writes the configured graph. Use an isolated non-production
account and graph for enrollment validation. Choose a dedicated collector
database credential where your Neo4j edition supports it; remote Neo4j requires
verified `bolt+s` or `neo4j+s`. Plaintext is limited to direct literal-loopback
Bolt. See the [runbook](RUNBOOK.md) for the database trust boundary.

Append `--watch --interval-seconds 300 --aws-interval-seconds 3600` to keep this
same process running. An AWS attempt runs before the first Guard poll. Later
attempts become due one hour after the previous attempt finishes, and start at
the next polling cycle. The clock is monotonic, failed attempts use the same
cadence, and missed periods are not replayed in a burst. AWS work can delay that
cycle's observer reads up to the configured capture/publication limits.

Every process targeting the same graph must use the same persistent lock file.
A separate hourly AWS job cannot run alongside a watcher holding that lock;
the integrated cadence avoids that conflict. `--aws-enrollment` is available
only with observer collection, not snapshot imports or archive receipt replay.
The AWS interval is bounded to 60–86,400 seconds and cannot enable collection
without an enrollment. No system timer or recurring automation is installed.

The CLI reads enrollment once at startup. Credentials are read from its process
environment for each attempt; changing the launching shell's environment does
not update an already running watcher. Restart with refreshed temporary
credentials before they expire. Rotating values while retaining the exact
expected caller/session identity does not change capture ownership. The graph
pins region and expected caller ARN: changing either requires a deliberate
enrollment/reconciliation procedure, not an automatic reassignment of existing
evidence. There is no credential issuance, automatic refresh or migration API.

## Publication, failures and limits

Capture succeeds only after every required page and bucket location has been
read and validated. Repeated pagination tokens, duplicate identities, foreign
account ARNs, invalid records, timeouts and quota overruns fail the entire
attempt. Raw provider responses are never persisted. The capture keeps only
the allowlisted metadata fields, optional minimized policy evidence and a capture timestamp.

AWS pagination and individual API reads do not form a transactional cloud
snapshot. Resources can change between pages or location lookups. `capturedAt`
records completion of the full collection, not a simultaneous observation of
every resource. The result is dated inventory evidence, not a live permission
decision.

Publication uses one bounded Neo4j transaction and the pinned Cartography
schemas/query builder. It updates provider metadata and the collection's
`G_AWS_OBSERVED` membership together. A failed publication preserves the previous
complete capture. A complete empty capture retires this collection's membership
without deleting shared provider nodes, account ownership, another account's
inventory or Agent Guard projections. Provider ownership conflicts fail closed.
Retained provider-node storage remains the operator's responsibility; bounded
current membership is not a database-wide retention policy. A refreshed provider
node timestamp here certifies metadata only. Independently collected policy/ACL
properties and permission edges may be older and keep their own semantics.

Cloud joins consult the managed membership when it exists. A preserved old
provider node that is absent from the latest complete capture is unresolved;
it cannot remain matched solely because an unrelated collector refreshed its
node timestamp. Managed capture freshness is checked independently of provider
node/account/ownership times and again during Guard publication. Legacy provider
inventory without a managed membership record retains the existing join rules.

If capture fails, the previous complete provider observation stays available
with its original capture time and becomes stale according to the cloud scope's
age limit. It is not relabeled as a fresh successful attempt. Guard observer
collection still runs; one-shot exit status is nonzero when the AWS attempt
fails. In watch mode, safe failure output is emitted and polling continues.

| Enrollment setting | Default | Maximum |
| --- | ---: | ---: |
| `timeoutSeconds` | 120 | 600 |
| `requestTimeoutSeconds` (connect/socket read idle timeout) | 5 | 30, and no greater than the total timeout |
| `maxApiCalls` | 1,000 | 10,000 |
| `maxPages` | 100 | 1,000 |
| `maxItems`, shared across roles/users/buckets | 10,000 | 50,000 |
| `maxResponseBytes` | 4 MiB | 8 MiB |
| `maxCaptureBytes` | 16 MiB | 64 MiB |
| `maxPolicyBytes`, aggregate IAM authorization response JSON | 8 MiB | 32 MiB |
| `maxPolicyStatements` | 10,000 | 50,000 |
| `maxPolicyEvaluations`, conservative statement/selector work estimate | 100,000 | 1,000,000 |
| `maxPolicyEdges` | 10,000 | 50,000 |

Policy limits never enable collection by themselves. Policy reads share the API,
page, response and overall time budgets with metadata. The final minimized
snapshot, including policy evidence, must fit `maxCaptureBytes`. Limits fail the
capture instead of truncating it into an apparently complete result.
`maxItems` also separately caps the IAM authorization entity census and inline
policy count. The mapping-work estimate charges every principal/bucket/action
probe, including principals without statements, and includes selector/statement
work. Candidate byte/edge limits are enforced during expansion.

The response byte ceiling is enforced before botocore parses a body. Logical
response and capture limits are checked again during projection. The per-request
setting is a socket/connect/read idle timeout, not an aggregate request deadline.
An owned child process enforces `timeoutSeconds` as the hard aggregate capture
deadline, including DNS resolution and all socket waits; timeout,
interruption or completion cleans up that process group. Publication has its
own transaction deadline, bounded to the smaller of 30 seconds and the capture
timeout. These controls do not certify a large production account's throughput.

AWS stdout records contain `kind: aws_collection`, status, an opaque collection
ID, capture time and role/user/bucket counts. Policy mode adds only candidate-edge
and unresolved-principal counts, a complete status and an unknown assessment.
Failure records contain only a
stable bounded error code and opaque collection ID. They omit credentials,
caller ARNs, resource names and raw provider/Neo4j errors. Restrict access to the
private graph and operational output: resource counts and capture cadence are
still inventory metadata.

## Validation and remaining rollout work

Tests use stubbed AWS SDK responses, a bounded local transport fixture and a
fresh disposable Neo4j graph. They cover exact identity checks, pagination and
limits, worker cleanup, serialized cadence, failures, atomic metadata membership
and existing cloud joins. No AWS credentials or live AWS account APIs are used
to validate this repository milestone.

Policy-milestone validation on 30 October 2026 passed **713 Python unit tests**
and **83 disposable-Neo4j integration tests**. These include 66 reducer cases,
80 SDK/capture/transport/worker cases, 39 enrollment cases and 22 orchestration
cases. Tests exercise real signed SDK parsing, complete group/managed-policy
resolution, conservative conditions, boundaries, limits, minimized output,
atomic replacement/opt-out, rollback and shared-edge preservation.
Ruff, wheel/source-archive builds, reconstruction of the wheel from the source
archive, and an isolated installed metadata/policy consumer passed. The
[milestone record](../../docs/cartography-integration-plan.md#iam-policy-candidate-collection-milestone)
records scope and remaining deployment limits. No JavaScript source changed in
this milestone; its existing API contract remains unchanged.

The subsequent scoped reference milestone exposes minimized candidates in the
existing Agent Map API and viewer. Its [validation report](validation/policy-reference-review-2026-10-30.md)
covers exact binding paths, independent freshness, corrupted/foreign evidence,
HTTP/MCP compatibility, package consumers and the rendered viewer. Candidates
remain unknown, including when their mapping is complete; absence is not denial.

Before enabling collection for a company, approve the one-account read role and
scope, verify the exact temporary caller ARN, test the intended buckets and
regions, and retain evidence of denied/wrong-account behavior, credential expiry,
freshness, empty captures, failures and restart. Confirm lock sharing with every
writer, review database privileges and perform the independent deployment
security review. A successful metadata capture does not validate IAM policy
semantics or effective permissions. Real cloud-account validation and company
rollout remain separate work.
