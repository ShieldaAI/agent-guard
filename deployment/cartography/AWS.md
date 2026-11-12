# Single-account AWS inventory and policy evidence

The [collector](../../integrations/cartography/README.md) can also capture IAM
role and user identifiers and S3 bucket names and regions for one explicitly
enrolled commercial AWS account. It writes them as Cartography's `AWSRole`,
`AWSUser` and `AWSS3Bucket` nodes, which the importer's cloud joins then link to
the AWS identities and resources the host declared in its manifest. A second
enrollment flag adds IAM identity-policy evidence for S3. Everything recorded is
an observation with `assessment: unknown`, never a permission decision.

AWS collection is off unless you pass `--aws-enrollment`. Installing the
package or collecting executors never discovers AWS accounts, reads credential
profiles or installs a schedule. It runs inside the collector process, under the
same lock.

In this guide **the executor** is the Agent Guard executor package and **the
host** is your trusted application code.

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
administration steps; the collector performs neither.

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
Cartography's permission mapper is applied with exactly three rules, which are
fixed in the collector:

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
policies, service control policies, trust policies and request-time context are
not evaluated.

[aws-permission-relationships.yaml](aws-permission-relationships.yaml) states
the same three rules in upstream Cartography's file format. The collector does
not read it; use it only if you also run upstream Cartography's AWS sync and
want its `CAN_*` edges to follow the same rules.

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

Candidates written by an older collector version are not rewritten on upgrade.
The graph does not keep the policies needed to recompute them: complete a new
AWS capture and then a new executor collection to replace them.

The Agent Map [reference API/viewer](../../packages/agent-map/README.md#iam-policy-evidence)
exposes this layer only through visible task, execution and resource bindings.
It verifies collection ownership, capture hashes/times, provider consistency and
independent freshness, then rechecks the observations before returning. It exposes
no account-wide policy digest or candidate counts. Unsupported or stale evidence
has an explicit reason; empty results never establish denial. A newer AWS capture
requires a new executor collection before those provider joins support candidates.
Historical snapshot comparisons do not claim policy history. Never use these
relationships for executor admission.

## Prepare the enrollment

You need a working collector for at least one executor first (see the
[README](../../integrations/cartography/README.md#collect-your-first-executor)),
on Linux or macOS; the capture worker uses POSIX process groups. The examples
use the same two directories as the rest of the documentation. From
`integrations/cartography`:

```sh
CONFIG="$HOME/.config/agent-guard-cartography"       # enrollment files
STATE="$HOME/.local/share/agent-guard-cartography"   # archive, lock, backups
install -m 600 examples/cloud-scope.json "$CONFIG/cloud-scope.json"
install -m 600 examples/aws-enrollment.json "$CONFIG/aws.json"
```

Edit both copies, and check that `$CONFIG/observer.json` is the enrollment of
the executor whose manifest names this account.
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
before the collector accepts it.

## Run a capture and keep it running

One process collects both AWS and the executors. From `integrations/cartography`,
with the Neo4j password, the observer token and the three AWS credentials in
the environment:

```sh
uv run agent-guard-cartography \
  --enrollment "$CONFIG/observer.json" \
  --cloud-scope "$CONFIG/cloud-scope.json" \
  --aws-enrollment "$CONFIG/aws.json" \
  --archive-dir "$STATE/archive" \
  --neo4j-uri bolt://127.0.0.1:7687
```

This command calls the enrolled AWS account, after verifying the caller
identity, and writes the graph. Try it first against a non-production account
and database. A remote Neo4j needs verified `bolt+s` or `neo4j+s`; plaintext is
limited to a literal loopback address.

Append `--watch --interval-seconds 300 --aws-interval-seconds 3600` to keep the
process running. An AWS attempt runs before the first executor poll. Later
attempts become due one hour after the previous attempt finishes, and start at
the next polling cycle. The clock is monotonic, failed attempts use the same
cadence, and missed periods are not replayed in a burst. AWS work can delay that
cycle's observer reads up to the configured capture/publication limits.

Every command that names this archive holds its lock (`$STATE/archive.lock`)
without being told to; a process that writes the same graph with another
archive, or with none, must share a `--lock-file` with the collector.
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
inventory or Agent Guard snapshots. Provider ownership conflicts fail closed.
Retained provider-node storage remains the operator's responsibility; bounded
current membership is not a database-wide retention policy. A refreshed provider
node timestamp here certifies metadata only. Independently collected policy/ACL
properties and permission edges may be older and keep their own semantics.

Cloud joins consult the managed membership when it exists. A preserved old
provider node that is absent from the latest complete capture is unresolved;
it cannot remain matched solely because an unrelated collector refreshed its
node timestamp. Managed capture freshness is checked independently of provider
node/account/ownership times and again during snapshot publication. Provider
inventory written by another collector, without a membership record, is matched
by its own node, account and ownership timestamps only.

If capture fails, the previous complete provider observation stays available
with its original capture time and becomes stale according to the cloud scope's
age limit. It is not relabeled as a fresh successful attempt. Executor
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

## Before you enable it for real

The repository's tests use stubbed AWS responses and call no AWS account, so
check these against your own account before relying on the result:

- The collection role allows exactly the reads listed above and nothing else.
- `expectedCallerArn` equals the caller ARN of the credentials you will use, and
  a wrong account or wrong caller is refused with `AWS_IDENTITY_MISMATCH`.
- The buckets and regions you expect are captured, and an expired credential
  produces a failure line while executor collection continues.
- Every command that writes this graph names the same `--archive-dir`, or shares
  a `--lock-file` with the collector.

A successful capture shows that metadata was read. It does not validate IAM
policy semantics or effective permissions.
