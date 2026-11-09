# Releasing the npm packages

**Current preparation: `0.1.0`, unpublished and blocked.** The
[candidate notes](releases/0.1.0.md) and root [release state](../release-state.json)
retain the required native failures, including all three +10 `b4bf2ce` runs,
and the new, unqualified +5 own-field candidate. Prior passes do not qualify a
changed implementation.
Exact-candidate performance verification, Node HIGH review, matching qualification
on future reviewed fixed Node images, and final merged-candidate checks remain
open. The security hold follows the existing
[production acceptance policy](production-readiness.md#remaining-acceptance-and-operational-limits).
Do not publish or create a stable GitHub release while these gates remain open.
Normal `npm run check` and `npm run pack` remain available for candidate work.
At the 6 November checkpoint, `b4bf2ce` passed all six ordinary workflows/11 CI
jobs and local **1,319/1,319 tests, zero skips, plus installed consumers**. Its
three native qualifications failed cold cadence; ordinary full admission passed
at 6.883%. The changed own-field candidate passed the full local check:
**1,329/1,329 tests, zero skips, plus all installed consumers**. Hosted verification
remains pending, with three native plus one ordinary full run required. Its 306 inventory
checks passed. The factored component confirmation reduced CPU on both fixtures,
but repeated-fixture total wall time regressed 5.17%; it is not acceptance.

## Node-update checklist for 0.1.0

This is a preparation checklist, not permission to publish while the release
state is blocked. Record results against one immutable candidate; retain failed
attempts and keep diagnostic/smoke evidence separate from acceptance.

1. Read the [official Node advisory](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases)
   and [official source](https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/november-2026-security-releases.md).
   On 6 November the notice still announces HIGH fixes for 22/24/26 on or shortly
   after 11 November, without individual issues or fixed versions. Record each
   disclosed issue, affected feature, fixed version and applicability decision.
   Keep the hold open until fixes or evidence-backed non-applicability are reviewed;
   an empty npm/OS audit does not resolve native Node findings.
2. Review replacement official Node images and pin repository digests. Update
   both `AGENT_GUARD_MCP_ISOLATION_IMAGE` and `NODE_IMAGE` in
   [CI](../.github/workflows/ci.yml), `NODE_IMAGE` in the
   [constrained acceptance workflow](../.github/workflows/constrained-observer.yml),
   `PINNED_IMAGE` in the [constrained runner configuration](../scripts/constrained-observer-validation.mjs),
   the version-floor map in
   [Dockerfile](../deployment/production/Dockerfile), and the corresponding floors
   in the [deployment runbook](../deployment/production/README.md#build-and-local-verification).
   The existing image is `node@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53`;
   existing floors are 22.23.4/24.22.1/26.12.1. The verified `b42620f` baseline used
   Node 22.23.4/24.22.2/26.13.0 in native CI and 24.22.1 in the production image.
   These are historical inputs, not the undisclosed November fixed versions.
   Record the replacement index digest, per-platform manifest, image ID and actual
   `node --version`. Preserve the dated advisory review; add a new review including
   base OS and builder-tool findings. Do not substitute a mutable tag or silently
   carry an old image's evidence forward.
3. With builds coordinated, run `npm ci --ignore-scripts`, `npm run check` and
   `npm run pack` on the new source/runtime. Require the ordinary hosted matrix,
   three browser engines, CodeQL, dependency review/audits, Python packaging and
   authenticated integration, installed consumers and unskipped required Linux
   isolation. Build production and verification images from the same source and
   base digest, then run the existing [image comparison and hardened recovery
   commands](../deployment/production/README.md#repeatable-deployment-gate).
   Record actual runner/runtime versions; a major-only `setup-node` selection is
   not an exact runtime identity. Preserve the real alpha.3 upgrade fixture.
4. Require the uninstrumented full graph/admission acceptance. Keep ABBA order,
   100 tasks/1,000 grants, 250 measured plus 50 warmup calls per phase, 250 ms
   serial polling, all 1,200 effects, zero failed/skipped polls, cleanup and the
   10% p95 bound unchanged. Declare **one ordinary full graph/admission run on the
   final candidate before execution; it must pass**. This is not a retry allowance.
   Retain every outcome. The run must explicitly select `linux-background` worker
   scheduling and verify the bounded before/after policy evidence.
   **The native Linux/cgroup v2 single-logical-CPU observer profile is not a 0.1.0
   gate** after the [9 November scope decision](releases/0.1.0.md#scope-decision-single-cpu-observer-profile).
   It remains unqualified with unchanged limits. Any run of it is retained as
   evidence but neither blocks nor qualifies 0.1.0. The instructions below remain
   for a later release that requalifies it. The separate
   graph-load/host-MCP fixture retains its default worker policy.
   Retain every measured sample and actual cgroup/resource settings. Instrumented
   diagnostics and smoke cannot qualify either profile. The existing full hosted
   workflow can be requested using `CANDIDATE_REF`, the frozen candidate branch or
   tag; verify the resulting run's head equals the recorded `CANDIDATE_COMMIT`:

   ```sh
   gh workflow run cartography-pilot.yml --ref "$CANDIDATE_REF" \
     -f full_benchmark=true -f admission_diagnostics=false -f admission_cpu_profile=false \
     -f worker_scheduling=linux-background
   ```

   This graph/admission workflow does not impose the one-CPU/512 MiB/no-extra-swap
   limits. The separate [constrained workflow](../.github/workflows/constrained-observer.yml)
   explicitly uses affinity `0` and `linux-background` for PR and default manual runs, with the original
   100 ms CPU period and zero burst. Manual affinity `none` is retained only for
   historical quota-only comparison. To run the configured profile after
   building, cache the reviewed image, create only the output's parent, and use a
   new output directory:

   ```sh
   docker pull "$NODE_IMAGE"
   mkdir -p artifacts/constrained-observer-runs
   node scripts/check-constrained-observer.mjs --image "$NODE_IMAGE" --cpu-affinity 0 \
     --worker-scheduling linux-background \
     --output artifacts/constrained-observer-runs/REVIEWED_UNIQUE_ATTEMPT
   ```

   Set `NODE_IMAGE` to the reviewed immutable digest. The runner requires a
   nonroot POSIX host and cached Linux image; it never pulls or builds. The output
   must be new, with an existing canonical parent shared with the Docker daemon.
   The runner creates a separate private input-stage sibling under that parent,
   mounts only that stage read-only and fresh output writable, and checks actual
   cgroup limits and cleanup. Keep `admission.json`, `resources.json`, `staged-inputs.json`
   and `verification.json` with the platform/image/source binding. Local and hosted
   qualifications are separate records. The exact `e4e42f` native Linux run passed
   at 7.2766% overhead, 1,200 effects and 149 polls without failures/skips under
   default worker scheduling. Separate `ba7deb6` runs of the explicit background
   profile passed at 5.457% and 9.280%, with 1,200 effects each and zero failed/skipped
   polls. Its local 1,307-test check and all 11 hosted CI jobs passed. The ordinary
   full workflow stopped at graph database readiness and never measured admission;
   the startup correction passed local lint/formatting, 1,022 unit tests, 150
   authenticated integration tests and package/installed-wheel checks. All six
   exact-source `b82dc4b` ordinary workflows and all 11 CI jobs passed; CodeQL
   alert 23 is fixed, not dismissed. Full graph and recovery passed, but ordinary
   admission failed at 27.422% overhead and both constrained runs failed at
   12.980%/13.017%, despite zero failed/skipped polls. The constrained staged
   runtime bytes match `ba7deb6`; its earlier passes do not establish repeatable
   margin. That checkpoint remained unqualified. The private core-worker decoder
   follow-up passed 311 focused checks and the full local check: **1,316/1,316,
   zero skips, plus all installed consumers**. Exact `f28b8e2` then passed both
   declared native qualifications at 6.863%/8.003% and ordinary full admission at
   0.204%, with 3,600 effects and 431 polls in total, zero failed/skipped polls,
   verified controls, graph/recovery and cleanup. Its six ordinary workflows and
   all 11 CI jobs passed. Those runs used +5. The required `b18b749` native
   follow-up used identical runtime bytes but failed at 10.667%, with 1,200 effects,
   161 polls and no failed/skipped polls. Its six ordinary workflows passed; smoke
   measured 11.533% with performance enforcement disabled. The +10 `b4bf2ce` follow-up failed all three native cold-cadence gates, with
   two busy skips each and numerical overheads 7.356%/5.527%/11.890%; ordinary
   full passed at 6.883%. The new +5 own-field candidate is pending qualification. The identifier-cache prototype was rejected and is not adopted.
   Prototype measurements and owner profiling are
   ineligible diagnostics. These are source-bound checkpoint results, not a
   publication authorization. Follow [PR #10 checks](https://github.com/ShieldaAI/agent-guard/pull/10/checks)
   for later exact-candidate outcomes and repeat qualification on reviewed fixed
   Node images. Prior quota-only,
   Colima-affined, diagnostic and 10 ms-period failures remain recorded. Do not add
   diagnostics, change limits, or retry away failures.
   The runner's generic default remains bandwidth-only; the configured acceptance
   command must explicitly include `--cpu-affinity 0 --worker-scheduling linux-background`.
   Generic worker scheduling remains `default`; manual historical comparisons
   select `default` and omit the new flag when checking older source. The new
   policy lowers only the observer worker's native JavaScript-thread priority by up to five
   nice points, capped at 19, with verified readback and unchanged owner priority.
   It makes no GC/helper-thread priority or latency guarantee. `--cpu-affinity SINGLE_INDEX`
   restricts execution to one selected
   logical CPU while retaining the same one-CPU quota, 100 ms period, zero burst,
   512 MiB memory, no extra swap and 128-PID limit. It provides neither exclusivity
   nor a physical-core guarantee. Its requested and effective CPU sets are checked
   before and after the workload and recorded as a separate profile. Its result
   does not qualify bandwidth-only placement, other platforms or unknown company
   installations. Match the [documented observer-service resources](../deployment/cartography/RUNBOOK.md#matching-the-observer-owning-service)
   and retain exact candidate evidence. The [one-CPU record](validation/one-cpu-observer-2026-11-06.json)
   preserves the controlled pass and the failed quota-only controls.
5. Bind reports to `git rev-parse HEAD`, `git rev-parse HEAD^{tree}` and
   `python3 docs/validation/protection-source-id.py`. Retain workflow/run/job IDs,
   actual tested merge/tree, artifact/log hashes, package integrity, dependency
   locks and production/verification manifest equality. Any changed protected
   source or Node image needs matching verification. Review those records before
   changing the exact-version release state to approved; it does not verify its
   evidence links automatically. Follow the protected merge and exact merged-commit
   checks below. Keep the release state blocked while any prepublication gate is open.
6. Authenticate with npm/MFA and publish the five packages in the order below.
   Registry integrity, exact `gitHead`, registry-installed consumers and final
   dist-tags are checked **after upload**, before the immutable tag/GitHub release.
   They are postpublication completion checks, not impossible prerequisites for
   the first upload. Do not repeat an accepted upload or reuse a published version
   with changed source. Keep this release incomplete if any post-upload check fails.

The repository contains five ESM package workspaces, versioned together, and a private viewer workspace. Version `0.1.0-alpha.2` introduced the executor and Agent Map to npm alongside updates to the other three packages. The GitHub organization is `ShieldaAI`; npm uses the lowercase scope `@shieldaai`. GitHub membership does not establish npm organization membership.

Publish only the five workspaces listed below. The React/Cytoscape viewer remains
private, and the Python Cartography integration has its own build and version;
neither is published by this npm release. Company service deployment is separate
from publishing the packages.

`0.1.0` is the planned first non-prerelease version of the existing `0.1.0-alpha`
line. It does not promise a 1.x API contract, long-term support or production
certification. The supported deployment scope and upgrade rules must accompany
the release. Preserve historical alpha notes, immutable tags and the real
alpha.3 downgrade/upgrade consumer; those versions are intentional test inputs.

## Authentication

Sign in interactively and complete npm's browser and two-factor authentication prompts:

```sh
npm login --auth-type=web --registry=https://registry.npmjs.org/
npm whoami
npm org ls shieldaai
```

The npm account must have publishing rights in the `shieldaai` organization. Keep credentials in npm's user configuration, outside the repository. A publish may open another browser challenge; complete it with the account's security key or authenticator.

## Publish and verify

1. Establish ownership of the npm `shieldaai` organization and publishing rights. Sign in using npm's supported authentication flow; never put a token in this repository.
2. Update the version in the root manifest, all five package manifests plus the private viewer manifest, and internal dependency versions together. Keep lockfile workspace metadata aligned without changing third-party resolution unnecessarily. If regenerating it, use `npm install --package-lock-only --ignore-scripts` and review the diff. Set public `publishConfig.tag` to `latest` for a non-prerelease or `alpha` for an alpha. Never publish changed source under an existing version.
3. Run `npm ci --ignore-scripts` and `npm run check`. Review the threat model, release notes and package contents. The checks install the actual tarballs in a temporary consumer, compile their public declarations and README TypeScript examples, execute an MCP dispatch, and run the conformance fixtures.
4. Run `npm run pack` and inspect `artifacts/`. Builds remove old output before compiling; direct workspace `npm pack` commands also rebuild through `prepack`. Only JavaScript, declarations, package metadata, README and license belong in the tarballs.
5. Resolve every applicable prepublication release gate. A stable release requires committed
   `release-state.json` with `schemaVersion: 1`, the exact candidate `version`,
   `status: "approved"`, an empty `blockers` array, and nonempty `evidence`
   references. This is the existing engineering acceptance decision, not a new
   human approval workflow. It does not independently validate linked reports;
   reviewers must verify exact source/image bindings and retain prior failures.
   A later stable version requires a new matching record. Do not mark approval
   from an instrumented diagnostic or a prerelease/smoke result.
6. Commit the reviewed source, manifests, lockfile, acceptance record and release
   notes. Review the pull request and merge through the protected release branch
   with passing checks and resolved conversations, then obtain successful CI and
   CodeQL on the exact merged release commit. Confirm the release checkout is
   clean. The sole-maintainer policy does not require a second person's approval.
   Only after these gates pass, publish core first, then the other packages.

Run the following as **separate operator steps, one package at a time**. Stop on
any failed command or uncertain upload result; do not paste them as one batch.
Before starting the next package, wait for the current exact version to become
available and verify its `gitHead`, registry integrity and reviewed package bytes
using the read-only commands below for that package; reserve the all-package
loop for final reconciliation. Complete any npm MFA challenge without bypassing hooks.

1. Publish core:

   ```sh
   npm publish --workspace packages/core --access public --tag latest
   ```

2. After core is verified, publish MCP:

   ```sh
   npm publish --workspace packages/mcp --access public --tag latest
   ```

3. After MCP is verified, publish scenarios:

   ```sh
   npm publish --workspace packages/scenarios --access public --tag latest
   ```

4. After scenarios is verified, publish executor:

   ```sh
   npm publish --workspace packages/executor --access public --tag latest
   ```

5. After executor is verified, publish Agent Map:

   ```sh
   npm publish --workspace packages/agent-map --access public --tag latest
   ```

For a future alpha, use `--tag alpha` and matching prerelease metadata instead;
do not move `latest` back from an accepted stable release. Each workspace's
prepublish hook requires the repository root, a clean Git checkout, matching
workspace/internal dependency versions and the approved record for a stable
version. It then runs the root checks and checks the release preconditions again.
Ignored build output is allowed. Normal local checks and packing do not require
a clean checkout or release approval. Do not bypass publication hooks with
`--ignore-scripts`. These instructions require the complete source checkout, not
just an extracted tarball. Use supported npm authentication with appropriate MFA.
If automated publication is added later, use trusted publishing with a restricted
release environment.

Package checks alone do not establish production acceptance. The intended
[single-owner Linux service](../deployment/production/README.md) must pass its
documented profile and security gates. Broader Docker isolation claims need the
applicable [platform evidence](../deployment/README.md); full Windows Docker
isolation remains a separate candidate profile. The manual platform workflow
requires provisioned disposable Docker/VM runners. Retain unskipped evidence for
every claimed platform rather than extending Linux results to other hosts.

An accepted publish can report that the package is still being processed. npm scans uploads before they become installable, so a temporary registry 404 is possible. Wait for each exact version to appear with `npm view <package>@<version> version dist-tags --json`; do not repeat an accepted publish or change the version to work around processing. See [npm's publish-time scanning announcement](https://github.blog/changelog/2026-07-28-npm-publish-time-malware-scanning-and-dual-use-metadata/).

If publication stops partway through, preserve the approved release commit,
reviewed artifacts and each package's upload result. Before resuming, reconcile
all five exact versions with the registry commands below. For versions already
available, verify `gitHead` against that same commit, validate the downloaded
tarball against `dist.integrity`, and compare its member bytes with the reviewed
package. An accepted but still-processing upload must be awaited, never repeated.
A temporary 404 or a lost client connection does not prove that npm rejected an
upload; resolve uncertain acceptance with npm before sending it again.

After recovering authentication/MFA and reconfirming the clean approved checkout,
resume only packages confirmed not to have been accepted, in the original order.
Skip already accepted packages. Do not change source or reuse a published version
to repair an integrity or commit mismatch; stop and resolve that release blocker.
Keep the release incomplete, with no version tag or GitHub release, until all five
packages and the registry-installed consumers have passed verification.

After all versions become available, install their exact versions from the public registry into a clean project, verify the MCP adapter and run the conformance suite. Verify their tarball integrity and recorded `gitHead` against the committed source used for publication. Create release notes and a version tag for that exact commit using an administrator account. Tags matching `v*` are protected against updates and deletion, so verify the commit before creating the tag. Preserve any existing stable `latest` version when publishing a prerelease, and do not imply a production security guarantee.

After approved `0.1.0` uploads, retrieve the registry metadata and tarballs:

```sh
mkdir -p artifacts/registry-0.1.0
for package in @shieldaai/agent-guard @shieldaai/agent-guard-mcp \
  @shieldaai/agent-guard-scenarios @shieldaai/agent-guard-executor @shieldaai/agent-map; do
  npm view "$package@0.1.0" version dist.integrity gitHead --json
  npm view "$package" dist-tags --json
  npm pack "$package@0.1.0" --ignore-scripts --pack-destination artifacts/registry-0.1.0
done
```

Compare each tarball with its registry integrity and reviewed package bytes;
compare each `gitHead` with the release commit and confirm `latest` is `0.1.0`.
Preserve that metadata, tarball hashes, fresh registry-installed consumer results
and exact release commit. Set `RELEASE_COMMIT` to that verified
merged commit before using the commands below
(these commands are **not authorized by the current blocked record**):

```sh
git tag -a v0.1.0 "$RELEASE_COMMIT" -m 'Agent Guard 0.1.0'
git push origin refs/tags/v0.1.0
gh release create v0.1.0 artifacts/registry-0.1.0/*-0.1.0.tgz --verify-tag --latest \
  --title 'Agent Guard 0.1.0' --notes-file docs/releases/0.1.0.md
```

Use a non-prerelease GitHub release only after registry verification. Before
running `gh release create`, prepare its notes from the candidate document with
the actual commit/check/registry-artifact identifiers and completed gate status;
retain the exact already-published source commit when creating the tag. GitHub
tag/release authority and npm organization rights are
separate; an existing GitHub login does not supply npm authentication.

Inspect the tags after a first publication. npm can also create `latest` even when an explicit prerelease tag is supplied; [npm/cli#8490](https://github.com/npm/cli/issues/8490) describes this behavior. For the initial release, npm assigned both `alpha` and `latest` to `0.1.0-alpha.0` and rejected removal of `latest` with HTTP 400. Document the tags assigned to each release and recommend explicit `@alpha` or exact-version installation while the packages remain experimental.

On 4 November 2026, all five packages were published as `0.1.0-alpha.2` from
`e8d8e82b31d7e4c60d565d9d37721953cc33c048`. Core, MCP and scenarios kept
`latest` at `0.1.0-alpha.0`. The new executor and Agent Map packages received
both `alpha` and `latest` at `0.1.0-alpha.2`. The registry tarballs matched the
reviewed builds. The release notes record the installed consumer results and
the macOS Agent Map CLI workaround. [Release notes](releases/0.1.0-alpha.2.md)

GitHub Actions validates Node 22, 24 and 26 and produces tarballs. It has no npm credential and does not publish packages. At the initial release, hosted runs were blocked by the GitHub account's billing lock; the release notes record local checks instead. [Run 40038764852, attempt 2](https://github.com/ShieldaAI/agent-guard/actions/runs/40038764852/attempts/2) subsequently passed on 2026-10-24 for commit `d0df90d730c41ae2fa87ad8792e63a0081bd5324`.

All three `0.1.0-alpha.1` packages were published from commit `86cf5902acbbc029b0872060c1906cc25964ec5d` on 2026-10-24. [CI run 40132729269](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729269) and [CodeQL run 40132729355](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729355) passed on that merge commit; [dependency-review run 40132541222](https://github.com/ShieldaAI/agent-guard/actions/runs/40132541222) passed on the final pull-request head. Registry tarballs, integrity hashes and `gitHead` matched the release artifacts and commit. A fresh registry consumer passed the declaration, README, MCP and conformance checks. The [GitHub prerelease](https://github.com/ShieldaAI/agent-guard/releases/tag/v0.1.0-alpha.1) records the same commit and includes the verified artifacts. The `alpha` tag moved to `0.1.0-alpha.1`; `latest` remains on `0.1.0-alpha.0`.

The sole-maintainer branch policy requires a pull request, successful `check (22)`, `check (24)` and `check (26)` runs, and resolved conversations. It does not require approval from another person. For future releases, check the final pull-request head before merging, then obtain successful CI and CodeQL runs on the merged release commit before publishing. The runs above cover only their recorded revisions.

The initial `0.1.0-alpha.0` packages record `gitHead` `6db7631a1f9ba070b5e5c9b2a5152be0584b0622`, while their package README files match the later release tag at `f7e4c77d675a6ec2fd7ab402858d49038ccc86ea`. The published files and integrity hashes were checked against the local release artifacts, but that first `gitHead` does not identify the exact full package source tree. The clean-checkout preflight applies to subsequent publications. The initial packages have npm registry signatures but no build provenance attestation; integrity verification alone does not establish a trusted build process.
