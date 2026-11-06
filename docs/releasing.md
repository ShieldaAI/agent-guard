# Releasing the npm packages

**Current preparation: `0.1.0`, unpublished and blocked.** The
[candidate notes](releases/0.1.0.md) and root [release state](../release-state.json)
retain the open Node HIGH review, admission-performance acceptance and final
candidate checks. The security hold follows the existing
[production acceptance policy](production-readiness.md#remaining-acceptance-and-operational-limits).
Do not publish or create a stable GitHub release while these gates remain open.
Normal `npm run check` and `npm run pack` remain available for candidate work.

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
5. Resolve every applicable release gate. A stable release requires committed
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
   Only after these gates pass, publish core first, then the other packages:

```sh
npm publish --workspace packages/core --access public --tag latest
npm publish --workspace packages/mcp --access public --tag latest
npm publish --workspace packages/scenarios --access public --tag latest
npm publish --workspace packages/executor --access public --tag latest
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

After all versions become available, install their exact versions from the public registry into a clean project, verify the MCP adapter and run the conformance suite. Verify their tarball integrity and recorded `gitHead` against the committed source used for publication. Create release notes and a version tag for that exact commit using an administrator account. Tags matching `v*` are protected against updates and deletion, so verify the commit before creating the tag. Preserve any existing stable `latest` version when publishing a prerelease, and do not imply a production security guarantee.

For the approved `0.1.0` release, verify `npm view <package>@0.1.0 version
dist.integrity gitHead --json` and `npm view <package> dist-tags --json` for each
of the five names. Preserve the public registry tarballs, their hashes, installed
consumer results and exact release commit. Set `RELEASE_COMMIT` to that verified
merged commit before using the commands below
(these commands are **not authorized by the current blocked record**):

```sh
git tag -a v0.1.0 "$RELEASE_COMMIT" -m 'Agent Guard 0.1.0'
git push origin refs/tags/v0.1.0
gh release create v0.1.0 artifacts/*-0.1.0.tgz --verify-tag --latest \
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
