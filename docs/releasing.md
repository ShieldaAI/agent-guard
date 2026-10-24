# Releasing the npm packages

The repository contains three ESM packages, versioned together. The GitHub organization is `ShieldaAI`; npm uses the lowercase scope `@shieldaai`. GitHub membership does not establish npm organization membership.

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
2. Update the version in the root manifest, all three package manifests, and internal dependency versions together. Regenerate the lockfile with `npm install --ignore-scripts`.
3. Run `npm ci --ignore-scripts` and `npm run check`. Review the threat model, release notes and package contents. The checks install the actual tarballs in a temporary consumer, compile their public declarations and README TypeScript examples, execute an MCP dispatch, and run the conformance fixtures.
4. Run `npm run pack` and inspect `artifacts/`. Builds remove old output before compiling; direct workspace `npm pack` commands also rebuild through `prepack`. Only JavaScript, declarations, package metadata, README and license belong in the tarballs.
5. Commit the reviewed source, manifests, lockfile and release notes. Review the pull request and merge through the protected release branch with passing checks and resolved conversations, then confirm the release checkout is clean. The sole-maintainer policy does not require a second person's approval. Publish core first, then adapters and scenarios, with the `alpha` tag:

```sh
npm publish --workspace packages/core --access public --tag alpha
npm publish --workspace packages/mcp --access public --tag alpha
npm publish --workspace packages/scenarios --access public --tag alpha
```

Each workspace's prepublish hook requires the repository root, a clean Git checkout, matching workspace versions, and exact matching versions for internal dependencies. It then runs the root checks and checks the release preconditions again. Ignored build output is allowed. Normal local checks and packing do not require a clean checkout. These instructions require the complete source checkout, not just an extracted tarball. Use a supported npm authentication method with appropriate MFA. If automated publication is added later, use trusted publishing with a restricted release environment.

An accepted publish can report that the package is still being processed. npm scans uploads before they become installable, so a temporary registry 404 is possible. Wait for each exact version to appear with `npm view <package>@<version> version dist-tags --json`; do not repeat an accepted publish or change the version to work around processing. See [npm's publish-time scanning announcement](https://github.blog/changelog/2026-07-28-npm-publish-time-malware-scanning-and-dual-use-metadata/).

After all versions become available, install their exact versions from the public registry into a clean project, verify the MCP adapter and run the conformance suite. Verify their tarball integrity and recorded `gitHead` against the committed source used for publication. Create release notes and a version tag for that exact commit using an administrator account. Tags matching `v*` are protected against updates and deletion, so verify the commit before creating the tag. Preserve any existing stable `latest` version when publishing a prerelease, and do not imply a production security guarantee.

Inspect the tags after a first publication. npm can also create `latest` even when an explicit prerelease tag is supplied; [npm/cli#8490](https://github.com/npm/cli/issues/8490) describes this behavior. For the initial release, npm assigned both `alpha` and `latest` to `0.1.0-alpha.0` and rejected removal of `latest` with HTTP 400. Document the tags assigned to each release and recommend explicit `@alpha` or exact-version installation while the packages remain experimental.

GitHub Actions validates Node 22, 24 and 26 and produces tarballs. It has no npm credential and does not publish packages. At the initial release, hosted runs were blocked by the GitHub account's billing lock; the release notes record local checks instead. [Run 40038764852, attempt 2](https://github.com/ShieldaAI/agent-guard/actions/runs/40038764852/attempts/2) subsequently passed on 2026-10-24 for commit `d0df90d730c41ae2fa87ad8792e63a0081bd5324`.

All three `0.1.0-alpha.1` packages were published from commit `86cf5902acbbc029b0872060c1906cc25964ec5d` on 2026-10-24. [CI run 40132729269](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729269) and [CodeQL run 40132729355](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729355) passed on that merge commit; [dependency-review run 40132541222](https://github.com/ShieldaAI/agent-guard/actions/runs/40132541222) passed on the final pull-request head. Registry tarballs, integrity hashes and `gitHead` matched the release artifacts and commit. A fresh registry consumer passed the declaration, README, MCP and conformance checks. The [GitHub prerelease](https://github.com/ShieldaAI/agent-guard/releases/tag/v0.1.0-alpha.1) records the same commit and includes the verified artifacts. The `alpha` tag moved to `0.1.0-alpha.1`; `latest` remains on `0.1.0-alpha.0`.

The sole-maintainer branch policy requires a pull request, successful `check (22)`, `check (24)` and `check (26)` runs, and resolved conversations. It does not require approval from another person. For future releases, check the final pull-request head before merging, then obtain successful CI and CodeQL runs on the merged release commit before publishing. The runs above cover only their recorded revisions.

The initial `0.1.0-alpha.0` packages record `gitHead` `6db7631a1f9ba070b5e5c9b2a5152be0584b0622`, while their package README files match the later release tag at `f7e4c77d675a6ec2fd7ab402858d49038ccc86ea`. The published files and integrity hashes were checked against the local release artifacts, but that first `gitHead` does not identify the exact full package source tree. The clean-checkout preflight applies to subsequent publications. The initial packages have npm registry signatures but no build provenance attestation; integrity verification alone does not establish a trusted build process.
