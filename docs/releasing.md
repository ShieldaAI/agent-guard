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
4. Run `npm run pack` and inspect `artifacts/`. Only JavaScript, declarations, package metadata, README and license belong in the tarballs.
5. Commit the reviewed source, manifests, lockfile and release notes. Confirm the checkout is clean. Publish core first, then adapters and scenarios, with the `alpha` tag:

```sh
npm publish --workspace packages/core --access public --tag alpha
npm publish --workspace packages/mcp --access public --tag alpha
npm publish --workspace packages/scenarios --access public --tag alpha
```

Each workspace's prepublish hook requires the repository root, a clean Git checkout, matching workspace versions, and exact matching versions for internal dependencies. It then runs the root checks and checks the release preconditions again. Ignored build output is allowed. Normal local checks and packing do not require a clean checkout. These instructions require the complete source checkout, not just an extracted tarball. Use a supported npm authentication method with appropriate MFA. If automated publication is added later, use trusted publishing with a restricted release environment.

An accepted publish can report that the package is still being processed. npm scans uploads before they become installable, so a temporary registry 404 is possible. Wait for each exact version to appear with `npm view <package>@<version> version dist-tags --json`; do not repeat an accepted publish or change the version to work around processing. See [npm's publish-time scanning announcement](https://github.blog/changelog/2026-07-28-npm-publish-time-malware-scanning-and-dual-use-metadata/).

After all versions become available, install their exact versions from the public registry into a clean project, verify the MCP adapter and run the conformance suite. Verify their tarball integrity and recorded `gitHead` against the committed source used for publication. Create release notes and a tag for that exact commit. Preserve any existing stable `latest` version when publishing a prerelease, and do not imply a production security guarantee.

Inspect the tags after a first publication. npm can also create `latest` even when an explicit prerelease tag is supplied; [npm/cli#8490](https://github.com/npm/cli/issues/8490) describes this behavior. For our initial release, both `alpha` and `latest` point to `0.1.0-alpha.0`. An authenticated attempt to remove `latest` was rejected by the registry with HTTP 400. Do not repeat authentication attempts for this cleanup or publish a placeholder version to work around it. Document the actual tags and recommend explicit `@alpha` or exact-version installation.

GitHub Actions is configured to validate Node 22, 24 and 26 and produce tarballs. It has no npm credential and does not publish packages. At the initial release, hosted runs were blocked by the GitHub account's billing lock; the release notes record local checks instead. A configured workflow is not evidence of a successful hosted run. Restore hosted execution and require successful checks before treating CI as a release gate.

The initial `0.1.0-alpha.0` packages record `gitHead` `6db7631a1f9ba070b5e5c9b2a5152be0584b0622`, while their package README files match the later release tag at `f7e4c77d675a6ec2fd7ab402858d49038ccc86ea`. The published files and integrity hashes were checked against the local release artifacts, but that first `gitHead` does not identify the exact full package source tree. The clean-checkout preflight applies to subsequent publications. The initial packages have npm registry signatures but no build provenance attestation; integrity verification alone does not establish a trusted build process.
