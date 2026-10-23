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
2. Update the version in all three package manifests and internal dependency versions together. Regenerate the lockfile with `npm install --ignore-scripts`.
3. Run `npm ci --ignore-scripts` and `npm run check`. Review the threat model, release notes and package contents. The checks install and run the actual tarballs in a temporary consumer.
4. Run `npm run pack` and inspect `artifacts/`. Only JavaScript, declarations, package metadata, README and license belong in the tarballs.
5. From the checked source checkout, publish core first, then adapters and scenarios, with the `alpha` tag:

```sh
npm publish --workspace packages/core --access public --tag alpha
npm publish --workspace packages/mcp --access public --tag alpha
npm publish --workspace packages/scenarios --access public --tag alpha
```

Each workspace's prepublish hook runs the root checks. These instructions require the complete source checkout, not just an extracted tarball. Use a supported npm authentication method with appropriate MFA. If automated publication is added later, use trusted publishing with a restricted release environment.

An accepted publish can report that the package is still being processed. npm scans uploads before they become installable, so a temporary registry 404 is possible. Wait for each exact version to appear with `npm view <package>@<version> version dist-tags --json`; do not repeat an accepted publish or change the version to work around processing. See [npm's publish-time scanning announcement](https://github.blog/changelog/2026-07-28-npm-publish-time-malware-scanning-and-dual-use-metadata/).

After all versions become available, install their exact versions from the public registry into a clean project, verify the MCP adapter and run the conformance suite. Update the release documentation and create release notes/tag for the tested source. Preserve any existing stable `latest` version when publishing a prerelease, and do not imply a production security guarantee.

Inspect the tags after a first publication. npm can also create `latest` even when an explicit prerelease tag is supplied; [npm/cli#8490](https://github.com/npm/cli/issues/8490) describes this behavior. For our initial release, both `alpha` and `latest` point to `0.1.0-alpha.0`. An authenticated attempt to remove `latest` was rejected by the registry with HTTP 400. Do not repeat authentication attempts for this cleanup or publish a placeholder version to work around it. Document the actual tags and recommend explicit `@alpha` or exact-version installation.

GitHub Actions currently validates Node 22, 24 and 26 and produces tarballs. It has no npm credential and does not publish packages.
