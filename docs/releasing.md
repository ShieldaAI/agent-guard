# Releasing the npm packages

The repository contains three ESM packages, versioned together. Registry publication has not happened yet. The GitHub organization is `ShieldaAI`; npm uses the lowercase scope `@shieldaai`. GitHub membership does not establish npm organization membership.

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

After publishing, verify each exact version in a clean project, then update the README's publication status and create release notes/tag for the exact tested commit. Do not move the `latest` tag to this experimental alpha or imply a production security guarantee.

GitHub Actions currently validates Node 22, 24 and 26 and produces tarballs. It has no npm credential and does not publish packages.
