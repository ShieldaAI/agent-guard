# Releasing the npm packages

Five ESM workspaces (core, MCP, scenarios, executor, Agent Map) are versioned together under `@shieldaai`;
the private viewer and Python Cartography are not published. Gates: [release notes](releases/1.1.1.md),
root [release state](../release-state.json) (do not publish while blocked), [support and limits](support-and-limits.md).

## Checklist

1. Confirm publishing rights in the npm `shieldaai` organization. Never put a token in the repository.
2. Update the version in the root, all five package and the private viewer manifests, and internal
   dependency versions together. Set `publishConfig.tag` to `latest` (stable) or `alpha`.
   Never publish changed source under an existing version.
3. Run the checks and pack; tarballs in `artifacts/` hold only JS, declarations, metadata, README, license.
4. In the same release pull request, set `release-state.json` to `schemaVersion: 1`, the exact `version`,
   `status: "approved"`, an empty `blockers` array and nonempty `evidence`. One pull request per release:
   `npm publish` is still blocked by the preflight until this file approves the version, and nothing is
   published until step 5 holds.
5. Merge, then require CI and CodeQL to pass on the exact merged commit before publishing. If they fail,
   fix forward in a new pull request; do not publish from a commit whose checks failed.
6. Publish one package at a time in the order below. Before the next one, wait for the version to
   appear and verify its `gitHead`, registry integrity and package bytes. Never use `--ignore-scripts` to bypass publish hooks.
7. Install the exact versions from the registry into a clean project, then tag and create the GitHub release.

Release notes link the release pull request and its CI run; add the merged commit's CI run in the GitHub release. If you publish from CI, use npm trusted publishing with `--provenance` so each package carries a signed statement of the commit it was built from; no workflow in this repository holds a publishing token today.

Timing signals (admission during polling, and the constrained observer) do not run on pull requests. Both run nightly on the
default branch and on manual dispatch; the job summary shows the p95 ratio, skipped polls and reasons. They are never a required check.

## Commands

```sh
npm login --auth-type=web --registry=https://registry.npmjs.org/
npm whoami
npm org ls shieldaai
npm ci --ignore-scripts
npm run check
npm run pack
```

Publish from a full clone of the repository at the release commit, not from a `git worktree` checkout:
npm does not record `gitHead` when it publishes from a worktree, and a published version cannot be
corrected. `@shieldaai/agent-guard@1.1.0` has no `gitHead` for this reason; its bytes match the reviewed pack.

Publish in this order, one command per verified step:

```sh
npm publish --workspace packages/core --access public --tag latest
npm publish --workspace packages/mcp --access public --tag latest
npm publish --workspace packages/scenarios --access public --tag latest
npm publish --workspace packages/executor --access public --tag latest
npm publish --workspace packages/agent-map --access public --tag latest
```

Wait for each with `npm view <package>@<version> version dist-tags --json`. Then verify and release (`RELEASE_COMMIT` = verified merged commit):

```sh
mkdir -p artifacts/registry-1.1.1
for package in @shieldaai/agent-guard @shieldaai/agent-guard-mcp \
  @shieldaai/agent-guard-scenarios @shieldaai/agent-guard-executor @shieldaai/agent-map; do
  npm view "$package@1.1.1" version dist.integrity gitHead --json
  npm view "$package" dist-tags --json
  npm pack "$package@1.1.1" --ignore-scripts --pack-destination artifacts/registry-1.1.1
done
git tag -a v1.1.1 "$RELEASE_COMMIT" -m 'Agent Guard 1.1.1'
git push origin refs/tags/v1.1.1
gh release create v1.1.1 artifacts/registry-1.1.1/*-1.1.1.tgz --verify-tag --latest \
  --title 'Agent Guard 1.1.1' --notes-file docs/releases/1.1.1.md
```

## Rollback and partial publication

npm versions are immutable: never reuse a published version or change source to repair a mismatch.
Do not move `latest` back from an accepted stable release. If publication stops partway, keep the
approved commit, reviewed artifacts and each upload result, and reconcile all five versions with the
registry commands above. A temporary 404 or lost connection does not prove npm rejected an upload;
await a still-processing upload, never repeat it. Resume, in order, only packages confirmed not accepted.
Create no tag or GitHub release until all five packages and registry-installed consumers pass.
Service image rollback: [upgrade and rollback procedure](../deployment/production/upgrades.md).

