import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error('Release requires a complete Git source checkout.');
  return result.stdout.trim();
}

/** Require a clean checkout, matching versions and reviewed stable-release approval. */
export function validateRelease(root) {
  const repository = git(root, ['rev-parse', '--show-toplevel']);
  // Resolve native directory aliases, including Windows short names returned by
  // temporary-directory APIs, before comparing with Git's canonical root.
  if (realpathSync.native(repository) !== realpathSync.native(root)) {
    throw new Error('Release must run from the Agent Guard repository root.');
  }
  git(root, ['rev-parse', '--verify', 'HEAD']);
  if (git(root, ['status', '--porcelain', '--untracked-files=all'])) {
    throw new Error('Commit or remove pending source changes before publishing; the release checkout must be clean.');
  }
  const readManifest = directory => JSON.parse(readFileSync(join(root, directory, 'package.json'), 'utf8'));
  const workspace = readManifest('.');
  if (
    typeof workspace.version !== 'string' ||
    workspace.version.length === 0 ||
    !Array.isArray(workspace.workspaces) ||
    workspace.workspaces.length === 0
  ) {
    throw new Error('Release requires a root version and explicit package workspaces.');
  }
  const manifests = workspace.workspaces.map(readManifest);
  const internalNames = new Set(manifests.map(manifest => manifest.name));
  for (const manifest of manifests) {
    if (manifest.version !== workspace.version) {
      throw new Error(`Release version mismatch: ${manifest.name} must use ${workspace.version}.`);
    }
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
      for (const [name, version] of Object.entries(manifest[field] ?? {})) {
        if (internalNames.has(name) && version !== workspace.version) {
          throw new Error(
            `Release dependency mismatch: ${manifest.name} ${field}.${name} must be exactly ${workspace.version}.`,
          );
        }
      }
    }
  }
  if (/^\d+\.\d+\.\d+(?:\+[0-9A-Za-z.-]+)?$/.test(workspace.version)) {
    let state;
    try {
      state = JSON.parse(readFileSync(join(root, 'release-state.json'), 'utf8'));
    } catch {
      throw new Error('Stable release is blocked: a valid release-state.json approval record is required.');
    }
    if (
      state?.schemaVersion !== 1 ||
      state.version !== workspace.version ||
      state.status !== 'approved' ||
      !Array.isArray(state.blockers) ||
      state.blockers.length !== 0 ||
      !Array.isArray(state.evidence) ||
      state.evidence.length === 0 ||
      state.evidence.some(reference => typeof reference !== 'string' || reference.trim().length === 0)
    ) {
      throw new Error(
        'Stable release is blocked: release-state.json must approve this exact version with evidence and no unresolved blockers.',
      );
    }
    // Evidence must name committed files in this checkout, not free text or paths outside it.
    for (const reference of state.evidence) {
      if (
        reference !== reference.trim() ||
        reference.startsWith('/') ||
        reference.includes('\\') ||
        reference.split('/').some(part => part === '' || part === '.' || part === '..')
      ) {
        throw new Error(
          `Stable release is blocked: evidence reference "${reference}" must be a relative repository path.`,
        );
      }
      const tracked = spawnSync('git', ['ls-files', '--error-unmatch', '--', reference], {
        cwd: root,
        encoding: 'utf8',
      });
      if (tracked.error || tracked.status !== 0 || tracked.stdout.trim() !== reference) {
        throw new Error(`Stable release is blocked: evidence file "${reference}" is not committed in this checkout.`);
      }
    }
  }
}
