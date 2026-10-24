import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error('Release requires a complete Git source checkout.');
  return result.stdout.trim();
}

/** Require a clean checkout and matching versions before publication. */
export function validateRelease(root) {
  const repository = git(root, ['rev-parse', '--show-toplevel']);
  if (realpathSync(repository) !== realpathSync(root)) {
    throw new Error('Release must run from the Agent Guard repository root.');
  }
  git(root, ['rev-parse', '--verify', 'HEAD']);
  if (git(root, ['status', '--porcelain', '--untracked-files=all'])) {
    throw new Error('Commit or remove pending source changes before publishing; the release checkout must be clean.');
  }
  const readManifest = directory => JSON.parse(readFileSync(join(root, directory, 'package.json'), 'utf8'));
  const workspace = readManifest('.');
  if (typeof workspace.version !== 'string' || workspace.version.length === 0 ||
      !Array.isArray(workspace.workspaces) || workspace.workspaces.length === 0) {
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
          throw new Error(`Release dependency mismatch: ${manifest.name} ${field}.${name} must be exactly ${workspace.version}.`);
        }
      }
    }
  }
}
