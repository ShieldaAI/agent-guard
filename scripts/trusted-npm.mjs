import { closeSync, fstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';

function readManifest(path) {
  const fd = openSync(path, 'r');
  try {
    const before = fstatSync(fd);
    const maximum = 64 * 1024;
    if (!before.isFile() || before.size > maximum) throw new Error('Invalid npm manifest.');
    // One extra byte detects growth beyond the limit without an unbounded
    // readFileSync allocation. Every read uses the already-validated descriptor.
    const bytes = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd);
    if (length > maximum || length !== before.size || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('Npm manifest changed during validation.');
    }
    return JSON.parse(bytes.subarray(0, length).toString('utf8'));
  } finally {
    closeSync(fd);
  }
}

// The Node installation is part of the build trust boundary. Never select
// executable JavaScript from npm_execpath, PATH, or a project-local npm shim.
// POSIX distributions (including Homebrew) link the sibling npm launcher to
// npm's CLI; official Windows installations put the package beside node.exe.
export function resolveInstallationNpmCli(nodeExecutable, platform) {
  try {
    const runtimeDirectory = dirname(realpathSync(nodeExecutable));
    const launcher = platform === 'win32'
      ? join(runtimeDirectory, 'node_modules', 'npm', 'bin', 'npm-cli.js')
      : join(runtimeDirectory, 'npm');
    const cli = realpathSync(launcher);
    const packageDirectory = dirname(dirname(cli));
    if (cli !== join(packageDirectory, 'bin', 'npm-cli.js') || !statSync(cli).isFile()) {
      throw new Error('Invalid npm entry point.');
    }
    const manifestFile = join(packageDirectory, 'package.json');
    const manifest = readManifest(manifestFile);
    if (manifest.name !== 'npm' || manifest.bin?.npm !== 'bin/npm-cli.js') {
      throw new Error('Invalid npm package.');
    }
    return cli;
  } catch {
    throw new Error('TRUSTED_NPM_NOT_FOUND: install npm with the running Node installation; npm_execpath and PATH overrides are not accepted.');
  }
}

export function trustedNpmCli() {
  return resolveInstallationNpmCli(process.execPath, process.platform);
}
