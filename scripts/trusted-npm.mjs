import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';

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
    const manifestStat = statSync(manifestFile);
    if (!manifestStat.isFile() || manifestStat.size > 64 * 1024) throw new Error('Invalid npm manifest.');
    const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
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
