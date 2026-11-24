/**
 * Command-line options of the programs that start MCP servers, and a reader for them, so the word
 * a server runs (a package or an image) is never taken from an option's value.
 *
 * Generated on 2026-11-24 from the programs' own definitions: npm 11.20 `@npmcli/config` (read as
 * npm's parser reads it: an option takes the next word unless its type is a switch without a
 * string), uv's CLI reference and `crates/uv-cli` source (`uv tool run` and global options),
 * `docker run --help` (Docker 29.9) and podman-run(1). Where both lists are complete, an option
 * in neither is unknown, and an unknown option followed by a word makes the command unreadable:
 * that word may be its value or the package.
 */

export interface FlagTable {
  /** Options whose value is the package to run (`npx -p pkg cmd`, `uvx --from pkg cmd`). */
  readonly main: ReadonlySet<string>;
  /** Options whose value is one more package to fetch (`uvx --with pkg`). */
  readonly extra: ReadonlySet<string>;
  /** Other options that take a value. */
  readonly valued: ReadonlySet<string>;
  /** Options that take no value. When set, an option in no list is unknown. */
  readonly plain?: ReadonlySet<string>;
  /** `--no-<anything>` is a switch (npm's parser). */
  readonly negation?: boolean;
}

const NPM_VALUED = [
  '--_auth',
  '--access',
  '--allow-directory',
  '--allow-file',
  '--allow-git',
  '--allow-remote',
  '--allow-scripts',
  '--also',
  '--audit-level',
  '--auth-type',
  '--before',
  '--browser',
  '--ca',
  '--cache',
  '--cache-max',
  '--cache-min',
  '--cafile',
  '--call',
  '--cert',
  '--cidr',
  '--cpu',
  '--depth',
  '--diff',
  '--diff-dst-prefix',
  '--diff-src-prefix',
  '--diff-unified',
  '--editor',
  '--enjoy-by',
  '--expect-result-count',
  '--expires',
  '--fetch-retries',
  '--fetch-retry-factor',
  '--fetch-retry-maxtimeout',
  '--fetch-retry-mintimeout',
  '--fetch-timeout',
  '--git',
  '--globalconfig',
  '--heading',
  '--https-proxy',
  '--include',
  '--init-author-email',
  '--init-author-name',
  '--init-author-url',
  '--init-license',
  '--init-module',
  '--init-type',
  '--init-version',
  '--init.author.email',
  '--init.author.name',
  '--init.author.url',
  '--init.license',
  '--init.module',
  '--init.version',
  '--install-strategy',
  '--key',
  '--libc',
  '--local-address',
  '--location',
  '--lockfile-version',
  '--loglevel',
  '--logs-dir',
  '--logs-max',
  '--maxsockets',
  '--message',
  '--min-release-age',
  '--min-release-age-exclude',
  '--name',
  '--node-gyp',
  '--node-options',
  '--noproxy',
  '--omit',
  '--only',
  '--orgs',
  '--orgs-permission',
  '--os',
  '--otp',
  '--pack-destination',
  '--packages',
  '--packages-and-scopes-permission',
  '--password',
  '--prefix',
  '--preid',
  '--provenance-file',
  '--proxy',
  '--reg',
  '--registry',
  '--replace-registry-host',
  '--save-prefix',
  '--sbom-format',
  '--sbom-type',
  '--scope',
  '--scopes',
  '--script-shell',
  '--searchexclude',
  '--searchlimit',
  '--searchopts',
  '--searchstaleness',
  '--shell',
  '--tag',
  '--tag-version-prefix',
  '--token-description',
  '--umask',
  '--user-agent',
  '--userconfig',
  '--viewer',
  '--which',
  '--workspace',
  '-C',
  '-L',
  '-c',
  '-m',
  '-w',
];
const NPM_PLAIN = [
  '--all',
  '--allow-same-version',
  '--allow-scripts-pending',
  '--allow-scripts-pin',
  '--audit',
  '--bin-links',
  '--bypass-2fa',
  '--color',
  '--commit-hooks',
  '--dangerously-allow-all-scripts',
  '--desc',
  '--description',
  '--dev',
  '--diff-ignore-all-space',
  '--diff-name-only',
  '--diff-no-prefix',
  '--diff-text',
  '--dry-run',
  '--engine-strict',
  '--expect-results',
  '--force',
  '--foreground-scripts',
  '--format-package-lock',
  '--fund',
  '--git-tag-version',
  '--global',
  '--global-style',
  '--if-present',
  '--ignore-scripts',
  '--include-attestations',
  '--include-staged',
  '--include-workspace-root',
  '--init-private',
  '--install-links',
  '--iwr',
  '--json',
  '--legacy-bundling',
  '--legacy-peer-deps',
  '--link',
  '--local',
  '--long',
  '--no',
  '--no-install',
  '--offline',
  '--omit-lockfile-registry-resolved',
  '--optional',
  '--package-lock',
  '--package-lock-only',
  '--packages-all',
  '--parseable',
  '--porcelain',
  '--prefer-dedupe',
  '--prefer-offline',
  '--prefer-online',
  '--production',
  '--progress',
  '--provenance',
  '--quiet',
  '--read-only',
  '--readonly',
  '--rebuild-bundle',
  '--save',
  '--save-bundle',
  '--save-dev',
  '--save-exact',
  '--save-optional',
  '--save-peer',
  '--save-prod',
  '--shrinkwrap',
  '--sign-git-commit',
  '--sign-git-tag',
  '--silent',
  '--strict-allow-scripts',
  '--strict-peer-deps',
  '--strict-ssl',
  '--timing',
  '--unicode',
  '--update-notifier',
  '--usage',
  '--verbose',
  '--version',
  '--versions',
  '--workspaces',
  '--workspaces-update',
  '--ws',
  '--yes',
  '-?',
  '-B',
  '-D',
  '-E',
  '-H',
  '-O',
  '-P',
  '-S',
  '-a',
  '-d',
  '-dd',
  '-ddd',
  '-f',
  '-g',
  '-h',
  '-l',
  '-n',
  '-q',
  '-s',
  '-v',
  '-y',
];
const UV_VALUED = [
  '--allow-insecure-host',
  '--build-constraint',
  '--build-constraints',
  '--cache-dir',
  '--color',
  '--config-file',
  '--config-setting',
  '--config-settings',
  '--config-settings-package',
  '--constraint',
  '--constraints',
  '--default-index',
  '--directory',
  '--env-file',
  '--exclude-newer',
  '--exclude-newer-package',
  '--extra-index-url',
  '--find-links',
  '--fork-strategy',
  '--index',
  '--index-strategy',
  '--index-url',
  '--keyring-provider',
  '--link-mode',
  '--no-binary-package',
  '--no-build-isolation-package',
  '--no-build-package',
  '--no-sources-package',
  '--override',
  '--overrides',
  '--prerelease',
  '--prerelease-package',
  '--preview-feature',
  '--preview-features',
  '--project',
  '--python',
  '--python-fetch',
  '--python-platform',
  '--python-preference',
  '--refresh-package',
  '--reinstall-package',
  '--resolution',
  '--torch-backend',
  '--trusted-host',
  '--upgrade-group',
  '--upgrade-package',
  '--with-requirements',
  '-C',
  '-P',
  '-b',
  '-c',
  '-f',
  '-i',
  '-p',
];
const UV_PLAIN = [
  '--allow-python-downloads',
  '--compile',
  '--compile-bytecode',
  '--force-reinstall',
  '--help',
  '--isolated',
  '--lfs',
  '--managed-python',
  '--no-binary',
  '--no-build',
  '--no-build-isolation',
  '--no-cache',
  '--no-cache-dir',
  '--no-color',
  '--no-config',
  '--no-env-file',
  '--no-index',
  '--no-installer-metadata',
  '--no-managed-python',
  '--no-offline',
  '--no-preview',
  '--no-progress',
  '--no-python-downloads',
  '--no-require-build-hashes',
  '--no-sources',
  '--offline',
  '--preview',
  '--quiet',
  '--refresh',
  '--reinstall',
  '--require-build-hashes',
  '--show-settings',
  '--system-certs',
  '--upgrade',
  '--verbose',
  '--version',
  '-U',
  '-V',
  '-h',
  '-n',
  '-q',
  '-v',
];
const RUN_VALUED = [
  '--add-host',
  '--annotation',
  '--arch',
  '--attach',
  '--authfile',
  '--blkio-weight',
  '--blkio-weight-device',
  '--cap-add',
  '--cap-drop',
  '--cert-dir',
  '--cgroup-conf',
  '--cgroup-parent',
  '--cgroupns',
  '--cgroups',
  '--chrootdirs',
  '--cidfile',
  '--conmon-pidfile',
  '--cpu-count',
  '--cpu-percent',
  '--cpu-period',
  '--cpu-quota',
  '--cpu-rt-period',
  '--cpu-rt-runtime',
  '--cpu-shares',
  '--cpus',
  '--cpuset-cpus',
  '--cpuset-mems',
  '--creds',
  '--decryption-key',
  '--detach-keys',
  '--device',
  '--device-cgroup-rule',
  '--device-read-bps',
  '--device-read-iops',
  '--device-write-bps',
  '--device-write-iops',
  '--dns',
  '--dns-opt',
  '--dns-option',
  '--dns-search',
  '--domainname',
  '--entrypoint',
  '--env',
  '--env-file',
  '--env-merge',
  '--expose',
  '--gidmap',
  '--gpus',
  '--group-add',
  '--group-entry',
  '--health-cmd',
  '--health-interval',
  '--health-log-destination',
  '--health-max-log-count',
  '--health-max-log-size',
  '--health-on-failure',
  '--health-retries',
  '--health-start-interval',
  '--health-start-period',
  '--health-startup-cmd',
  '--health-startup-interval',
  '--health-startup-retries',
  '--health-startup-success',
  '--health-startup-timeout',
  '--health-timeout',
  '--hostname',
  '--hosts-file',
  '--hostuser',
  '--image-volume',
  '--init-path',
  '--io-maxbandwidth',
  '--io-maxiops',
  '--ip',
  '--ip6',
  '--ipc',
  '--isolation',
  '--kernel-memory',
  '--label',
  '--label-file',
  '--link',
  '--link-local-ip',
  '--log-driver',
  '--log-opt',
  '--mac-address',
  '--memory',
  '--memory-reservation',
  '--memory-swap',
  '--memory-swappiness',
  '--mount',
  '--name',
  '--net',
  '--net-alias',
  '--network',
  '--network-alias',
  '--oom-score-adj',
  '--os',
  '--passwd-entry',
  '--personality',
  '--pid',
  '--pidfile',
  '--pids-limit',
  '--platform',
  '--pod',
  '--pod-id-file',
  '--preserve-fd',
  '--preserve-fds',
  '--publish',
  '--pull',
  '--rdt-class',
  '--requires',
  '--restart',
  '--retry',
  '--retry-delay',
  '--runtime',
  '--sdnotify',
  '--seccomp-policy',
  '--secret',
  '--security-opt',
  '--shm-size',
  '--shm-size-systemd',
  '--stop-signal',
  '--stop-timeout',
  '--storage-opt',
  '--subgidname',
  '--subuidname',
  '--sysctl',
  '--systemd',
  '--timeout',
  '--tmpfs',
  '--tz',
  '--uidmap',
  '--ulimit',
  '--umask',
  '--unsetenv',
  '--user',
  '--userns',
  '--uts',
  '--variant',
  '--volume',
  '--volume-driver',
  '--volumes-from',
  '--workdir',
  '-a',
  '-c',
  '-e',
  '-h',
  '-l',
  '-m',
  '-p',
  '-u',
  '-v',
  '-w',
];
const RUN_PLAIN = [
  '--detach',
  '--disable-content-trust',
  '--env-host',
  '--help',
  '--http-proxy',
  '--init',
  '--interactive',
  '--no-healthcheck',
  '--no-hostname',
  '--no-hosts',
  '--oom-kill-disable',
  '--passwd',
  '--permissive',
  '--privileged',
  '--publish-all',
  '--quiet',
  '--read-only',
  '--read-only-tmpfs',
  '--replace',
  '--rm',
  '--rmi',
  '--rootfs',
  '--sig-proxy',
  '--tls-verify',
  '--tty',
  '--unsetenv-all',
  '--use-api-socket',
  '-P',
  '-d',
  '-i',
  '-q',
  '-t',
];

const set = (...lists: readonly (readonly string[])[]) => new Set(lists.flat());

export const FLAG_TABLES: Readonly<Record<string, FlagTable>> = {
  npm: {
    main: set(['-p', '--package']),
    extra: set(['-p', '--package']),
    valued: set(NPM_VALUED),
    plain: set(NPM_PLAIN),
    negation: true,
  },
  uv: {
    main: set(['--from']),
    extra: set(['--with', '-w', '--with-editable']),
    valued: set(UV_VALUED),
    plain: set(UV_PLAIN),
  },
  // pnpm, yarn, bun and pipx document few options; an option missing here is read as a switch.
  pnpm: {
    main: set(['--package']),
    extra: set(['--package']),
    valued: set([
      '--allow-build',
      '--cache-dir',
      '--child-concurrency',
      '--config-dir',
      '--dir',
      '-C',
      '--fetch-retries',
      '--fetch-timeout',
      '--filter',
      '-F',
      '--global-bin-dir',
      '--global-dir',
      '--loglevel',
      '--lockfile-dir',
      '--modules-dir',
      '--network-concurrency',
      '--node-linker',
      '--registry',
      '--reporter',
      '--state-dir',
      '--store-dir',
      '--use-node-version',
      '--virtual-store-dir',
      '--workspace-dir',
    ]),
  },
  yarn: { main: set(['-p', '--package']), extra: set(['-p', '--package']), valued: set([]) },
  bun: { main: set(['-p', '--package']), extra: set(['-p', '--package']), valued: set(['--registry', '--cwd']) },
  pipx: { main: set(['--spec']), extra: set([]), valued: set(['--python', '--index-url', '-i', '--pip-args']) },
  run: { main: set([]), extra: set([]), valued: set(RUN_VALUED), plain: set(RUN_PLAIN) },
};

export interface ReadArgs {
  /** Index of the first word that is not an option, or -1. */
  readonly at: number;
  readonly main: readonly string[];
  readonly extra: readonly string[];
  /** Every option named, values left out. */
  readonly seen: ReadonlySet<string>;
  /** An option in no list, followed by a word that may be its value. */
  readonly unknown?: { readonly option: string; readonly word: string };
}

const takesValue = (table: FlagTable, name: string) =>
  table.main.has(name) || table.extra.has(name) || table.valued.has(name);
const isPlain = (table: FlagTable, name: string) =>
  table.plain?.has(name) === true || (table.negation === true && name.startsWith('--no-'));

/**
 * Reads options up to the first word that is not one. Reads `--opt value`, `--opt=value`,
 * `-o value`, `-o=value`, `-ovalue` and joined switches (`-it`) as the programs do.
 */
export function readArgs(args: readonly string[], table: FlagTable): ReadArgs {
  const main: string[] = [];
  const extra: string[] = [];
  const seen = new Set<string>();
  const done = (at: number, unknown?: ReadArgs['unknown']): ReadArgs => ({
    at,
    main,
    extra,
    seen,
    ...(unknown ? { unknown } : {}),
  });
  const take = (name: string, value: string) => {
    if (table.main.has(name)) main.push(value);
    else if (table.extra.has(name)) extra.push(value);
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === '--') return done(i + 1 < args.length ? i + 1 : -1);
    if (!arg.startsWith('-') || arg === '-') return done(i);
    const next = args[i + 1];
    const nextIsWord = next !== undefined && !next.startsWith('-');
    if (arg.startsWith('--') || arg.length === 2 || arg[2] === '=') {
      const eq = arg.indexOf('=');
      const name = eq > 0 ? arg.slice(0, eq) : arg;
      seen.add(name);
      if (takesValue(table, name)) {
        const value = eq > 0 ? arg.slice(eq + 1) : args[(i += 1)];
        if (value === undefined) return done(-1);
        take(name, value);
      } else if (eq < 0 && !isPlain(table, name) && table.plain && nextIsWord)
        return done(-1, { option: name, word: next });
      continue;
    }
    // A single dash with more letters: a listed option (`-dd`), or one-letter options joined (`-it`,
    // `-qv`), where the first one that takes a value takes the rest of the word, or the next word.
    if (takesValue(table, arg) || isPlain(table, arg)) {
      seen.add(arg);
      if (takesValue(table, arg)) {
        const value = args[(i += 1)];
        if (value === undefined) return done(-1);
        take(arg, value);
      }
      continue;
    }
    for (let j = 1; j < arg.length; j += 1) {
      const name = `-${arg[j]}`;
      seen.add(name);
      if (takesValue(table, name)) {
        const rest = arg.slice(j + 1).replace(/^=/, '');
        const value = rest || args[(i += 1)];
        if (value === undefined) return done(-1);
        take(name, value);
        break;
      }
      if (isPlain(table, name)) continue;
      if (!table.plain) continue;
      const rest = arg.slice(j + 1);
      if (rest) return done(-1, { option: name, word: rest });
      if (nextIsWord) return done(-1, { option: name, word: next });
    }
  }
  return done(-1);
}

/**
 * The packages one `uvx --with` value names: uv splits it on commas outside brackets, except a comma
 * before a version operator (`requests>=2.1,<3` is one requirement).
 */
export function splitUvRequirements(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < value.length; i += 1) {
    const c = value[i]!;
    if (c === '[') depth += 1;
    else if (c === ']') depth = Math.max(0, depth - 1);
    else if (c === ',' && depth === 0) {
      const after = value.slice(i + 1).trimStart()[0];
      if (after !== undefined && '!=<>~'.includes(after)) continue;
      out.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(value.slice(start).trim());
  return out.filter(Boolean);
}
