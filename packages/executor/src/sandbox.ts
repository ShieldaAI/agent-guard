import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { readWorkspaceInput } from './workspace-input.js';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import {
  codedError,
  foldPath,
  MAX_PATH_COUNT,
  pipelineError,
  portablePathListProblem,
  portablePathProblem,
} from './path-rules.js';
import { ExecutorError } from './store.js';

export interface SandboxProfile {
  image: string;
  memoryMb?: number;
  cpus?: number;
  pidsLimit?: number;
  timeoutMs?: number;
  workspaceMb?: number;
  maxInputBytes?: number;
  maxOutputBytes?: number;
  maxExportBytes?: number;
}
export interface ValidatedSandboxProfile {
  image: string;
  memoryMb: number;
  cpus: number;
  pidsLimit: number;
  timeoutMs: number;
  workspaceMb: number;
  maxInputBytes: number;
  maxOutputBytes: number;
  maxExportBytes: number;
}
export interface SandboxExport {
  path: string;
  sha256: string;
  size: number;
  contentBase64: string;
}
export interface SandboxResult {
  exitCode: number;
  /** Lossy UTF-8 view for display. The exact bytes are in `stdoutBase64`. */
  stdout: string;
  /** Lossy UTF-8 view for display. The exact bytes are in `stderrBase64`. */
  stderr: string;
  /** The bytes the command wrote, unmodified. Signed receipts hash these bytes. */
  stdoutBase64: string;
  stderrBase64: string;
  exports: SandboxExport[];
  image: string;
  isolation: 'linux-container-network-none';
}
const MiB = 1024 * 1024;
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
function bounded(value: number | undefined, fallback: number, min: number, max: number, integer = true): number {
  const result = value ?? fallback;
  if (!Number.isFinite(result) || result < min || result > max || (integer && !Number.isInteger(result)))
    throw pipelineError('SANDBOX_PROFILE_INVALID', 'Invalid sandbox resource limit');
  return result;
}
/** Fixed isolation settings have no caller overrides. Images must already be available locally. */
export function validateSandboxProfile(profile: SandboxProfile): ValidatedSandboxProfile {
  if (
    !profile ||
    typeof profile !== 'object' ||
    typeof profile.image !== 'string' ||
    !/^[a-z0-9][a-z0-9._/:\-]*@sha256:[a-f0-9]{64}$/.test(profile.image) ||
    profile.image.includes('..')
  )
    throw pipelineError('SANDBOX_PROFILE_INVALID', 'A repository image pinned by sha256 digest is required');
  const allowed = new Set([
    'image',
    'memoryMb',
    'cpus',
    'pidsLimit',
    'timeoutMs',
    'workspaceMb',
    'maxInputBytes',
    'maxOutputBytes',
    'maxExportBytes',
  ]);
  if (Object.keys(profile).some(key => !allowed.has(key)))
    throw pipelineError('SANDBOX_PROFILE_INVALID', 'Unsupported sandbox profile option');
  return {
    image: profile.image,
    memoryMb: bounded(profile.memoryMb, 256, 64, 4096),
    cpus: bounded(profile.cpus, 1, 0.1, 8, false),
    pidsLimit: bounded(profile.pidsLimit, 64, 16, 512),
    timeoutMs: bounded(profile.timeoutMs, 30_000, 100, 600_000),
    workspaceMb: bounded(profile.workspaceMb, 64, 8, 512),
    maxInputBytes: bounded(profile.maxInputBytes, 16 * MiB, 1, 64 * MiB),
    maxOutputBytes: bounded(profile.maxOutputBytes, MiB, 1, 16 * MiB),
    maxExportBytes: bounded(profile.maxExportBytes, 16 * MiB, 1, 64 * MiB),
  };
}
function invalidPath(detail: string): never {
  throw pipelineError('SANDBOX_PATH_INVALID', 'Expected portable relative file paths without collisions', { detail });
}
function portablePath(value: unknown): string {
  const problem = portablePathProblem(value);
  if (problem) invalidPath(problem);
  return value as string;
}
function paths(values: unknown): string[] {
  const problem = portablePathListProblem(values);
  if (problem) invalidPath(problem);
  return [...(values as string[])];
}

export function buildDockerCreateArgs(profile: SandboxProfile, staging: string, name: string): string[] {
  const p = validateSandboxProfile(profile);
  if (!isAbsolute(staging) || /[,\r\n\u0000]/.test(staging) || !/^agent-guard-[a-f0-9-]{36}$/.test(name))
    throw pipelineError('SANDBOX_ARGUMENT_INVALID', 'Invalid private staging directory or container name');
  return [
    'create',
    '--name',
    name,
    `--label=io.shielda.agent-guard.owner-pid=${process.pid}`,
    '--pull=never',
    '--network=none',
    '--read-only',
    '--user=1000:1000',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true',
    '--pids-limit',
    String(p.pidsLimit),
    '--memory',
    `${p.memoryMb}m`,
    '--memory-swap',
    `${p.memoryMb}m`,
    '--cpus',
    String(p.cpus),
    '--ulimit',
    'nofile=256:256',
    '--ulimit',
    'core=0:0',
    '--ipc=private',
    '--cgroupns=private',
    '--init',
    '--no-healthcheck',
    '--restart=no',
    '--log-driver=none',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
    '--tmpfs',
    `/workspace:rw,nosuid,nodev,size=${p.workspaceMb}m,uid=1000,gid=1000,mode=0700`,
    '--mount',
    `type=bind,source=${staging},target=/input,readonly,bind-propagation=rprivate`,
    '--workdir=/workspace',
    '--env=HOME=/tmp',
    '--env=TMPDIR=/tmp',
    '--env=PATH=/usr/local/bin:/usr/bin:/bin',
    '--entrypoint=/bin/sh',
    p.image,
    '-c',
    'while :; do sleep 3600; done',
  ];
}
interface CommandResult {
  stdout: Buffer;
  stderr: Buffer;
  code: number;
}
function docker(args: string[], maximum: number, timeoutMs: number, signal?: AbortSignal): Promise<CommandResult> {
  return new Promise((resolvePromise, reject) => {
    if (signal?.aborted) {
      reject(pipelineError('SANDBOX_ABORTED', 'Sandbox operation aborted'));
      return;
    }
    const unavailable = (cause: unknown) =>
      pipelineError('SANDBOX_DOCKER_FAILED', 'Docker could not be started', { detail: 'CLI_UNAVAILABLE', cause });
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn('docker', args, {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(unavailable(error));
      return;
    }
    const out: Buffer[] = [],
      err: Buffer[] = [];
    let size = 0,
      failure: ExecutorError | undefined;
    const stop = (code: string, hint: string) => {
      failure ??= pipelineError(code, hint);
      child.kill('SIGKILL');
    };
    const timer = setTimeout(() => stop('SANDBOX_TIMEOUT', 'Sandbox operation exceeded its time limit'), timeoutMs);
    const aborted = () => stop('SANDBOX_ABORTED', 'Sandbox operation aborted');
    signal?.addEventListener('abort', aborted, { once: true });
    const collect = (parts: Buffer[]) => (part: Buffer) => {
      size += part.length;
      if (size > maximum) stop('SANDBOX_OUTPUT_LIMIT', 'Sandbox output exceeded its byte limit');
      else parts.push(part);
    };
    child.stdout!.on('data', collect(out));
    child.stderr!.on('data', collect(err));
    let settled = false;
    const settle = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', aborted);
      if (failure) reject(failure);
      else
        resolvePromise({
          stdout: Buffer.concat(out),
          stderr: Buffer.concat(err),
          code: code ?? 1,
        });
    };
    child.on('error', error => {
      failure ??= unavailable(error);
      // A process that never started emits no close event.
      if (child.pid === undefined) settle(null);
    });
    child.on('close', settle);
  });
}
/**
 * Docker's stderr can quote host paths, image names and guest output, so none of it is
 * relayed. Only the first 4 KiB is inspected and reduced to one fixed category.
 */
const DOCKER_FAILURES: readonly (readonly [RegExp, string])[] = [
  [
    /cannot connect to the docker daemon|is the docker daemon running|error during connect|dial unix|open \/\/\.\/pipe/,
    'DAEMON_UNAVAILABLE',
  ],
  [/permission denied|access is denied/, 'PERMISSION_DENIED'],
  [/no such image|pull access denied|manifest unknown|unable to find image|image not found/, 'IMAGE_NOT_FOUND'],
  [/no such container/, 'CONTAINER_NOT_FOUND'],
  [/is not running|is paused|is restarting/, 'CONTAINER_NOT_RUNNING'],
  [/is already in use|conflict/, 'NAME_CONFLICT'],
  [/no space left|cannot allocate memory|out of memory|too many open files/, 'RESOURCE_EXHAUSTED'],
  [/executable file not found|no such file or directory/, 'EXECUTABLE_NOT_FOUND'],
  [/context .{0,128}(?:does not exist|not found)/, 'CONTEXT_NOT_FOUND'],
];
function dockerFailureCategory(stderr: Buffer): string {
  const text = stderr.subarray(0, 4096).toString('latin1').toLowerCase();
  return DOCKER_FAILURES.find(([pattern]) => pattern.test(text))?.[1] ?? 'UNCLASSIFIED';
}
type DockerOperation = 'context inspect' | 'version' | 'info' | 'image inspect' | 'create' | 'start' | 'exec' | 'rm';
async function checked(
  operation: DockerOperation,
  args: string[],
  maximum = MiB,
  timeoutMs = 15_000,
  signal?: AbortSignal,
): Promise<CommandResult> {
  const result = await docker(args, maximum, timeoutMs, signal);
  if (result.code !== 0)
    throw pipelineError(
      'SANDBOX_DOCKER_FAILED',
      `Docker ${operation} failed; verify the local Linux daemon and pinned image`,
      { detail: dockerFailureCategory(result.stderr) },
    );
  return result;
}
function dockerJson(result: CommandResult): unknown {
  try {
    return JSON.parse(result.stdout.toString('utf8'));
  } catch {
    throw pipelineError('SANDBOX_DOCKER_FAILED', 'Docker returned an unreadable description', {
      detail: 'RESPONSE_INVALID',
    });
  }
}

function stageInputs(workspace: string, selected: string[], target: string, limit: number): void {
  const root = resolve(workspace);
  let directory = false;
  try {
    directory = lstatSync(root).isDirectory();
  } catch {
    // Reported below without the host path.
  }
  if (!directory)
    throw pipelineError('SANDBOX_ARGUMENT_INVALID', 'Workspace must be a directory', {
      detail: 'WORKSPACE_UNAVAILABLE',
    });
  let remaining = limit;
  for (const path of selected) {
    const data = readWorkspaceInput(root, path, remaining);
    remaining -= data.length;
    const destination = join(target, ...path.split('/'));
    mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
    writeFileSync(destination, data, { flag: 'wx', mode: 0o444 });
  }
  chmodSync(target, 0o555);
}

const utf8 = new TextDecoder('utf-8', { fatal: true });
/** Entries per archive, counting long-name and pax records. */
const MAX_ARCHIVE_ENTRIES = 4096;
/** A GNU long-name record holds one path: "./", the path, an optional "/" and a NUL. */
const MAX_LONG_NAME_BYTES = 1024;
const MAX_PAX_BYTES = 8192;
// Keys that never change which bytes belong to the entry. Any other key is refused.
const PAX_IGNORED = /^(?:atime|ctime|mtime|uid|gid|uname|gname|comment|(?:SCHILY|LIBARCHIVE)\.[\x21-\x7e]+)$/;

function invalidArchive(detail: string, hint = 'Invalid sandbox archive'): never {
  throw pipelineError('SANDBOX_ARCHIVE_INVALID', hint, { detail });
}
function archiveName(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    return invalidArchive('ARCHIVE_NAME');
  }
}
/** The `path` of a pax extended header, or undefined when it only carries ignorable keys. */
function paxPath(data: Buffer): string | undefined {
  let path: string | undefined;
  for (let start = 0; start < data.length;) {
    const space = data.indexOf(0x20, start);
    const digits = space === -1 ? '' : data.subarray(start, space).toString('latin1');
    if (!/^[1-9][0-9]{0,4}$/.test(digits)) invalidArchive('ARCHIVE_EXTENSION');
    const end = start + Number(digits);
    if (end > data.length || data[end - 1] !== 0x0a) invalidArchive('ARCHIVE_EXTENSION');
    const record = data.subarray(space + 1, end - 1);
    const equals = record.indexOf(0x3d);
    if (equals < 1) invalidArchive('ARCHIVE_EXTENSION');
    const key = record.subarray(0, equals).toString('latin1');
    if (key === 'path') {
      if (path !== undefined) invalidArchive('ARCHIVE_EXTENSION');
      path = archiveName(record.subarray(equals + 1));
    } else if (!PAX_IGNORED.test(key)) invalidArchive('ARCHIVE_EXTENSION');
    start = end;
  }
  return path;
}

/**
 * Parses an untrusted tar stream into memory. Never extracts an archive to the host filesystem.
 * Reads ustar, GNU long-name ("L") and pax ("x", `path` only) entries, so every path the shared
 * rule accepts can be carried; links, devices, sparse files and global headers are refused.
 */
export function readSandboxArchive(archive: Buffer, selectedPaths: string[], maxExportBytes: number): SandboxExport[] {
  if (
    !Buffer.isBuffer(archive) ||
    archive.length > 136 * MiB ||
    !Number.isSafeInteger(maxExportBytes) ||
    maxExportBytes < 1 ||
    maxExportBytes > 64 * MiB
  )
    throw pipelineError('SANDBOX_ARGUMENT_INVALID', 'Invalid or oversized sandbox archive');
  const selected = new Set(paths(selectedPaths));
  const output = new Map<string, SandboxExport>();
  const seen = new Set<string>();
  let offset = 0,
    count = 0,
    exportedBytes = 0,
    terminated = false,
    // Set by a long-name or pax record for the one entry that follows it.
    longName: string | undefined,
    extended = false;
  const bytes = (block: Buffer, start: number, length: number) => {
    const part = block.subarray(start, start + length);
    const end = part.indexOf(0);
    return end === -1 ? part : part.subarray(0, end);
  };
  const field = (block: Buffer, start: number, length: number) => bytes(block, start, length).toString('latin1');
  const octal = (value: string) => {
    if (!/^[0-7]* *$/.test(value) || !value.trim()) invalidArchive('ARCHIVE_NUMERIC');
    const result = Number.parseInt(value.trim(), 8);
    if (!Number.isSafeInteger(result) || result < 0) invalidArchive('ARCHIVE_NUMERIC');
    return result;
  };
  while (offset + 512 <= archive.length) {
    const block = archive.subarray(offset, offset + 512);
    offset += 512;
    if (block.every(value => value === 0)) {
      terminated = true;
      if (!archive.subarray(offset).every(value => value === 0)) invalidArchive('ARCHIVE_TRAILING');
      break;
    }
    if (++count > MAX_ARCHIVE_ENTRIES) invalidArchive('ARCHIVE_ENTRY_LIMIT');
    const checksum = octal(field(block, 148, 8));
    let computed = 0;
    for (let i = 0; i < 512; i++) computed += i >= 148 && i < 156 ? 32 : block[i]!;
    if (checksum !== computed) invalidArchive('ARCHIVE_CHECKSUM');
    const magic = field(block, 257, 6);
    if (magic && magic !== 'ustar' && magic !== 'ustar ') invalidArchive('ARCHIVE_FORMAT');
    const type = field(block, 156, 1) || '0';
    const size = octal(field(block, 124, 12));
    const padded = Math.ceil(size / 512) * 512;
    if (size > archive.length - offset || !Number.isSafeInteger(padded)) invalidArchive('ARCHIVE_TRUNCATED');
    if (type === 'L' || type === 'x') {
      // One extension record per entry: a second one could contradict the first.
      if (extended || size < 1 || size > (type === 'L' ? MAX_LONG_NAME_BYTES : MAX_PAX_BYTES))
        invalidArchive('ARCHIVE_EXTENSION');
      const data = archive.subarray(offset, offset + size);
      longName = type === 'L' ? archiveName(bytes(data, 0, size)) : paxPath(data);
      extended = true;
      offset += padded;
      continue;
    }
    if (type !== '0' && type !== '5')
      invalidArchive(
        'ARCHIVE_ENTRY_TYPE',
        'Sandbox exports reject symlinks, hardlinks, devices, sparse files and global tar headers',
      );
    let path: string;
    if (longName !== undefined) path = longName;
    else {
      const prefix = magic === 'ustar' ? archiveName(bytes(block, 345, 155)) : '';
      path = `${prefix ? `${prefix}/` : ''}${archiveName(bytes(block, 0, 100))}`;
    }
    longName = undefined;
    extended = false;
    if (path.startsWith('./')) path = path.slice(2);
    if (type === '5') {
      if (size !== 0) invalidArchive('ARCHIVE_DIRECTORY');
      path = path.replace(/\/$/, '');
      if (path && path !== '.') {
        const problem = portablePathProblem(path);
        if (problem) invalidArchive(problem);
      }
    } else {
      const problem = portablePathProblem(path);
      if (problem) invalidArchive(problem);
      const folded = foldPath(path);
      if (seen.has(folded)) invalidArchive('ARCHIVE_DUPLICATE');
      seen.add(folded);
      if (selected.has(path)) {
        exportedBytes += size;
        if (exportedBytes > maxExportBytes)
          throw pipelineError('SANDBOX_EXPORT_LIMIT', 'Sandbox exports exceeded their byte limit');
        const data = archive.subarray(offset, offset + size);
        output.set(path, {
          path,
          sha256: sha256(data),
          size,
          contentBase64: data.toString('base64'),
        });
      }
    }
    offset += padded;
  }
  if (!terminated || extended) invalidArchive('ARCHIVE_INCOMPLETE');
  if (output.size !== selected.size)
    throw pipelineError('SANDBOX_EXPORT_MISSING', 'A selected output is missing from the sandbox workspace');
  return [...output.values()];
}

/** Whether a container exists for the name: never asked for, refused by Docker, uncertain or created. */
type ContainerState = 'none' | 'refused' | 'unknown' | 'created';

export async function runDockerSandbox(options: {
  profile: SandboxProfile;
  workspace: string;
  inputFiles: string[];
  command: string[];
  exportFiles?: string[];
  signal?: AbortSignal;
}): Promise<SandboxResult> {
  const profile = validateSandboxProfile(options.profile);
  const input = paths(options.inputFiles),
    exported = paths(options.exportFiles ?? []);
  if (
    !Array.isArray(options.command) ||
    !options.command.length ||
    options.command.length > 128 ||
    options.command.some(value => typeof value !== 'string' || value.includes('\0') || value.length > 8192) ||
    options.command.join('').length > 128 * 1024
  )
    throw pipelineError('SANDBOX_ARGUMENT_INVALID', 'Expected a bounded executable argument array');
  const unsupported = (detail: string, hint: string) => pipelineError('SANDBOX_HOST_UNSUPPORTED', hint, { detail });
  if (!['linux', 'darwin', 'win32'].includes(process.platform))
    throw unsupported('PLATFORM', 'Unsupported sandbox host platform');
  if (process.env.DOCKER_HOST && !/^(?:unix:\/\/|npipe:\/\/)/.test(process.env.DOCKER_HOST))
    throw unsupported('REMOTE_ENDPOINT', 'Remote Docker endpoints are not supported');
  const context = await checked(
    'context inspect',
    ['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'],
    MiB,
    15_000,
    options.signal,
  );
  const endpoint = dockerJson(context);
  if (typeof endpoint !== 'string' || !/^(?:unix:\/\/|npipe:\/\/)/.test(endpoint))
    throw unsupported('REMOTE_ENDPOINT', 'A local Docker endpoint is required');
  const daemon = await checked('version', ['version', '--format', '{{.Server.Os}}'], MiB, 15_000, options.signal);
  if (daemon.stdout.toString('utf8').trim() !== 'linux')
    throw unsupported('DAEMON_NOT_LINUX', 'A Linux Docker daemon is required; macOS and Windows need a Linux VM');
  const hostInfo = await checked('info', ['info', '--format', '{{json .}}'], MiB, 15_000, options.signal);
  const controls = (dockerJson(hostInfo) ?? {}) as {
    MemoryLimit?: boolean;
    SwapLimit?: boolean;
    PidsLimit?: boolean;
    CpuCfsQuota?: boolean;
    SecurityOptions?: string[];
  };
  if (
    controls.MemoryLimit !== true ||
    controls.SwapLimit !== true ||
    controls.PidsLimit !== true ||
    controls.CpuCfsQuota !== true ||
    !Array.isArray(controls.SecurityOptions) ||
    !controls.SecurityOptions.includes('name=seccomp,profile=builtin') ||
    !controls.SecurityOptions.includes('name=cgroupns')
  )
    throw unsupported(
      'CONTROLS_MISSING',
      'Docker daemon must support memory/swap/process/CPU limits, default seccomp and cgroup namespaces',
    );
  const image = await checked(
    'image inspect',
    ['image', 'inspect', profile.image, '--format', '{{json .}}'],
    MiB,
    15_000,
    options.signal,
  );
  const imageInfo = (dockerJson(image) ?? {}) as {
    Os?: string;
    Config?: { Volumes?: Record<string, unknown> };
    RepoDigests?: string[];
  };
  if (
    imageInfo.Os !== 'linux' ||
    !Array.isArray(imageInfo.RepoDigests) ||
    !imageInfo.RepoDigests.some(
      value => typeof value === 'string' && value.endsWith(profile.image.slice(profile.image.indexOf('@'))),
    ) ||
    Object.keys(imageInfo.Config?.Volumes ?? {}).length
  )
    throw pipelineError('SANDBOX_IMAGE_INVALID', 'Pinned image must be Linux and must not declare implicit volumes');
  const name = `agent-guard-${randomUUID()}`;
  let temporary: string | undefined,
    staging: string | undefined,
    container: ContainerState = 'none';
  const run = async (): Promise<SandboxResult> => {
    let mounted: string;
    try {
      temporary = mkdtempSync(join(homedir(), '.agent-guard-stage-'));
      mounted = staging = join(temporary, 'input');
      mkdirSync(staging, { mode: 0o755 });
      stageInputs(options.workspace, input, staging, profile.maxInputBytes);
    } catch (error) {
      throw codedError(error, 'SANDBOX_STAGING_FAILED', 'Sandbox inputs could not be staged');
    }
    // From here a container may exist even when the command that creates it fails:
    // a timeout or an abort stops the CLI, not the daemon.
    container = 'unknown';
    try {
      await checked('create', buildDockerCreateArgs(profile, mounted, name), MiB, 15_000, options.signal);
      container = 'created';
    } catch (error) {
      // Docker answered and refused: nothing was created, so a failed removal is not a leak.
      if (error instanceof ExecutorError && error.code === 'SANDBOX_DOCKER_FAILED') container = 'refused';
      throw error;
    }
    await checked('start', ['start', name], MiB, 15_000, options.signal);
    await checked(
      'exec',
      ['exec', name, '/bin/sh', '-c', 'cp -R /input/. /workspace/ && chmod -R u+w /workspace'],
      MiB,
      15_000,
      options.signal,
    );
    const result = await docker(
      ['exec', '--workdir=/workspace', name, ...options.command],
      profile.maxOutputBytes,
      profile.timeoutMs,
      options.signal,
    );
    let files: SandboxExport[] = [];
    // A failed command has no reviewed output to export: return its exit code and streams
    // instead of failing the archive step, which would leave the action's outcome unknown.
    if (exported.length && result.code === 0) {
      const archive = await checked(
        'exec',
        ['exec', name, '/bin/tar', '-C', '/workspace', '-cf', '-', '.'],
        profile.maxInputBytes + profile.maxExportBytes + 8 * MiB,
        15_000,
        options.signal,
      );
      files = readSandboxArchive(archive.stdout, exported, profile.maxExportBytes);
    }
    return {
      exitCode: result.code,
      stdout: result.stdout.toString('utf8'),
      stderr: result.stderr.toString('utf8'),
      stdoutBase64: result.stdout.toString('base64'),
      stderrBase64: result.stderr.toString('base64'),
      exports: files,
      image: profile.image,
      isolation: 'linux-container-network-none',
    };
  };
  /** Returns what could not be removed. Never throws, so it cannot replace the run's own error. */
  const cleanup = async (): Promise<'CONTAINER_LEFT' | 'STAGING_LEFT' | undefined> => {
    let left: 'CONTAINER_LEFT' | 'STAGING_LEFT' | undefined;
    if (container !== 'none') {
      try {
        await checked('rm', ['rm', '--force', '--volumes', name]);
      } catch (error) {
        const absent = error instanceof ExecutorError && error.detail === 'CONTAINER_NOT_FOUND';
        if (container !== 'refused' && !absent) left = 'CONTAINER_LEFT';
      }
    }
    if (temporary !== undefined) {
      try {
        if (staging !== undefined) chmodSync(staging, 0o755);
      } catch {
        // The staging directory was never created; removing its parent below decides.
      }
      try {
        rmSync(temporary, { recursive: true, force: true });
      } catch {
        left ??= 'STAGING_LEFT';
      }
    }
    return left;
  };
  let outcome: { result: SandboxResult } | { error: unknown };
  try {
    outcome = { result: await run() };
  } catch (error) {
    outcome = { error: codedError(error, 'SANDBOX_FAILED', 'Sandbox run failed') };
  }
  const left = await cleanup();
  if (left)
    // The run's own error stays reachable as the cause instead of being replaced.
    throw pipelineError(
      'SANDBOX_CLEANUP_FAILED',
      left === 'CONTAINER_LEFT'
        ? `Sandbox cleanup failed; remove container ${name} before continuing`
        : 'Sandbox cleanup failed; remove the private staging directory before continuing',
      { detail: left, ...('error' in outcome ? { cause: outcome.error } : {}) },
    );
  if ('error' in outcome) throw outcome.error;
  return outcome.result;
}

/** Host-side reviewer supplies exact paths AND hashes. Creates a new destination, never overwrites. */
export function writeReviewedExports(
  result: SandboxResult,
  approved: { path: string; sha256: string }[],
  destination: string,
): string[] {
  const review = (detail: string, hint: string) => pipelineError('SANDBOX_EXPORT_REVIEW_INVALID', hint, { detail });
  if (
    !result ||
    typeof result !== 'object' ||
    !Array.isArray(result.exports) ||
    result.exports.length > MAX_PATH_COUNT ||
    !Array.isArray(approved) ||
    approved.length > MAX_PATH_COUNT ||
    approved.some(item => !item || typeof item !== 'object') ||
    typeof destination !== 'string' ||
    !destination
  )
    throw review('REVIEW_SHAPE', 'Invalid sandbox export review');
  paths(approved.map(item => item.path));
  if (!approved.length) return [];
  let total = 0;
  const files = approved.map(selection => {
    const file = result.exports.find(item => item && item.path === selection.path);
    if (
      !file ||
      typeof selection.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(selection.sha256) ||
      file.sha256 !== selection.sha256
    )
      throw review('REVIEW_HASH', 'Export review does not match the selected artifact hash');
    if (
      !Number.isSafeInteger(file.size) ||
      file.size < 0 ||
      file.size > 64 * MiB ||
      typeof file.contentBase64 !== 'string' ||
      file.contentBase64.length > Math.ceil((64 * MiB) / 3) * 4
    )
      throw review('REVIEW_SIZE', 'Invalid export content size');
    total += file.size;
    if (total > 64 * MiB) throw review('REVIEW_SIZE', 'Reviewed exports exceed 64 MiB');
    const bytes = Buffer.from(file.contentBase64, 'base64');
    if (
      bytes.toString('base64') !== file.contentBase64 ||
      bytes.length !== file.size ||
      sha256(bytes) !== selection.sha256
    )
      throw review('REVIEW_INTEGRITY', 'Export content failed integrity verification');
    return { path: portablePath(file.path), bytes };
  });
  const unavailable = (error: unknown) =>
    codedError(error, 'SANDBOX_EXPORT_DESTINATION_UNAVAILABLE', 'The reviewed export destination could not be created');
  let root: string;
  try {
    const target = resolve(destination);
    const parent = realpathSync(dirname(target));
    root = join(parent, relative(dirname(target), target));
    mkdirSync(root, { mode: 0o700 });
  } catch (error) {
    throw unavailable(error);
  }
  try {
    for (const file of files) {
      const path = join(root, ...file.path.split('/'));
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      writeFileSync(path, file.bytes, { flag: 'wx', mode: 0o600 });
    }
    return files.map(file => join(root, ...file.path.split('/')));
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw unavailable(error);
  }
}
