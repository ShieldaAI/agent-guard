import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  chmodSync,
  closeSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

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
  stdout: string;
  stderr: string;
  exports: SandboxExport[];
  image: string;
  isolation: "linux-container-network-none";
}
const MiB = 1024 * 1024;
const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
function bounded(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
  integer = true,
): number {
  const result = value ?? fallback;
  if (
    !Number.isFinite(result) ||
    result < min ||
    result > max ||
    (integer && !Number.isInteger(result))
  )
    throw new Error("Invalid sandbox resource limit");
  return result;
}
/** Fixed isolation settings have no caller overrides. Images must already be available locally. */
export function validateSandboxProfile(
  profile: SandboxProfile,
): ValidatedSandboxProfile {
  if (
    !profile ||
    !/^[a-z0-9][a-z0-9._/:\-]*@sha256:[a-f0-9]{64}$/.test(profile.image) ||
    profile.image.includes("..")
  )
    throw new Error("A repository image pinned by sha256 digest is required");
  const allowed = new Set([
    "image",
    "memoryMb",
    "cpus",
    "pidsLimit",
    "timeoutMs",
    "workspaceMb",
    "maxInputBytes",
    "maxOutputBytes",
    "maxExportBytes",
  ]);
  if (Object.keys(profile).some((key) => !allowed.has(key)))
    throw new Error("Unsupported sandbox profile option");
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
function portablePath(value: string): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 240 ||
    value.includes("\\") ||
    value.includes(":") ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    value.startsWith("/") ||
    value
      .split("/")
      .some(
        (part) =>
          !part ||
          part === "." ||
          part === ".." ||
          /[. ]$/.test(part) ||
          /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part),
      )
  )
    throw new Error("Expected a portable relative file path");
  return value;
}
function paths(values: string[]): string[] {
  if (!Array.isArray(values) || values.length > 256)
    throw new Error("At most 256 explicit file paths are permitted");
  const result = values.map(portablePath);
  if (
    new Set(result.map((value) => value.toLowerCase())).size !== result.length
  )
    throw new Error("Duplicate or case-colliding file paths");
  return result;
}

export function buildDockerCreateArgs(
  profile: SandboxProfile,
  staging: string,
  name: string,
): string[] {
  const p = validateSandboxProfile(profile);
  if (
    !isAbsolute(staging) ||
    /[,\r\n\u0000]/.test(staging) ||
    !/^agent-guard-[a-f0-9-]{36}$/.test(name)
  )
    throw new Error("Invalid private staging directory or container name");
  return [
    "create",
    "--name",
    name,
    `--label=io.shielda.agent-guard.owner-pid=${process.pid}`,
    "--pull=never",
    "--network=none",
    "--read-only",
    "--user=1000:1000",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit",
    String(p.pidsLimit),
    "--memory",
    `${p.memoryMb}m`,
    "--memory-swap",
    `${p.memoryMb}m`,
    "--cpus",
    String(p.cpus),
    "--ulimit",
    "nofile=256:256",
    "--ulimit",
    "core=0:0",
    "--ipc=private",
    "--cgroupns=private",
    "--init",
    "--no-healthcheck",
    "--restart=no",
    "--log-driver=none",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
    "--tmpfs",
    `/workspace:rw,nosuid,nodev,size=${p.workspaceMb}m,uid=1000,gid=1000,mode=0700`,
    "--mount",
    `type=bind,source=${staging},target=/input,readonly,bind-propagation=rprivate`,
    "--workdir=/workspace",
    "--env=HOME=/tmp",
    "--env=TMPDIR=/tmp",
    "--env=PATH=/usr/local/bin:/usr/bin:/bin",
    "--entrypoint=/bin/sh",
    p.image,
    "-c",
    "while :; do sleep 3600; done",
  ];
}
interface CommandResult {
  stdout: Buffer;
  stderr: Buffer;
  code: number;
}
function docker(
  args: string[],
  maximum: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<CommandResult> {
  return new Promise((resolvePromise, reject) => {
    if (signal?.aborted) {
      reject(new Error("Sandbox operation aborted"));
      return;
    }
    const child = spawn("docker", args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out: Buffer[] = [],
      err: Buffer[] = [];
    let size = 0,
      failure: Error | undefined;
    const stop = (message: string) => {
      failure ??= new Error(message);
      child.kill("SIGKILL");
    };
    const timer = setTimeout(
      () => stop("Sandbox operation exceeded its time limit"),
      timeoutMs,
    );
    const aborted = () => stop("Sandbox operation aborted");
    signal?.addEventListener("abort", aborted, { once: true });
    child.stdout.on("data", (part: Buffer) => {
      size += part.length;
      if (size > maximum) stop("Sandbox output exceeded its byte limit");
      else out.push(part);
    });
    child.stderr.on("data", (part: Buffer) => {
      size += part.length;
      if (size > maximum) stop("Sandbox output exceeded its byte limit");
      else err.push(part);
    });
    child.on("error", () => {
      failure ??= new Error("Docker could not be started");
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      if (failure) reject(failure);
      else
        resolvePromise({
          stdout: Buffer.concat(out),
          stderr: Buffer.concat(err),
          code: code ?? 1,
        });
    });
  });
}
async function checked(
  args: string[],
  maximum = MiB,
  timeoutMs = 15_000,
  signal?: AbortSignal,
): Promise<CommandResult> {
  const result = await docker(args, maximum, timeoutMs, signal);
  if (result.code !== 0)
    throw new Error(
      "Docker operation failed; verify the local Linux daemon and pinned image",
    );
  return result;
}

function stageInputs(
  workspace: string,
  selected: string[],
  target: string,
  limit: number,
): void {
  const root = realpathSync(workspace);
  if (!lstatSync(root).isDirectory())
    throw new Error("Workspace must be a directory");
  let bytes = 0;
  for (const path of selected) {
    let current = root;
    for (const part of path.split("/")) {
      current = join(current, part);
      const stat = lstatSync(current);
      if (stat.isSymbolicLink())
        throw new Error("Workspace input symlinks are not permitted");
    }
    const actual = realpathSync(current);
    if (
      relative(root, actual).startsWith(`..${sep}`) ||
      relative(root, actual) === ".." ||
      isAbsolute(relative(root, actual))
    )
      throw new Error("Workspace input escaped the selected root");
    const expected = lstatSync(current);
    const handle = openSync(
      actual,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const stat = fstatSync(handle);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.dev !== expected.dev ||
        stat.ino !== expected.ino ||
        stat.size > limit - bytes
      )
        throw new Error(
          "Inputs must be bounded regular files without hard links",
        );
      const buffer = Buffer.alloc(stat.size + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = readSync(
          handle,
          buffer,
          length,
          buffer.length - length,
          null,
        );
        if (!count) break;
        length += count;
      }
      if (length !== stat.size)
        throw new Error("Workspace input changed during its bounded copy");
      const data = buffer.subarray(0, length);
      bytes += data.length;
      if (bytes > limit)
        throw new Error("Workspace input exceeded its byte limit");
      const destination = join(target, ...path.split("/"));
      mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
      writeFileSync(destination, data, { flag: "wx", mode: 0o444 });
    } finally {
      closeSync(handle);
    }
  }
  chmodSync(target, 0o555);
}

/** Parses an untrusted tar stream into memory. Never extracts an archive to the host filesystem. */
export function readSandboxArchive(
  archive: Buffer,
  selectedPaths: string[],
  maxExportBytes: number,
): SandboxExport[] {
  if (
    !Buffer.isBuffer(archive) ||
    archive.length > 136 * MiB ||
    !Number.isSafeInteger(maxExportBytes) ||
    maxExportBytes < 1 ||
    maxExportBytes > 64 * MiB
  )
    throw new Error("Invalid or oversized sandbox archive");
  const selected = new Set(paths(selectedPaths));
  const output = new Map<string, SandboxExport>();
  const seen = new Set<string>();
  const seenFolded = new Set<string>();
  let offset = 0,
    count = 0,
    exportedBytes = 0,
    terminated = false;
  const field = (block: Buffer, start: number, length: number) =>
    block
      .subarray(start, start + length)
      .toString("utf8")
      .split("\0")[0]!;
  const octal = (value: string) => {
    if (!/^[0-7]* *$/.test(value) || !value.trim())
      throw new Error("Unsupported tar numeric field");
    const result = Number.parseInt(value.trim(), 8);
    if (!Number.isSafeInteger(result) || result < 0)
      throw new Error("Invalid tar size");
    return result;
  };
  while (offset + 512 <= archive.length) {
    const block = archive.subarray(offset, offset + 512);
    offset += 512;
    if (block.every((value) => value === 0)) {
      terminated = true;
      if (!archive.subarray(offset).every((value) => value === 0))
        throw new Error("Unexpected tar trailing content");
      break;
    }
    if (++count > 4096) throw new Error("Too many sandbox archive entries");
    const checksum = octal(field(block, 148, 8));
    let computed = 0;
    for (let i = 0; i < 512; i++)
      computed += i >= 148 && i < 156 ? 32 : block[i]!;
    if (checksum !== computed)
      throw new Error("Invalid sandbox archive checksum");
    const magic = field(block, 257, 6);
    if (magic && magic !== "ustar" && magic !== "ustar ")
      throw new Error("Unsupported sandbox archive format");
    const prefix = magic === "ustar" ? field(block, 345, 155) : "";
    let path = `${prefix ? `${prefix}/` : ""}${field(block, 0, 100)}`;
    if (path.startsWith("./")) path = path.slice(2);
    const type = field(block, 156, 1) || "0";
    const size = octal(field(block, 124, 12));
    if (
      size > archive.length - offset ||
      !Number.isSafeInteger(Math.ceil(size / 512) * 512)
    )
      throw new Error("Truncated sandbox archive");
    if (type !== "0" && type !== "5")
      throw new Error(
        "Sandbox exports reject symlinks, hardlinks, devices and extended tar records",
      );
    if (type === "5") {
      if (size !== 0) throw new Error("Invalid archive directory");
      path = path.replace(/\/$/, "");
      if (path && path !== ".") portablePath(path);
    } else {
      portablePath(path);
      if (seen.has(path) || seenFolded.has(path.toLowerCase()))
        throw new Error("Duplicate sandbox archive path");
      seen.add(path);
      seenFolded.add(path.toLowerCase());
      if (selected.has(path)) {
        exportedBytes += size;
        if (exportedBytes > maxExportBytes)
          throw new Error("Sandbox exports exceeded their byte limit");
        const data = archive.subarray(offset, offset + size);
        output.set(path, {
          path,
          sha256: sha256(data),
          size,
          contentBase64: data.toString("base64"),
        });
      }
    }
    offset += Math.ceil(size / 512) * 512;
  }
  if (!terminated || output.size !== selected.size)
    throw new Error("Incomplete sandbox archive or missing selected output");
  return [...output.values()];
}

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
    options.command.some(
      (value) =>
        typeof value !== "string" ||
        value.includes("\0") ||
        value.length > 8192,
    ) ||
    options.command.join("").length > 128 * 1024
  )
    throw new Error("Expected a bounded executable argument array");
  if (!["linux", "darwin", "win32"].includes(process.platform))
    throw new Error("Unsupported sandbox host platform");
  if (
    process.env.DOCKER_HOST &&
    !/^(?:unix:\/\/|npipe:\/\/)/.test(process.env.DOCKER_HOST)
  )
    throw new Error("Remote Docker endpoints are not supported");
  const context = await checked(
    ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    MiB,
    15_000,
    options.signal,
  );
  const endpoint: unknown = JSON.parse(context.stdout.toString("utf8"));
  if (
    typeof endpoint !== "string" ||
    !/^(?:unix:\/\/|npipe:\/\/)/.test(endpoint)
  )
    throw new Error("A local Docker endpoint is required");
  const daemon = await checked(
    ["version", "--format", "{{.Server.Os}}"],
    MiB,
    15_000,
    options.signal,
  );
  if (daemon.stdout.toString("utf8").trim() !== "linux")
    throw new Error(
      "A Linux Docker daemon is required; macOS and Windows need a Linux VM",
    );
  const hostInfo = await checked(
    ["info", "--format", "{{json .}}"],
    MiB,
    15_000,
    options.signal,
  );
  const controls = JSON.parse(hostInfo.stdout.toString("utf8")) as {
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
    !controls.SecurityOptions?.includes("name=seccomp,profile=builtin") ||
    !controls.SecurityOptions.includes("name=cgroupns")
  )
    throw new Error(
      "Docker daemon must support memory/swap/process/CPU limits, default seccomp and cgroup namespaces",
    );
  const image = await checked(
    ["image", "inspect", profile.image, "--format", "{{json .}}"],
    MiB,
    15_000,
    options.signal,
  );
  const imageInfo = JSON.parse(image.stdout.toString("utf8")) as {
    Os?: string;
    Config?: { Volumes?: Record<string, unknown> };
    RepoDigests?: string[];
  };
  if (
    imageInfo.Os !== "linux" ||
    !imageInfo.RepoDigests?.some((value) =>
      value.endsWith(profile.image.slice(profile.image.indexOf("@"))),
    ) ||
    Object.keys(imageInfo.Config?.Volumes ?? {}).length
  )
    throw new Error(
      "Pinned image must be Linux and must not declare implicit volumes",
    );
  const temporary = mkdtempSync(join(homedir(), ".agent-guard-stage-"));
  const staging = join(temporary, "input");
  mkdirSync(staging, { mode: 0o755 });
  const name = `agent-guard-${randomUUID()}`;
  let created = false;
  try {
    stageInputs(options.workspace, input, staging, profile.maxInputBytes);
    created = true;
    await checked(
      buildDockerCreateArgs(profile, staging, name),
      MiB,
      15_000,
      options.signal,
    );
    await checked(["start", name], MiB, 15_000, options.signal);
    await checked(
      [
        "exec",
        name,
        "/bin/sh",
        "-c",
        "cp -R /input/. /workspace/ && chmod -R u+w /workspace",
      ],
      MiB,
      15_000,
      options.signal,
    );
    const result = await docker(
      ["exec", "--workdir=/workspace", name, ...options.command],
      profile.maxOutputBytes,
      profile.timeoutMs,
      options.signal,
    );
    let files: SandboxExport[] = [];
    if (exported.length) {
      const archive = await checked(
        ["exec", name, "/bin/tar", "-C", "/workspace", "-cf", "-", "."],
        profile.maxInputBytes + profile.maxExportBytes + 8 * MiB,
        15_000,
        options.signal,
      );
      files = readSandboxArchive(
        archive.stdout,
        exported,
        profile.maxExportBytes,
      );
    }
    return {
      exitCode: result.code,
      stdout: result.stdout.toString("utf8"),
      stderr: result.stderr.toString("utf8"),
      exports: files,
      image: profile.image,
      isolation: "linux-container-network-none",
    };
  } finally {
    let cleanupFailure = false;
    if (created) {
      try {
        await checked(["rm", "--force", "--volumes", name], MiB, 15_000);
      } catch {
        cleanupFailure = true;
      }
    }
    chmodSync(staging, 0o755);
    rmSync(temporary, { recursive: true, force: true });
    if (cleanupFailure)
      throw new Error(
        `Sandbox cleanup failed; remove container ${name} before continuing`,
      );
  }
}

/** Host-side reviewer supplies exact paths AND hashes. Creates a new destination, never overwrites. */
export function writeReviewedExports(
  result: SandboxResult,
  approved: { path: string; sha256: string }[],
  destination: string,
): string[] {
  if (
    !Array.isArray(result.exports) ||
    result.exports.length > 256 ||
    !Array.isArray(approved)
  )
    throw new Error("Invalid sandbox export review");
  paths(approved.map((item) => item.path));
  if (!approved.length) return [];
  let total = 0;
  const files = approved.map((selection) => {
    const file = result.exports.find((item) => item.path === selection.path);
    if (
      !file ||
      !/^[a-f0-9]{64}$/.test(selection.sha256) ||
      file.sha256 !== selection.sha256
    )
      throw new Error(
        "Export review does not match the selected artifact hash",
      );
    if (
      !Number.isSafeInteger(file.size) ||
      file.size < 0 ||
      file.size > 64 * MiB ||
      typeof file.contentBase64 !== "string" ||
      file.contentBase64.length > Math.ceil((64 * MiB) / 3) * 4
    )
      throw new Error("Invalid export content size");
    total += file.size;
    if (total > 64 * MiB) throw new Error("Reviewed exports exceed 64 MiB");
    const bytes = Buffer.from(file.contentBase64, "base64");
    if (
      bytes.toString("base64") !== file.contentBase64 ||
      bytes.length !== file.size ||
      sha256(bytes) !== selection.sha256
    )
      throw new Error("Export content failed integrity verification");
    return { path: portablePath(file.path), bytes };
  });
  const target = resolve(destination);
  const parent = realpathSync(dirname(target));
  const root = join(parent, relative(dirname(target), target));
  mkdirSync(root, { mode: 0o700 });
  try {
    for (const file of files) {
      const path = join(root, ...file.path.split("/"));
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      writeFileSync(path, file.bytes, { flag: "wx", mode: 0o600 });
    }
    return files.map((file) => join(root, ...file.path.split("/")));
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}
