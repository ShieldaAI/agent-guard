import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import {
  constants,
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  canonicalJson,
  digestJson,
  immutableJson,
  type Action,
  type Json,
  type TaskIdentity,
  type ToolDefinition,
} from "@shieldaai/agent-guard";
import { createRestrictedFetch, type NetworkPolicy } from "./network.js";
import { ExecutorError } from "./store.js";

export type PublicToolDefinition = Pick<
  ToolDefinition,
  | "name"
  | "description"
  | "inputSchema"
  | "metadata"
  | "requiresApproval"
  | "maxCost"
>;
/** Safe model-facing metadata only: never expose handlers or credential callbacks. */
export function publicToolDefinition(
  tool: ToolDefinition,
): PublicToolDefinition {
  return immutableJson({
    name: tool.name,
    description: tool.description,
    ...(tool.inputSchema === undefined
      ? {}
      : { inputSchema: tool.inputSchema }),
    ...(tool.metadata === undefined ? {} : { metadata: tool.metadata }),
    ...(tool.requiresApproval === undefined
      ? {}
      : { requiresApproval: tool.requiresApproval }),
    ...(tool.maxCost === undefined ? {} : { maxCost: tool.maxCost }),
  }) as PublicToolDefinition;
}
function fail(code: string): never {
  throw new ExecutorError(code);
}
function identifier(value: string): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 256 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  )
    fail("ADAPTER_CONFIG_INVALID");
  return value;
}
function prefix(value: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$/.test(value)
  )
    fail("ADAPTER_CONFIG_INVALID");
  return value;
}
function object(
  value: Json,
  allowed: string[],
  required: string[],
): Record<string, Json> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !allowed.includes(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  )
    fail("ADAPTER_ARGUMENT_INVALID");
  return value as Record<string, Json>;
}
function relativeFile(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 240 ||
    value.normalize("NFC") !== value ||
    /[\\:\u0000-\u001f\u007f]/u.test(value) ||
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
    fail("ADAPTER_PATH_INVALID");
  return value;
}
function limit(value: number | undefined, fallback: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 16 * 1024 * 1024)
    fail("ADAPTER_CONFIG_INVALID");
  return result;
}
const hash = (data: Buffer) =>
  `sha256:${createHash("sha256").update(data).digest("hex")}`;
type Context = Parameters<ToolDefinition["execute"]>[1];
function assertContext(
  args: Json,
  context: Context,
  tenantId: string,
  resourceId: string,
  version: string,
  recipient?: string,
): void {
  if (context.signal.aborted) fail("ADAPTER_ABORTED");
  if (
    context.task.tenantId !== tenantId ||
    context.action.tenantId !== tenantId ||
    context.action.resourceId !== resourceId ||
    context.action.resourceVersion !== version ||
    canonicalJson(context.action.args) !== canonicalJson(args) ||
    (recipient !== undefined &&
      (context.action.external !== true ||
        context.action.recipient !== recipient))
  )
    fail("ADAPTER_BINDING_CHANGED");
}
function privateStat(stat: Stats, directory: boolean): void {
  if (
    stat.isSymbolicLink() ||
    (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1) ||
    (process.platform !== "win32" &&
      ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))
  )
    fail("ADAPTER_PRIVATE_PATH_UNSAFE");
}

export interface PrivateFileToolsOptions {
  /** Existing executor-owned private directory. Never mount it into a guest or expose it to an untrusted process. */
  directory: string;
  tenantId: string;
  resourcePrefix: string;
  namePrefix?: string;
  maxBytes?: number;
  sensitiveReads?: boolean;
  requireWriteApproval?: boolean;
}
export function createPrivateFileTools(options: PrivateFileToolsOptions): {
  read: ToolDefinition;
  write: ToolDefinition;
} {
  const root = resolve(options.directory),
    tenantId = identifier(options.tenantId),
    resourcePrefix = prefix(options.resourcePrefix),
    namePrefix = prefix(options.namePrefix ?? "private_file");
  const maxBytes = limit(options.maxBytes, 1024 * 1024),
    sensitive = options.sensitiveReads ?? true;
  const validateRoot = () => {
    privateStat(lstatSync(root), true);
    if (realpathSync(root) !== root) fail("ADAPTER_PRIVATE_PATH_UNSAFE");
  };
  validateRoot();
  const versionKey = randomBytes(32);
  const versionToken = (path: string, bytes?: Buffer) =>
    `hmac-sha256:${createHmac("sha256", versionKey)
      .update(tenantId)
      .update("\0")
      .update(resourcePrefix)
      .update("\0")
      .update(path)
      .update(bytes === undefined ? "\0absent\0" : "\0present\0")
      .update(bytes ?? Buffer.alloc(0))
      .digest("hex")}`;
  const locate = (
    path: string,
    allowMissing: boolean,
  ): { path: string; stat?: Stats } => {
    validateRoot();
    const parts = relativeFile(path).split("/");
    let current = root;
    for (let index = 0; index < parts.length; index++) {
      const part = parts[index]!;
      const entries = readdirSync(current);
      if (
        entries.some(
          (entry) =>
            entry.toLowerCase() === part.toLowerCase() && entry !== part,
        )
      )
        fail("ADAPTER_PATH_ALIAS");
      const next = join(current, part);
      let stat: Stats;
      try {
        stat = lstatSync(next);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT" && allowMissing)
          return { path: join(root, ...parts) };
        throw new ExecutorError("ADAPTER_FILE_UNAVAILABLE");
      }
      if (!entries.includes(part)) fail("ADAPTER_PATH_ALIAS");
      privateStat(stat, index !== parts.length - 1);
      if (index === parts.length - 1) return { path: next, stat };
      current = next;
    }
    return fail("ADAPTER_PATH_INVALID");
  };
  const snapshot = (
    path: string,
    allowMissing: boolean,
  ): { version: string; bytes?: Buffer } => {
    const located = locate(path, allowMissing);
    if (!located.stat) return { version: versionToken(path) };
    if (located.stat.size > maxBytes) fail("ADAPTER_SIZE_LIMIT");
    const fd = openSync(
      located.path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const stat = fstatSync(fd);
      privateStat(stat, false);
      if (
        stat.dev !== located.stat.dev ||
        stat.ino !== located.stat.ino ||
        stat.size > maxBytes
      )
        fail("ADAPTER_RESOURCE_CHANGED");
      const bytes = Buffer.alloc(stat.size + 1);
      let size = 0;
      while (size < bytes.length) {
        const read = readSync(fd, bytes, size, bytes.length - size, null);
        if (!read) break;
        size += read;
      }
      if (size !== stat.size) fail("ADAPTER_RESOURCE_CHANGED");
      const value = bytes.subarray(0, size);
      return { version: versionToken(path, value), bytes: value };
    } finally {
      closeSync(fd);
    }
  };
  const parse = (input: Json, write: boolean): Json => {
    const value = object(
      input,
      write ? ["path", "content"] : ["path"],
      write ? ["path", "content"] : ["path"],
    );
    const path = relativeFile(value.path);
    if (!write) return { path };
    if (
      typeof value.content !== "string" ||
      Buffer.byteLength(value.content, "utf8") > maxBytes
    )
      fail("ADAPTER_SIZE_LIMIT");
    return { path, content: value.content };
  };
  const resource = (path: string) => `${resourcePrefix}/${path}`;
  const metadata: Json = {
    adapter: "private-file-v1",
    tenantId,
    resourcePrefix,
    rootIdentity: digestJson(root),
    maxBytes,
  };
  const read: ToolDefinition = {
    name: `${namePrefix}.read`,
    description:
      "Read one version-bound UTF-8 file from an executor-owned private store.",
    metadata,
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", maxLength: 240 } },
      required: ["path"],
      additionalProperties: false,
    },
    parse: (args) => parse(args, false),
    resolve: (args, task) => {
      const input = parse(args, false) as { path: string };
      if (task.tenantId !== tenantId) fail("ADAPTER_TENANT_DENIED");
      return {
        resourceId: resource(input.path),
        tenantId,
        sensitive,
        resourceVersion: snapshot(input.path, false).version,
      };
    },
    execute: (args, context) => {
      const input = parse(args, false) as { path: string },
        state = snapshot(input.path, false);
      assertContext(
        input,
        context,
        tenantId,
        resource(input.path),
        state.version,
      );
      let content: string;
      try {
        content = new TextDecoder("utf-8", { fatal: true }).decode(state.bytes);
      } catch {
        return fail("ADAPTER_TEXT_INVALID");
      }
      return {
        value: {
          path: input.path,
          content,
          version: hash(state.bytes!),
          bytes: state.bytes!.length,
        },
      };
    },
  };
  const write: ToolDefinition = {
    name: `${namePrefix}.write`,
    description:
      "Atomically write one approved UTF-8 file if its prepared version is unchanged.",
    metadata,
    requiresApproval: options.requireWriteApproval ?? true,
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", maxLength: 240 },
        content: { type: "string" },
      },
      required: ["path", "content"],
      additionalProperties: false,
    },
    parse: (args) => parse(args, true),
    resolve: (args, task) => {
      const input = parse(args, true) as { path: string; content: string };
      if (task.tenantId !== tenantId) fail("ADAPTER_TENANT_DENIED");
      return {
        resourceId: resource(input.path),
        tenantId,
        resourceVersion: snapshot(input.path, true).version,
      };
    },
    execute: (args, context) => {
      const input = parse(args, true) as { path: string; content: string };
      const state = snapshot(input.path, true);
      assertContext(
        input,
        context,
        tenantId,
        resource(input.path),
        state.version,
      );
      const target = join(root, ...input.path.split("/"));
      let parent = root;
      for (const part of input.path.split("/").slice(0, -1)) {
        parent = join(parent, part);
        try {
          mkdirSync(parent, { mode: 0o700 });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        privateStat(lstatSync(parent), true);
      }
      const temporary = join(
        dirname(target),
        `.agent-guard-${randomUUID()}.pending`,
      );
      let fd: number | undefined;
      try {
        fd = openSync(
          temporary,
          constants.O_CREAT |
            constants.O_EXCL |
            constants.O_WRONLY |
            (constants.O_NOFOLLOW ?? 0),
          0o600,
        );
        const bytes = Buffer.from(input.content, "utf8");
        writeFileSync(fd, bytes);
        fsyncSync(fd);
        closeSync(fd);
        fd = undefined;
        if (snapshot(input.path, true).version !== state.version)
          fail("ADAPTER_RESOURCE_CHANGED");
        if (context.signal.aborted) fail("ADAPTER_ABORTED");
        renameSync(temporary, target);
        if (process.platform !== "win32") {
          const directory = openSync(dirname(target), constants.O_RDONLY);
          try {
            fsyncSync(directory);
          } finally {
            closeSync(directory);
          }
        }
        return {
          value: {
            path: input.path,
            version: hash(bytes),
            bytes: bytes.length,
          },
        };
      } finally {
        if (fd !== undefined) closeSync(fd);
        rmSync(temporary, { force: true });
      }
    },
  };
  return { read, write };
}

interface AdapterHostOptions {
  name: string;
  tenantId: string;
  resourcePrefix: string;
  network: NetworkPolicy;
}
export interface HttpReadResource {
  url: string;
  etag?: string;
  sensitive?: boolean;
}
export interface HttpGetToolOptions extends AdapterHostOptions {
  resources: Readonly<Record<string, HttpReadResource>>;
}
function endpoint(value: string): string {
  const url = new URL(value);
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash ||
    url.href.length > 4096
  )
    fail("ADAPTER_CONFIG_INVALID");
  return url.href;
}
function etag(value: string | undefined): string | undefined {
  if (value !== undefined && !/^"[\x21\x23-\x7e]{1,256}"$/.test(value))
    fail("ADAPTER_CONFIG_INVALID");
  return value;
}
export function createHttpGetTool(options: HttpGetToolOptions): ToolDefinition {
  const name = prefix(options.name),
    tenantId = identifier(options.tenantId),
    resourcePrefix = prefix(options.resourcePrefix);
  const resources = new Map(
    Object.entries(options.resources).map(([alias, item]) => [
      prefix(alias),
      {
        url: endpoint(item.url),
        ...(etag(item.etag) ? { etag: item.etag! } : {}),
        sensitive: item.sensitive ?? false,
      },
    ]),
  );
  if (!resources.size || resources.size > 256) fail("ADAPTER_CONFIG_INVALID");
  const fetch = createRestrictedFetch(options.network);
  const parse = (args: Json): Json => {
    const input = object(args, ["resource"], ["resource"]);
    if (typeof input.resource !== "string" || !resources.has(input.resource))
      fail("ADAPTER_ARGUMENT_INVALID");
    return { resource: input.resource };
  };
  const binding = (args: Json) => {
    const input = parse(args) as { resource: string },
      selected = resources.get(input.resource)!;
    return {
      input,
      selected,
      resourceId: `${resourcePrefix}/${input.resource}`,
      version: `sha256:${digestJson(selected)}`,
    };
  };
  return {
    name,
    description:
      "Fetch JSON from one host-approved endpoint, with optional strong ETag enforcement.",
    metadata: {
      adapter: "http-get-v1",
      tenantId,
      resourcePrefix,
      resources: Object.fromEntries(resources),
    },
    inputSchema: {
      type: "object",
      properties: { resource: { type: "string", enum: [...resources.keys()] } },
      required: ["resource"],
      additionalProperties: false,
    },
    parse,
    resolve: (args, task) => {
      const item = binding(args);
      if (task.tenantId !== tenantId) fail("ADAPTER_TENANT_DENIED");
      return {
        resourceId: item.resourceId,
        tenantId,
        external: true,
        recipient: item.selected.url,
        sensitive: item.selected.sensitive,
        resourceVersion: item.version,
      };
    },
    execute: async (args, context) => {
      const item = binding(args);
      assertContext(
        item.input,
        context,
        tenantId,
        item.resourceId,
        item.version,
        item.selected.url,
      );
      const response = await fetch(item.selected.url, {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(item.selected.etag ? { "if-match": item.selected.etag } : {}),
        },
        signal: context.signal,
        redirect: "error",
      });
      if (
        !response.ok ||
        (item.selected.etag &&
          response.headers.get("etag") !== item.selected.etag)
      ) {
        await response.body?.cancel();
        return fail("ADAPTER_HTTP_VERSION_OR_STATUS");
      }
      if (
        !/^application\/(?:[a-z0-9.+-]*\+)?json(?:;|$)/i.test(
          response.headers.get("content-type") ?? "",
        )
      ) {
        await response.body?.cancel();
        return fail("ADAPTER_HTTP_CONTENT_TYPE");
      }
      let value: Json;
      try {
        value = immutableJson(await response.json()) as Json;
      } catch {
        return fail("ADAPTER_HTTP_JSON_INVALID");
      }
      return {
        value: {
          resource: item.input.resource,
          status: response.status,
          etag: response.headers.get("etag"),
          body: value,
        },
      };
    },
  };
}

export interface OutboundJsonToolOptions extends AdapterHostOptions {
  endpoint: string;
  resource: string;
  recipient: string;
  credentialVersion: string;
  credential: () => { value: string; version: string };
  /** Trusted synchronous schema validation/normalization for payload fields; receives no routing or credential arguments. */
  parsePayload: (value: Json) => Json;
  payloadSchema: Json;
  expectedETag?: string;
  maxPayloadBytes?: number;
}
export function createOutboundJsonTool(
  options: OutboundJsonToolOptions,
): ToolDefinition {
  const name = prefix(options.name),
    tenantId = identifier(options.tenantId),
    resourceId = `${prefix(options.resourcePrefix)}/${prefix(options.resource)}`;
  const url = endpoint(options.endpoint),
    recipient = identifier(options.recipient),
    credentialVersion = identifier(options.credentialVersion);
  if (
    new URL(url).search ||
    typeof options.credential !== "function" ||
    typeof options.parsePayload !== "function"
  )
    fail("ADAPTER_CONFIG_INVALID");
  const expectedETag = etag(options.expectedETag),
    maxPayload = limit(options.maxPayloadBytes, 256 * 1024),
    credential = options.credential,
    parsePayload = options.parsePayload;
  const fetch = createRestrictedFetch(options.network);
  const version = `sha256:${digestJson({ url, recipient, credentialVersion, expectedETag: expectedETag ?? null })}`;
  const normalized = (args: Json): Json => {
    const input = object(args, ["payload"], ["payload"]);
    const payload = input.payload!;
    if (
      !payload ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      Buffer.byteLength(canonicalJson(payload), "utf8") > maxPayload
    )
      fail("ADAPTER_ARGUMENT_INVALID");
    return { payload };
  };
  const parse = (args: Json): Json => {
    const input = object(args, ["payload"], ["payload"]);
    return normalized({
      payload: immutableJson(parsePayload(input.payload!)) as Json,
    });
  };
  return {
    name,
    description:
      "Send one approved JSON payload to a fixed recipient and endpoint using a host-owned credential.",
    requiresApproval: true,
    metadata: {
      adapter: "outbound-json-v1",
      tenantId,
      resourceId,
      endpoint: url,
      recipient,
      credentialVersion,
      expectedETag: expectedETag ?? null,
    },
    inputSchema: {
      type: "object",
      properties: { payload: immutableJson(options.payloadSchema) as Json },
      required: ["payload"],
      additionalProperties: false,
    },
    parse,
    resolve: (args, task) => {
      normalized(args);
      if (task.tenantId !== tenantId) fail("ADAPTER_TENANT_DENIED");
      return {
        resourceId,
        tenantId,
        external: true,
        recipient,
        resourceVersion: version,
      };
    },
    execute: async (args, context) => {
      const input = normalized(args);
      assertContext(input, context, tenantId, resourceId, version, recipient);
      const token = credential();
      if (
        token.version !== credentialVersion ||
        typeof token.value !== "string" ||
        !/^[\x21-\x7e]{1,4096}$/.test(token.value)
      )
        fail("ADAPTER_CREDENTIAL_CHANGED");
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token.value}`,
          ...(expectedETag ? { "if-match": expectedETag } : {}),
        },
        body: canonicalJson({
          recipient,
          payload: (input as { payload: Json }).payload,
        }),
        signal: context.signal,
        redirect: "error",
      });
      await response.arrayBuffer();
      if (!response.ok) return fail("ADAPTER_HTTP_STATUS");
      return {
        value: {
          accepted: true,
          status: response.status,
          recipient,
          etag: response.headers.get("etag"),
        },
      };
    },
  };
}
