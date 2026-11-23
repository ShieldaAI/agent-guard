import type { AgentGuard, Budget, Json, ToolDefinition } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';

/** A plain JSON object. */
export type JsonObject = { readonly [key: string]: Json };

/** What a model needs to know about one tool: provider adapters turn it into their own format. */
export interface ToolSpec {
  readonly name: string;
  readonly description: string;
  /** A JSON Schema for the arguments, always an object schema. */
  readonly inputSchema: JsonObject;
}

/** Anything with `toolChanges()`: the core guard and the durable executor both have it. */
export interface ToolDefinitionSource {
  toolChanges(name: string): { readonly approved: boolean; readonly definition?: Json };
}

/** JSON with ordinary mutable arrays and objects: what provider SDK types expect. */
export type PlainJson = null | boolean | number | string | PlainJson[] | { [key: string]: PlainJson };
/** A JSON Schema for tool arguments, as provider SDKs accept it: always `type: 'object'`. */
export type ObjectSchema = { type: 'object'; [key: string]: PlainJson };

/**
 * A deep, unfrozen copy of a spec's schema with `type: 'object'`. The guard keeps definitions
 * frozen; some frameworks (LangChain's validator, for one) write into the schema object they
 * are given, so every adapter hands them their own copy.
 */
export function objectSchema(schema: JsonObject): ObjectSchema {
  return { ...(structuredClone(schema) as { [key: string]: PlainJson }), type: 'object' };
}
/** A deep, unfrozen copy of any JSON value. */
export function plainJson(value: Json): PlainJson {
  return structuredClone(value) as PlainJson;
}

const EMPTY_OBJECT_SCHEMA: JsonObject = Object.freeze({ type: 'object', properties: Object.freeze({}) });

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Tool specs for the model, read from the guard's own approved registrations. What the model
 * is shown is then exactly the definition you approved: the same name, description and schema
 * that the fingerprint covers. Throws TOOL_NOT_APPROVED when a tool's current registration is
 * not approved, so a changed tool is never offered to the model before review; pass
 * `{ unapproved: 'skip' }` to leave such tools out instead.
 */
export function toolSpecs(
  source: ToolDefinitionSource,
  names: readonly string[],
  options: { unapproved?: 'throw' | 'skip' } = {},
): readonly ToolSpec[] {
  if (!Array.isArray(names)) throw new AdapterError('INVALID_OPTIONS');
  const skip = options?.unapproved === 'skip';
  const specs: ToolSpec[] = [];
  for (const name of names) {
    const changes = source.toolChanges(name);
    if (!changes.approved) {
      if (skip) continue;
      throw new AdapterError('TOOL_NOT_APPROVED', name);
    }
    const definition = changes.definition;
    if (!isObject(definition) || typeof definition.description !== 'string')
      throw new AdapterError('TOOL_DEFINITION_UNAVAILABLE', name);
    const schema = definition.inputSchema;
    if (isObject(schema) && schema.type !== undefined && schema.type !== 'object')
      throw new AdapterError('UNSUPPORTED_SCHEMA', name);
    specs.push(
      Object.freeze({
        name,
        description: definition.description,
        inputSchema: isObject(schema) ? schema : EMPTY_OBJECT_SCHEMA,
      }),
    );
  }
  return Object.freeze(specs);
}

/** Options for `registerApprovedTools()`. */
export interface RegisterOptions {
  /**
   * Expected fingerprints by tool name, for example from a file checked into your repository.
   * A tool whose fingerprint differs, or that has no pin, is left unapproved and the call
   * throws TOOL_PIN_MISMATCH naming it, so a changed or new definition cannot reach production
   * without someone updating the pins.
   */
  pinned?: Readonly<Record<string, string>>;
}

/**
 * Registers each tool and approves its definition, the usual start-up step for tools defined
 * in your own code. Returns each tool's fingerprint by name: save it as a pin if you want CI to
 * notice definition changes. Tools from outside your code (MCP servers, plug-ins) deserve a
 * person's review instead: use `toolChanges()` and `approveTool()` for those.
 */
export function registerApprovedTools(
  guard: Pick<AgentGuard, 'registerTool' | 'approveTool'>,
  tools: readonly ToolDefinition[],
  options: RegisterOptions = {},
): Readonly<Record<string, string>> {
  if (!Array.isArray(tools)) throw new AdapterError('INVALID_OPTIONS');
  const pinned = options?.pinned;
  if (pinned !== undefined && !isObject(pinned)) throw new AdapterError('INVALID_OPTIONS');
  const fingerprints: Record<string, string> = {};
  const mismatched: string[] = [];
  for (const tool of tools) {
    const fingerprint = guard.registerTool(tool);
    // defineProperty, not assignment: a tool named "__proto__" must stay an ordinary key.
    Object.defineProperty(fingerprints, tool.name, {
      value: fingerprint,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    const expected = pinned === undefined ? undefined : Object.hasOwn(pinned, tool.name) ? pinned[tool.name] : null;
    if (expected !== undefined && expected !== fingerprint) {
      mismatched.push(tool.name);
      continue;
    }
    guard.approveTool(tool.name, fingerprint);
  }
  if (mismatched.length > 0) throw new AdapterError('TOOL_PIN_MISMATCH', mismatched.join(', '));
  return Object.freeze(fingerprints);
}

/**
 * A budget with sensible defaults: one call at a time, no cost, and a deadline `ttlMs` from now.
 * `maxCalls` and `ttlMs` are required because they are the limits that matter most.
 */
export function taskBudget(options: {
  maxCalls: number;
  ttlMs: number;
  maxConcurrent?: number;
  maxCost?: number;
  /** The guard's clock. Default `Date.now`. */
  clock?: () => number;
}): Budget {
  if (options === null || typeof options !== 'object') throw new AdapterError('INVALID_OPTIONS');
  const { maxCalls, ttlMs, maxConcurrent = 1, maxCost = 0 } = options;
  for (const value of [maxCalls, ttlMs, maxConcurrent, maxCost])
    if (!Number.isSafeInteger(value) || value < 0) throw new AdapterError('INVALID_OPTIONS');
  if (ttlMs <= 0) throw new AdapterError('INVALID_OPTIONS');
  const now = (options.clock ?? Date.now)();
  return Object.freeze({ maxCalls, maxConcurrent, maxCost, deadline: now + ttlMs });
}
