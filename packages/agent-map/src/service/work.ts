import { Buffer } from 'node:buffer';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { buildGraphIndex, fail, type GraphIndex } from '../common.js';
import type { JsonObject, JsonValue, MapEdge, MapNode, MapProjection } from '../types.js';

export const string = (node: MapNode, key: string): string | null =>
  typeof node.properties[key] === 'string' ? (node.properties[key] as string) : null;
export const number = (node: MapNode, key: string): number | null =>
  typeof node.properties[key] === 'number' ? (node.properties[key] as number) : null;
export const strings = (node: MapNode, key: string): readonly string[] =>
  Array.isArray(node.properties[key])
    ? (node.properties[key] as readonly JsonValue[]).filter((v): v is string => typeof v === 'string')
    : [];
export const matching = (node: MapNode, id: string, native: string): boolean =>
  node.entityId === id || string(node, native) === id;
export const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];
export interface ProjectionLookup {
  /** The first tool node of each name. */
  readonly tools: ReadonlyMap<string, MapNode>;
  /** Resource bindings by `bindingKey(tool, resource_ref)`. */
  readonly bindings: ReadonlyMap<string, readonly MapNode[]>;
}
export const bindingKey = (tool: string, reference: string): string => JSON.stringify([tool, reference]);
/** Count authorized work and elapsed monotonic time, including synchronous projection. */
export class QueryWork {
  readonly #deadline: number;
  readonly #indices = new WeakMap<MapProjection, GraphIndex>();
  readonly #derived = new WeakMap<MapProjection, Map<string, unknown>>();
  readonly #lookups = new WeakMap<MapProjection, ProjectionLookup>();
  #remaining = 200_000;
  #evidenceBytes: number;
  #evidenceCount = 0;
  constructor(timeout: number, maxBytes: number) {
    this.#deadline = performance.now() + timeout;
    this.#evidenceBytes = maxBytes;
  }
  /** Milliseconds left before this query's deadline. */
  remaining(): number {
    return Math.max(0, this.#deadline - performance.now());
  }
  step(amount = 1): void {
    if (performance.now() >= this.#deadline) fail('MAP_TIMEOUT');
    this.#remaining -= amount;
    if (this.#remaining < 0) fail('MAP_LIMIT_EXCEEDED');
  }
  index(projection: MapProjection): GraphIndex {
    this.step();
    const existing = this.#indices.get(projection);
    if (existing) return existing;
    this.step(projection.nodes.length + projection.edges.length);
    const result = buildGraphIndex(projection.nodes, projection.edges);
    this.#indices.set(projection, result);
    this.step();
    return result;
  }
  /** A value derived from one projection, built once per query (for example its validated policy evidence). */
  cached<T>(projection: MapProjection, name: string, build: () => T): T {
    let values = this.#derived.get(projection);
    if (!values) {
      values = new Map();
      this.#derived.set(projection, values);
    }
    if (!values.has(name)) values.set(name, build());
    return values.get(name) as T;
  }
  evidence(value: JsonObject): JsonObject {
    this.step();
    if (++this.#evidenceCount > 1000) fail('MAP_LIMIT_EXCEEDED');
    let copy: JsonObject;
    try {
      copy = immutableJson(value, 24, 25_000, this.#evidenceBytes) as JsonObject;
    } catch {
      return fail('MAP_LIMIT_EXCEEDED');
    }
    this.#evidenceBytes -= Buffer.byteLength(JSON.stringify(copy));
    this.step();
    return copy;
  }
  /**
   * Tools by name and resource bindings by tool and reference, in projection order. Built once
   * per projection, so a row of evidence costs its own lookups and not a scan of every node.
   */
  lookup(projection: MapProjection): ProjectionLookup {
    const existing = this.#lookups.get(projection);
    if (existing) return existing;
    this.step(projection.nodes.length);
    const tools = new Map<string, MapNode>(),
      bindings = new Map<string, MapNode[]>();
    for (const node of projection.nodes) {
      if (node.label === 'GuardTool') {
        const name = string(node, 'name');
        if (name !== null && !tools.has(name)) tools.set(name, node);
      } else if (node.label === 'GuardResourceBinding') {
        const tool = string(node, 'tool'),
          reference = string(node, 'resource_ref');
        if (tool === null || reference === null) continue;
        const key = bindingKey(tool, reference),
          items = bindings.get(key);
        if (items) items.push(node);
        else bindings.set(key, [node]);
      }
    }
    const result = { tools, bindings };
    this.#lookups.set(projection, result);
    return result;
  }
}
export function connected(
  projection: MapProjection,
  ids: Set<string>,
  kind: MapEdge['kind'],
  work: QueryWork,
  reverse = false,
): MapNode[] {
  const index = work.index(projection),
    selected = new Set<string>();
  work.step(ids.size);
  for (const id of ids) {
    const targets = (reverse ? index.incoming : index.outgoing).get(id)?.get(kind) ?? [];
    work.step(targets.length);
    for (const target of targets) selected.add(target);
  }
  return [...selected].flatMap(id => (index.nodes.get(id) ? [index.nodes.get(id)!] : []));
}
export const nodeIds = (nodes: readonly MapNode[]): Set<string> => new Set(nodes.map(node => node.id));
