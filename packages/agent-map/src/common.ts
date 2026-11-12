import { MapQueryError, type MapEdge, type MapIdentityScope, type MapNode } from './types.js';

// Helpers shared by the service, the store and the HTTP boundaries. Nothing in this file touches
// the network, the file system or a Node-only module. The service as a whole is not free of
// them: `service/work.ts` and `service/policy.ts` import `node:buffer`, and the JSON helpers of
// `@shieldaai/agent-guard/internal` import `node:buffer`, `node:crypto` and `node:util/types`.
// A browser bundle of `@shieldaai/agent-map/service` must supply stand-ins for those three
// (the viewer build does).

export function fail(code: string): never {
  throw new MapQueryError(code);
}
/** A safe integer option within `[min, max]`, or `fallback` when it is not set. */
export function integer(value: unknown, fallback: number, min: number, max: number): number {
  const result = value === undefined ? fallback : value;
  if (typeof result !== 'number' || !Number.isSafeInteger(result) || result < min || result > max)
    fail('MAP_CONFIG_INVALID');
  return result;
}
/** Unicode code-point order (the order Python sorts strings in), independent of host locale. */
export function compareCodePoints(a: string, b: string): number {
  let left = 0,
    right = 0;
  while (left < a.length && right < b.length) {
    const ac = a.codePointAt(left)!,
      bc = b.codePointAt(right)!;
    if (ac !== bc) return ac - bc;
    left += ac > 0xffff ? 2 : 1;
    right += bc > 0xffff ? 2 : 1;
  }
  return a.length - left - (b.length - right);
}
const S3_ARN = /^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:\/(.*))?$/;
/**
 * The bucket and object key of an S3 ARN, or null when it is not one. `key` is undefined for
 * a bare bucket ARN and may be empty for one that ends in a slash.
 */
export function parseS3Arn(arn: unknown): { readonly bucket: string; readonly key: string | undefined } | null {
  const match = S3_ARN.exec(typeof arn === 'string' ? arn : '');
  return match ? { bucket: match[1]!, key: match[2] } : null;
}
/** The bucket name of an S3 bucket or object ARN, or null. */
export const s3BucketName = (arn: unknown): string | null => parseS3Arn(arn)?.bucket ?? null;

export const LIST_SHORTENED = 'bucket_list_shortened';
/**
 * An identity-scope record with its bucket list cut to `keep` entries. Only the list changes:
 * the status came from the full comparison and stands.
 */
export function shortenScopeList(record: MapIdentityScope, keep: number): MapIdentityScope {
  if (record.extraResources.length <= keep) return record;
  return {
    ...record,
    extraResources: record.extraResources.slice(0, keep),
    truncated: true,
    notes: record.notes?.includes(LIST_SHORTENED) ? record.notes : [...(record.notes ?? []), LIST_SHORTENED],
  };
}

/** Adjacency over one projection's nodes and edges, in projection order. */
export interface GraphIndex {
  readonly nodes: Map<string, MapNode>;
  /** Positions of each node ID in the node list, so subgraphs keep projection order. */
  readonly nodePositions: Map<string, number[]>;
  /** Positions of each source's edges in the edge list. */
  readonly edgesFrom: Map<string, number[]>;
  readonly outgoing: Map<string, Map<MapEdge['kind'], string[]>>;
  readonly incoming: Map<string, Map<MapEdge['kind'], string[]>>;
}
/** Builds the index in one pass; callers account for the work themselves. */
export function buildGraphIndex(nodes: readonly MapNode[], edges: readonly MapEdge[]): GraphIndex {
  const result: GraphIndex = {
    nodes: new Map(),
    nodePositions: new Map(),
    edgesFrom: new Map(),
    outgoing: new Map(),
    incoming: new Map(),
  };
  const push = (map: Map<string, number[]>, key: string, position: number): void => {
    const list = map.get(key);
    if (list) list.push(position);
    else map.set(key, [position]);
  };
  nodes.forEach((node, position) => {
    result.nodes.set(node.id, node);
    push(result.nodePositions, node.id, position);
  });
  const add = (map: GraphIndex['outgoing'], from: string, kind: MapEdge['kind'], to: string): void => {
    let kinds = map.get(from);
    if (!kinds) {
      kinds = new Map();
      map.set(from, kinds);
    }
    const items = kinds.get(kind);
    if (items) items.push(to);
    else kinds.set(kind, [to]);
  };
  edges.forEach((edge, position) => {
    push(result.edgesFrom, edge.source, position);
    add(result.outgoing, edge.source, edge.kind, edge.target);
    add(result.incoming, edge.target, edge.kind, edge.source);
  });
  return result;
}
