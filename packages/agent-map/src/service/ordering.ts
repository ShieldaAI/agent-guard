import { compareCodePoints } from '../common.js';
import type { JsonObject, JsonValue } from '../types.js';
import { number, string } from './work.js';

export const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
// Sort keys compare field by field in Unicode code-point order, so "Reader" comes before
// "Reader 2" and paging is identical on every host and locale. Equal names fall back to the
// source and the stable id.
export const sortText = (value: JsonValue | undefined): string =>
  typeof value === 'string' ? value : value === null || value === undefined ? '' : JSON.stringify(value);
export function compareSortKeys(a: readonly string[], b: readonly string[]): number {
  for (let index = 0; index < a.length; index++) {
    const order = compareCodePoints(a[index]!, b[index]!);
    if (order) return order;
  }
  return 0;
}
/** Sorts in place by precomputed keys: each row's key is built once, not once per comparison. */
export function sortedBy<T extends object>(items: T[], key: (item: T) => readonly string[]): T[] {
  const keys = new Map(items.map(item => [item, key(item)]));
  return items.sort((a, b) => compareSortKeys(keys.get(a)!, keys.get(b)!));
}
// Unnamed agents sort last.
export const agentSortKey = (agent: JsonObject): readonly string[] => [
  agent.name === null || agent.name === undefined ? '1' : '0',
  sortText(agent.name),
  sortText(agent.sourceId),
  sortText(agent.id),
];
export function ordered(items: JsonObject[]): JsonObject[] {
  return sortedBy(items, item => [
    sortText(item.name ?? item.displayName),
    sortText(item.sourceId),
    sortText(item.id ?? item.entityId),
    sortText(item.source),
    sortText(item.target),
    sortText(item.kind),
  ]);
}
export function page(items: readonly JsonObject[], args: Readonly<Record<string, JsonValue>>): JsonObject {
  const offset = (args.offset as number | undefined) ?? 0,
    limit = (args.limit as number | undefined) ?? 50;
  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    offset,
    limit,
    truncated: offset + limit < items.length,
  };
}
