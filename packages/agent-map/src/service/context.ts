import type { JsonObject, MapReadRequest, MapView, ReadScope } from '../types.js';
import type { QueryArguments } from './schemas.js';
import type { FocusedGraph } from './summaries.js';
import { number, QueryWork, string } from './work.js';

/** What every operation handler is given: the validated request, the clock and the bounded reads. */
export interface OperationContext {
  readonly scope: ReadScope;
  readonly args: QueryArguments;
  /** The service clock at the start of the query, in milliseconds. */
  readonly now: number;
  readonly work: QueryWork;
  /** The response byte limit; separate work budgets are sized from it. */
  readonly maxBytes: number;
  readonly staleSeconds: number;
  /** One store read under this query's scope, with the query timeout unless a shorter one is given. */
  read(request: MapReadRequest, timeout?: number): Promise<MapView>;
}
export interface OperationResult {
  data: JsonObject;
  /** Only get_agent_access returns a graph; the service drops it when it is too large. */
  graph?: FocusedGraph;
}
export interface Operation {
  /**
   * The read the service runs before the handler, or null when the handler plans its own
   * reads. It also refuses argument combinations that no read could answer.
   */
  request(args: QueryArguments): MapReadRequest | null;
  run(context: OperationContext, view: MapView): OperationResult | Promise<OperationResult>;
}
export const sourceSelection = (args: QueryArguments): { sourceId?: string } =>
  args.sourceId ? { sourceId: args.sourceId as string } : {};
