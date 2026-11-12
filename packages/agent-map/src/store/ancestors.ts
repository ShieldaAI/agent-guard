import neo4j from 'neo4j-driver';
import { MapQueryError, type MapEdge, type MapNode, type MapSource } from '../types.js';
import { safeNode, text } from './nodes.js';
import { ANCESTOR_TASKS, ANCESTORS, EDGES } from './queries.js';
import { StoreRead } from './read.js';

/**
 * Delegation ancestors last, after every source's own nodes and edges, so they never crowd out
 * an agent's own evidence: each source's ancestors are added only if they fit what is left of
 * the node, edge and byte budgets (keeping a quarter of the bytes for evidence). Otherwise none
 * are added and the projection says so.
 */
export async function loadAncestors(read: StoreRead, sources: MapSource[]): Promise<void> {
  const { accessMode } = read;
  for (const job of read.ancestorJobs) {
    const index = sources.findIndex(item => item.id === job.sourceId);
    const current = sources[index]!.current;
    const loaded = new Set(current.nodes.map(node => node.id));
    const entities = new Set(current.nodes.map(node => node.entityId));
    const nodeRoom = read.limits.nodes - read.nodeCount;
    const found: string[] = [];
    const foundIds = new Set<string>();
    await read.run(
      ANCESTORS[accessMode]!,
      {
        ...job.params,
        GuardDeploymentIds: current.nodes.filter(node => node.label === 'GuardDeployment').map(node => node.id),
        nodeLimit: neo4j.int(read.limits.nodes + 1),
      },
      item => {
        const ancestor = text(item.get('id'));
        if (!loaded.has(ancestor) && !foundIds.has(ancestor) && found.length <= nodeRoom) {
          foundIds.add(ancestor);
          found.push(ancestor);
        }
      },
    );
    let notLoaded = found.length > nodeRoom;
    const records: MapNode[] = [],
      extra: MapEdge[] = [];
    if (!notLoaded && found.length) {
      const requested = new Set(found);
      await read.run(
        ANCESTOR_TASKS,
        { ...job.params, ancestorTaskIds: found, nodeLimit: neo4j.int(found.length + 1) },
        item => {
          if (item.get('label') !== 'GuardTask') throw new MapQueryError('MAP_UNAVAILABLE');
          const node = safeNode(item.get('node'), 'GuardTask', job.sourceId, current.id);
          // Each requested id once: a second node with the same id is malformed.
          if (!requested.delete(node.id) || entities.has(node.entityId)) throw new MapQueryError('MAP_UNAVAILABLE');
          entities.add(node.entityId);
          records.push(node);
        },
      );
      // Only delegation and handoff edges touch ancestors (their grants and deployments
      // are not read).
      const ancestorSet = new Set(records.map(node => node.id));
      const taskIds = [
        ...current.nodes.filter(node => node.label === 'GuardTask').map(node => node.id),
        ...ancestorSet,
      ];
      const tasks = new Set(taskIds);
      const edgeRoom = read.limits.edges - read.edgeCount;
      await read.run(
        EDGES,
        {
          ...job.params,
          nodeIds: taskIds,
          relationships: ['G_DELEGATED_FROM', 'G_DERIVED_FROM'],
          edgeLimit: neo4j.int(read.limits.edges + 1),
        },
        item => {
          const source = text(item.get('source')),
            target = text(item.get('target'));
          const kind = item.get('kind');
          if ((kind !== 'G_DELEGATED_FROM' && kind !== 'G_DERIVED_FROM') || !tasks.has(source) || !tasks.has(target))
            throw new MapQueryError('MAP_UNAVAILABLE');
          if (!ancestorSet.has(source) && !ancestorSet.has(target)) return;
          if (extra.length <= edgeRoom) extra.push({ source, target, kind });
        },
      );
      const bytes = Buffer.byteLength(JSON.stringify([records, extra]), 'utf8');
      notLoaded = extra.length > edgeRoom || read.materializedBytes + bytes > read.limits.bytes * 0.75;
      if (!notLoaded) {
        read.charge([records, extra]);
        read.nodeCount += records.length;
        read.edgeCount += extra.length;
      }
    }
    sources[index] = {
      ...sources[index]!,
      current: notLoaded
        ? { ...current, ancestorsNotLoaded: true }
        : { ...current, nodes: [...current.nodes, ...records], edges: [...current.edges, ...extra] },
    };
  }
}
