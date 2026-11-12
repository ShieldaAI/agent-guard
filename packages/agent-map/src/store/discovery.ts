import neo4j from 'neo4j-driver';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { collectionKey } from '../policy-reader.js';
import {
  MAP_LABELS,
  MapQueryError,
  type MapCloudAccount,
  type MapSource,
  type MapUnclaimedIdentities,
  type MapUnclaimedIdentity,
  type MapUndeclaredActivity,
  type MapUndeclaredPrincipal,
  type MapUndeclaredTask,
  type MapView,
} from '../types.js';
import { converted, coreCaptureTimes, coverage, text } from './nodes.js';
import {
  AWS_COLLECTION_COLUMNS,
  AWS_COLLECTION_LIMIT,
  AWS_COLLECTIONS,
  AWS_MEMBER_LIMIT,
  BINDINGS_WITHOUT_IDENTITY,
  CLAIM_LIMIT,
  CLAIMED_IDENTITIES,
  UNCLAIMED_COUNTS,
  UNCLAIMED_PAGE,
  UNDECLARED_COUNT_LIMIT,
  UNDECLARED_COUNTS,
  UNDECLARED_PRINCIPALS,
  UNDECLARED_TASKS,
} from './queries.js';
import { StoreRead } from './read.js';

/**
 * Discovery reads load no nodes: fixed, bounded queries per source, then the same publication
 * recheck as every other read. `undeclared` counts (and pages) activity no declared agent
 * accounts for; `unclaimedIdentities` lists IAM roles and users no declared binding names.
 */
export async function readDiscovery(read: StoreRead): Promise<MapView> {
  const { scope, selection } = read;
  const malformed = (): never => {
    throw new MapQueryError('MAP_UNAVAILABLE');
  };
  const whole = (value: unknown, maximum: number): number => {
    const number = converted(value);
    return typeof number === 'number' && Number.isSafeInteger(number) && number >= 0 && number <= maximum
      ? number
      : malformed();
  };
  const flag = (value: unknown): boolean | null =>
    value === null || value === undefined ? null : typeof value === 'boolean' ? value : malformed();
  const page = selection.page;
  const listed: MapSource[] = [];
  const claimed = new Set<string>();
  let claimsExceeded = false;
  let bindingsWithoutIdentity = false;
  // The strictest enrolled cloud age per tenant, under the host ceiling.
  const maximumAges = new Map<string, number>();
  for (const record of read.selected) {
    const sourceId = text(record.get('id'));
    const tenantId = text(record.get('tenantId'));
    const currentId = text(record.get('currentId'));
    const profile = record.get('profile');
    if (!scope.tenantIds.includes(tenantId) || !['core', 'host', 'host-mcp'].includes(profile)) malformed();
    const params = { ...read.common, sourceId, tenantId, projectionId: currentId, labels: [...MAP_LABELS] };
    const captures = coreCaptureTimes(record.get('currentCoverage'));
    let undeclared: MapUndeclaredActivity | undefined;
    if (selection.undeclared === true) {
      const counts = await read.run(UNDECLARED_COUNTS, {
        ...params,
        countLimit: neo4j.int(UNDECLARED_COUNT_LIMIT + 1),
      });
      if (counts.length !== 1) malformed();
      const tasks = whole(counts[0]!.get('tasks'), UNDECLARED_COUNT_LIMIT + 1);
      const principals = whole(counts[0]!.get('principals'), UNDECLARED_COUNT_LIMIT + 1);
      let listing: MapUndeclaredActivity['page'];
      if (page !== undefined) {
        const paging = { ...params, pageOffset: neo4j.int(page.offset), pageLimit: neo4j.int(page.limit) };
        const seen = new Set<string>();
        // A second row for one entity is malformed, never a longer list.
        const once = (id: string): string => {
          if (seen.has(id)) malformed();
          seen.add(id);
          return id;
        };
        if (page.kind === 'tasks') {
          const items: MapUndeclaredTask[] = [];
          await read.run(UNDECLARED_TASKS, paging, item => {
            if (items.length >= page.limit) malformed();
            const tools = converted(item.get('tools'));
            if (!Array.isArray(tools) || tools.length > 33) malformed();
            const names = [...new Set((tools as unknown[]).map(tool => text(tool)))].sort();
            const principalId = item.get('principalId');
            const parentDeclared = item.get('parentDeclared');
            if (typeof parentDeclared !== 'boolean') malformed();
            const row: MapUndeclaredTask = {
              id: once(text(item.get('id'))),
              taskId: text(item.get('taskId')),
              principalId: principalId === null || principalId === undefined ? null : text(principalId),
              delegated: flag(item.get('delegated')),
              derived: flag(item.get('derived')),
              revoked: flag(item.get('revoked')),
              parentDeclared,
              tools: names.slice(0, 32),
              toolsTruncated: (tools as unknown[]).length > 32,
            };
            read.charge(row);
            items.push(row);
          });
          listing = { kind: 'tasks', items };
        } else {
          const items: MapUndeclaredPrincipal[] = [];
          await read.run(UNDECLARED_PRINCIPALS, paging, item => {
            if (items.length >= page.limit) malformed();
            const tasks = whole(item.get('tasks'), 1001);
            const row: MapUndeclaredPrincipal = {
              id: once(text(item.get('id'))),
              principalId: text(item.get('principalId')),
              tasks: Math.min(tasks, 1000),
              tasksCapped: tasks > 1000,
            };
            read.charge(row);
            items.push(row);
          });
          listing = { kind: 'principals', items };
        }
      }
      undeclared = {
        tasks: Math.min(tasks, UNDECLARED_COUNT_LIMIT),
        tasksCapped: tasks > UNDECLARED_COUNT_LIMIT,
        principals: Math.min(principals, UNDECLARED_COUNT_LIMIT),
        principalsCapped: principals > UNDECLARED_COUNT_LIMIT,
        ...(listing ? { page: listing } : {}),
      };
    } else {
      const enrolled = record.get('policyCoverage');
      if (enrolled !== null && enrolled !== undefined)
        maximumAges.set(
          tenantId,
          Math.min(maximumAges.get(tenantId) ?? read.limits.policyAge, read.maximumAgeFor(enrolled)),
        );
      if (!claimsExceeded)
        await read.run(
          CLAIMED_IDENTITIES,
          { ...params, claimLimit: neo4j.int(CLAIM_LIMIT - claimed.size + 1) },
          item => {
            const arn = item.get('arn');
            if (typeof arn !== 'string' || !arn || arn.length > 2048) malformed();
            claimed.add(arn);
            if (claimed.size > CLAIM_LIMIT) claimsExceeded = true;
          },
        );
      if (!bindingsWithoutIdentity) {
        const [open] = await read.run(BINDINGS_WITHOUT_IDENTITY, params);
        // Only an explicit "none" clears it.
        bindingsWithoutIdentity = open?.get('open') !== false;
      }
    }
    listed.push({
      id: sourceId,
      tenantId,
      sourceId: text(record.get('nativeSourceId')),
      profile,
      current: {
        id: currentId,
        snapshotId: text(record.get('currentSnapshotId')),
        generatedAt: text(record.get('currentGeneratedAt')),
        status: 'published',
        nodes: [],
        edges: [],
        // Only what this read rests on: when the tasks were captured.
        coverage: { tasks: { status: 'complete', ...(captures.tasks ? { observedAt: captures.tasks } : {}) } },
        ...(undeclared ? { undeclared } : {}),
      },
      previous: null,
    });
  }
  let unclaimedIdentities: MapUnclaimedIdentities | undefined;
  if (selection.unclaimedIdentities === true) {
    const readCollections = async (): Promise<Record<string, unknown>[]> =>
      (await read.run(AWS_COLLECTIONS, { ...read.common, collectionLimit: neo4j.int(AWS_COLLECTION_LIMIT + 1) })).map(
        item => Object.fromEntries(AWS_COLLECTION_COLUMNS.map(column => [column, converted(item.get(column))])),
      );
    const collections = await readCollections();
    if (collections.length > AWS_COLLECTION_LIMIT) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
    const stamp = read.now();
    const claims = [...claimed].sort();
    const accounts: MapCloudAccount[] = [];
    const complete = new Map<string, MapCloudAccount>();
    let total = 0;
    for (const collection of collections) {
      const { tenantId, partition, accountId, capturedAt } = collection;
      // Without these the account cannot even be named.
      if (
        typeof tenantId !== 'string' ||
        !scope.tenantIds.includes(tenantId) ||
        typeof partition !== 'string' ||
        !['aws', 'aws-cn', 'aws-us-gov'].includes(partition) ||
        typeof accountId !== 'string' ||
        !/^[0-9]{12}$/.test(accountId)
      ) {
        malformed();
        continue;
      }
      const account = (
        reason: MapCloudAccount['reason'],
        observedAt: string | null,
        counts: { observed: number; unclaimed: number } | null = null,
      ): MapCloudAccount => ({
        tenantId,
        partition,
        accountId,
        status: reason === null && counts ? 'complete' : 'unknown',
        reason,
        observedAt,
        observed: counts?.observed ?? null,
        unclaimed: counts?.unclaimed ?? null,
      });
      const id = collection.id;
      if (
        typeof id !== 'string' ||
        id !== collectionKey(scope.companyId, tenantId, partition, accountId) ||
        complete.has(id) ||
        collection.schemaVersion !== 1 ||
        collection.status !== 'complete' ||
        typeof collection.contentHash !== 'string' ||
        !/^[a-f0-9]{64}$/.test(collection.contentHash) ||
        typeof capturedAt !== 'number' ||
        !Number.isSafeInteger(capturedAt) ||
        capturedAt < 0 ||
        capturedAt > stamp
      ) {
        accounts.push(account('collection_invalid', null));
        continue;
      }
      const observedAt = new Date(capturedAt * 1000).toISOString();
      if (stamp - capturedAt > (maximumAges.get(tenantId) ?? read.limits.policyAge)) {
        accounts.push(account('stale', observedAt));
        continue;
      }
      // Without the full set of claims, "unclaimed" would overstate.
      if (claimsExceeded) {
        accounts.push(account('claims_limit_exceeded', observedAt));
        continue;
      }
      const counted = await read.run(UNCLAIMED_COUNTS, {
        ...read.common,
        collectionId: id,
        collectionTenantId: tenantId,
        claimed: claims,
        memberLimit: neo4j.int(AWS_MEMBER_LIMIT + 1),
      });
      if (counted.length !== 1) malformed();
      const observed = whole(counted[0]!.get('observed'), AWS_MEMBER_LIMIT + 1);
      const unclaimed = whole(counted[0]!.get('unclaimed') ?? 0, AWS_MEMBER_LIMIT + 1);
      const inconsistent = whole(counted[0]!.get('inconsistent') ?? 0, AWS_MEMBER_LIMIT + 1);
      if (observed > AWS_MEMBER_LIMIT) accounts.push(account('limit_exceeded', observedAt));
      else if (inconsistent) accounts.push(account('changed', observedAt));
      else {
        const judged = account(null, observedAt, { observed, unclaimed });
        accounts.push(judged);
        complete.set(id, judged);
        total += unclaimed;
      }
    }
    const identities: MapUnclaimedIdentity[] = [];
    if (page !== undefined && complete.size && page.offset < total)
      await read.run(
        UNCLAIMED_PAGE,
        {
          ...read.common,
          collectionIds: [...complete.keys()],
          claimed: claims,
          pageOffset: neo4j.int(page.offset),
          pageLimit: neo4j.int(page.limit),
        },
        item => {
          const account = complete.get(item.get('collectionId'));
          const arn = item.get('arn'),
            name = item.get('name'),
            path = item.get('path');
          const role = item.get('role'),
            user = item.get('user');
          // The same shape the collector accepted: one kind, and an ARN built from its parts.
          if (
            identities.length >= page.limit ||
            !account ||
            typeof role !== 'boolean' ||
            typeof user !== 'boolean' ||
            role === user ||
            typeof name !== 'string' ||
            !/^[A-Za-z0-9+=,.@_-]{1,128}$/.test(name) ||
            typeof path !== 'string' ||
            path.length > 512 ||
            !/^\/(?:[\x21-\x7e]+\/)?$/.test(path) ||
            arn !== `arn:${account.partition}:iam::${account.accountId}:${role ? 'role' : 'user'}${path}${name}` ||
            claimed.has(arn)
          ) {
            malformed();
            return;
          }
          const row: MapUnclaimedIdentity = {
            arn,
            kind: role ? 'role' : 'user',
            name,
            path,
            tenantId: account.tenantId,
            partition: account.partition,
            accountId: account.accountId,
          };
          read.charge(row);
          identities.push(row);
        },
      );
    // A collection published during the read would mix two captures.
    if (JSON.stringify(collections) !== JSON.stringify(await readCollections())) malformed();
    unclaimedIdentities = { accounts, identities, total, bindingsWithoutIdentity };
  }
  await read.recheckSources();
  try {
    return immutableJson(
      { sources: listed, ...(unclaimedIdentities ? { unclaimedIdentities } : {}) },
      16,
      200_000,
      4 * 1024 * 1024,
    ) as object as MapView;
  } catch {
    throw new MapQueryError('MAP_LIMIT_EXCEEDED');
  }
}
