import { ExecutorError, type Ledger } from './store.js';

/**
 * Durable executor ledger format.
 *
 * Two independent markers describe a ledger:
 * - `schema` (1, 2 or 3) is the authority-mode marker that 0.1 readers already check:
 *   2 means lifecycle/history state may be present, 3 means a recovery mirror is enrolled.
 *   It stays as the fence that stops older readers from opening newer authority modes.
 * - `formatVersion` (this module) versions the ledger's data layout. Each step is a pure
 *   migration run at executor open, inside the exclusive startup transaction, so the
 *   witness and mirror are updated in the same commit.
 *
 * Compatibility policy: every 1.x executor opens every ledger written by 0.1.0-alpha.3 or
 * later and migrates it forward. Downgrade is never supported: a ledger with a newer
 * formatVersion than this build knows is refused with STORE_FORMAT_UNSUPPORTED.
 */
export const LEDGER_FORMAT_VERSION = 1;

export type LedgerFeature = 'key-custody' | 'custody-catalog' | 'lifecycle' | 'recovery-mirror' | 'retention';

/** Optional state that features add to a ledger. Derived, never trusted as authority. */
export function ledgerFeatures(state: Ledger): LedgerFeature[] {
  const features: LedgerFeature[] = [];
  if (typeof state.keyCustody === 'string') features.push('key-custody');
  if (state.custody !== undefined) features.push('custody-catalog');
  if (state.lifecycle !== undefined) features.push('lifecycle');
  if (state.recoveryMirror === 1) features.push('recovery-mirror');
  if (state.retention !== undefined) features.push('retention');
  return features;
}

/** One forward step. Pure: it only rewrites the given mutable state. */
interface Migration {
  readonly from: number;
  readonly to: number;
  readonly migrate: (state: Ledger) => void;
}

const migrations: readonly Migration[] = Object.freeze([
  {
    // 0.1.0-alpha.3 through 0.2 pre-release: no explicit version. Record it and the features.
    from: 0,
    to: 1,
    migrate: state => {
      state.formatVersion = 1;
      state.features = ledgerFeatures(state);
    },
  },
]);

function ledgerFormatVersion(state: Ledger): number {
  const version = state.formatVersion ?? 0;
  if (!Number.isSafeInteger(version) || version < 0) throw new ExecutorError('STORE_FORMAT_INVALID');
  return version;
}

/**
 * Runs every migration from the ledger's version to LEDGER_FORMAT_VERSION in order.
 * Returns the version it started from. Refuses a newer ledger without changing it.
 */
export function migrateLedger(state: Ledger): number {
  const start = ledgerFormatVersion(state);
  if (start > LEDGER_FORMAT_VERSION) throw new ExecutorError('STORE_FORMAT_UNSUPPORTED');
  for (let version = start; version < LEDGER_FORMAT_VERSION;) {
    const step = migrations.find(migration => migration.from === version);
    if (!step || step.to !== version + 1) throw new ExecutorError('STORE_FORMAT_UNSUPPORTED');
    step.migrate(state);
    version = step.to;
    if (ledgerFormatVersion(state) !== version) throw new ExecutorError('STORE_FORMAT_INVALID');
  }
  return start;
}

export interface LedgerFormat {
  readonly formatVersion: number;
  readonly schema: Ledger['schema'];
  readonly features: readonly LedgerFeature[];
}
export function describeLedgerFormat(state: Ledger): LedgerFormat {
  return Object.freeze({
    formatVersion: ledgerFormatVersion(state),
    schema: state.schema,
    features: Object.freeze(ledgerFeatures(state)),
  });
}
