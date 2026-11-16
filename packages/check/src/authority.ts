import { CAPABILITIES, type Agent, type Capability, type CapabilityState, type Grant } from './types.js';

/** What an agent can do for one capability, after headless agents lose their prompt-only paths. */
export function capabilityState(agent: Agent, capability: Capability): CapabilityState {
  const grants = agent.grants.filter(
    grant => grant.capability === capability && !(agent.headless && grant.approval === 'ask'),
  );
  const yes = grants.filter(grant => grant.certainty === 'yes');
  if (yes.length) return { value: 'yes', approval: yes.some(g => g.approval === 'auto') ? 'auto' : 'ask', grants: yes };
  if (grants.length)
    return { value: 'unknown', approval: grants.some(g => g.approval === 'auto') ? 'auto' : 'ask', grants };
  return { value: 'no', approval: null, grants: [] };
}

export function authority(agent: Agent): Record<Capability, CapabilityState> {
  const out = {} as Record<Capability, CapabilityState>;
  for (const capability of CAPABILITIES) out[capability] = capabilityState(agent, capability);
  return out;
}

/** The grant a fix should target: the first one that needs no approval, else the first one. */
export function primaryGrant(state: CapabilityState): Grant | undefined {
  return state.grants.find(grant => grant.approval === 'auto') ?? state.grants[0];
}

/** Ranks how much an agent can do, for diffs: 0 none, 1 unknown, 2 behind approval, 3 without approval. */
export function level(state: CapabilityState): number {
  if (state.value === 'no') return 0;
  if (state.value === 'unknown') return 1;
  return state.approval === 'auto' ? 3 : 2;
}

export function describeLevel(state: CapabilityState): string {
  if (state.value === 'no') return 'no';
  if (state.value === 'unknown') return 'unknown';
  return state.approval === 'auto' ? 'yes, no approval' : 'yes, with approval';
}
