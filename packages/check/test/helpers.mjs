import { MemorySource, scan } from '@shieldaai/agent-guard-check';

/** Scans in-memory files. Synthetic content only. */
export function scanFiles(files, options = {}) {
  return scan({ root: '/repo', source: new MemorySource(files), ...options });
}

export function ruleIds(result) {
  return result.findings.map(finding => finding.ruleId);
}

export function findingsFor(result, ruleId) {
  return result.findings.filter(finding => finding.ruleId === ruleId);
}

export const json = value => JSON.stringify(value, null, 2);

export function settings(permissions = {}, extra = {}) {
  return json({ permissions, ...extra });
}

export function mcp(servers) {
  return json({ mcpServers: servers });
}

/** A synthetic token-shaped string that matches the GitHub pattern but is not a real credential. */
export const FAKE_GITHUB_TOKEN = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
