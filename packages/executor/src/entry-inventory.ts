/**
 * Inventory observer, host manifest and MCP inventory composition: `@shieldaai/agent-guard-executor/inventory`.
 * Experimental: no admission-latency promise under frequent polling, and the API may change in a minor release.
 */
export {
  startInventoryServer,
  createInventoryObserverToken,
  type InventoryServerOptions,
  type InventoryObserverCredential,
} from './inventory-http.js';
export {
  validateInventoryManifest,
  composeInventorySnapshot,
  type InventoryManifest,
  type HostInventorySnapshot,
  type InventoryAwsReference,
  type InventoryAwsResourceReference,
  type InventoryManifestAgent,
  type InventoryManifestDeployment,
  type InventoryManifestTaskBinding,
  type InventoryManifestResourceBinding,
  type InventoryManifestExecutionBinding,
  type InventoryManifestV1,
  type InventoryManifestV2,
  type InventoryOwnershipStatus,
  type InventoryOwner,
  type InventoryCredentialReference,
  type InventoryHostResourceReference,
  type InventoryManifestAgentV2,
  type InventoryManifestDeploymentV2,
  type InventoryManifestResourceBindingV2,
} from './inventory-manifest.js';
export {
  validateMcpConnectionInventory,
  validateMcpInventorySources,
  composeMcpInventorySnapshot,
  type InventoryMcpConnection,
  type InventoryMcpSourceBinding,
  type InventoryMcpConnectionRecord,
  type McpInventorySnapshot,
} from './inventory-mcp.js';
export type {
  InventoryScope,
  InventorySnapshot,
  InventoryBudget,
  InventoryGrant,
  InventoryTask,
  InventoryTool,
  InventoryUsage,
} from './inventory.js';
