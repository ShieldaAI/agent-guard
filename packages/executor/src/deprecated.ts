/**
 * Deprecated root aliases for exports that moved to subpaths in 0.2. They keep 0.1
 * imports working for one minor release and are removed in 0.3.
 */
import * as sandbox from './entry-sandbox.js';
import * as inventory from './entry-inventory.js';
import * as pilot from './entry-pilot.js';
import * as ops from './entry-ops.js';
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const ArtifactBroker = sandbox.ArtifactBroker;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type ArtifactBroker = sandbox.ArtifactBroker;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const runGovernedSandbox = sandbox.runGovernedSandbox;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const createSandboxTool = sandbox.createSandboxTool;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type ArtifactSensitivity = sandbox.ArtifactSensitivity;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type ArtifactPayload = sandbox.ArtifactPayload;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type SignedArtifactEnvelope = sandbox.SignedArtifactEnvelope;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type ArtifactInput = sandbox.ArtifactInput;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type GovernedSandboxResult = sandbox.GovernedSandboxResult;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type GovernedSandboxOptions = sandbox.GovernedSandboxOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type SandboxToolOptions = sandbox.SandboxToolOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type BuildArtifactPolicy = sandbox.BuildArtifactPolicy;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type BuildArtifactRule = sandbox.BuildArtifactRule;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type BuildAttestationEnvelope = sandbox.BuildAttestationEnvelope;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type BuildProvenanceEvidence = sandbox.BuildProvenanceEvidence;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const validateSandboxProfile = sandbox.validateSandboxProfile;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const buildDockerCreateArgs = sandbox.buildDockerCreateArgs;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const runDockerSandbox = sandbox.runDockerSandbox;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const readSandboxArchive = sandbox.readSandboxArchive;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export const writeReviewedExports = sandbox.writeReviewedExports;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type SandboxProfile = sandbox.SandboxProfile;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type ValidatedSandboxProfile = sandbox.ValidatedSandboxProfile;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type SandboxExport = sandbox.SandboxExport;
/** @deprecated Import from `@shieldaai/agent-guard-executor/sandbox`; this root alias is removed in 0.3. */
export type SandboxResult = sandbox.SandboxResult;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const startInventoryServer = inventory.startInventoryServer;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const createInventoryObserverToken = inventory.createInventoryObserverToken;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryServerOptions = inventory.InventoryServerOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryObserverCredential = inventory.InventoryObserverCredential;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const validateInventoryManifest = inventory.validateInventoryManifest;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const composeInventorySnapshot = inventory.composeInventorySnapshot;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifest = inventory.InventoryManifest;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type HostInventorySnapshot = inventory.HostInventorySnapshot;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryAwsReference = inventory.InventoryAwsReference;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryAwsResourceReference = inventory.InventoryAwsResourceReference;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestAgent = inventory.InventoryManifestAgent;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestDeployment = inventory.InventoryManifestDeployment;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestTaskBinding = inventory.InventoryManifestTaskBinding;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestResourceBinding = inventory.InventoryManifestResourceBinding;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestExecutionBinding = inventory.InventoryManifestExecutionBinding;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestV1 = inventory.InventoryManifestV1;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestV2 = inventory.InventoryManifestV2;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryOwnershipStatus = inventory.InventoryOwnershipStatus;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryOwner = inventory.InventoryOwner;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryCredentialReference = inventory.InventoryCredentialReference;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryHostResourceReference = inventory.InventoryHostResourceReference;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestAgentV2 = inventory.InventoryManifestAgentV2;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestDeploymentV2 = inventory.InventoryManifestDeploymentV2;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryManifestResourceBindingV2 = inventory.InventoryManifestResourceBindingV2;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const validateMcpConnectionInventory = inventory.validateMcpConnectionInventory;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const validateMcpInventorySources = inventory.validateMcpInventorySources;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export const composeMcpInventorySnapshot = inventory.composeMcpInventorySnapshot;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryMcpConnection = inventory.InventoryMcpConnection;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryMcpSourceBinding = inventory.InventoryMcpSourceBinding;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryMcpConnectionRecord = inventory.InventoryMcpConnectionRecord;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type McpInventorySnapshot = inventory.McpInventorySnapshot;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryScope = inventory.InventoryScope;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventorySnapshot = inventory.InventorySnapshot;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryBudget = inventory.InventoryBudget;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryGrant = inventory.InventoryGrant;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryTask = inventory.InventoryTask;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryTool = inventory.InventoryTool;
/** @deprecated Import from `@shieldaai/agent-guard-executor/inventory`; this root alias is removed in 0.3. */
export type InventoryUsage = inventory.InventoryUsage;
/** @deprecated Import from `@shieldaai/agent-guard-executor/pilot`; this root alias is removed in 0.3. */
export const verifyPilotReview = pilot.verifyPilotReview;
/** @deprecated Import from `@shieldaai/agent-guard-executor/pilot`; this root alias is removed in 0.3. */
export type PilotReviewPolicy = pilot.PilotReviewPolicy;
/** @deprecated Import from `@shieldaai/agent-guard-executor/pilot`; this root alias is removed in 0.3. */
export type PilotReviewBundle = pilot.PilotReviewBundle;
/** @deprecated Import from `@shieldaai/agent-guard-executor/pilot`; this root alias is removed in 0.3. */
export type PilotReviewResult = pilot.PilotReviewResult;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const createLedgerKeyring = ops.createLedgerKeyring;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const readLedgerKeyring = ops.readLedgerKeyring;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const readLedgerKeyringPolicy = ops.readLedgerKeyringPolicy;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const configureLedgerKeyring = ops.configureLedgerKeyring;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const loadLedgerKey = ops.loadLedgerKey;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const rotateLedgerKey = ops.rotateLedgerKey;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const rotateLedgerKeyring = ops.rotateLedgerKeyring;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerKey = ops.LedgerKey;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerKeyOptions = ops.LedgerKeyOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerKeyringPolicy = ops.LedgerKeyringPolicy;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerRotationResult = ops.LedgerRotationResult;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const manageLedgerCustody = ops.manageLedgerCustody;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerCustodyOptions = ops.LedgerCustodyOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type CustodyStore = ops.CustodyStore;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type CustodyHistoryAdapter = ops.CustodyHistoryAdapter;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type CustodyRequest = ops.CustodyRequest;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type CustodyResult = ops.CustodyResult;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export const manageLedgerRecovery = ops.manageLedgerRecovery;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerRecoveryOptions = ops.LedgerRecoveryOptions;
/** @deprecated Import from `@shieldaai/agent-guard-executor/ops`; this root alias is removed in 0.3. */
export type LedgerRecoveryResult = ops.LedgerRecoveryResult;
