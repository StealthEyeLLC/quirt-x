export const QUIRT_CONTRACT_SCHEMA_VERSION = "1.0.0" as const;
export const QUIRT_CONTRACT_VERSION = "1.0.0" as const;
export const QES2_PROTOCOL_SPEC_VERSION = "1.0.0" as const;
export const QES2_PROTOCOL_SPEC_STATUS = "FROZEN_FOR_Q2_IMPLEMENTATION" as const;

export const QUIRT_OWNER_SUBJECT = "stealtheye-owner" as const;
export const QUIRT_OWNER_AUTHORITY_CLASS = "unrestricted-owner" as const;

export const QUIRT_SOCKET_PATH = "/run/horsey/quirt.sock" as const;
export const QUIRT_SOCKET_OWNER = "root" as const;
export const QUIRT_SOCKET_GROUP = "horsey" as const;
export const QUIRT_SOCKET_MODE = "0660" as const;
export const QUIRT_DAEMON_UID = 0 as const;

export const QUIRT_STATE_ROOT = "/var/lib/stealtheye-quirt" as const;
export const QUIRT_CONFIG_ROOT = "/etc/stealtheye-quirt" as const;
export const QUIRT_RELEASE_ROOT = "/opt/stealtheye-quirt" as const;

export const QUIRT_PROGRAM_STATUSES = Object.freeze([
  "planned",
  "source in progress",
  "source complete",
  "validated",
  "release complete",
  "deployed",
  "production accepted",
  "blocked",
  "explicitly removed by Jamie"
] as const);
export type QuirtProgramStatus = typeof QUIRT_PROGRAM_STATUSES[number];

export const QUIRT_PROVIDER_LIFECYCLE_VERBS = Object.freeze([
  "discover", "install", "configure", "connect", "health", "capabilities",
  "execute", "observe", "upgrade", "repair", "disable", "remove", "fallback"
] as const);

export const QUIRT_REPAIR_LEVELS = Object.freeze([
  "observe", "retry", "reconnect", "restart_component", "reconcile",
  "repair_local_state", "provider_fallback", "skill_repair", "release_rollback",
  "rescue", "external_limitation"
] as const);

export const QUIRT_DEPRECATION_STATES = Object.freeze([
  "active", "deprecated", "migration_available", "disabled_by_default", "removed"
] as const);

export const QUIRT_ABI_VERSIONS = Object.freeze({
  contract: QUIRT_CONTRACT_VERSION,
  wireProtocol: "1.0.0",
  operationDescriptor: "1.0.0",
  stateSchema: "1.0.0",
  providerAbi: "1.0.0",
  skillAbi: "1.0.0",
  receiptSchema: "1.0.0",
  releaseContract: "1.0.0",
  auditSchema: "1.0.0",
  extensionAbi: "1.0.0"
} as const);

export const QUIRT_STATE_SUBPATHS = Object.freeze([
  "sessions", "jobs", "streams", "transfers", "recordings", "snapshots",
  "repositories", "credentials", "tunnels", "browsers", "providers", "skills",
  "capabilities", "repairs", "releases", "artifacts", "receipts", "backups",
  "quarantine", "state.sqlite"
] as const);

export const QUIRT_CONFIG_FILES = Object.freeze([
  "quirt.json", "providers.json", "trusted-authority.json",
  "compatibility.json", "release-policy.json"
] as const);

export const QUIRT_PRODUCT = Object.freeze({
  name: "StealthEye Horsey / Quirt-X",
  repository: "StealthEyeLLC/quirt-x",
  ownerSubject: QUIRT_OWNER_SUBJECT,
  authorityClass: QUIRT_OWNER_AUTHORITY_CLASS
} as const);

export type QuirtImplementationOwner = "Horsey" | "Neigh" | "Fix" | "Quirt";

export interface QuirtOperationDescriptor {
  readonly operationId: string;
  readonly operationVersion: string;
  readonly title: string;
  readonly summary: string;
  readonly owner: typeof QUIRT_OWNER_SUBJECT;
  readonly implementationModule: string;
  readonly providerId: string;
  readonly capabilityIds: readonly string[];
  readonly inputSchemaRef: string;
  readonly outputSchemaRef: string;
  readonly binaryInputSupport: boolean;
  readonly binaryOutputSupport: boolean;
  readonly streamingMode: "none" | "bounded" | "event";
  readonly executionClass: "immediate" | "durable";
  readonly idempotencyBehavior: string;
  readonly duplicateRequestBehavior: string;
  readonly cancellationBehavior: string;
  readonly timeoutBehavior: string;
  readonly sideEffectClass: string;
  readonly reversibility: string;
  readonly rollbackMethod: string;
  readonly verificationMethod: string;
  readonly receiptRequirements: string;
  readonly secretReferenceBehavior: string;
  readonly networkExposure: string;
  readonly dataExposure: string;
  readonly availabilityState: QuirtProgramStatus;
  readonly healthBehavior: string;
  readonly implementationStatus: QuirtProgramStatus;
  readonly deprecationState: typeof QUIRT_DEPRECATION_STATES[number];
}

export interface QuirtProviderDescriptor {
  readonly providerId: string;
  readonly semanticVersion: string;
  readonly providerFamily: string;
  readonly implementationModule: string;
  readonly installationState: QuirtProgramStatus;
  readonly executableVersion: string | null;
  readonly supportedOperations: readonly string[];
  readonly requiredHostCapabilities: readonly string[];
  readonly requiredKernelCapabilities: readonly string[];
  readonly requiredConfiguration: readonly string[];
  readonly authenticationNeeds: readonly string[];
  readonly secretReferences: readonly string[];
  readonly dataDirectories: readonly string[];
  readonly activeInstanceModel: string;
  readonly healthModel: string;
  readonly currentLimitations: readonly string[];
  readonly fallbackChain: readonly string[];
  readonly installationMethod: string;
  readonly upgradeMethod: string;
  readonly repairMethod: string;
  readonly disableMethod: string;
  readonly removalMethod: string;
  readonly reversibility: string;
  readonly rollbackMethod: string;
  readonly verificationMethod: string;
  readonly cost: string;
  readonly networkExposure: string;
  readonly dataExposure: string;
  readonly license: string;
  readonly sourceRepository: string;
  readonly sourceVersion: string;
  readonly sourceDigestRule: string;
  readonly implementationStatus: QuirtProgramStatus;
  readonly lifecycleVerbs: readonly string[];
}

export interface QuirtCapabilityDescriptor {
  readonly capabilityId: string;
  readonly semanticVersion: string;
  readonly humanName: string;
  readonly description: string;
  readonly owner: typeof QUIRT_OWNER_SUBJECT;
  readonly implementationOwner: QuirtImplementationOwner;
  readonly providerId: string | null;
  readonly operations: readonly string[];
  readonly operationSchemas: readonly string[];
  readonly availability: QuirtProgramStatus;
  readonly health: string;
  readonly installationMethod: string;
  readonly authenticationNeeds: readonly string[];
  readonly secretReferences: readonly string[];
  readonly profile: string | null;
  readonly driver: string | null;
  readonly reversibility: string;
  readonly rollbackMethod: string;
  readonly verificationMethod: string;
  readonly cost: string;
  readonly networkExposure: string;
  readonly dataExposure: string;
  readonly license: string;
  readonly sourceProvenance: string;
  readonly implementationStatus: QuirtProgramStatus;
  readonly limitations: readonly string[];
  readonly dependencyCapabilityIds: readonly string[];
  readonly fallbackCapabilityIds: readonly string[];
}

export interface QuirtConformanceEntry {
  readonly area: string;
  readonly targetContract: string;
  readonly currentSourceBehavior: string;
  readonly implementationStatus: QuirtProgramStatus;
  readonly firstPlannedPhase: string;
  readonly evidence: string;
  readonly knownGap: string;
  readonly acceptableInQ1: boolean;
}

export interface QuirtPhaseStatus {
  readonly phase: string;
  readonly status: QuirtProgramStatus;
  readonly notes: string;
}

export interface QuirtAuthorityContract {
  readonly ownerSubject: typeof QUIRT_OWNER_SUBJECT;
  readonly authorityClass: typeof QUIRT_OWNER_AUTHORITY_CLASS;
  readonly issuerMatching: "exact_required";
  readonly subjectMatching: "exact_required";
  readonly authorityClassMatching: "exact_required";
  readonly beforeAuthentication: readonly string[];
  readonly afterAuthentication: readonly string[];
  readonly prohibitedAuthorization: readonly string[];
  readonly securityMechanisms: readonly string[];
  readonly unknownOperationBehavior: string;
  readonly futureOperationInheritance: string;
}

export interface QuirtProtocolContract {
  readonly specification: "QES-2";
  readonly version: typeof QES2_PROTOCOL_SPEC_VERSION;
  readonly status: typeof QES2_PROTOCOL_SPEC_STATUS;
  readonly versions: typeof QUIRT_ABI_VERSIONS;
  readonly currentRuntimeSignatureAlgorithm: "ed25519" | "hmac-sha256";
  readonly targetSignatureAlgorithm: "ed25519";
  readonly q1CryptographicConformance: "target_contract_frozen_runtime_migration_planned_q2" | "q2_ed25519_runtime_implemented_with_explicit_hmac_compatibility";
  readonly publicRootListener: false;
  readonly activeMcpServer: false;
  readonly activeOAuthServer: false;
}

export interface QuirtPathContract {
  readonly socket: {
    readonly path: typeof QUIRT_SOCKET_PATH;
    readonly owner: typeof QUIRT_SOCKET_OWNER;
    readonly group: typeof QUIRT_SOCKET_GROUP;
    readonly mode: typeof QUIRT_SOCKET_MODE;
    readonly persistence: "ephemeral_runtime";
    readonly publicListener: false;
  };
  readonly stateRoot: typeof QUIRT_STATE_ROOT;
  readonly stateSubpaths: typeof QUIRT_STATE_SUBPATHS;
  readonly configRoot: typeof QUIRT_CONFIG_ROOT;
  readonly configFiles: typeof QUIRT_CONFIG_FILES;
  readonly releaseRoot: typeof QUIRT_RELEASE_ROOT;
  readonly daemonUid: typeof QUIRT_DAEMON_UID;
}

export interface QuirtProgramStatusRegistry {
  readonly statusTaxonomy: readonly QuirtProgramStatus[];
  readonly phases: readonly QuirtPhaseStatus[];
}

export interface QuirtContractBundle {
  readonly schemaVersion: typeof QUIRT_CONTRACT_SCHEMA_VERSION;
  readonly contractVersion: typeof QUIRT_CONTRACT_VERSION;
  readonly product: typeof QUIRT_PRODUCT;
  readonly architecture: Record<string, unknown>;
  readonly authority: QuirtAuthorityContract;
  readonly protocol: QuirtProtocolContract;
  readonly operations: readonly QuirtOperationDescriptor[];
  readonly providers: readonly QuirtProviderDescriptor[];
  readonly capabilities: readonly QuirtCapabilityDescriptor[];
  readonly skills: Record<string, unknown>;
  readonly repair: Record<string, unknown>;
  readonly release: Record<string, unknown>;
  readonly update: Record<string, unknown>;
  readonly rollback: Record<string, unknown>;
  readonly rescue: Record<string, unknown>;
  readonly paths: QuirtPathContract;
  readonly audit: Record<string, unknown>;
  readonly receipt: Record<string, unknown>;
  readonly compatibility: Record<string, unknown>;
  readonly deprecation: Record<string, unknown>;
  readonly migrations: Record<string, unknown>;
  readonly extensionAbi: Record<string, unknown>;
  readonly statusTaxonomy: QuirtProgramStatusRegistry;
  readonly conformance: readonly QuirtConformanceEntry[];
  readonly extensions: Record<string, unknown>;
}

export type QuirtSkillContract = Record<string, unknown>;
export type QuirtRepairContract = Record<string, unknown>;
export type QuirtReleaseContract = Record<string, unknown>;
export type QuirtUpdateContract = Record<string, unknown>;
export type QuirtRollbackContract = Record<string, unknown>;
export type QuirtRescueContract = Record<string, unknown>;
export type QuirtAuditEventContract = Record<string, unknown>;
export type QuirtReceiptContract = Record<string, unknown>;
export type QuirtCompatibilityContract = Record<string, unknown>;
export type QuirtDeprecationContract = Record<string, unknown>;
export type QuirtMigrationContract = Record<string, unknown>;
export type QuirtExtensionContract = Record<string, unknown>;
