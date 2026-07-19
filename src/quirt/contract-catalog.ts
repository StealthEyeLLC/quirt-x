import {
  QUIRT_CORE_OPERATIONS,
  QUIRT_NATIVE_FOUNDATION_OPERATIONS,
  QUIRT_NATIVE_OPERATOR_OPERATIONS,
  QUIRT_OPERATIONS
} from "./catalog.js";
import {
  POWER_PROVIDER_DEFINITIONS,
  QUIRT_POWER_OPERATIONS,
  powerProviderForOperation,
  type PowerProviderDefinition
} from "./power-catalog.js";
import {
  QUIRT_ABI_VERSIONS,
  QUIRT_CONFIG_FILES,
  QUIRT_CONFIG_ROOT,
  QUIRT_CONTRACT_SCHEMA_VERSION,
  QUIRT_CONTRACT_VERSION,
  QUIRT_DAEMON_UID,
  QUIRT_DEPRECATION_STATES,
  QUIRT_OWNER_AUTHORITY_CLASS,
  QUIRT_OWNER_SUBJECT,
  QUIRT_PRODUCT,
  QUIRT_PROGRAM_STATUSES,
  QUIRT_PROVIDER_LIFECYCLE_VERBS,
  QUIRT_RELEASE_ROOT,
  QUIRT_REPAIR_LEVELS,
  QUIRT_SOCKET_GROUP,
  QUIRT_SOCKET_MODE,
  QUIRT_SOCKET_OWNER,
  QUIRT_SOCKET_PATH,
  QUIRT_STATE_ROOT,
  QUIRT_STATE_SUBPATHS,
  QES2_PROTOCOL_SPEC_STATUS,
  QES2_PROTOCOL_SPEC_VERSION,
  type QuirtAuthorityContract,
  type QuirtCapabilityDescriptor,
  type QuirtConformanceEntry,
  type QuirtContractBundle,
  type QuirtOperationDescriptor,
  type QuirtPathContract,
  type QuirtPhaseStatus,
  type QuirtProgramStatus,
  type QuirtProgramStatusRegistry,
  type QuirtProtocolContract,
  type QuirtProviderDescriptor
} from "./contract-types.js";

const OPERATION_VERSION = "1.0.0" as const;
const PROVIDER_MODULE = "src/quirt/power-provider.ts" as const;
const NATIVE_MODULE = "src/quirt/operations.ts" as const;

const PROVIDER_FAMILY_MAP: Readonly<Record<string, string>> = Object.freeze({
  "terminal.tmux": "terminal",
  "ide.code-server": "IDE",
  "preview.process": "preview",
  "browser.playwright": "browser",
  "sync.syncthing": "sync",
  "storage.rclone": "remote storage",
  "snapshot.restic": "snapshots",
  "network.linux": "network",
  "tunnel.openssh": "network",
  "trace.linux": "tracing",
  "checkpoint.criu": "checkpointing",
  "desktop.vnc": "desktop",
  "fleet.ssh": "fleet"
});

const PLANNED_PROVIDER_FAMILIES = Object.freeze([
  { providerId: "backup.planned", providerFamily: "backup", implementationStatus: "planned" as const },
  { providerId: "database.planned", providerFamily: "databases", implementationStatus: "planned" as const },
  { providerId: "hardware.planned", providerFamily: "hardware", implementationStatus: "planned" as const },
  { providerId: "container.planned", providerFamily: "container", implementationStatus: "planned" as const },
  { providerId: "wasi.planned", providerFamily: "WASI", implementationStatus: "planned" as const },
  { providerId: "vm.planned", providerFamily: "VM", implementationStatus: "planned" as const }
]);

function capabilityForOperation(operationId: string): string {
  const segment = operationId.split(".")[1] ?? "core";
  const map: Record<string, string> = {
    status: "quirt.core.status",
    capabilities: "quirt.core.capabilities",
    version: "quirt.core.version",
    exec: "quirt.core.exec",
    session: "quirt.session",
    job: "quirt.job",
    file: "quirt.files",
    directory: "quirt.directories",
    transfer: "quirt.transfers",
    git: "quirt.git",
    record: "quirt.recordings",
    process: "quirt.processes",
    pane: "quirt.terminal.panes",
    ide: "quirt.ide",
    browser: "quirt.browser",
    preview: "quirt.preview",
    sync: "quirt.sync",
    remote: "quirt.remote.storage",
    snapshot: "quirt.snapshots",
    network: "quirt.network",
    tunnel: "quirt.tunnels",
    trace: "quirt.tracing",
    checkpoint: "quirt.checkpointing",
    desktop: "quirt.desktop",
    host: "quirt.fleet",
    fleet: "quirt.fleet"
  };
  return map[segment] ?? `quirt.${segment}`;
}

function operationDefaults(operationId: string): Pick<
  QuirtOperationDescriptor,
  | "binaryInputSupport" | "binaryOutputSupport" | "streamingMode" | "executionClass"
  | "idempotencyBehavior" | "duplicateRequestBehavior" | "cancellationBehavior" | "timeoutBehavior"
  | "sideEffectClass" | "reversibility" | "rollbackMethod" | "verificationMethod" | "receiptRequirements"
  | "secretReferenceBehavior" | "networkExposure" | "dataExposure" | "healthBehavior"
> {
  const readOnly = /^(quirt\.(status|capabilities|version|session\.(list|get|read)|job\.(list|get|read)|file\.(stat|read|search)|directory\.(list|watch)|transfer\.(read|status)|record\.(list|search|replay|export)|process\.(list|get|tree|namespaces)|.*\.(list|get|status|interfaces|routes|connections|listeners|firewall|follow|report|flamegraph|diff|repository|port|screenshot|video|logs)))$/u.test(operationId);
  const binaryIn = /^(quirt\.(exec|session\.write|job\.input|file\.write|transfer\.write|.*\.upload))$/u.test(operationId);
  const binaryOut = /^(quirt\.(exec|session\.read|job\.read|file\.read|transfer\.read|.*\.(screenshot|video|download|capture|report|flamegraph|export)))$/u.test(operationId);
  const durable = /^(quirt\.(session\.|job\.|transfer\.|record\.|git\.|sync\.|remote\.|snapshot\.|tunnel\.|trace\.|checkpoint\.|desktop\.|fleet\.|host\.|pane\.|ide\.|browser\.|preview\.|network\.))/u.test(operationId);
  return {
    binaryInputSupport: binaryIn,
    binaryOutputSupport: binaryOut,
    streamingMode: /read|follow|attach|replay|capture/u.test(operationId) ? "bounded" : /event/u.test(operationId) ? "event" : "none",
    executionClass: durable ? "durable" : "immediate",
    idempotencyBehavior: readOnly ? "naturally_idempotent" : "semantic_idempotency_required_for_mutations",
    duplicateRequestBehavior: "replay_protected_by_nonce_and_request_hash",
    cancellationBehavior: /cancel|close|stop|remove|unmount/u.test(operationId) ? "explicit_cancellation_supported" : "request_abort_supported_where_applicable",
    timeoutBehavior: "no_default_owner_timeout_gate",
    sideEffectClass: readOnly ? "read_only" : "host_mutation_possible",
    reversibility: readOnly ? "naturally_reversible" : "operation_specific_rollback_or_compensation",
    rollbackMethod: readOnly ? "none_required" : "release_or_state_restore_as_applicable",
    verificationMethod: "post_operation_host_state_or_artifact_verification",
    receiptRequirements: "terminal_receipt_required_for_durable_mutations",
    secretReferenceBehavior: /credential|tunnel|remote|git|host|fleet|ide|desktop/u.test(operationId) ? "secret_reference_only_never_inline" : "none_by_default",
    networkExposure: /network|tunnel|remote|browser|ide|preview|desktop|fleet|host|sync|git/u.test(operationId) ? "may_use_private_network_paths" : "local_host_default",
    dataExposure: readOnly ? "bounded_metadata_and_declared_artifacts" : "bounded_metadata_with_optional_artifact_references",
    healthBehavior: "provider_or_native_health_probe_where_applicable"
  };
}

function titleForOperation(operationId: string): string {
  return operationId.replace(/^quirt\./u, "").replace(/\./gu, " / ");
}

function buildOperationDescriptor(operationId: string): QuirtOperationDescriptor {
  const isPower = (QUIRT_POWER_OPERATIONS as readonly string[]).includes(operationId);
  const provider = isPower ? powerProviderForOperation(operationId as never) : null;
  const defaults = operationDefaults(operationId);
  return Object.freeze({
    operationId,
    operationVersion: OPERATION_VERSION,
    title: titleForOperation(operationId),
    summary: isPower ? `${titleForOperation(operationId)} via ${provider!.providerId}` : `${titleForOperation(operationId)} via native Quirt`,
    owner: QUIRT_OWNER_SUBJECT,
    implementationModule: isPower ? PROVIDER_MODULE : NATIVE_MODULE,
    providerId: isPower ? provider!.providerId : "native",
    capabilityIds: Object.freeze([capabilityForOperation(operationId)]),
    inputSchemaRef: `schemas/operations/${operationId}.json`,
    outputSchemaRef: `schemas/operations/${operationId}.response.json`,
    ...defaults,
    availabilityState: "source complete",
    implementationStatus: isPower ? "source complete" : "source complete",
    deprecationState: "active"
  });
}

function providerDescriptor(definition: PowerProviderDefinition): QuirtProviderDescriptor {
  return Object.freeze({
    providerId: definition.providerId,
    semanticVersion: "1.0.0",
    providerFamily: PROVIDER_FAMILY_MAP[definition.providerId] ?? "container",
    implementationModule: `src/quirt/providers/${definition.providerId.split(".")[1] ?? "provider"}-provider.ts`,
    installationState: "source complete",
    executableVersion: definition.requiredExecutables[0]?.minimumVersion ?? null,
    supportedOperations: Object.freeze([...definition.operationIds]),
    requiredHostCapabilities: Object.freeze([...definition.requiredHostFeatures]),
    requiredKernelCapabilities: Object.freeze([...definition.requiredKernelFeatures]),
    requiredConfiguration: Object.freeze(Object.keys(definition.configurationSchema)),
    authenticationNeeds: Object.freeze(Object.keys(definition.credentialReferenceSchema).length > 0 ? ["secret_reference"] : []),
    secretReferences: Object.freeze(Object.keys(definition.credentialReferenceSchema)),
    dataDirectories: Object.freeze([`${QUIRT_STATE_ROOT}/providers/${definition.providerId}`]),
    activeInstanceModel: "durable_provider_instance_registry",
    healthModel: "process_identity_port_and_provider_specific_probes",
    currentLimitations: Object.freeze([...definition.limitations]),
    fallbackChain: Object.freeze(["native_cli", "root_pty", "package_installation"]),
    installationMethod: "host_package_or_release_binary",
    upgradeMethod: "provider_upgrade_with_state_migration",
    repairMethod: "graduated_repair_ladder",
    disableMethod: "provider_disable_without_removing_root_authority",
    removalMethod: "provider_remove_with_cleanup",
    reversibility: "provider_specific_with_release_rollback",
    rollbackMethod: "release_pointer_restore_and_provider_state_reconcile",
    verificationMethod: "health_probe_and_operation_smoke",
    cost: "host_resource_bound",
    networkExposure: definition.providerId.includes("network") || definition.providerId.includes("tunnel") || definition.providerId.includes("browser") ? "private_by_default" : "local_default",
    dataExposure: "bounded_metadata_and_declared_artifacts",
    license: "source_implementation_in_repository",
    sourceRepository: "StealthEyeLLC/quirt-x",
    sourceVersion: "standalone",
    sourceDigestRule: "release_archive_digest_binding",
    implementationStatus: "source complete",
    lifecycleVerbs: QUIRT_PROVIDER_LIFECYCLE_VERBS
  });
}

function plannedProviderDescriptor(entry: typeof PLANNED_PROVIDER_FAMILIES[number]): QuirtProviderDescriptor {
  return Object.freeze({
    providerId: entry.providerId,
    semanticVersion: "0.0.0",
    providerFamily: entry.providerFamily,
    implementationModule: "planned",
    installationState: "planned",
    executableVersion: null,
    supportedOperations: Object.freeze([]),
    requiredHostCapabilities: Object.freeze([]),
    requiredKernelCapabilities: Object.freeze([]),
    requiredConfiguration: Object.freeze([]),
    authenticationNeeds: Object.freeze([]),
    secretReferences: Object.freeze([]),
    dataDirectories: Object.freeze([]),
    activeInstanceModel: "planned",
    healthModel: "planned",
    currentLimitations: Object.freeze(["not_implemented_in_q1"]),
    fallbackChain: Object.freeze(["native_cli", "root_pty"]),
    installationMethod: "planned",
    upgradeMethod: "planned",
    repairMethod: "planned",
    disableMethod: "planned",
    removalMethod: "planned",
    reversibility: "planned",
    rollbackMethod: "planned",
    verificationMethod: "planned",
    cost: "planned",
    networkExposure: "planned",
    dataExposure: "planned",
    license: "planned",
    sourceRepository: "StealthEyeLLC/quirt-x",
    sourceVersion: "planned",
    sourceDigestRule: "planned",
    implementationStatus: entry.implementationStatus,
    lifecycleVerbs: QUIRT_PROVIDER_LIFECYCLE_VERBS
  });
}

function buildCapabilityDescriptors(
  operations: readonly QuirtOperationDescriptor[],
  providers: readonly QuirtProviderDescriptor[]
): QuirtCapabilityDescriptor[] {
  const byCapability = new Map<string, { operations: string[]; providerId: string | null }>();
  for (const operation of operations) {
    const capabilityId = operation.capabilityIds[0]!;
    const current = byCapability.get(capabilityId) ?? { operations: [], providerId: operation.providerId === "native" ? null : operation.providerId };
    current.operations.push(operation.operationId);
    if (operation.providerId !== "native") current.providerId = operation.providerId;
    byCapability.set(capabilityId, current);
  }
  const descriptors: QuirtCapabilityDescriptor[] = [];
  for (const [capabilityId, value] of [...byCapability.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const provider = value.providerId === null ? null : providers.find((item) => item.providerId === value.providerId) ?? null;
    descriptors.push(Object.freeze({
      capabilityId,
      semanticVersion: "1.0.0",
      humanName: capabilityId.replace(/^quirt\./u, "").replace(/\./gu, " "),
      description: `Capability graph node for ${capabilityId}`,
      owner: QUIRT_OWNER_SUBJECT,
      implementationOwner: "Quirt",
      providerId: value.providerId,
      operations: Object.freeze([...value.operations].sort()),
      operationSchemas: Object.freeze(value.operations.map((operationId) => `schemas/operations/${operationId}.json`).sort()),
      availability: provider?.implementationStatus ?? "source complete",
      health: provider?.healthModel ?? "native_health_probe",
      installationMethod: provider?.installationMethod ?? "native_runtime",
      authenticationNeeds: provider?.authenticationNeeds ?? [],
      secretReferences: provider?.secretReferences ?? [],
      profile: null,
      driver: null,
      reversibility: provider?.reversibility ?? "operation_specific",
      rollbackMethod: provider?.rollbackMethod ?? "release_or_state_restore",
      verificationMethod: provider?.verificationMethod ?? "operation_smoke",
      cost: provider?.cost ?? "host_resource_bound",
      networkExposure: provider?.networkExposure ?? "local_default",
      dataExposure: provider?.dataExposure ?? "bounded_metadata",
      license: "StealthEyeLLC/quirt-x",
      sourceProvenance: "StealthEyeLLC/quirt-x standalone source",
      implementationStatus: provider?.implementationStatus ?? "source complete",
      limitations: provider?.currentLimitations ?? [],
      dependencyCapabilityIds: capabilityId === "quirt.core.exec" ? Object.freeze([]) : Object.freeze(["quirt.core.exec"]),
      fallbackCapabilityIds: capabilityId === "quirt.core.exec" ? Object.freeze([]) : Object.freeze(["quirt.core.exec"])
    }));
  }
  return descriptors;
}

function buildAuthorityContract(): QuirtAuthorityContract {
  return Object.freeze({
    ownerSubject: QUIRT_OWNER_SUBJECT,
    authorityClass: QUIRT_OWNER_AUTHORITY_CLASS,
    issuerMatching: "exact_required",
    subjectMatching: "exact_required",
    authorityClassMatching: "exact_required",
    beforeAuthentication: Object.freeze([
      "no_operation_dispatch", "no_skill_activation", "no_provider_execution",
      "no_session_attachment", "no_file_access", "no_raw_execution", "no_capability_mutation"
    ]),
    afterAuthentication: Object.freeze([
      "every_registered_operation_available", "future_operations_inherit_owner_authority",
      "arbitrary_executable_execution", "arbitrary_shell_execution", "arbitrary_host_path_access",
      "arbitrary_network_and_service_control", "arbitrary_package_installation", "raw_pty_authority"
    ]),
    prohibitedAuthorization: Object.freeze([
      "command_allowlists", "executable_allowlists", "argument_allowlists", "path_allowlists",
      "repository_restrictions", "workspace_requirements", "provider_permission_gates",
      "per_operation_grants", "mandatory_plan_apply", "routine_confirmations", "mandatory_dry_runs", "default_timeouts"
    ]),
    securityMechanisms: Object.freeze([
      "exact_issuer", "exact_subject", "authority_class", "signatures", "canonical_encoding",
      "nonces", "replay_protection", "peer_credentials", "private_socket_access", "process_ownership",
      "evidence", "redaction", "rollback", "recovery"
    ]),
    unknownOperationBehavior: "stable_structured_unknown_operation_error",
    futureOperationInheritance: "automatic_unrestricted_owner_authority_without_second_authorization_table"
  });
}

function buildProtocolContract(): QuirtProtocolContract {
  return Object.freeze({
    specification: "QES-2",
    version: QES2_PROTOCOL_SPEC_VERSION,
    status: QES2_PROTOCOL_SPEC_STATUS,
    versions: QUIRT_ABI_VERSIONS,
    currentRuntimeSignatureAlgorithm: "hmac-sha256",
    targetSignatureAlgorithm: "ed25519",
    q1CryptographicConformance: "target_contract_frozen_runtime_migration_planned_q2",
    publicRootListener: false,
    activeMcpServer: false,
    activeOAuthServer: false
  });
}

function buildPathContract(): QuirtPathContract {
  return Object.freeze({
    socket: Object.freeze({
      path: QUIRT_SOCKET_PATH,
      owner: QUIRT_SOCKET_OWNER,
      group: QUIRT_SOCKET_GROUP,
      mode: QUIRT_SOCKET_MODE,
      persistence: "ephemeral_runtime",
      publicListener: false
    }),
    stateRoot: QUIRT_STATE_ROOT,
    stateSubpaths: QUIRT_STATE_SUBPATHS,
    configRoot: QUIRT_CONFIG_ROOT,
    configFiles: QUIRT_CONFIG_FILES,
    releaseRoot: QUIRT_RELEASE_ROOT,
    daemonUid: QUIRT_DAEMON_UID
  });
}

function buildPhaseRegistry(): QuirtProgramStatusRegistry {
  const phases: QuirtPhaseStatus[] = [
    { phase: "Q0", status: "validated", notes: "Standalone source-complete release foundation merged to main" },
    { phase: "Q1", status: "validated", notes: "Canonical standalone contracts frozen at merge candidate" }
  ];
  for (let index = 2; index <= 26; index += 1) {
    phases.push({ phase: `Q${index}`, status: "planned", notes: "Not started in Q1" });
  }
  return Object.freeze({
    statusTaxonomy: QUIRT_PROGRAM_STATUSES,
    phases: Object.freeze(phases)
  });
}

function buildConformanceMatrix(): QuirtConformanceEntry[] {
  const entries: QuirtConformanceEntry[] = [
    { area: "repository_identity", targetContract: "StealthEyeLLC/quirt-x canonical standalone repository", currentSourceBehavior: "StealthEyeLLC/quirt-x standalone checkout", implementationStatus: "validated", firstPlannedPhase: "Q0", evidence: "origin remote and extraction manifest", knownGap: "none", acceptableInQ1: true },
    { area: "private_socket", targetContract: QUIRT_SOCKET_PATH, currentSourceBehavior: "config and systemd socket unit use /run/horsey/quirt.sock", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "deployment-contract.test.ts and config.ts", knownGap: "production socket activation not exercised in CI", acceptableInQ1: true },
    { area: "uid0_daemon_intent", targetContract: "daemon UID 0", currentSourceBehavior: "systemd service User=root", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "ops/systemd/stealtheye-quirt.service", knownGap: "not deployed", acceptableInQ1: true },
    { area: "authority_identity", targetContract: "stealtheye-owner unrestricted-owner exact issuer", currentSourceBehavior: "exact principal verification in authority.ts", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "authority.test.ts", knownGap: "production issuer configured at deploy time", acceptableInQ1: true },
    { area: "current_hmac_signatures", targetContract: "HMAC-SHA256 runtime signatures", currentSourceBehavior: "authority.ts uses hmac-sha256", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "protocol.ts algorithm field", knownGap: "not Ed25519", acceptableInQ1: true },
    { area: "target_ed25519_signatures", targetContract: "Ed25519 target signatures", currentSourceBehavior: "not implemented", implementationStatus: "planned", firstPlannedPhase: "Q2", evidence: "QES-2 protocol contract", knownGap: "runtime migration required", acceptableInQ1: true },
    { area: "replay_protection", targetContract: "nonce and request-hash replay store", currentSourceBehavior: "reservation store in authority path", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "authority.ts reserveRequest", knownGap: "Q2 replay-store redesign planned", acceptableInQ1: true },
    { area: "root_execution", targetContract: "unrestricted authenticated root execution", currentSourceBehavior: "quirt.exec and sessions without allowlists", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "operations.ts and authority contract", knownGap: "not production deployed", acceptableInQ1: true },
    { area: "providers", targetContract: "provider lifecycle and fallback without disabling root authority", currentSourceBehavior: "13 source providers with provider_unavailable path", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "power-catalog.ts", knownGap: "not all lifecycle verbs implemented", acceptableInQ1: true },
    { area: "release_packaging", targetContract: "immutable release layout with contract bundle inclusion", currentSourceBehavior: "release builder packages dist and evidence", implementationStatus: "source complete", firstPlannedPhase: "Q1", evidence: "build-quirt-release.sh", knownGap: "contract bundle inclusion added in Q1", acceptableInQ1: true },
    { area: "rollback", targetContract: "automatic rollback triggers and verification", currentSourceBehavior: "contract only", implementationStatus: "planned", firstPlannedPhase: "Q8", evidence: "rollback contract", knownGap: "runtime not implemented", acceptableInQ1: true },
    { area: "rescue", targetContract: "independent rescue CLI", currentSourceBehavior: "contract only", implementationStatus: "planned", firstPlannedPhase: "Q9", evidence: "rescue contract", knownGap: "CLI not built", acceptableInQ1: true },
    { area: "skills", targetContract: "skill package validation without removing root authority", currentSourceBehavior: "contract only", implementationStatus: "planned", firstPlannedPhase: "Q14", evidence: "skill contract", knownGap: "platform not implemented", acceptableInQ1: true },
    { area: "repair", targetContract: "graduated repair ladder", currentSourceBehavior: "contract only", implementationStatus: "planned", firstPlannedPhase: "Q12", evidence: "repair contract", knownGap: "execution not implemented", acceptableInQ1: true },
    { area: "rsi", targetContract: "recursive skill improvement boundaries", currentSourceBehavior: "not implemented", implementationStatus: "planned", firstPlannedPhase: "Q15", evidence: "architecture contract", knownGap: "explicitly out of Q1 scope", acceptableInQ1: true },
    { area: "observability", targetContract: "audit chain and receipts", currentSourceBehavior: "schemas frozen; partial gateway audit metadata", implementationStatus: "source complete", firstPlannedPhase: "Q18", evidence: "audit and receipt contracts", knownGap: "full chain writer not implemented", acceptableInQ1: true },
    { area: "fleet", targetContract: "SSH fleet provider", currentSourceBehavior: "source adapter with explicit inventory", implementationStatus: "source complete", firstPlannedPhase: "Q0", evidence: "conditional-providers.ts", knownGap: "live fleet not validated in CI", acceptableInQ1: true },
    { area: "hardware", targetContract: "hardware provider family", currentSourceBehavior: "planned provider descriptor only", implementationStatus: "planned", firstPlannedPhase: "Q25", evidence: "provider contract", knownGap: "not implemented", acceptableInQ1: true }
  ];
  return entries.map((entry) => Object.freeze(entry));
}

function staticContractSection(name: string, body: Record<string, unknown>): Record<string, unknown> {
  return Object.freeze({ contract: name, version: QUIRT_CONTRACT_VERSION, ...body });
}

export function buildQuirtOperationDescriptors(): QuirtOperationDescriptor[] {
  return QUIRT_OPERATIONS.map(buildOperationDescriptor);
}

export function buildQuirtProviderDescriptors(): QuirtProviderDescriptor[] {
  return [
    ...POWER_PROVIDER_DEFINITIONS.map(providerDescriptor),
    ...PLANNED_PROVIDER_FAMILIES.map(plannedProviderDescriptor)
  ];
}

export function buildQuirtContractBundle(): QuirtContractBundle {
  const operations = buildQuirtOperationDescriptors();
  const providers = buildQuirtProviderDescriptors();
  const capabilities = buildCapabilityDescriptors(operations, providers);
  return Object.freeze({
    schemaVersion: QUIRT_CONTRACT_SCHEMA_VERSION,
    contractVersion: QUIRT_CONTRACT_VERSION,
    product: QUIRT_PRODUCT,
    architecture: staticContractSection("architecture", {
      topology: [
        "Jamie",
        "ChatGPT / Horsey",
        "Thin unprivileged OAuth and MCP gateway",
        "Signed private Quirt protocol",
        QUIRT_SOCKET_PATH,
        "Standalone UID-0 Quirt-X daemon"
      ],
      horseyOwns: ["oauth", "capability_discovery", "capability_routing", "objectives", "audit_navigation", "release_coordination"],
      neighOwns: ["objective_continuity"],
      fixOwns: ["rootless_execution_substrate"],
      quirtOwns: ["privileged_local_machine_authority"],
      quirtMustNotBecome: ["public_control_plane", "oauth_server", "public_mcp_server", "duplicate_horsey", "duplicate_neigh_scheduler", "duplicate_fix_kernel", "hosted_saas", "fixed_command_menu"]
    }),
    authority: buildAuthorityContract(),
    protocol: buildProtocolContract(),
    operations: Object.freeze(operations),
    providers: Object.freeze(providers),
    capabilities: Object.freeze(capabilities),
    skills: staticContractSection("skill", {
      packageLayout: ["SKILL.md", "skill.json", "schemas", "scripts", "src", "tests", "fixtures", "install", "upgrade", "rollback", "licenses", "provenance"],
      discoveryRequirements: ["locate_skill_md", "parse_metadata", "normalize_manifest", "hash_files", "hash_tree", "reject_duplicate_ids", "detect_drift", "reject_symlink_escape", "reject_path_traversal"],
      powerInvariant: "failed_skill_validation_does_not_remove_unrestricted_owner_execution",
      implementationStatus: "planned"
    }),
    repair: staticContractSection("repair", {
      levels: QUIRT_REPAIR_LEVELS,
      episodeRecordFields: ["repairId", "failedOperation", "levelEntered", "attempts", "evidence", "verification", "terminalClassification"],
      implementationStatus: "planned"
    }),
    release: staticContractSection("release", {
      layout: { releases: `${QUIRT_RELEASE_ROOT}/releases/`, current: `${QUIRT_RELEASE_ROOT}/current`, previous: `${QUIRT_RELEASE_ROOT}/previous`, rescue: `${QUIRT_RELEASE_ROOT}/rescue/` },
      identityBindings: ["sourceRepository", "sourceCommit", "sourceTree", "lockfileDigest", "contractBundleDigest", "contractSchemaDigest", "archiveDigest"],
      states: ["planned", "building", "built", "verified", "staged", "active", "previous", "rolled_back", "rejected", "corrupt", "incompatible"],
      verification: ["archive_digest", "extracted_tree_digest", "contract_bundle", "contract_schema", "no_operator_gateway_code", "no_public_mcp_oauth_runtime"],
      implementationStatus: "source complete"
    }),
    update: staticContractSection("update", {
      classifications: ["automatic", "canary_then_promote", "explicit_release_checkpoint"],
      procedureSteps: ["resolve_source", "verify_source", "build_in_isolation", "run_tests", "stage_release", "compatibility_preflight", "deployment_lock", "atomic_pointer_switch", "health_verification", "retain_previous_release"],
      implementationStatus: "planned"
    }),
    rollback: staticContractSection("rollback", {
      triggers: ["daemon_fails_to_start", "socket_missing", "release_identity_mismatch", "health_deadline_exceeded", "secret_leak_detection", "repeated_crash_loop"],
      successRequires: ["health_verification", "exact_restored_identity"],
      implementationStatus: "planned"
    }),
    rescue: staticContractSection("rescue", {
      capabilities: ["list_releases", "verify_releases", "activate_previous", "restore_configuration", "restore_state_backup", "inspect_logs", "verify_socket", "collect_emergency_evidence"],
      forbiddenDependencies: ["horsey_gateway", "oauth", "main_state_database_health", "browser", "github", "network"],
      implementationStatus: "planned"
    }),
    paths: buildPathContract(),
    audit: staticContractSection("audit", {
      schemaVersion: QUIRT_ABI_VERSIONS.auditSchema,
      requiredFields: ["eventId", "timestamp", "operationId", "authenticatedSubject", "authorityClass", "eventClass", "resultClassification"],
      tamperEvidence: ["previousDigest", "hashChain", "merkleReference"],
      secretPolicy: "secret_values_forbidden",
      implementationStatus: "source complete"
    }),
    receipt: staticContractSection("receipt", {
      schemaVersion: QUIRT_ABI_VERSIONS.receiptSchema,
      immutabilityRules: ["terminal_receipts_immutable", "one_final_receipt_per_logical_execution", "no_secret_values", "artifacts_referenced_by_digest"],
      implementationStatus: "source complete"
    }),
    compatibility: staticContractSection("compatibility", {
      dimensions: ["contract", "wire_protocol", "operation", "provider_abi", "skill_abi", "state_schema", "receipt_schema", "release_format", "rescue_format", "gateway_compatibility"],
      unknownFieldBehavior: "reject_unknown_top_level_properties_unless_namespaced_extension",
      downgradeBehavior: "explicit_negotiated_evidence_backed_only"
    }),
    deprecation: staticContractSection("deprecation", {
      lifecycle: QUIRT_DEPRECATION_STATES,
      immediateRemovalForbiddenWithout: ["compatibility_analysis", "migration", "rollback", "major_release_checkpoint"],
      authorityPreservation: "deprecation_does_not_reduce_unrestricted_owner_authority"
    }),
    migrations: staticContractSection("migration", {
      scopes: ["state_schema", "audit_schema", "receipt_schema", "provider_state", "skill_state", "capability_graph", "release_metadata", "configuration"],
      rules: ["backup_before_mutation", "verify_backup", "detect_interrupted_migration", "no_success_before_post_validation"],
      implementationStatus: "planned"
    }),
    extensionAbi: staticContractSection("extension_abi", {
      kinds: ["operation", "provider", "capability", "skill", "profile", "driver", "health_probe", "lifecycle_hook"],
      rules: ["no_public_root_listener", "no_bypass_exact_authentication", "no_per_operation_owner_permission_gate", "failed_extension_validation_does_not_remove_raw_root_authority"],
      implementationStatus: "planned"
    }),
    statusTaxonomy: buildPhaseRegistry(),
    conformance: Object.freeze(buildConformanceMatrix()),
    extensions: Object.freeze({})
  });
}

export function assertCatalogOperationCoverage(): void {
  const descriptors = buildQuirtOperationDescriptors();
  if (descriptors.length !== QUIRT_OPERATIONS.length) throw new Error("Operation descriptor count mismatch");
  const ids = new Set(descriptors.map((item) => item.operationId));
  for (const operation of QUIRT_OPERATIONS) {
    if (!ids.has(operation)) throw new Error(`Missing descriptor for ${operation}`);
  }
  for (const group of [QUIRT_CORE_OPERATIONS, QUIRT_NATIVE_FOUNDATION_OPERATIONS, QUIRT_NATIVE_OPERATOR_OPERATIONS, QUIRT_POWER_OPERATIONS] as const) {
    for (const operation of group) {
      if (!ids.has(operation)) throw new Error(`Catalog group operation missing descriptor: ${operation}`);
    }
  }
}

assertCatalogOperationCoverage();
