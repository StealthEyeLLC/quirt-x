export const POWER_PROVIDER_LIFECYCLE_STATES = Object.freeze([
  "creating", "starting", "ready", "degraded", "stopping", "stopped", "failed", "lost", "unavailable", "unknown"
] as const);
export type PowerProviderLifecycleState = typeof POWER_PROVIDER_LIFECYCLE_STATES[number];

export const POWER_PROVIDER_AVAILABILITY_STATES = Object.freeze([
  "source_implemented", "locally_tested", "deterministic_adapter_tested", "executable_absent",
  "executable_version_unsupported", "dependency_absent", "kernel_feature_absent", "permission_denied",
  "configuration_absent", "credentials_absent", "degraded", "host_available", "live_validation_pending",
  "production_validated", "unsupported_on_current_host"
] as const);
export type PowerProviderAvailabilityState = typeof POWER_PROVIDER_AVAILABILITY_STATES[number];

export const QUIRT_POWER_OPERATION_GROUPS = Object.freeze({
  panes: Object.freeze([
    "quirt.pane.open", "quirt.pane.list", "quirt.pane.split", "quirt.pane.focus",
    "quirt.pane.resize", "quirt.pane.move", "quirt.pane.broadcast", "quirt.pane.close"
  ] as const),
  ide: Object.freeze([
    "quirt.ide.open", "quirt.ide.list", "quirt.ide.repository", "quirt.ide.port", "quirt.ide.close"
  ] as const),
  browser: Object.freeze([
    "quirt.browser.open", "quirt.browser.list", "quirt.browser.command", "quirt.browser.screenshot",
    "quirt.browser.video", "quirt.browser.download", "quirt.browser.upload", "quirt.browser.show", "quirt.browser.close"
  ] as const),
  preview: Object.freeze([
    "quirt.preview.open", "quirt.preview.list", "quirt.preview.get", "quirt.preview.logs", "quirt.preview.close"
  ] as const),
  sync: Object.freeze([
    "quirt.sync.create", "quirt.sync.list", "quirt.sync.status", "quirt.sync.pause", "quirt.sync.resume", "quirt.sync.remove"
  ] as const),
  remote: Object.freeze([
    "quirt.remote.add", "quirt.remote.list", "quirt.remote.mount", "quirt.remote.copy",
    "quirt.remote.sync", "quirt.remote.serve", "quirt.remote.unmount"
  ] as const),
  snapshot: Object.freeze([
    "quirt.snapshot.create", "quirt.snapshot.list", "quirt.snapshot.get", "quirt.snapshot.diff",
    "quirt.snapshot.mount", "quirt.snapshot.restore", "quirt.snapshot.unmount", "quirt.snapshot.remove"
  ] as const),
  network: Object.freeze([
    "quirt.network.interfaces", "quirt.network.routes", "quirt.network.connections",
    "quirt.network.listeners", "quirt.network.firewall", "quirt.network.capture"
  ] as const),
  tunnel: Object.freeze([
    "quirt.tunnel.open", "quirt.tunnel.list", "quirt.tunnel.get",
    "quirt.tunnel.pause", "quirt.tunnel.resume", "quirt.tunnel.close"
  ] as const),
  trace: Object.freeze([
    "quirt.trace.start", "quirt.trace.list", "quirt.trace.follow",
    "quirt.trace.stop", "quirt.trace.report", "quirt.trace.flamegraph"
  ] as const),
  checkpoint: Object.freeze([
    "quirt.checkpoint.create", "quirt.checkpoint.list", "quirt.checkpoint.get",
    "quirt.checkpoint.restore", "quirt.checkpoint.remove"
  ] as const),
  desktop: Object.freeze([
    "quirt.desktop.open", "quirt.desktop.list", "quirt.desktop.capture",
    "quirt.desktop.input", "quirt.desktop.resize", "quirt.desktop.close"
  ] as const),
  fleet: Object.freeze([
    "quirt.host.add", "quirt.host.list", "quirt.host.get", "quirt.host.remove", "quirt.host.shell",
    "quirt.fleet.exec", "quirt.fleet.copy", "quirt.fleet.playbook", "quirt.fleet.status"
  ] as const)
} as const);

export const QUIRT_POWER_OPERATIONS = Object.freeze(
  Object.values(QUIRT_POWER_OPERATION_GROUPS).flat()
);
export type QuirtPowerOperation = typeof QUIRT_POWER_OPERATIONS[number];

export interface PowerExecutableRequirement {
  path: string;
  versionArguments: readonly string[];
  minimumVersion?: string;
  optional?: boolean;
}

export interface PowerProviderDefinition {
  providerId: string;
  providerVersion: "1";
  title: string;
  description: string;
  operationIds: readonly QuirtPowerOperation[];
  requiredExecutables: readonly PowerExecutableRequirement[];
  requiredHostFeatures: readonly string[];
  requiredKernelFeatures: readonly string[];
  requiredPrivileges: readonly string[];
  configurationSchema: Readonly<Record<string, string>>;
  credentialReferenceSchema: Readonly<Record<string, string>>;
  capabilityProbes: readonly string[];
  lifecycleHooks: readonly string[];
  healthProbes: readonly string[];
  recoveryHooks: readonly string[];
  cleanupHooks: readonly string[];
  limitations: readonly string[];
  metadata: Readonly<Record<string, unknown>>;
}

function provider(
  providerId: string,
  title: string,
  description: string,
  operationIds: readonly QuirtPowerOperation[],
  requiredExecutables: readonly PowerExecutableRequirement[],
  options: Partial<Pick<PowerProviderDefinition, "requiredHostFeatures" | "requiredKernelFeatures" | "requiredPrivileges" | "configurationSchema" | "credentialReferenceSchema" | "limitations" | "metadata">> = {}
): PowerProviderDefinition {
  return Object.freeze({
    providerId, providerVersion: "1" as const, title, description, operationIds,
    requiredExecutables,
    requiredHostFeatures: options.requiredHostFeatures ?? [],
    requiredKernelFeatures: options.requiredKernelFeatures ?? [],
    requiredPrivileges: options.requiredPrivileges ?? [],
    configurationSchema: Object.freeze(options.configurationSchema ?? {}),
    credentialReferenceSchema: Object.freeze(options.credentialReferenceSchema ?? {}),
    capabilityProbes: Object.freeze(["executable_identity", "executable_version", "host_features", "kernel_features", "permissions", "configuration", "credential_references"]),
    lifecycleHooks: Object.freeze(["create", "start", "status", "health", "stop", "restart", "remove", "attach", "logs", "events", "cancel"]),
    healthProbes: Object.freeze(["process_identity", "port_ownership", "provider_specific"]),
    recoveryHooks: Object.freeze(["adopt_verified_process", "classify_lost", "resume_durable_operation"]),
    cleanupHooks: Object.freeze(["terminate_verified_process", "release_port", "remove_temporary_secret", "expire_state"]),
    limitations: options.limitations ?? [],
    metadata: Object.freeze({ checkpoint: "D", sourceImplemented: true, deterministicAdapter: true, ...options.metadata })
  });
}

export const POWER_PROVIDER_DEFINITIONS = Object.freeze([
  provider("terminal.tmux", "Tmux pane topology", "Quirt-private tmux windows and panes with durable topology identity.", QUIRT_POWER_OPERATION_GROUPS.panes, [{ path: "/usr/bin/tmux", versionArguments: ["-V"], minimumVersion: "3.2" }], { requiredHostFeatures: ["pty"], limitations: ["Control mode is used only for structured topology operations."] }),
  provider("ide.code-server", "code-server IDE", "Private code-server instances bound to authorized workspaces.", QUIRT_POWER_OPERATION_GROUPS.ide, [{ path: "/usr/bin/code-server", versionArguments: ["--version"] }], { configurationSchema: { bindAddress: "private IP literal", workspacePath: "authorized absolute path" }, credentialReferenceSchema: { authentication: "required secret reference" }, limitations: ["Public routing is release/deployment work and is not configured by this provider."] }),
  provider("preview.process", "Application preview", "Managed or registered local services with verified port ownership and bounded logs.", QUIRT_POWER_OPERATION_GROUPS.preview, [], { configurationSchema: { bindAddress: "IP literal", readiness: "http|tcp|none" }, limitations: ["Wildcard listeners require explicit opt-in."] }),
  provider("browser.playwright", "Persistent Playwright browser", "Supervisor-owned persistent browser contexts, pages, events, downloads, and artifacts.", QUIRT_POWER_OPERATION_GROUPS.browser, [{ path: "/usr/bin/chromium", versionArguments: ["--version"], optional: true }], { requiredHostFeatures: ["user_data_directory"], configurationSchema: { engine: "chromium|firefox|webkit", headless: "boolean" }, limitations: ["In-memory page identity is classified lost after an unrecoverable browser crash."] }),
  provider("sync.syncthing", "Continuous synchronization", "Syncthing-backed durable folder synchronization without destructive conflict resolution.", QUIRT_POWER_OPERATION_GROUPS.sync, [{ path: "/usr/bin/syncthing", versionArguments: ["--version"] }], { configurationSchema: { folderPath: "authorized absolute path", deviceIds: "bounded peer identity list" }, limitations: ["Peers and configuration are required for host availability."] }),
  provider("storage.rclone", "Remote storage", "Structured rclone remotes, copy/sync, mounts, serving, progress, and cancellation.", QUIRT_POWER_OPERATION_GROUPS.remote, [{ path: "/usr/bin/rclone", versionArguments: ["version"] }, { path: "/usr/bin/fusermount3", versionArguments: ["--version"], optional: true }], { requiredHostFeatures: ["filesystem"], configurationSchema: { backend: "rclone backend identifier" }, credentialReferenceSchema: { config: "required non-local rclone config-file reference" }, limitations: ["Mount support is distinct from copy support and requires FUSE."] }),
  provider("snapshot.restic", "Versioned snapshots", "Restic repositories, immutable snapshot identities, verification, mounts, and conflict-safe restore.", QUIRT_POWER_OPERATION_GROUPS.snapshot, [{ path: "/usr/bin/restic", versionArguments: ["version"] }, { path: "/usr/bin/fusermount3", versionArguments: ["--version"], optional: true }], { configurationSchema: { repository: "structured repository identity" }, credentialReferenceSchema: { passwordFile: "required restic password-file reference" }, limitations: ["Restore never overwrites without an explicit conflict policy."] }),
  provider("network.linux", "Linux network diagnostics", "Bounded structured interfaces, routes, sockets, listeners, firewall state, and capture.", QUIRT_POWER_OPERATION_GROUPS.network, [{ path: "/usr/sbin/ip", versionArguments: ["-V"] }, { path: "/usr/bin/ss", versionArguments: ["-V"] }, { path: "/usr/sbin/nft", versionArguments: ["--version"], optional: true }, { path: "/usr/bin/tcpdump", versionArguments: ["--version"], optional: true }], { requiredHostFeatures: ["procfs"], requiredPrivileges: ["network capture and firewall inspection may require root"], limitations: ["Capture requires tcpdump and permission; inventory operations remain independently available."] }),
  provider("tunnel.openssh", "Universal tunnels", "OpenSSH/socat forwarding with host-key verification and private binding defaults.", QUIRT_POWER_OPERATION_GROUPS.tunnel, [{ path: "/usr/bin/ssh", versionArguments: ["-V"] }], { configurationSchema: { endpoint: "structured host/port/socket", bindAddress: "IP literal" }, credentialReferenceSchema: { identityFile: "required SSH identity-file reference", knownHostsFile: "required host-key database reference" }, limitations: ["UDP and QUIC require an installed compatible adapter."] }),
  provider("trace.linux", "Tracing and diagnostics", "Strong-identity Linux userspace, kernel, and network tracing with bounded events and exports.", QUIRT_POWER_OPERATION_GROUPS.trace, [{ path: "/usr/bin/strace", versionArguments: ["--version"], optional: true }, { path: "/usr/bin/perf", versionArguments: ["--version"], optional: true }, { path: "/usr/bin/bpftrace", versionArguments: ["--version"], optional: true }, { path: "/usr/bin/tcpdump", versionArguments: ["--version"], optional: true }], { requiredKernelFeatures: ["ptrace or selected tracing facility"], requiredPrivileges: ["provider dependent"], limitations: ["Kernel/eBPF support and permission are probed independently; no capability is inferred from source presence."] }),
  provider("checkpoint.criu", "Process checkpointing", "Conditional process-tree checkpoint and restore with compatibility and integrity manifests.", QUIRT_POWER_OPERATION_GROUPS.checkpoint, [{ path: "/usr/sbin/criu", versionArguments: ["--version"] }], { requiredKernelFeatures: ["checkpoint_restore"], requiredPrivileges: ["root or compatible delegated capability"], limitations: ["Sockets, devices, namespaces, and kernel compatibility may prevent checkpointing; portability is never implied."] }),
  provider("desktop.vnc", "Private desktop", "Conditional authenticated private graphical sessions with bounded resources and expiry.", QUIRT_POWER_OPERATION_GROUPS.desktop, [{ path: "/usr/bin/Xvnc", versionArguments: ["-version"], optional: true }], { requiredHostFeatures: ["display infrastructure"], credentialReferenceSchema: { passwordFile: "required desktop password-file reference" }, limitations: ["Host support is conditional and no public unauthenticated listener is permitted."] }),
  provider("fleet.ssh", "Authenticated fleet", "Explicit-inventory SSH/Ansible operations with host-key verification and bounded per-host outcomes.", QUIRT_POWER_OPERATION_GROUPS.fleet, [{ path: "/usr/bin/ssh", versionArguments: ["-V"] }, { path: "/usr/bin/ansible-playbook", versionArguments: ["--version"], optional: true }], { configurationSchema: { inventory: "explicit authenticated target list" }, credentialReferenceSchema: { identityFile: "required SSH identity-file reference", knownHostsFile: "required host-key database reference" }, limitations: ["No host discovery occurs and unavailable inventory is reported precisely."] })
] satisfies readonly PowerProviderDefinition[]);

const DEFINITION_BY_OPERATION = new Map<QuirtPowerOperation, PowerProviderDefinition>();
for (const definition of POWER_PROVIDER_DEFINITIONS) {
  for (const operation of definition.operationIds) {
    if (DEFINITION_BY_OPERATION.has(operation)) throw new Error(`Duplicate power operation: ${operation}`);
    DEFINITION_BY_OPERATION.set(operation, definition);
  }
}
if (DEFINITION_BY_OPERATION.size !== QUIRT_POWER_OPERATIONS.length) throw new Error("Incomplete power provider operation registry");

export function isQuirtPowerOperation(value: string): value is QuirtPowerOperation {
  return DEFINITION_BY_OPERATION.has(value as QuirtPowerOperation);
}

export function powerProviderForOperation(operation: QuirtPowerOperation): PowerProviderDefinition {
  const definition = DEFINITION_BY_OPERATION.get(operation);
  if (definition === undefined) throw new Error(`Missing provider definition for ${operation}`);
  return definition;
}

const READ_VERBS = new Set(["list", "get", "status", "logs", "repository", "port", "screenshot", "video", "download", "show", "diff", "interfaces", "routes", "connections", "listeners", "firewall", "follow", "report", "flamegraph", "capture"]);
const EVENT_VERBS = new Set(["logs", "follow", "status", "command", "capture", "exec", "copy", "sync", "playbook", "open", "create", "restore", "mount", "serve"]);
const CANCELLABLE_VERBS = new Set(["open", "create", "command", "copy", "sync", "mount", "serve", "start", "restore", "capture", "exec", "playbook", "shell"]);

export interface PowerOperationMatrixEntry {
  operationId: QuirtPowerOperation;
  providerId: string;
  purpose: string;
  inputSchema: string;
  outputSchema: string;
  lifecycleBehavior: string;
  durableState: string;
  idempotency: "semantic_required";
  eventBehavior: string;
  paginationOrOffset: string;
  artifactOrTransferBehavior: string;
  cancellationBehavior: string;
  credentialReferences: string;
  processIdentity: string;
  restartBehavior: string;
  recoveryBehavior: string;
  hostDependencies: readonly string[];
  securityConstraints: readonly string[];
  deterministicTest: string;
  liveHostTest: string;
  expectedSupportClassification: string;
}

function matrixEntry(operationId: QuirtPowerOperation): PowerOperationMatrixEntry {
  const definition = powerProviderForOperation(operationId);
  const verb = operationId.split(".").at(-1)!;
  const read = READ_VERBS.has(verb);
  const processBacked = definition.requiredExecutables.length > 0 || ["preview.process", "browser.playwright"].includes(definition.providerId);
  return Object.freeze({
    operationId,
    providerId: definition.providerId,
    purpose: `${verb} through ${definition.title}`,
    inputSchema: `strict MCP schema: ${operationId}`,
    outputSchema: "bounded JSON metadata plus optional existing file/transfer reference",
    lifecycleBehavior: read ? "read-only inspection of durable provider state" : "durable provider transition persisted before response",
    durableState: "provider instance, operation result, health, recovery, cleanup, and related identities",
    idempotency: "semantic_required" as const,
    eventBehavior: EVENT_VERBS.has(verb) ? "bounded durable monotonic provider events" : "lifecycle event on state change",
    paginationOrOffset: read ? "bounded page/cursor or byte offset where output may grow" : "durable identity for subsequent bounded reads",
    artifactOrTransferBehavior: ["screenshot", "video", "download", "upload", "capture", "report", "flamegraph", "copy", "sync", "restore"].includes(verb) ? "large or binary data uses existing file/transfer/artifact references" : "inline metadata only",
    cancellationBehavior: CANCELLABLE_VERBS.has(verb) ? "AbortSignal and durable cancellation classification" : "not applicable beyond request cancellation",
    credentialReferences: Object.keys(definition.credentialReferenceSchema).length > 0 ? "references only; values never persist or cross Gateway audit" : "none required by default",
    processIdentity: processBacked ? "PID + start time + boot identity + executable device/inode where available" : "not process-backed or inherited from related durable instance",
    restartBehavior: processBacked ? "verify and adopt exact identity or classify lost" : "reopen durable state and resume bounded operation classification",
    recoveryBehavior: "adopt, mark degraded/lost, or complete cleanup without fabricating survival",
    hostDependencies: Object.freeze([...definition.requiredHostFeatures, ...definition.requiredKernelFeatures, ...definition.requiredExecutables.map(item => item.path)]),
    securityConstraints: Object.freeze(["exact principal", "target-host binding", "bounded output", "no plaintext credentials", "private binding by default", "metadata-only Gateway audit"]),
    deterministicTest: `${definition.providerId} deterministic adapter test for ${operationId}`,
    liveHostTest: `conditional live ${definition.providerId} test with explicit skip reason`,
    expectedSupportClassification: "implemented; host support determined only by live capability probe"
  });
}

export const QUIRT_POWER_OPERATION_MATRIX = Object.freeze(QUIRT_POWER_OPERATIONS.map(matrixEntry));

export function validatePowerCatalog(): void {
  if (QUIRT_POWER_OPERATIONS.length !== 86) throw new Error(`Frozen Checkpoint D operation count changed: ${QUIRT_POWER_OPERATIONS.length}`);
  if (new Set(QUIRT_POWER_OPERATIONS).size !== QUIRT_POWER_OPERATIONS.length) throw new Error("Duplicate Checkpoint D operation");
  if (QUIRT_POWER_OPERATION_MATRIX.length !== QUIRT_POWER_OPERATIONS.length) throw new Error("Incomplete Checkpoint D operation matrix");
}
validatePowerCatalog();
