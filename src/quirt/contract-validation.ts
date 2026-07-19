import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../canonical.js";
import { QUIRT_OPERATIONS } from "./catalog.js";
import { POWER_PROVIDER_DEFINITIONS } from "./power-catalog.js";
import { buildQuirtContractBundle } from "./contract-catalog.js";
import {
  QUIRT_DAEMON_UID,
  QUIRT_OWNER_AUTHORITY_CLASS,
  QUIRT_OWNER_SUBJECT,
  QUIRT_PROGRAM_STATUSES,
  QUIRT_SOCKET_GROUP,
  QUIRT_SOCKET_MODE,
  QUIRT_SOCKET_OWNER,
  QUIRT_SOCKET_PATH,
  type QuirtContractBundle,
  type QuirtProgramStatus
} from "./contract-types.js";

export interface QuirtContractValidationIssue {
  readonly path: string;
  readonly message: string;
}

const STATUS_SET = new Set<string>(QUIRT_PROGRAM_STATUSES);
const HISTORICAL_BOUNDARY_MARKERS = [
  ["@", "modelcontextprotocol", "/", "sdk"].join(""),
  ["Mcp", "Server"].join(""),
  [".", "register", "Tool", "("].join("")
];

function issue(path: string, message: string): QuirtContractValidationIssue {
  return Object.freeze({ path, message });
}

const STATUS_FIELD_NAMES = new Set([
  "implementationStatus",
  "availabilityState",
  "installationState",
  "availability"
]);

function collectStatuses(value: unknown, path: string, issues: QuirtContractValidationIssue[]): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectStatuses(item, `${path}[${index}]`, issues));
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = path.length === 0 ? key : `${path}.${key}`;
    if (STATUS_FIELD_NAMES.has(key) && typeof child === "string" && !STATUS_SET.has(child)) {
      issues.push(issue(childPath, `Status value is not in approved vocabulary: ${child}`));
    }
    if (key === "phases" && Array.isArray(child)) {
      for (const [index, phase] of child.entries()) {
        if (phase !== null && typeof phase === "object" && "status" in phase) {
          const status = (phase as { status?: unknown }).status;
          if (typeof status === "string" && !STATUS_SET.has(status)) {
            issues.push(issue(`${childPath}[${index}].status`, `Status value is not in approved vocabulary: ${status}`));
          }
        }
      }
    }
    collectStatuses(child, childPath, issues);
  }
}

function hasCycle(edges: Map<string, readonly string[]>, start: string): boolean {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const walk = (node: string): boolean => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    for (const next of edges.get(node) ?? []) {
      if (walk(next)) return true;
    }
    visiting.delete(node);
    visited.add(node);
    return false;
  };
  return walk(start);
}

export function validateQuirtContractSemantics(
  bundle: QuirtContractBundle,
  options: { repositoryRoot?: string } = {}
): QuirtContractValidationIssue[] {
  const issues: QuirtContractValidationIssue[] = [];
  const root = options.repositoryRoot ?? process.cwd();

  const descriptorById = new Map(bundle.operations.map((item) => [item.operationId, item]));
  const providerById = new Map(bundle.providers.map((item) => [item.providerId, item]));
  const capabilityById = new Map(bundle.capabilities.map((item) => [item.capabilityId, item]));

  if (bundle.operations.length !== QUIRT_OPERATIONS.length) {
    issues.push(issue("operations", `Expected ${QUIRT_OPERATIONS.length} operation descriptors, found ${bundle.operations.length}`));
  }
  for (const operation of QUIRT_OPERATIONS) {
    if (!descriptorById.has(operation)) issues.push(issue("operations", `Missing descriptor for catalog operation ${operation}`));
  }
  for (const descriptor of bundle.operations) {
    if (!QUIRT_OPERATIONS.includes(descriptor.operationId as never)) {
      issues.push(issue(`operations.${descriptor.operationId}`, "Descriptor references unknown operation"));
    }
    if (descriptor.operationVersion.length < 1) issues.push(issue(`operations.${descriptor.operationId}.operationVersion`, "Operation is unversioned"));
    if (descriptor.owner !== QUIRT_OWNER_SUBJECT) issues.push(issue(`operations.${descriptor.operationId}.owner`, "Operation owner must be stealtheye-owner"));
    for (const capabilityId of descriptor.capabilityIds) {
      if (!capabilityById.has(capabilityId)) issues.push(issue(`operations.${descriptor.operationId}.capabilityIds`, `Unknown capability ${capabilityId}`));
    }
    if (descriptor.providerId !== "native" && !providerById.has(descriptor.providerId)) {
      issues.push(issue(`operations.${descriptor.operationId}.providerId`, `Unknown provider ${descriptor.providerId}`));
    }
    if (descriptor.providerId === "native" && (QUIRT_OPERATIONS as readonly string[]).includes(descriptor.operationId) === false) {
      issues.push(issue(`operations.${descriptor.operationId}.providerId`, "Native operation must exist in catalog"));
    }
  }

  const duplicateOperations = bundle.operations.map((item) => item.operationId).filter((value, index, array) => array.indexOf(value) !== index);
  if (duplicateOperations.length > 0) issues.push(issue("operations", `Duplicate operation IDs: ${[...new Set(duplicateOperations)].join(", ")}`));

  for (const provider of bundle.providers) {
    for (const operationId of provider.supportedOperations) {
      if (!descriptorById.has(operationId)) issues.push(issue(`providers.${provider.providerId}.supportedOperations`, `Unknown operation ${operationId}`));
    }
  }
  for (const provider of POWER_PROVIDER_DEFINITIONS) {
    for (const operationId of provider.operationIds) {
      const descriptor = descriptorById.get(operationId);
      if (descriptor === undefined) issues.push(issue("providers", `Provider operation ${operationId} lacks descriptor`));
      else if (descriptor.providerId !== provider.providerId) issues.push(issue(`operations.${operationId}.providerId`, `Expected provider ${provider.providerId}`));
    }
  }

  for (const capability of bundle.capabilities) {
    for (const operationId of capability.operations) {
      if (!descriptorById.has(operationId)) issues.push(issue(`capabilities.${capability.capabilityId}.operations`, `Unknown operation ${operationId}`));
    }
    if (capability.providerId !== null && !providerById.has(capability.providerId)) {
      issues.push(issue(`capabilities.${capability.capabilityId}.providerId`, `Unknown provider ${capability.providerId}`));
    }
    for (const dependencyId of capability.dependencyCapabilityIds) {
      if (!capabilityById.has(dependencyId)) issues.push(issue(`capabilities.${capability.capabilityId}.dependencyCapabilityIds`, `Unknown dependency ${dependencyId}`));
    }
    for (const fallbackId of capability.fallbackCapabilityIds) {
      if (!capabilityById.has(fallbackId)) issues.push(issue(`capabilities.${capability.capabilityId}.fallbackCapabilityIds`, `Unknown fallback ${fallbackId}`));
    }
  }

  const dependencyEdges = new Map<string, readonly string[]>(bundle.capabilities.map((item) => [item.capabilityId, item.dependencyCapabilityIds]));
  for (const capabilityId of dependencyEdges.keys()) {
    if (hasCycle(dependencyEdges, capabilityId)) issues.push(issue(`capabilities.${capabilityId}.dependencyCapabilityIds`, "Mandatory dependency cycle detected"));
  }
  const fallbackEdges = new Map<string, readonly string[]>(bundle.capabilities.map((item) => [item.capabilityId, item.fallbackCapabilityIds]));
  for (const capabilityId of fallbackEdges.keys()) {
    if (hasCycle(fallbackEdges, capabilityId)) issues.push(issue(`capabilities.${capabilityId}.fallbackCapabilityIds`, "Fallback cycle detected"));
  }

  collectStatuses(bundle, "", issues);

  if (bundle.paths.socket.path !== QUIRT_SOCKET_PATH) issues.push(issue("paths.socket.path", "Socket path must be exact"));
  if (bundle.paths.socket.owner !== QUIRT_SOCKET_OWNER) issues.push(issue("paths.socket.owner", "Socket owner must be root"));
  if (bundle.paths.socket.group !== QUIRT_SOCKET_GROUP) issues.push(issue("paths.socket.group", "Socket group must be horsey"));
  if (bundle.paths.socket.mode !== QUIRT_SOCKET_MODE) issues.push(issue("paths.socket.mode", "Socket mode must be 0660"));
  if (bundle.paths.daemonUid !== QUIRT_DAEMON_UID) issues.push(issue("paths.daemonUid", "Daemon UID must be 0"));
  if (bundle.protocol.publicRootListener !== false) issues.push(issue("protocol.publicRootListener", "Public root listener must be false"));
  if (bundle.protocol.activeMcpServer !== false) issues.push(issue("protocol.activeMcpServer", "Active MCP server must be false"));
  if (bundle.protocol.activeOAuthServer !== false) issues.push(issue("protocol.activeOAuthServer", "Active OAuth server must be false"));
  if (bundle.protocol.currentRuntimeSignatureAlgorithm !== "ed25519" && bundle.protocol.currentRuntimeSignatureAlgorithm !== "hmac-sha256") {
    issues.push(issue("protocol.currentRuntimeSignatureAlgorithm", "Current runtime signature algorithm must be declared"));
  }
  if (bundle.protocol.targetSignatureAlgorithm !== "ed25519") issues.push(issue("protocol.targetSignatureAlgorithm", "Target signature algorithm must be Ed25519"));
  if (bundle.authority.authorityClass !== QUIRT_OWNER_AUTHORITY_CLASS) issues.push(issue("authority.authorityClass", "Authority class must be unrestricted-owner"));
  if (!bundle.authority.prohibitedAuthorization.includes("command_allowlists")) issues.push(issue("authority.prohibitedAuthorization", "Command allowlists must be prohibited"));
  if (!bundle.authority.afterAuthentication.includes("arbitrary_executable_execution")) issues.push(issue("authority.afterAuthentication", "Raw execution must remain available"));
  if (bundle.authority.unknownOperationBehavior !== "stable_structured_unknown_operation_error") issues.push(issue("authority.unknownOperationBehavior", "Unknown operations must fail cleanly"));

  const rescueDeps = bundle.rescue["forbiddenDependencies"];
  if (!Array.isArray(rescueDeps) || !(rescueDeps as string[]).includes("horsey_gateway")) {
    issues.push(issue("rescue.forbiddenDependencies", "Rescue must not depend on Horsey gateway"));
  }
  if (!("rollback" in bundle.release) && !("states" in bundle.release)) issues.push(issue("release", "Release contract must define rollback-related lifecycle"));
  if (!("procedureSteps" in bundle.update)) issues.push(issue("update", "Update contract must define preflight and lock steps"));
  if (!("rules" in bundle.migrations)) issues.push(issue("migrations", "Migration contract must define backup and rollback rules"));
  if (!("tamperEvidence" in bundle.audit)) issues.push(issue("audit", "Audit contract must define tamper evidence"));
  if (!("immutabilityRules" in bundle.receipt)) issues.push(issue("receipt", "Receipt contract must forbid secrets and false termination"));

  for (const phase of bundle.statusTaxonomy.phases) {
    if (phase.phase.match(/^Q([4-9]|1\d|2[0-6])$/u) && phase.status !== "planned") {
      issues.push(issue(`statusTaxonomy.phases.${phase.phase}`, "Future phases beyond Q3 must remain planned"));
    }
  }
  const q0 = bundle.statusTaxonomy.phases.find((item) => item.phase === "Q0");
  const q1 = bundle.statusTaxonomy.phases.find((item) => item.phase === "Q1");
  const q2 = bundle.statusTaxonomy.phases.find((item) => item.phase === "Q2");
  const q3 = bundle.statusTaxonomy.phases.find((item) => item.phase === "Q3");
  if (q0?.status !== "validated") issues.push(issue("statusTaxonomy.phases.Q0", "Q0 must be validated"));
  if (q1?.status !== "validated") issues.push(issue("statusTaxonomy.phases.Q1", "Q1 must be validated"));
  if (q2 !== undefined && q2.status === "planned") issues.push(issue("statusTaxonomy.phases.Q2", "Q2 must not remain planned after Q2 runtime implementation"));
  if (q3 !== undefined && q3.status === "planned") issues.push(issue("statusTaxonomy.phases.Q3", "Q3 must not remain planned after Q3 execution kernel implementation"));

  for (const entry of bundle.conformance) {
    if (entry.area === "target_ed25519_signatures" && entry.implementationStatus === "validated") {
      issues.push(issue(`conformance.${entry.area}`, "Ed25519 must not be presented as production-validated in Q2"));
    }
    if (entry.area === "current_hmac_signatures" && entry.currentSourceBehavior.includes("ed25519") && !entry.currentSourceBehavior.includes("HMAC")) {
      issues.push(issue(`conformance.${entry.area}`, "HMAC must not be misrepresented as Ed25519"));
    }
  }

  const serialized = JSON.stringify(bundle);
  if (/"commit"\s*:\s*"[a-f0-9]{40}"/u.test(serialized) || /"archiveDigest"\s*:\s*"[a-f0-9]{64}"/u.test(serialized)) {
    issues.push(issue("bundle", "Contract bundle must not contain self-referential commit or archive digest fields"));
  }

  let activeSource = "";
  try {
    activeSource = readFileSync(join(root, "src/quirt/operations.ts"), "utf8");
  } catch {
    issues.push(issue("repository", "Unable to read active runtime source for boundary checks"));
  }
  for (const marker of HISTORICAL_BOUNDARY_MARKERS.slice(1)) {
    if (activeSource.includes(marker)) issues.push(issue("src/quirt", `Active runtime source contains forbidden marker ${marker}`));
  }
  try {
    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
    if (packageJson.dependencies?.[HISTORICAL_BOUNDARY_MARKERS[0]!] !== undefined) {
      issues.push(issue("package.json", "Active dependencies must not include MCP SDK"));
    }
  } catch {
    issues.push(issue("package.json", "Unable to read package.json for dependency boundary check"));
  }

  return issues;
}

export function assertQuirtContractSemantics(bundle?: QuirtContractBundle, options: { repositoryRoot?: string } = {}): void {
  const target = bundle ?? buildQuirtContractBundle();
  const issues = validateQuirtContractSemantics(target, options);
  if (issues.length > 0) {
    throw new Error(issues.map((item) => `${item.path}: ${item.message}`).join("\n"));
  }
}

export function deterministicContractBundleJson(bundle?: QuirtContractBundle): string {
  const target = bundle ?? buildQuirtContractBundle();
  return `${canonicalJson(target as never)}\n`;
}

export function isApprovedProgramStatus(value: string): value is QuirtProgramStatus {
  return STATUS_SET.has(value);
}
