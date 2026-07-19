#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { QUIRT_OPERATIONS } from "../dist/quirt/catalog.js";
import { POWER_PROVIDER_DEFINITIONS } from "../dist/quirt/power-catalog.js";
import { buildQuirtContractBundle } from "../dist/quirt/contract-catalog.js";
import {
  QUIRT_CONFIG_ROOT,
  QUIRT_RELEASE_ROOT,
  QUIRT_SOCKET_PATH,
  QUIRT_STATE_ROOT
} from "../dist/quirt/contract-types.js";
import {
  assertQuirtContractSemantics,
  deterministicContractBundleJson,
  validateQuirtContractSemantics
} from "../dist/quirt/contract-validation.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = join(root, "contracts/quirt-x-contracts-v1.json");
const schemaPath = join(root, "schemas/quirt-x-contracts-v1.schema.json");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true });
addFormats(ajv);
if (!ajv.validateSchema(schema, true)) {
  throw new Error(`Contract schema is invalid: ${ajv.errorsText(ajv.errors)}`);
}

const bundleJson = readFileSync(bundlePath, "utf8");
const bundle = JSON.parse(bundleJson);
const generated = buildQuirtContractBundle();
const generatedJson = deterministicContractBundleJson(generated);
if (bundleJson !== generatedJson) {
  throw new Error("Committed contract bundle is not deterministic with TypeScript catalog output");
}

const validateBundle = ajv.compile(schema);
if (!validateBundle(bundle)) {
  throw new Error(`Contract bundle failed schema validation: ${ajv.errorsText(validateBundle.errors)}`);
}

const semanticIssues = validateQuirtContractSemantics(bundle, { repositoryRoot: root });
if (semanticIssues.length > 0) {
  throw new Error(semanticIssues.map((item) => `${item.path}: ${item.message}`).join("\n"));
}
assertQuirtContractSemantics(bundle, { repositoryRoot: root });

if (bundle.operations.length !== QUIRT_OPERATIONS.length) {
  throw new Error(`Operation descriptor count ${bundle.operations.length} does not match catalog ${QUIRT_OPERATIONS.length}`);
}
if (bundle.providers.filter((item) => item.implementationStatus !== "planned").length !== POWER_PROVIDER_DEFINITIONS.length) {
  throw new Error("Implemented provider descriptor count mismatch");
}
for (const requiredPath of [QUIRT_SOCKET_PATH, QUIRT_STATE_ROOT, QUIRT_CONFIG_ROOT, QUIRT_RELEASE_ROOT]) {
  if (!bundleJson.includes(requiredPath)) throw new Error(`Required path missing from bundle: ${requiredPath}`);
}

const summary = {
  contractVersion: bundle.contractVersion,
  contractBundlePath: "contracts/quirt-x-contracts-v1.json",
  contractBundleSha256: sha256(bundlePath),
  contractSchemaPath: "schemas/quirt-x-contracts-v1.schema.json",
  contractSchemaSha256: sha256(schemaPath),
  operationDescriptorCount: bundle.operations.length,
  providerDescriptorCount: bundle.providers.length,
  capabilityDescriptorCount: bundle.capabilities.length
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
