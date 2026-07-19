#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildQuirtContractBundle } from "../dist/quirt/contract-catalog.js";
import { deterministicContractBundleJson } from "../dist/quirt/contract-validation.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = join(root, "contracts/quirt-x-contracts-v1.json");
const bundle = buildQuirtContractBundle();
const json = deterministicContractBundleJson(bundle);
mkdirSync(dirname(bundlePath), { recursive: true });
writeFileSync(bundlePath, json, "utf8");
const digest = createHash("sha256").update(json).digest("hex");
process.stdout.write(`${JSON.stringify({
  contractVersion: bundle.contractVersion,
  bundlePath: "contracts/quirt-x-contracts-v1.json",
  bundleSha256: digest,
  operationDescriptorCount: bundle.operations.length,
  providerDescriptorCount: bundle.providers.length,
  capabilityDescriptorCount: bundle.capabilities.length
}, null, 2)}\n`);
