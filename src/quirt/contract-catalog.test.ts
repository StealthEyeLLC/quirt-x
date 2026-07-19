import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { QUIRT_OPERATIONS } from "./catalog.js";
import { POWER_PROVIDER_DEFINITIONS } from "./power-catalog.js";
import {
  buildQuirtContractBundle,
  buildQuirtOperationDescriptors,
  buildQuirtProviderDescriptors
} from "./contract-catalog.js";
import { deterministicContractBundleJson } from "./contract-validation.js";

describe("Quirt contract catalog", () => {
  it("maps every catalog operation to exactly one descriptor", () => {
    const descriptors = buildQuirtOperationDescriptors();
    assert.equal(descriptors.length, QUIRT_OPERATIONS.length);
    const ids = new Set(descriptors.map((item) => item.operationId));
    assert.equal(ids.size, QUIRT_OPERATIONS.length);
    for (const operation of QUIRT_OPERATIONS) assert.ok(ids.has(operation), operation);
  });

  it("maps every implemented provider and preserves native operation ownership", () => {
    const providers = buildQuirtProviderDescriptors();
    const implemented = providers.filter((item) => item.implementationStatus !== "planned");
    assert.equal(implemented.length, POWER_PROVIDER_DEFINITIONS.length);
    for (const descriptor of buildQuirtOperationDescriptors()) {
      if (descriptor.providerId === "native") assert.equal(descriptor.implementationModule.includes("operations.ts"), true);
      else assert.ok(providers.some((provider) => provider.providerId === descriptor.providerId));
    }
  });

  it("produces a deterministic contract bundle", () => {
    const first = deterministicContractBundleJson(buildQuirtContractBundle());
    const second = deterministicContractBundleJson(buildQuirtContractBundle());
    assert.equal(first, second);
    const bundle = buildQuirtContractBundle();
    assert.equal(bundle.operations.length, 146);
    assert.equal(bundle.providers.length, 19);
    assert.equal(bundle.capabilities.length, 25);
    assert.equal(bundle.statusTaxonomy.phases.find((item) => item.phase === "Q0")?.status, "validated");
    assert.equal(bundle.statusTaxonomy.phases.find((item) => item.phase === "Q1")?.status, "validated");
    assert.equal(bundle.statusTaxonomy.phases.find((item) => item.phase === "Q2")?.status, "planned");
  });
});
