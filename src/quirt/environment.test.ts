import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { quirtEnvironment } from "./environment.js";

describe("Quirt process environment", () => {
  it("uses a controlled root baseline and never inherits unrelated supervisor secrets", () => {
    const name = "QUIRT_TEST_INHERITED_SECRET"; const prior = process.env[name]; process.env[name] = "must-not-cross";
    try {
      const value = quirtEnvironment("/bin/bash", { EXPLICIT_VALUE: "preserved" }); assert.equal(value.HOME, "/root"); assert.equal(value.USER, "root"); assert.equal(value.SHELL, "/bin/bash"); assert.equal(value.EXPLICIT_VALUE, "preserved"); assert.equal(value[name], undefined); assert.equal(JSON.stringify(value).includes("must-not-cross"), false);
    } finally { if (prior === undefined) delete process.env[name]; else process.env[name] = prior; }
  });

  it("rejects malformed names, NUL values, and oversized environment sets", () => {
    assert.throws(() => quirtEnvironment("/bin/bash", { "BAD-NAME": "x" }), /invalid/u); assert.throws(() => quirtEnvironment("/bin/bash", { VALUE: "x\0y" }), /invalid/u);
    assert.throws(() => quirtEnvironment("/bin/bash", Object.fromEntries(Array.from({ length: 513 }, (_, index) => [`VALUE_${index}`, "x"]))), /too large/u);
  });
});
