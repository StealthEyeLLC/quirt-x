import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  QUIRT_CONTRACT_VERSION,
  QUIRT_OWNER_AUTHORITY_CLASS,
  QUIRT_OWNER_SUBJECT,
  QUIRT_PROGRAM_STATUSES,
  QUIRT_SOCKET_GROUP,
  QUIRT_SOCKET_MODE,
  QUIRT_SOCKET_OWNER,
  QUIRT_SOCKET_PATH
} from "./contract-types.js";

describe("Quirt contract types", () => {
  it("exports canonical owner and socket constants", () => {
    assert.equal(QUIRT_OWNER_SUBJECT, "stealtheye-owner");
    assert.equal(QUIRT_OWNER_AUTHORITY_CLASS, "unrestricted-owner");
    assert.equal(QUIRT_SOCKET_PATH, "/run/horsey/quirt.sock");
    assert.equal(QUIRT_SOCKET_OWNER, "root");
    assert.equal(QUIRT_SOCKET_GROUP, "horsey");
    assert.equal(QUIRT_SOCKET_MODE, "0660");
    assert.equal(QUIRT_CONTRACT_VERSION, "1.0.0");
  });

  it("uses the exact authorized program status vocabulary", () => {
    assert.deepEqual(QUIRT_PROGRAM_STATUSES, [
      "planned",
      "source in progress",
      "source complete",
      "validated",
      "release complete",
      "deployed",
      "production accepted",
      "blocked",
      "explicitly removed by Jamie"
    ]);
  });
});
