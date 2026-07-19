#!/usr/bin/env node
import { createHash } from "node:crypto";

const [commit, tree, epochText] = process.argv.slice(2);
if (!/^[a-f0-9]{40}$/u.test(commit ?? "") || !/^[a-f0-9]{40}$/u.test(tree ?? "") || !/^[0-9]+$/u.test(epochText ?? "")) {
  process.stderr.write("usage: normalize-quirt-sbom.mjs <commit> <tree> <source-date-epoch>\n");
  process.exit(2);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const document = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (document?.bomFormat !== "CycloneDX" || document.metadata === null || typeof document.metadata !== "object" || Array.isArray(document.metadata)) {
  throw new Error("npm produced an invalid CycloneDX document");
}

const seed = createHash("sha256").update(`stealtheye-quirt:${commit}:${tree}`).digest("hex");
const variant = ((Number.parseInt(seed[16], 16) & 0x3) | 0x8).toString(16);
const uuid = `${seed.slice(0, 8)}-${seed.slice(8, 12)}-5${seed.slice(13, 16)}-${variant}${seed.slice(17, 20)}-${seed.slice(20, 32)}`;
document.serialNumber = `urn:uuid:${uuid}`;
document.metadata.timestamp = new Date(Number(epochText) * 1000).toISOString();
document.metadata.component = {
  ...(document.metadata.component ?? {}),
  "bom-ref": `pkg:npm/%40stealtheye/quirt@${commit}`,
  name: "@stealtheye/quirt",
  type: "application",
  version: commit,
  properties: [
    { name: "stealtheye:source-commit", value: commit },
    { name: "stealtheye:source-tree", value: tree },
    { name: "stealtheye:source-epoch", value: epochText },
    { name: "stealtheye:release-component", value: "stealtheye-quirt" }
  ]
};

function normalized(value) {
  if (Array.isArray(value)) return value.map(normalized).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right), "en"));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, normalized(value[key])]));
  }
  return value;
}

const output = `${JSON.stringify(normalized(document))}\n`;
if (/-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:^|["/])(?:\.git|\.npmrc|\.env)(?:["/])|\/workspace\/|\/home\/[A-Za-z0-9._-]+\//u.test(output)) {
  throw new Error("SBOM contains prohibited secret or build-host material");
}
process.stdout.write(output);
