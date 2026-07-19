import { readFileSync, existsSync } from "node:fs";
import { execSync } from "node:child_process";

const manifestPath = "provenance/extraction-manifest.json";
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const errors = [];

const records = manifest.records;
const included = records.filter((r) => r.included);
const excluded = records.filter((r) => !r.included);
if (included.length !== manifest.includedCount) errors.push("included count mismatch");
if (excluded.length !== manifest.excludedCount) errors.push("excluded count mismatch");
if (records.length !== manifest.totalRecordCount) errors.push("total count mismatch");

const seen = new Set();
for (const record of records) {
  if (seen.has(record.sourcePath)) errors.push(`duplicate source record ${record.sourcePath}`);
  seen.add(record.sourcePath);
  if (record.included) {
    if (!record.destinationPath || !existsSync(record.destinationPath)) errors.push(`missing destination ${record.sourcePath}`);
    const actual = execSync(`git hash-object ${JSON.stringify(record.destinationPath)}`, { encoding: "utf8" }).trim();
    if (actual !== record.destinationBlob) errors.push(`destination blob mismatch ${record.destinationPath}`);
  } else if (record.destinationPath) {
    errors.push(`excluded record has destination ${record.sourcePath}`);
  }
}

for (const blob of manifest.rejectedBlobList) {
  for (const record of included) {
    if (record.destinationBlob === blob || record.sourceBlob === blob) errors.push(`rejected blob accepted ${blob}`);
  }
}

const prohibited = [
  ".github/workflows/quirt-materialize.yml",
  "ops/systemd/stealtheye-fix-operator.service",
  "src/server.ts",
];
for (const path of prohibited) {
  if (existsSync(path)) errors.push(`prohibited path present ${path}`);
}

if (!existsSync("reference/operator-boundary/ops/systemd/stealtheye-fix-operator.service")) {
  errors.push("missing operator boundary reference unit");
}
if (!existsSync("reference/operator-boundary/src/server.ts")) {
  errors.push("missing operator boundary reference server");
}

if (errors.length) {
  for (const error of errors) errors.length && console.error(error);
  process.exit(1);
}
console.log(`validated extraction manifest: ${included.length} included, ${excluded.length} excluded`);
