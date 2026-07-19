#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const EXPECTED = Object.freeze({
  sourceRepository: "StealthEyeLLC/stealtheye-fix-operator",
  sourceBranch: "build/quirt-unrestricted-root",
  sourceCommit: "6b4968e9443653af6636f2490bf3c4fc14da4cea",
  sourceTree: "358516dd79dc18c2080b99779ce0b3e428fc9b63",
  evidenceCommit: "f103c0377c73c3831af31544d14842832516499a",
  evidenceTree: "26174a31e20cabed9c5d9d00751984f3d8591ec0",
  destinationRepository: "StealthEyeLLC/quirt-x",
  snapshotCommit: "9008f6dd494cd848851234d1f4215cefb42549c0",
  snapshotTree: "82dca3c7d6aeef358a85e299e37b0234a882c518",
  environmentBlob: "df676396e630b5ff2b496e02652eaad432595820"
});
const SHA1 = /^[a-f0-9]{40}$/u;
const MODE = /^(?:100644|100755|120000)$/u;
const manifest = JSON.parse(readFileSync("provenance/extraction-manifest.json", "utf8"));
const corrections = JSON.parse(readFileSync("provenance/audit-corrections.json", "utf8"));

function fail(message) { throw new Error(`extraction manifest: ${message}`); }
function equal(actual, expected, label) { if (actual !== expected) fail(`${label} mismatch`); }
function git(args, options = {}) { return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...options }).trim(); }
function tree(ref, repository = ".") {
  const raw = execFileSync("git", ["-C", repository, "ls-tree", "-rz", "--full-tree", ref], { encoding: "buffer" });
  const result = new Map();
  for (const entry of raw.toString("utf8").split("\0")) {
    if (entry.length === 0) continue;
    const match = /^(\d+) (\S+) ([a-f0-9]{40})\t(.+)$/u.exec(entry);
    if (match === null) fail(`malformed Git tree entry for ${ref}`);
    result.set(match[4], { mode: match[1], type: match[2], sha: match[3] });
  }
  return result;
}

for (const [key, expected] of Object.entries({
  authoritativeSourceRepository: EXPECTED.sourceRepository,
  authoritativeBranch: EXPECTED.sourceBranch,
  sourceCommit: EXPECTED.sourceCommit,
  verifiedSourceTree: EXPECTED.sourceTree,
  evidenceCommit: EXPECTED.evidenceCommit,
  verifiedEvidenceTree: EXPECTED.evidenceTree,
  destinationRepository: EXPECTED.destinationRepository
})) equal(manifest[key], expected, key);

equal(corrections.extractionSnapshotCommit, EXPECTED.snapshotCommit, "audit correction snapshot commit");
equal(corrections.extractionSnapshotTree, EXPECTED.snapshotTree, "audit correction snapshot tree");
equal(manifest.finalDestinationCommit, EXPECTED.snapshotCommit, "manifest snapshot commit");
equal(manifest.finalDestinationTree, EXPECTED.snapshotTree, "manifest snapshot tree");
if (git(["rev-parse", `${EXPECTED.snapshotCommit}^{tree}`]) !== EXPECTED.snapshotTree) fail("snapshot commit does not resolve to the recorded tree");
try { git(["merge-base", "--is-ancestor", EXPECTED.snapshotCommit, "HEAD"]); } catch { fail("snapshot commit is not an ancestor of HEAD"); }

const snapshot = tree(EXPECTED.snapshotCommit);
const current = tree("HEAD");
const records = manifest.records;
if (!Array.isArray(records)) fail("records are missing");
const sourcePaths = new Set();
const destinationPaths = new Set();
let included = 0, excluded = 0, exact = 0, transformed = 0;
for (const record of records) {
  equal(record.sourceRepository, EXPECTED.sourceRepository, `${record.sourcePath ?? "record"} source repository`);
  equal(record.sourceBranch, EXPECTED.sourceBranch, `${record.sourcePath ?? "record"} source branch`);
  equal(record.sourceCommit, EXPECTED.sourceCommit, `${record.sourcePath ?? "record"} source commit`);
  equal(record.sourceTree, EXPECTED.sourceTree, `${record.sourcePath ?? "record"} source tree`);
  if (typeof record.sourcePath !== "string" || record.sourcePath.length === 0 || sourcePaths.has(record.sourcePath)) fail("source paths must be non-empty and unique");
  sourcePaths.add(record.sourcePath);
  if (!MODE.test(record.sourceMode) || !SHA1.test(record.sourceBlob) || !Number.isSafeInteger(record.sourceSize) || record.sourceSize < 0) fail(`invalid source object metadata for ${record.sourcePath}`);
  if (record.included === true) {
    included += 1;
    if (record.classification !== "standalone-quirt" || typeof record.destinationPath !== "string" || record.destinationPath.length === 0 || !SHA1.test(record.destinationBlob)) fail(`invalid included record for ${record.sourcePath}`);
    if (destinationPaths.has(record.destinationPath)) fail(`duplicate destination mapping for ${record.destinationPath}`);
    destinationPaths.add(record.destinationPath);
    const object = snapshot.get(record.destinationPath);
    if (object === undefined || object.type !== "blob" || object.sha !== record.destinationBlob) fail(`snapshot destination object mismatch for ${record.destinationPath}`);
    if (record.copyOrTransformation === "exact-copy") {
      exact += 1;
      if (record.sourceBlob !== record.destinationBlob || record.sourceMode !== object.mode || record.transformationDescription !== null) fail(`invalid exact-copy record for ${record.sourcePath}`);
    } else if (record.copyOrTransformation === "transformed") {
      transformed += 1;
      if (record.sourceBlob === record.destinationBlob || typeof record.transformationDescription !== "string" || record.transformationDescription.length === 0) fail(`invalid transformed record for ${record.sourcePath}`);
    } else fail(`unknown included classification for ${record.sourcePath}`);
  } else if (record.included === false) {
    excluded += 1;
    if (record.copyOrTransformation !== "excluded" || record.destinationPath !== null || record.destinationBlob !== null || record.transformationDescription !== null || typeof record.reason !== "string" || record.reason.length === 0) fail(`invalid excluded record for ${record.sourcePath}`);
  } else fail(`included flag is invalid for ${record.sourcePath}`);
}

if (records.length !== 188 || sourcePaths.size !== 188 || included !== 87 || excluded !== 101 || included + excluded !== records.length) fail("record classification totals are invalid");
if (exact + transformed !== included) fail("computed copy/transformation totals do not equal included records");
if (!Array.isArray(corrections.summaryFieldsSupersededByRecordComputation) || !corrections.summaryFieldsSupersededByRecordComputation.includes("exactCopyCount") || !corrections.summaryFieldsSupersededByRecordComputation.includes("transformedCount")) fail("audit correction does not supersede inconsistent manifest summary fields");

const environment = records.find((record) => record.sourcePath === "src/quirt/environment.test.ts");
if (environment === undefined || environment.sourceBlob !== EXPECTED.environmentBlob) fail("environment test authoritative anchor is incorrect");
for (const [path, phrase] of [["src/server.ts", "public MCP"], ["ops/systemd/stealtheye-fix-operator.service", "operator service"]]) {
  const record = records.find((item) => item.sourcePath === path);
  if (record === undefined || record.included !== false || !String(record.reason).toLowerCase().includes(phrase.toLowerCase())) fail(`required boundary reclassification is missing for ${path}`);
}

const rejected = new Set(manifest.rejectedBlobList);
if (rejected.size !== 5 || [...rejected].some((sha) => !SHA1.test(sha))) fail("rejected object list is invalid");
for (const [path, object] of [...snapshot, ...current]) if (rejected.has(object.sha)) fail(`rejected object ${object.sha} is accepted at ${path}`);
for (const path of ["src/server.ts", "src/principal-grant.ts", "ops/systemd/stealtheye-fix-operator.service"]) if (current.has(path)) fail(`operator/public boundary path remains active: ${path}`);
for (const path of ["reference/operator-boundary/src/server.ts", "reference/operator-boundary/ops/systemd/stealtheye-fix-operator.service", "reference/operator-boundary/src/principal-grant.ts", "reference/operator-boundary/src/quirt/tools.ts"]) if (!current.has(path)) fail(`required historical boundary reference is missing: ${path}`);
for (const [path, object] of current) {
  if (!path.startsWith("src/") || object.type !== "blob" || !/\.(?:ts|js)$/u.test(path)) continue;
  const text = git(["show", `HEAD:${path}`]);
  if (/@modelcontextprotocol\/sdk|\bMcpServer\b|\.registerTool\s*\(/u.test(text)) fail(`active standalone source contains public MCP registration: ${path}`);
}

const authoritativePath = process.env.QUIRT_AUTHORITATIVE_REPOSITORY;
let sourceVerification = "external-github-audit-required";
if (typeof authoritativePath === "string" && authoritativePath.length > 0) {
  const authoritativeTree = tree(EXPECTED.sourceCommit, authoritativePath);
  if (git(["-C", authoritativePath, "rev-parse", `${EXPECTED.sourceCommit}^{tree}`]) !== EXPECTED.sourceTree) fail("authoritative source commit tree mismatch");
  if (git(["-C", authoritativePath, "rev-parse", `${EXPECTED.evidenceCommit}^{tree}`]) !== EXPECTED.evidenceTree) fail("authoritative evidence commit tree mismatch");
  for (const record of records) {
    const object = authoritativeTree.get(record.sourcePath);
    if (object === undefined || object.type !== "blob" || object.sha !== record.sourceBlob || object.mode !== record.sourceMode) fail(`authoritative source object mismatch for ${record.sourcePath}`);
  }
  sourceVerification = "verified-from-local-authoritative-repository";
}

console.log(JSON.stringify({
  status: "complete",
  snapshotCommit: EXPECTED.snapshotCommit,
  snapshotTree: EXPECTED.snapshotTree,
  records: records.length,
  included,
  excluded,
  exactCopies: exact,
  transformed,
  currentHead: git(["rev-parse", "HEAD"]),
  currentTree: git(["rev-parse", "HEAD^{tree}"]),
  authoritativeObjectVerification: sourceVerification
}, null, 2));
