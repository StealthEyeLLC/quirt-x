#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C LANG=C TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RECEIPT_DIR="$ROOT/.ci-receipts"
mkdir -p "$RECEIPT_DIR"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git rev-parse HEAD)"
TREE="$(git rev-parse 'HEAD^{tree}')"
BRANCH="$(git symbolic-ref --quiet --short HEAD || printf '%s' '(detached)')"
RECEIPT="$RECEIPT_DIR/ci-${COMMIT}.json"
GATES=()

tracked_clean() { [[ -z "$(git status --porcelain --untracked-files=no)" ]]; }
gate() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  if "$@"; then
    GATES+=("{\"name\":\"$name\",\"result\":\"pass\"}")
    return 0
  fi
  GATES+=("{\"name\":\"$name\",\"result\":\"fail\"}")
  return 1
}
require_cmd() { command -v "$1" >/dev/null 2>&1 || { printf 'missing required host tool: %s\n' "$1" >&2; return 1; }; }

write_receipt() {
  local result="$1"
  local finish_ts pty_path pty_digest gates_json working_tree_status
  finish_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pty_path="node_modules/node-pty/build/Release/pty.node"
  if [[ -f "$pty_path" ]]; then pty_digest="$(sha256sum "$pty_path" | awk '{print $1}')"; else pty_digest=""; fi
  if tracked_clean; then working_tree_status="clean"; else working_tree_status="dirty"; fi
  gates_json="$(printf '%s\n' "${GATES[@]}" | node --input-type=module -e 'import { readFileSync } from "node:fs"; const gates=readFileSync(0,"utf8").trim().split(/\n/).filter(Boolean).map((line)=>JSON.parse(line)); process.stdout.write(JSON.stringify(gates));')"
  node --input-type=module - "$RECEIPT" "$result" "$COMMIT" "$TREE" "$BRANCH" "$START_TS" "$finish_ts" "$working_tree_status" "$pty_path" "$pty_digest" "$gates_json" <<'NODE'
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const [path, result, commit, tree, branch, start, finish, workingTreeStatus, ptyPath, ptyDigest, gatesJson] = process.argv.slice(2);
const gates = JSON.parse(gatesJson);
const npmVersion = execSync("npm --version", { encoding: "utf8" }).trim();
const tsVersion = execSync("npx tsc --version", { encoding: "utf8" }).trim().replace(/^Version /, "");
const releaseRoot = "release-output";
const archiveName = existsSync(releaseRoot) ? readdirSync(releaseRoot).find((name) => /^stealtheye-quirt-[a-f0-9]{64}\.tar\.gz$/u.test(name)) ?? null : null;
const markerName = existsSync(releaseRoot) ? readdirSync(releaseRoot).find((name) => /^stealtheye-quirt-[a-f0-9]{64}\.release-id$/u.test(name)) ?? null : null;
const archivePath = archiveName === null ? null : join(releaseRoot, archiveName);
const releaseArchiveSha256 = archivePath === null ? null : createHash("sha256").update(readFileSync(archivePath)).digest("hex");
const releaseId = markerName === null ? null : readFileSync(join(releaseRoot, markerName), "utf8").trim();
const contractBundlePath = "contracts/quirt-x-contracts-v1.json";
const contractSchemaPath = "schemas/quirt-x-contracts-v1.schema.json";
const contractBundleSha256 = existsSync(contractBundlePath) ? createHash("sha256").update(readFileSync(contractBundlePath)).digest("hex") : null;
const contractSchemaSha256 = existsSync(contractSchemaPath) ? createHash("sha256").update(readFileSync(contractSchemaPath)).digest("hex") : null;
let contractVersion = null;
let operationDescriptorCount = null;
let providerDescriptorCount = null;
let capabilityDescriptorCount = null;
if (existsSync(contractBundlePath)) {
  const bundle = JSON.parse(readFileSync(contractBundlePath, "utf8"));
  contractVersion = bundle.contractVersion ?? null;
  operationDescriptorCount = Array.isArray(bundle.operations) ? bundle.operations.length : null;
  providerDescriptorCount = Array.isArray(bundle.providers) ? bundle.providers.length : null;
  capabilityDescriptorCount = Array.isArray(bundle.capabilities) ? bundle.capabilities.length : null;
}
writeFileSync(path, `${JSON.stringify({
  schemaVersion: "1.1.0",
  repository: "StealthEyeLLC/quirt-x",
  branch,
  commit,
  tree,
  workingTreeStatus,
  nodeVersion: process.version,
  npmVersion,
  typescriptVersion: tsVersion,
  operatingSystem: process.platform,
  architecture: process.arch,
  gates,
  nativeNodePtyPath: ptyPath,
  nativeNodePtyDigest: ptyDigest || null,
  releaseId,
  releaseArchive: archiveName,
  releaseArchiveSha256,
  contractVersion,
  contractBundlePath,
  contractBundleSha256,
  contractSchemaPath,
  contractSchemaSha256,
  operationDescriptorCount,
  providerDescriptorCount,
  capabilityDescriptorCount,
  startTimestamp: start,
  finishTimestamp: finish,
  overallResult: result
}, null, 2)}\n`);
NODE
}

trap 'status=$?; if [[ $status -ne 0 ]]; then write_receipt fail || true; fi' EXIT

gate "host-tools" require_cmd git
gate "host-tools-node" require_cmd node
gate "host-tools-npm" require_cmd npm
gate "host-tools-tsc" bash -c 'npx tsc --version >/dev/null'
gate "host-tools-shellcheck" require_cmd shellcheck
gate "host-tools-systemd-analyze" require_cmd systemd-analyze
gate "host-tools-tmux" require_cmd tmux
gate "host-tools-python3" require_cmd python3

gate "clean-working-tree" tracked_clean
gate "node-version" bash -c '[[ "$(node --version)" == "v24.18.0" ]]'
gate "npm-version" bash -c '[[ "$(npm --version)" == "11.16.0" ]]'
gate "typescript-version" bash -c '[[ "$(npx tsc --version)" == "Version 5.9.3" ]]'

gate "clean-install" bash -c 'rm -rf node_modules dist .test-dist && npm ci'
gate "dependency-tree" npm ls --all >/dev/null
gate "standalone-dependency-boundary" bash -c '! npm ls --omit=dev @modelcontextprotocol/sdk >/dev/null 2>&1'
gate "production-audit" bash -c 'npm audit --omit=dev --audit-level=high'
gate "typecheck" npm run check
gate "contract-validation" npm run test:contracts
gate "test-compile" bash -c 'npm run clean && npx tsc -p tsconfig.test.json'
gate "unit-tests" npm test
gate "production-build" npm run build
gate "riding-guide" npm run test:riding-guide
gate "extraction-manifest" node scripts/validate-extraction-manifest.mjs
gate "systemd-verify" bash -c 'rm -rf /tmp/quirt-systemd-verify && mkdir -p /tmp/quirt-systemd-verify/opt/node-v24.18.0-linux-x64/bin && ln -sf "$(command -v node)" /tmp/quirt-systemd-verify/opt/node-v24.18.0-linux-x64/bin/node && sed "s|/opt/node-v24.18.0-linux-x64/bin/node|/tmp/quirt-systemd-verify/opt/node-v24.18.0-linux-x64/bin/node|" ops/systemd/stealtheye-quirt.service > /tmp/quirt-systemd-verify/stealtheye-quirt.service && systemd-analyze verify /tmp/quirt-systemd-verify/stealtheye-quirt.service ops/systemd/stealtheye-quirt.socket'
gate "shell-syntax" bash -n scripts/build-quirt-release.sh scripts/test-quirt-release-reproducibility.sh scripts/ci.sh scripts/validate-secrets.sh
gate "secret-scan" bash scripts/validate-secrets.sh
gate "node-pty-binary" test -f node_modules/node-pty/build/Release/pty.node
gate "node-pty-load" node --input-type=module -e "import { createRequire } from 'node:module'; createRequire(import.meta.url)('node-pty');"
gate "pty-smoke" node scripts/pty-smoke.mjs
gate "quirt-release-tests" npm run test:quirt-release

BUILD_EPOCH="$(git show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH="$BUILD_EPOCH"
gate "release-build" bash -c "rm -rf release-output && npm run build && scripts/build-quirt-release.sh $COMMIT $TREE release-output $BUILD_EPOCH"
gate "final-clean-working-tree" tracked_clean

write_receipt pass
trap - EXIT
printf 'CI passed for %s (%s)\n' "$COMMIT" "$TREE"
