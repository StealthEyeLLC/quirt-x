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
RECEIPT="$RECEIPT_DIR/ci-${COMMIT}.json"
GATES=()

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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { printf 'missing required host tool: %s\n' "$1" >&2; return 1; }
}

write_receipt() {
  local result="$1"
  local finish_ts pty_path pty_digest
  finish_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pty_path="node_modules/node-pty/build/Release/pty.node"
  if [[ -f "$pty_path" ]]; then pty_digest="$(sha256sum "$pty_path" | awk '{print $1}')"; else pty_digest=""; fi
  node --input-type=module - "$RECEIPT" "$result" "$COMMIT" "$TREE" "$START_TS" "$finish_ts" "$pty_path" "$pty_digest" "${GATES[*]}" <<'NODE'
import { writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
const [path, result, commit, tree, start, finish, ptyPath, ptyDigest, ...gateParts] = process.argv.slice(2);
const gates = gateParts.map((item) => JSON.parse(item));
const npmVersion = execSync("npm --version", { encoding: "utf8" }).trim();
const tsVersion = execSync("npx tsc --version", { encoding: "utf8" }).trim().replace(/^Version /, "");
writeFileSync(path, `${JSON.stringify({
  schemaVersion: "1.0.0",
  repository: "StealthEyeLLC/quirt-x",
  branch: "build/quirt-x-source-complete",
  commit,
  tree,
  workingTreeStatus: "clean",
  nodeVersion: process.version,
  npmVersion,
  typescriptVersion: tsVersion,
  operatingSystem: process.platform,
  architecture: process.arch,
  gates,
  nativeNodePtyPath: ptyPath,
  nativeNodePtyDigest: ptyDigest,
  startTimestamp: start,
  finishTimestamp: finish,
  overallResult: result,
}, null, 2)}\n`);
NODE
}

fail() {
  write_receipt fail
  exit 1
}

trap 'if [[ $? -ne 0 ]]; then write_receipt fail || true; fi' EXIT

gate "host-tools" require_cmd git
gate "host-tools-node" require_cmd node
gate "host-tools-npm" require_cmd npm
gate "host-tools-tsc" require_cmd tsc
gate "host-tools-shellcheck" require_cmd shellcheck
gate "host-tools-systemd-analyze" require_cmd systemd-analyze
gate "host-tools-tmux" require_cmd tmux
gate "host-tools-python3" require_cmd python3

gate "clean-working-tree" bash -c '[[ -z "$(git status --porcelain)" ]]'

gate "node-version" bash -c '[[ "$(node --version)" == "v24.18.0" ]]'
gate "npm-version" bash -c '[[ "$(npm --version)" == "11.16.0" ]]'
gate "typescript-version" bash -c '[[ "$(npx tsc --version)" == "Version 5.9.3" ]]'

gate "clean-install" bash -c 'rm -rf node_modules dist .test-dist && npm ci'
gate "dependency-tree" npm ls --all >/dev/null
gate "production-audit" bash -c 'npm audit --omit=dev --audit-level=high'
gate "typecheck" npm run check
gate "test-compile" npm run clean && tsc -p tsconfig.test.json
gate "unit-tests" npm test
gate "production-build" npm run build
gate "riding-guide" npm run test:riding-guide
gate "extraction-manifest" node scripts/validate-extraction-manifest.mjs
gate "systemd-verify" systemd-analyze verify ops/systemd/stealtheye-quirt.service ops/systemd/stealtheye-quirt.socket
gate "shell-syntax" bash -n scripts/build-quirt-release.sh scripts/test-quirt-release-reproducibility.sh scripts/ci.sh scripts/validate-secrets.sh
gate "secret-scan" bash scripts/validate-secrets.sh
gate "node-pty-binary" test -f node_modules/node-pty/build/Release/pty.node
gate "node-pty-load" node --input-type=module -e "import { createRequire } from 'node:module'; createRequire(import.meta.url)('node-pty');"
gate "pty-smoke" node scripts/pty-smoke.mjs
gate "quirt-release-tests" npm run test:quirt-release

SOURCE_EPOCH="$(git show -s --format=%ct 6b4968e9443653af6636f2490bf3c4fc14da4cea)"
export SOURCE_DATE_EPOCH="$SOURCE_EPOCH"
gate "release-build" bash -c "scripts/build-quirt-release.sh 6b4968e9443653af6636f2490bf3c4fc14da4cea 358516dd79dc18c2080b99779ce0b3e428fc9b63 release-output $SOURCE_EPOCH"

write_receipt pass
printf 'CI passed for %s\n' "$COMMIT"
