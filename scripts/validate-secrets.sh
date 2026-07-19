#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C LANG=C TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$ROOT" --no-banner --redact --verbose
  exit $?
fi

patterns=(
  'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY'
  'ghp_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'ghs_[A-Za-z0-9]{20,}'
  'x-access-token:[A-Za-z0-9]+'
  'Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~+/-]{20,}'
)
found=0
while IFS= read -r -d '' file; do
  [[ "$file" == "scripts/validate-secrets.sh" ]] && continue
  [[ -f "$file" ]] || continue
  grep -Iq . "$file" || continue
  for pattern in "${patterns[@]}"; do
    while IFS= read -r match; do
      [[ -z "$match" ]] && continue
      if [[ "$file" == "src/quirt/release.test.ts" ]] && [[ "$match" == *'const headers=['* || "$match" == *'payload.txt'* ]]; then
        continue
      fi
      printf 'secret pattern matched in %s at %s\n' "$file" "${match%%:*}" >&2
      found=1
    done < <(grep -En "$pattern" "$file" 2>/dev/null || true)
  done
done < <(git ls-files -z)
exit "$found"
