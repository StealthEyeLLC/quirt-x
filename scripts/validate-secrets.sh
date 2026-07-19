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
)
found=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.test.ts|*.test.js|scripts/validate-secrets.sh|reference/*) continue ;;
  esac
  for pattern in "${patterns[@]}"; do
    if grep -En "$pattern" "$file" >/dev/null 2>&1; then
      printf 'secret pattern matched in %s\n' "$file" >&2
      found=1
    fi
  done
done < <(git ls-files -z)
exit "$found"
