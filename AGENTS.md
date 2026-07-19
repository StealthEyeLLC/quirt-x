# AGENTS

- Treat `provenance/extraction-manifest.json` as the standalone extraction authority.
- GitHub Actions CI is authorized while repository visibility is public. Every runner-consuming job must refuse to run when the repository is private. No workflow may use paid private-repository runner minutes. No workflow may use repository or organization secrets for ordinary CI. Workflows must use least-privilege permissions. `pull_request_target` is forbidden. Untrusted pull-request code must never receive write tokens or secrets. `npm run ci` remains the authoritative repository validation command. Q2 does not authorize deployment workflows.
- Preserve unrestricted-owner authority semantics for authenticated `stealtheye-owner`.
- Keep Quirt limited to the private Unix socket surface; do not add public root HTTP listeners.
- Run `npm run ci` before pushing.
