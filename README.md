# Quirt-X

StealthEye Quirt-X is the future standalone unrestricted-root operator program. It preserves the QES unrestricted-owner design but is not the currently deployed production authority.

## Current production authority

Standalone Baby Quirt is the canonical owner-authorized authority currently deployed on the StealthEye VPS.

The normal path is:

```text
ChatGPT
  -> bbyquirt.call_quirt
  -> authenticated baby-quirt-mcp
  -> signed QRT1 over /run/horsey/baby-quirt.sock
  -> Baby Quirt as UID 0
```

Baby currently owns unrestricted root execution, host mutation, durable jobs, streams, PTYs, files, artifacts, production deployment, release lifecycle, self-hosting, recovery, replay controls, and supervisor-signed receipts.

Stock systemd-nspawn is the canonical isolated environment for build, test, certification, destructive rehearsal, staging, and production-shaped acceptance. systemd is the durable host lifecycle manager.

Termius, manual SSH, browser terminals, and user-pasted commands are break-glass only when Baby is unreachable.

## Quirt-X role

Quirt-X remains the source-complete future expansion path for the broader unrestricted-root operator and provider ecosystem. It must not be represented as deployed until exact production activation and signed acceptance prove that fact.

Quirt-X is intended to expose a private Unix socket at `/run/horsey/quirt.sock`, serve signed replay-resistant unrestricted-owner operations, and operate without Horsey as a runtime dependency. Horsey remains an optional controller.

Quirt-X must preserve the same accepted doctrine:

- full owner-authorized UID-0 authority rather than a fixed command broker;
- persistent and reconnectable root operation;
- no mandatory executable, argument, path, package, service, or destination allowlists after authorization;
- systemd-nspawn as the default isolated engineering and certification substrate;
- systemd for durable host lifecycle;
- immutable releases, guarded activation, readback, signed evidence, and deterministic rollback;
- no normal dependency on Termius, manual SSH, GitHub Actions, Fix, or the Fix broker.

## Program status

| Phase | Status |
| --- | --- |
| Q0 | `validated` — standalone source-complete release foundation merged to `main` |
| Q1 | `validated` — canonical standalone contracts frozen |
| Q2 | `source complete` — Ed25519 runtime, key rotation, replay/reconnect hardening, compression negotiation |
| Q3 | `source complete` — full-power execution kernel with process identity, receipts, environment policy, and termination semantics |
| Q4–Q26 | `planned` |
| Production | `not deployed`; Baby Quirt is the active authority |

## Identity

- Owner subject: `stealtheye-owner`
- Authority class: `unrestricted-owner`
- Planned private socket: `/run/horsey/quirt.sock`
- Socket owner/group/mode: `root` / `horsey` / `0660`
- Public root listener: none
- Runtime signatures: Ed25519 with explicit negotiated compatibility where specified

## Requirements

- Node `v24.18.0`
- npm `11.16.0`
- TypeScript `5.9.3`
- Linux build host with `gcc`, `python3`, `tmux`, `shellcheck`, `systemd-analyze`, and stock systemd-nspawn for certification

## Commands

```bash
npm ci
npm run check
npm run test:contracts
npm test
npm run build
npm run ci
npm run release:quirt
```

## Canonical contracts

- Architecture: `docs/QUIRT_X_ARCHITECTURE.md`
- Protocol (QES-2): `docs/QUIRT_X_PROTOCOL_SPEC.md`
- Contract reference: `docs/QUIRT_X_CONTRACTS.md`
- Standalone contracts ADR: `docs/adr/ADR-QUIRT-X-STANDALONE-CONTRACTS.md`
- Current production authority ADR: `docs/adr/ADR-BABY-QUIRT-PRODUCTION-AUTHORITY.md`
- Machine-readable bundle: `contracts/quirt-x-contracts-v1.json`
- JSON Schema: `schemas/quirt-x-contracts-v1.schema.json`

## Historical material

- QES-1 implementation history: `docs/QUIRT_ENGINEERING_SPEC.md`
- Original unrestricted-root ADR: `docs/adr/ADR-QUIRT-UNRESTRICTED-ROOT.md`
- Operator gateway boundary reference: `reference/operator-boundary/`

The frozen QES documents remain historical design contracts. This README and the production-authority ADR identify which implementation is actually active now.

## Operational notes

- Quirt-X is not deployed from the current checkpoint.
- No public root listener exists in active source.
- No model API is required.
- Repository readiness never proves production deployment; exact live identity must be read from the active runtime and signed evidence.
