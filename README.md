# Quirt-X

StealthEye Quirt-X is the standalone UID-0 root-control daemon for Horsey. It exposes a private Unix socket at `/run/horsey/quirt.sock` and serves signed, replay-resistant operations for unrestricted owner authority after exact authentication of `stealtheye-owner`.

This repository is the canonical standalone program repository `StealthEyeLLC/quirt-x`. Historical extraction provenance remains in `provenance/extraction-manifest.json`.

## Program status

| Phase | Status |
| --- | --- |
| Q0 | `validated` — standalone source-complete release foundation merged to `main` |
| Q1 | `validated` — canonical standalone contracts frozen on `build/quirt-x-q1-canonical-contracts` |
| Q2–Q26 | `planned` |

Q1 is a source-and-contract checkpoint. It freezes contracts and validation; it does not deploy Quirt or implement Q2 runtime cryptography.

## Identity

- Owner subject: `stealtheye-owner`
- Authority class: `unrestricted-owner`
- Private socket: `/run/horsey/quirt.sock`
- Socket owner/group/mode: `root` / `horsey` / `0660`
- Public root listener: none
- Current runtime signatures: HMAC-SHA256
- Q2 target signatures: Ed25519

## Requirements

- Node `v24.18.0`
- npm `11.16.0`
- TypeScript `5.9.3`
- Linux build host with `gcc`, `python3`, `tmux`, `shellcheck`, and `systemd-analyze`

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
- ADR: `docs/adr/ADR-QUIRT-X-STANDALONE-CONTRACTS.md`
- Machine-readable bundle: `contracts/quirt-x-contracts-v1.json`
- JSON Schema: `schemas/quirt-x-contracts-v1.schema.json`

## Historical material

- QES-1 implementation history: `docs/QUIRT_ENGINEERING_SPEC.md`
- Operator gateway boundary reference: `reference/operator-boundary/`

## What begins in Q2

Ed25519 signing runtime, key rotation, replay-store redesign, reconnect redesign, compression negotiation, and other Q2 runtime systems defined by the frozen QES-2 contract.

## Operational notes

- Quirt is not deployed from this checkpoint.
- No public root listener exists in active source.
- No GitHub Actions workflow is required.
- No model API is required.
