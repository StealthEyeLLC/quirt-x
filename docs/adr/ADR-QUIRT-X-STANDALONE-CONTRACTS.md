# ADR: Quirt-X Standalone Contracts

**Status:** Accepted  
**Date:** 2026-07-19  
**Phase:** Q1

## Context

The standalone `StealthEyeLLC/quirt-x` repository completed Q0 as a source-complete release foundation. The Q0–Q26 program requires a contract checkpoint that freezes permanent interfaces before Q2 runtime work begins.

QES-1 was authored before the standalone repository became canonical. The program needs a successor specification that states exactly what QES-1 supersedes and what remains valid.

## Decision

1. Freeze Q1 canonical contracts in:
   - `docs/QUIRT_X_ARCHITECTURE.md`
   - `docs/QUIRT_X_PROTOCOL_SPEC.md` (QES-2)
   - `docs/QUIRT_X_CONTRACTS.md`
   - `contracts/quirt-x-contracts-v1.json`
   - `schemas/quirt-x-contracts-v1.schema.json`
   - TypeScript sources under `src/quirt/contract-*.ts`

2. Preserve QES-1 as historical implementation evidence without rewriting its history.

3. Use independent version axes for contract, wire protocol, operation, state schema, provider ABI, skill ABI, receipt schema, and release contract.

4. Document current HMAC-SHA256 runtime behavior and Ed25519 Q2 target behavior truthfully in the conformance matrix.

5. Include contract artifacts in immutable release packages and CI receipts.

6. Initialize program status with Q0 `validated`, Q1 `validated` on merge candidate, and Q2–Q26 `planned`.

## Non-goals in Q1

- Ed25519 signing runtime
- key rotation runtime
- skill installation or RSI
- repair execution
- rescue CLI
- production deployment
- GitHub Actions
- public listeners

## Consequences

- Q2–Q26 implementation must conform to the frozen bundle or change the bundle through an explicit future contract checkpoint.
- CI gains a deterministic contract validation gate.
- Release archives carry operator-facing contract documentation and machine-readable schemas.
- Gaps between target and current behavior are explicit and acceptable in Q1 when recorded in the conformance matrix.

## Rollback

Revert the Q1 merge commit. No production state exists to restore.
