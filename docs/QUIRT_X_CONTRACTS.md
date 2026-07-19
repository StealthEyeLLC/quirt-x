# Quirt-X Contracts Reference

**Contract version:** 1.0.0  
**Bundle:** `contracts/quirt-x-contracts-v1.json`  
**Schema:** `schemas/quirt-x-contracts-v1.schema.json`

## Frozen Q1 contracts

Q1 freezes the permanent contracts that Q2–Q26 must implement against:

1. Architecture
2. QES-2 protocol specification
3. Authority contract
4. Operation contract
5. Provider contract
6. Capability contract
7. Skill contract
8. Repair contract
9. Release contract
10. Update contract
11. Rollback contract
12. Rescue contract
13. Host-state path contract
14. Runtime path contract
15. Audit-event schema
16. Receipt schema
17. Compatibility guarantees
18. Deprecation process
19. Schema-migration contract
20. Extension ABI

## Authority contract

- Subject: `stealtheye-owner`
- Authority class: `unrestricted-owner`
- Issuer: exact configured issuer only; no prefix or wildcard matching
- Before authentication: no dispatch, no file access, no raw execution
- After authentication: every registered operation is available; future operations inherit owner authority automatically
- Security must not be implemented by reducing Jamie's authenticated authority

## Operation contract

Every catalog operation resolves to exactly one versioned descriptor with provider mapping, capability mapping, execution class, receipt requirements, and deprecation state. Current catalog size: 146 operations.

## Provider contract

Implemented providers: 13 source-complete adapters across terminal, IDE, preview, browser, sync, remote storage, snapshots, network, tunnel, tracing, checkpointing, desktop, and fleet families. Additional families are declared as `planned` without claiming implementation.

Provider absence returns `provider_unavailable` and never disables unrestricted root sessions, arbitrary root execution, native files, or native transfers.

## Capability contract

Capabilities form one descriptive routable graph shared conceptually across Horsey, Fix, and Quirt. The graph is not a second scheduler.

## Skill contract

Defines package layout, manifest fields, discovery requirements, and the power invariant: failed skill validation does not remove unrestricted owner execution.

## Repair contract

Defines the graduated repair ladder from observe through rescue and external limitation. Q1 defines descriptors only.

## Release, update, rollback, rescue

- Release identity binds source repository, commit, tree, lockfile digest, contract bundle digest, contract schema digest, SBOM digest, provenance digest, and archive digest without self-referential precomputation.
- Update classifications: automatic, canary then promote, explicit release checkpoint.
- Rollback success requires health and identity verification, not pointer movement alone.
- Rescue path is independent of Horsey gateway, OAuth, main state database health, browser, GitHub, and network availability.

## Paths

| Path | Class |
| --- | --- |
| `/run/horsey/quirt.sock` | ephemeral runtime socket |
| `/var/lib/stealtheye-quirt/` | persistent state root |
| `/etc/stealtheye-quirt/` | configuration root |
| `/opt/stealtheye-quirt/` | immutable release root |

## Audit and receipt

Audit events define tamper evidence and forbid secret values. Receipts are terminal, immutable, single-final-per-logical-execution, and reference artifacts by digest.

## Program status vocabulary

The only authorized machine statuses are:

- `planned`
- `source in progress`
- `source complete`
- `validated`
- `release complete`
- `deployed`
- `production accepted`
- `blocked`
- `explicitly removed by Jamie`

## Validation

```bash
npm run test:contracts
```

Semantic validation checks catalog cross-references, graph invariants, socket contract, authority prohibitions, rescue independence, status vocabulary, and deterministic bundle output.
