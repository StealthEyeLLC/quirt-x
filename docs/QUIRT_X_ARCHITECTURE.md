# Quirt-X Architecture

**Status:** Q1 frozen canonical architecture  
**Repository:** StealthEyeLLC/quirt-x  
**Owner subject:** `stealtheye-owner`  
**Authority class:** `unrestricted-owner`

## Purpose

Quirt-X is the standalone UID-0 privileged local-machine authority for StealthEye Horsey. It executes signed requests from the thin unprivileged Horsey gateway over a private Unix socket. Quirt is not a public control plane, OAuth server, MCP server, objective scheduler, or rootless execution kernel.

## Topology

```text
Jamie
  ↓
ChatGPT / Horsey
  ↓
Thin unprivileged OAuth and MCP gateway
  ↓
Signed private Quirt protocol
  ↓
/run/horsey/quirt.sock
  ↓
Standalone UID-0 Quirt-X daemon
```

## Ownership boundaries

| Component | Owns |
| --- | --- |
| Horsey | OAuth, owner identity, capability discovery/routing, objectives, audit navigation, release coordination, node selection |
| Neigh | Objective continuity: observe → discover → plan → execute → diagnose → repair → validate → continue |
| Fix | Rootless workspaces, jobs, workers, leases, profiles, drivers, streams, artifacts, receipts |
| Quirt | UID-0 execution, host files, packages, users, groups, systemd, journald, networking, firewall, mounts, PTYs, tunnels, releases, rollback, rescue, privileged providers |

## Required Quirt identity

- Daemon UID: `0`
- Socket path: `/run/horsey/quirt.sock`
- Socket owner: `root`
- Socket group: `horsey`
- Socket mode: `0660`
- Public root listener: forbidden

## Persistent layout

- State root: `/var/lib/stealtheye-quirt/`
- Configuration root: `/etc/stealtheye-quirt/`
- Immutable release root: `/opt/stealtheye-quirt/`

## Q0–Q26 program model

Q1 freezes contracts only. Runtime systems for Q2–Q26 remain planned unless explicitly marked `source complete` in the conformance matrix.

| Phase | Machine status at Q1 merge |
| --- | --- |
| Q0 | `validated` |
| Q1 | `validated` |
| Q2–Q26 | `planned` |

## Relationship to QES-1

`docs/QUIRT_ENGINEERING_SPEC.md` remains the historical frozen implementation specification from the operator-era repository. QES-2 and the Q1 contract bundle supersede repository identity, standalone lifecycle, capability graph, release/update/rollback/rescue contracts, compatibility, deprecation, migration, and extension ABI for the standalone program.

QES-1 remains authoritative historical evidence for:

- unrestricted UID-0 intent
- private Unix socket topology
- immediate execution
- persistent PTY semantics
- root shell escape hatch
- no public Quirt listener
- terminal fidelity
- native file and transfer authority
- provider absence not disabling core root authority
- immutable release intent
- Riding Guide requirements

## Conformance principle

Where target contract differs from current runtime, the machine-readable conformance matrix states the gap truthfully. Q1 does not claim Q2 cryptographic migration, skill platform, repair execution, rescue CLI, or production deployment.

## Canonical artifacts

- Machine-readable bundle: `contracts/quirt-x-contracts-v1.json`
- JSON Schema: `schemas/quirt-x-contracts-v1.schema.json`
- Human contract reference: `docs/QUIRT_X_CONTRACTS.md`
- Protocol specification: `docs/QUIRT_X_PROTOCOL_SPEC.md`
- ADR: `docs/adr/ADR-QUIRT-X-STANDALONE-CONTRACTS.md`
