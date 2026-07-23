# ADR: Baby Quirt production authority and nspawn operating model

- **Status:** Accepted
- **Date:** 2026-07-23
- **Owner:** Jamie Currier / StealthEye LLC
- **Scope:** Current StealthEye VPS root, deployment, recovery, and isolation model

## Context

QES-1 and the original Quirt ADR superseded the older doctrine that Fix and its bounded privilege broker were the sole execution and root authorities. The unrestricted-owner design was then implemented and deployed through standalone Baby Quirt before the broader Quirt-X program reached production.

Canonical documents in several repositories still described Fix or the Fix broker as the sole authority, or described standalone Baby as only a recovery substrate. Those descriptions no longer matched live production.

The owner has explicitly selected Baby Quirt, unrestricted root, systemd-nspawn, and systemd as the operating model from this point forward.

## Decision

### Active authority

Baby Quirt is the current canonical owner-authorized authority for:

- unrestricted UID-0 execution;
- host filesystem, package, process, network, mount, user, group, permission, and systemd operations;
- durable jobs, streams, PTYs, and artifacts;
- production build, stage, verify, activate, rollback, repair, and prune lifecycle;
- self-host source, acceptance, and evidence operations;
- recovery, replay state, release identity, and supervisor-signed receipts.

The authenticated `baby-quirt-mcp` gateway exposes one public `call_quirt` action and transports signed QRT1 requests over the private Unix socket. The gateway is not a second executor, scheduler, release database, recovery authority, artifact authority, privileged boundary, or receipt signer.

### Isolation

Stock systemd-nspawn is the default isolated environment for:

- clean builds;
- test execution;
- destructive engineering work;
- release certification;
- production-shaped rehearsal;
- staging and preactivation acceptance.

Real systemd shall run inside disposable machines when service, socket, timer, reboot, recovery, guard, rollback, or peer-credential behavior matters. Capability, namespace, seccomp, UID, mount, cleanup, and machine-termination truth shall be recorded honestly.

### Durable host lifecycle

systemd is the canonical durable host lifecycle manager for Baby, the gateway, private sockets, guards, timers, and production services.

### Production mutation

Unrestricted root is the authorized capability, not permission for undocumented live editing. Production changes shall preserve:

- exact source commits and trees;
- reproducible artifacts;
- immutable release directories;
- guarded atomic pointer changes;
- service and public acceptance readback;
- signed durable evidence;
- deterministic rollback;
- reconciliation of emergency repairs back into source.

### Legacy paths

Fix remains available as a bounded deterministic execution kernel. Its privilege broker remains valid for narrowly defined Fix operations but is not the sole privileged path and does not mediate Baby-owned work.

The StealthEye Fix Operator is retained for bounded legacy and break-glass functions. It is not the normal production authority.

Termius, manual SSH, browser terminals, and user-pasted shell commands are break-glass only when Baby itself is unreachable.

### Quirt-X

Quirt-X remains the future expansion path for the broader unrestricted-root operator and provider program. It must not be represented as deployed until exact activation and signed production acceptance prove that status.

Frozen QES documents remain historical design contracts and are not rewritten to pretend they described later implementation history. This ADR records the accepted current production implementation.

## Consequences

- Canonical documents must no longer call Fix or the Fix broker the sole execution or root authority.
- New conversations should use `bbyquirt.call_quirt`, call `baby.describe`, and poll durable jobs to terminal state before reporting completion.
- Routine engineering and certification should happen in systemd-nspawn rather than directly on the host.
- Host and production work should use Baby unrestricted root rather than Termius or manual SSH.
- Source readiness, nspawn certification, repository head, installed release identity, and live health remain separate facts and must be read independently.

## Active identity at acceptance

At the time of this ADR, production identified:

| Component | Commit |
| --- | --- |
| Baby Quirt runtime | `29fa50b56cee5fdad973d318fdb32c1d3e152e43` |
| Baby Quirt MCP gateway | `0bfcd99757afe198151e96b18771626388914205` |

Future operations must re-read live signed identity rather than relying on this historical record.
