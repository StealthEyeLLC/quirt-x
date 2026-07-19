# ADR: Quirt unrestricted root authority

- **Status:** Accepted and frozen for QES-1
- **Date:** 2026-07-17
- **Owner:** Jamie Currier / StealthEye LLC
- **Scope:** Horsey privileged host operation

## Context

The existing Horsey architecture made Fix the sole durable execution kernel and the bounded privilege broker the sole privileged root boundary. That design is appropriate for deterministic, narrowly authorized automated operations, but it does not provide the full interactive host authority required to eliminate routine Termius use.

The owner has explicitly required a persistent, reconnectable, fully interactive remote root shell with complete filesystem, network, process, package-manager, Git, systemd, journald, terminal, transfer, browser, IDE, storage, snapshot, tunnel, tracing, and fleet capabilities.

Plan/apply and fixed-operation-only interfaces are not acceptable as the primary Quirt interaction model.

## Decision

Horsey shall add **Quirt**, a separate Jamie-exclusive unrestricted privileged terminal authority.

Quirt shall:

- run its supervisor as UID 0;
- provide persistent real PTYs and immediate arbitrary root execution;
- retain shell and terminal state across individual MCP requests and gateway reconnects;
- provide native transfer and optional provider-backed accelerators;
- expose its capabilities through Horsey;
- preserve unrestricted root shell access beneath every structured convenience operation;
- own Quirt-specific session, stream, recording, transfer, and provider state;
- avoid translating interactive terminal work into Fix plans.

The existing Fix execution kernel and bounded privilege broker remain valid and available for their established roles. They are no longer the sole privileged path once Quirt is accepted.

## Repository placement

- Primary runtime and gateway implementation: `StealthEyeLLC/stealtheye-fix-operator`
- Product integration and exact pinning: `StealthEyeLLC/horsey`
- Fix runtime code remains separate.

## Consequences

### Positive

- Horsey can replace routine Termius use.
- Interactive programs and long-lived terminal state become first-class.
- Root authority no longer depends on enumerating every future administrative operation.
- New capabilities can be added as providers without weakening the shell.
- Conversation handoff can attach to real durable state rather than reconstructing it from prose.

### Architectural cost

- Horsey gains a second privileged execution authority with a different lifecycle from Fix.
- Quirt must own and persist terminal-oriented state.
- Documentation that names the bounded broker as the sole root boundary must be updated or qualified.
- Production acceptance must prove exact behavior rather than infer capability from source.

## Non-negotiable implementation constraints

Quirt may not silently add:

- mandatory plan/apply;
- executable, argument, path, package, service, or destination allowlists;
- rootless-only execution;
- fixed-operation-only access;
- dependence on Termius;
- dependence on GitHub Actions;
- a design in which provider availability gates the root shell.

Any change requires an explicit owner decision, a new ADR, a QES version increment, and a Riding Guide entry.

## Source of truth

The complete frozen contract is `docs/QUIRT_ENGINEERING_SPEC.md` QES-1 v1.0.0.
