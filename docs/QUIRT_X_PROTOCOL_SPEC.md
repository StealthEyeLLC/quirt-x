# QES-2 Standalone Protocol Specification

**Specification:** QES-2  
**Version:** 1.0.0  
**Status:** FROZEN FOR Q2 IMPLEMENTATION  
**Product:** StealthEye Horsey / Quirt-X  
**Repository:** StealthEyeLLC/quirt-x  
**Owner subject:** `stealtheye-owner`  
**Authority class:** `unrestricted-owner`

## Supersedes and preserves

This specification supersedes the standalone lifecycle, versioning model, cryptographic target, compatibility rules, and wire-contract details for the Q0–Q26 program. It does not erase QES-1 history.

QES-1 in `docs/QUIRT_ENGINEERING_SPEC.md` remains valid historical evidence for unrestricted root intent, private socket topology, immediate execution, PTY semantics, native file authority, and Riding Guide requirements.

## Version dimensions

QES-2 uses independent version axes:

| Axis | Q1 frozen version |
| --- | --- |
| Contract version | 1.0.0 |
| Wire protocol version | 1.0.0 |
| Operation descriptor version | 1.0.0 |
| State schema version | 1.0.0 |
| Provider ABI version | 1.0.0 |
| Skill ABI version | 1.0.0 |
| Receipt schema version | 1.0.0 |
| Release contract version | 1.0.0 |
| Audit schema version | 1.0.0 |

## Transport

- Transport: private Unix domain socket at `/run/horsey/quirt.sock`
- Framing: binary `QRT1` header, typed frame kinds, bounded payload size
- Peer binding: Unix peer credentials (`SO_PEERCRED`) plus configured gateway UID
- Public HTTP/HTTPS/MCP/OAuth listeners on Quirt: forbidden

## Request envelope

Every request carries:

- `protocolVersion`
- `requestId`
- `operation`
- exact `principal` envelope
- exact `authority` envelope
- `targetHost`
- ISO timestamp
- canonical JSON `payload`
- declared `binaryLength`
- bounded metadata only in logs

## Authority envelope

Current runtime:

- algorithm: `hmac-sha256`
- `gatewayId`: exact configured issuer identity
- `nonce`: independent replay nonce
- `signature`: HMAC over canonical signing document

Q2 target:

- algorithm: `ed25519`
- key ID binding
- algorithm binding
- independent nonce store
- key rotation with previous-key grace period
- constant-time comparisons
- SHA-256 or stronger content digests
- no secret material in request logs

Q1 status: target contract frozen; runtime migration planned for Q2. Q1 does not claim cryptographic runtime conformance to Ed25519.

## Frame classes

- `hello` / `welcome`
- `request` / `response` / `error`
- `event`
- `cancel`
- `ping` / `pong`

## Negotiation and bounds

- feature negotiation on connect
- compression negotiation reserved for Q2
- maximum frame size bounded by configuration
- bounded metadata and buffered bytes
- partial or truncated frames rejected
- replay handling via nonce and semantic request hash
- restart and reconnect behavior defined in compatibility contract

## Errors

Structured errors include stable `code`, human `message`, `retryable`, and optional bounded `details`. Unknown operations return the stable `unknown_operation` error without requiring a second authorization-table change.

## Q2 migration path

The narrowest compatible migration is:

1. freeze QES-2 envelope and digest rules in Q1
2. add Ed25519 verification alongside existing HMAC in Q2 behind explicit negotiated feature flags
3. rotate signing keys with previous-key grace and independent nonce storage
4. retain canonical encoding and exact principal matching throughout

No Q1 runtime change implements this migration.

## Validation

Canonical bundle validation: `npm run test:contracts`
