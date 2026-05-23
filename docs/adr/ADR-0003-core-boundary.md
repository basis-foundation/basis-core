# ADR-0003 — The Core Boundary: What Belongs in This Library

**Status**: Accepted
**Date**: 2026-05-22

## Context

A library that tries to do too much becomes difficult to test, difficult to integrate, and difficult to reason about. A library that does too little forces consumers to reimplement the same logic in every application. The boundary needs to be defined.

The central question is: what is the minimum set of components that constitutes the authorization boundary, such that an application consuming the library can build a complete enforcement point without reimplementing authorization logic?

From the PoC and the architecture documentation, the authorization boundary requires exactly three things:

1. **A way to express policy** — the rules that determine who may do what to which resource.
2. **A way to evaluate a request** — submitting a (subject, action, resource) triple against the policy and getting a decision.
3. **A way to record the decision** — persisting enough context about the decision for forensic and compliance purposes.

Everything else — transport, storage backends, identity provider integration, protocol adapters — is infrastructure that sits above or outside these three functions.

## Decision

The core boundary is the intersection of policy evaluation and audit recording, mediated by the `EnforcementPoint`.

The library includes:

- **domain/**: The normalized types (Subject, Resource, Action, IdentityContext) that the policy engine and audit system reason about. These are the shared vocabulary.
- **policy/**: The `PolicyEngine` and the `Policy` protocol. The chain-of-responsibility evaluator and the `RolePolicy` concrete implementation.
- **decisions/**: `DecisionRequest` and `DecisionResponse`. The data contract for submitting requests and receiving results.
- **audit/**: `AuditEvent` and the `AuditWriter` protocol. What gets recorded, and the interface for recording it.
- **adapters/**: `AdapterBase` and `NormalizedEvent`. The lifecycle contract for adapters, and the normalized representation they produce.
- **api/**: `EnforcementPoint`. The component that connects a request to the policy engine and the audit writer.

The library does not include:

- Any HTTP framework or route handler.
- Any database or storage backend.
- Any identity provider or token validation logic.
- Any protocol adapter implementation (BACnet, Modbus, MQTT, etc.).
- Any deployment infrastructure.

## Consequences

The library is testable in isolation. Tests for the policy engine require no infrastructure. Tests for the enforcement point require no running services. This is the primary benefit of the boundary as drawn.

Applications that use the library will need to supply infrastructure: a web framework for HTTP exposure, an `AuditWriter` implementation for persistence, a token validator for building `Subject` objects from credentials. These are genuine application concerns, and the library does not make choices about them on the application's behalf.

The boundary will need to be revisited if the authorization logic itself requires infrastructure access — for example, if time-window policies need to read from a shared configuration store, or if policy evaluation needs to query a credential revocation list at runtime. If that happens, the correct response is to provide a protocol for the external dependency (following the same pattern as `AuditWriter`) rather than introducing a concrete infrastructure dependency into the library.
