# Kernel Constitution

## Purpose

This document states the non-negotiable invariants of basis-core — the laws that must remain true regardless of how the library evolves, what features are added, or what components are built around it.

It is not a substitute for the detailed specifications in `docs/evaluation-semantics.md`, `docs/extension-contracts.md`, `docs/schema-versioning.md`, `docs/kernel-boundary.md`, and `docs/import-boundaries.md`. Those documents define *how* each invariant is implemented and enforced. This document defines *what* must never change about the kernel as a whole.

For the process that governs changes to public contracts (schemas, fixtures, public API, evaluation semantics, extension interfaces, audit behavior, action vocabulary), see `docs/breaking-change-discipline.md`.

When a proposed change raises the question "does this belong in basis-core?" — this is the first place to check.

---

## Constitutional Invariants

### 1. The kernel is isolated

basis-core is the authorization kernel. It is not a gateway, an API server, a database layer, a user interface, a deployment system, or a protocol adapter implementation.

The kernel contains exactly: domain primitives, decision contracts, policy evaluation semantics, enforcement boundary semantics, failure mode contracts, audit event contracts, the audit writer protocol, and adapter interface contracts. Nothing beyond this list belongs here.

A change that introduces infrastructure — HTTP frameworks, database clients, cloud SDKs, container tooling, identity provider SDKs — violates this invariant regardless of how the motivation is framed.

*Governed by*: `docs/kernel-boundary.md`, `docs/import-boundaries.md`, `docs/architecture/basis-ecosystem.md` (basis-architecture), `docs/kernel-boundary-rules.md` (basis-architecture).

### 2. The kernel evaluates; it does not transport

`EnforcementPoint.evaluate()` receives a `DecisionRequest` — a normalized, protocol-agnostic structure — and returns a `DecisionResponse`. How the request arrived (HTTP, MQTT, WebSocket, BACnet, a direct in-process call) is irrelevant to the kernel. The kernel never sees transport metadata.

No transport-layer code may enter any kernel subpackage. No network I/O may occur during policy evaluation. Policy rules must not make network calls, database queries, or file I/O.

*Governed by*: `docs/enforcement-boundary.md`, `docs/extension-contracts.md` (Forbidden side effects), `docs/kernel-boundary-rules.md` (basis-architecture).

### 3. The kernel is protocol-agnostic

The policy engine and enforcement point reason about normalized subjects, resources, and actions. They have no knowledge of BACnet, Modbus, MQTT, OPC-UA, or any other field or application protocol.

Protocol-specific logic belongs in adapters, which live outside the kernel. The adapter's job is normalization; the kernel's job is evaluation. These roles must never be mixed.

*Governed by*: `docs/adapter-contracts.md`, Architecture Principle 5 (basis-architecture), `docs/architecture/action-vocabulary.md` (basis-architecture).

### 4. The kernel is identity-provider-agnostic

The kernel receives a `Subject` — a normalized, pre-verified identity context — and reasons from that. It does not verify tokens, fetch JWKS endpoints, perform LDAP lookups, or call any identity system.

Identity verification occurs before the enforcement boundary. The application layer that constructs the `Subject` is responsible for credential verification. The kernel assumes the identity it receives reflects a real, authenticated principal.

*Governed by*: `docs/kernel-boundary.md`, `docs/scope.md`, `docs/kernel-boundary-rules.md` (basis-architecture).

### 5. Evaluation is deterministic

For the same subject, action, resource identifier, and policy configuration, `PolicyEngine.evaluate()` must return the same outcome on every call. Evaluation must not depend on wall-clock time, call count, thread identity, random values, or any mutable external state.

Policy rules must be stateless at evaluation time. State needed for evaluation (role tables, allowlists) must be loaded at construction time and held as an immutable reference. Non-deterministic evaluation makes the audit record an unreliable account of what happened.

*Governed by*: `docs/evaluation-semantics.md` (Statelessness and determinism), `docs/extension-contracts.md` (Determinism), `docs/kernel-boundary-rules.md` (basis-architecture).

### 6. Enforcement fails closed

Every failure path returns DENY. The enforcement point never permits an action it cannot safely evaluate.

If a policy rule raises, if a request fails validation, if the policy engine encounters an unexpected error, or if any internal exception escapes — the response is DENY with an appropriate `failure_reason`. `EnforcementPoint.evaluate()` never raises. Raw exception text never reaches the caller.

Uncovered actions — where no policy rule matches — are resolved to DENY. Absence of a matching policy is not permission.

*Governed by*: `docs/enforcement-boundary.md`, `docs/failure-modes.md`, `docs/evaluation-semantics.md`, Architecture Principle 7 (basis-architecture).

### 7. Adapters normalize; they do not authorize

Protocol adapters translate field-protocol messages into the normalized subject-resource-action representation the kernel evaluates. They do not evaluate authorization themselves. They do not call `EnforcementPoint.evaluate()` from inside a rule or from inside `start()`/`stop()`. They do not make authorization decisions.

A change to adapter normalization mapping — a different `resource_id` for the same device point, a different `action` for the same protocol operation — is a compatibility-sensitive event. Normalization changes affect deployed policies and historical audit records in the same way action name changes do.

*Governed by*: `docs/adapter-contracts.md`, `docs/extension-contracts.md` (AdapterBase contract), `docs/architecture/compatibility-philosophy.md` (basis-architecture).

### 8. Audit records evidence; it does not decide

The audit system records decisions. It does not make them, constrain them, or reverse them.

An `AuditEvent` is immutable once constructed. An audit write failure does not change the authorization decision already reached — the `DecisionResponse` is returned unchanged. An audit gap is an operational incident, not a cause for decision reversal.

`AuditWriter` implementations must not raise exceptions that propagate to the enforcement path. They must treat write failures as their own operational problem.

*Governed by*: `docs/audit-model.md`, `docs/enforcement-boundary.md` (Audit failure behavior), Architecture Principle 14 (basis-architecture).

### 9. Compatibility is a public contract

The schemas in `schemas/`, the action vocabulary, the evaluation semantics, the extension interfaces, and the failure mode contracts are external compatibility surfaces. Changes to them are felt by every consumer simultaneously — including audit consumers that must interpret stored records retroactively.

Field removal, field renaming, semantic redefinition, enum value removal, and required field addition are breaking changes. They require architecture review in basis-architecture and, in most cases, an ADR before they can proceed. Compatibility discipline is a governance obligation, not a coding preference.

*Governed by*: `docs/schema-versioning.md`, `docs/schema-contracts.md`, `docs/evaluation-semantics.md` (Breaking changes), `docs/extension-contracts.md` (Breaking changes), `docs/architecture/compatibility-philosophy.md` (basis-architecture).

### 10. Dependency arrows point inward

Every component in the ecosystem depends on basis-core. basis-core depends on none of them.

basis-core must not import from basis-gateway, basis-console, basis-adapters, basis-deploy, or any BASAuth component. Within the kernel, import direction is strictly downward: `domain` is the dependency sink; `enforcement` is the top layer; lower layers never import from higher ones.

A proposed change that requires basis-core to depend on a higher-level component, a cloud platform SDK, or any external runtime service is categorically out of scope. The correct response to such a design pressure is to reconsider whether the concern belongs in the kernel at all.

*Governed by*: `docs/import-boundaries.md`, `docs/kernel-boundary.md`, `docs/architecture/basis-ecosystem.md` (basis-architecture), `docs/kernel-boundary-rules.md` (basis-architecture).

---

## Relationship to Other Documents

This document is the highest-level summary of the kernel's laws. It answers "must this be true?" The documents below answer "how is it true?":

| Document | Role |
|---|---|
| `docs/kernel-boundary.md` | What the kernel contains and why; boundary enforcement via import tests |
| `docs/import-boundaries.md` | Precise subpackage dependency rules; static analysis enforcement |
| `docs/evaluation-semantics.md` | Deterministic evaluation contract; DENY short-circuit; first ALLOW; error behavior |
| `docs/enforcement-boundary.md` | Fail-closed guarantees; what the enforcement point does and does not do |
| `docs/extension-contracts.md` | PolicyRule, AuditWriter, AdapterBase behavioral contracts; breaking-change definitions |
| `docs/schema-versioning.md` | Schema evolution rules; breaking vs. additive changes; open versioning questions |
| `docs/schema-contracts.md` | Per-schema stability rules, model/schema alignment, open compatibility questions |
| `docs/audit-model.md` | Audit record model; append-only semantics; AuditWriter protocol |
| `docs/failure-modes.md` | Concrete failure scenarios and library behavior in each case |
| `docs/adapter-contracts.md` | Normalization requirements; NormalizedEvent contracts |
| `docs/breaking-change-discipline.md` | Unified process: how to classify, govern, and execute public contract changes |
| `docs/architecture/compatibility-philosophy.md` (basis-architecture) | Governing rationale for compatibility as an architectural concern |
| `docs/kernel-boundary-rules.md` (basis-architecture) | Enforceable boundary rules; boundary decision test; disallowed concerns |

When the constitution and a detailed document appear to conflict, raise the conflict in basis-architecture — do not resolve it silently in either document.

---

## Contributor Guidance

Before proposing a change to basis-core, answer these questions:

**Scope**
- Does this introduce transport, runtime, or infrastructure concerns (HTTP, databases, cloud SDKs, deployment tooling) into the kernel?
- Does this add a dependency on a specific identity provider, OT protocol, or cloud platform?
- Would basis-gateway, basis-adapters, or basis-deploy be a more appropriate owner?

**Evaluation integrity**
- Does this change the determinism guarantee — could the same inputs now produce different outputs?
- Does this weaken fail-closed behavior — could any failure path now return something other than DENY?
- Does this allow exceptions or internal state to reach the caller?

**Compatibility**
- Does this modify schema field names, required-field sets, or enum values?
- Does this change evaluation semantics — how outcomes are combined, what short-circuits, what appears in the trace?
- Does this change extension interface signatures or behavioral contracts (PolicyRule, AuditWriter, AdapterBase)?
- Does this alter the audit model — immutability, what is recorded, how failures are handled?

**Process**
- If any compatibility answer is yes: has architecture review occurred in basis-architecture? Is there an ADR?
- If any scope answer is yes: the change does not belong here. Determine the correct component.

A change that passes all scope questions, preserves evaluation integrity, and either introduces no compatibility break or follows the full breaking-change process is a candidate for basis-core. A change that fails a scope question is not a candidate regardless of how the motivation is framed.
