# Core Domain

The authorization model is built on three primitives. Every authorization request is defined by these three values, and nothing else.

## Subject

A Subject is the entity performing the action. It may be a human operator, a physical device, a service process, a protocol gateway, or an automated agent. The Subject carries a stable identifier, a human-readable name, a type classification, and a list of role assignments.

The policy engine does not distinguish between human and device subjects unless the policy explicitly conditions on `subject.type`. A policy that grants access to role `operator` applies equally to a human with that role and a service principal with that role. Policies that should apply differently across subject types must express that condition explicitly.

Subject is immutable once constructed. It is created from verified credentials (a JWT, a device certificate, a service token) and passed through the authorization path without modification. The policy engine never modifies a Subject.

## Resource

A Resource is the target of the action. It carries a normalized identifier that is protocol-agnostic. An HVAC setpoint on a BACnet controller and an HVAC setpoint on a Modbus device are different resources with different identifiers, but the identifier format is consistent: `"{type}:{qualifier}"`.

The normalized identifier is what appears in policy rules and audit records. A policy that grants access to `hvac:zone-a` applies regardless of whether that resource is served by a BACnet adapter, a Modbus adapter, or any other protocol. The adapter is responsible for mapping the protocol-native address to the normalized resource identifier before the request reaches the enforcement point.

Resource type classifications (`hvac`, `sensor`, `device`, `zone`, `gateway`) reflect OT domain concepts, not protocol identities. Adding a new protocol means adding a new adapter; it does not require a new ResourceType.

## Action

An Action is the specific operation being requested. Action names are stable identifiers in the format `"{verb}:{domain}[:{object}]"`. They appear verbatim in policy rules and audit records.

The granularity of action definitions determines the expressiveness of the policy model. A model that distinguishes only between `read` and `write` cannot express that an operator is permitted to write setpoints but not device configuration. The action vocabulary should match the operational distinctions the policy model needs to express.

Action names are treated as external identifiers once in production use. Renaming an action breaks audit trail continuity across the rename boundary. Deprecated actions are left in place with documentation.

## The evaluation loop

A request is evaluated as follows:

1. An adapter receives a field-protocol message and normalizes it into a `DecisionRequest` (subject_id, resource_id, action).
2. The `EnforcementPoint` receives the request and submits it to the `PolicyEngine`.
3. The `PolicyEngine` walks its policy chain. Each policy returns a `Decision` or `None`.
4. The first `Decision` returned wins. If no policy claims the action, the engine returns DENY.
5. The `EnforcementPoint` records an `AuditEvent` and returns a `DecisionResponse`.
6. The adapter applies the decision: permit the operation or reject it.

The policy engine does not carry operational traffic. It evaluates; it does not route, relay, or proxy.

## Compatibility constraints

**Action names** are compatibility-sensitive contracts. They appear simultaneously in deployed policies and in audit records. Once an action name is in production use — referenced in a policy, recorded in an audit event, or emitted by an adapter normalization mapping — it must not be renamed or have its scope changed without a versioned, documented break and a defined deprecation period. There is no runtime signal when a normalization and a policy diverge on an action name; the result is silent denial.

**Resource identifiers** are audit-sensitive contracts. The `{type}:{qualifier}` format is a compatibility surface. Changing the identifier format invalidates policy references and breaks correlation in audit queries that span the format boundary.

See `docs/architecture/compatibility-philosophy.md` and `docs/architecture/action-vocabulary.md` in basis-architecture for the governance rules that apply to these decisions.
