# Extension Contracts

This document specifies the behavioral contracts for all stable extension points in basis-core. The extension points are the interfaces where external code — custom policy rules, audit backends, and protocol adapters — integrates with the authorization kernel.

These contracts define what the kernel guarantees to extension implementations and what it requires of them in return. Implementations that satisfy these contracts will work correctly; implementations that violate them may produce silent authorization failures, audit gaps, or undefined behavior.

Cross-references: `docs/policy-model.md` and `docs/evaluation-semantics.md` cover PolicyEngine behavior. `docs/audit-model.md` covers the audit record model. `docs/adapter-contracts.md` covers normalization semantics. `docs/enforcement-boundary.md` covers EnforcementPoint guarantees. `docs/import-boundaries.md` defines which packages extension implementations may import. `docs/architecture/compatibility-philosophy.md` in basis-architecture establishes the governing compatibility rules.

---

## PolicyRule contract

The `PolicyRule` interface is the primary extension point. Any object that implements `evaluate()` with the correct signature satisfies the interface; no class inheritance is required.

### Required signature

```python
def evaluate(
    self,
    subject: Subject,
    action: str,
    resource_id: str | None = None,
    identity_context: IdentityContext | None = None,
    context: dict[str, Any] | None = None,
) -> Decision: ...
```

### Required behavior

**Return an explicit `Decision`.** `evaluate()` must always return a `Decision` object with an explicit `PolicyOutcome`. It must never return `None`, raise without catching, or call `sys.exit()`.

**Use NOT_APPLICABLE for out-of-scope requests.** When a rule does not cover the action, resource type, or subject class in the current request, it must return `PolicyOutcome.NOT_APPLICABLE`. A rule must not return `PolicyOutcome.DENY` for requests it simply does not recognize. Returning DENY for unknown actions prevents downstream rules from allowing them and violates deny-overrides composition.

**Populate `evaluated_by` with a stable, non-empty identifier.** The `evaluated_by` field on the returned `Decision` is copied verbatim into `DecisionResponse.evaluated_by` and into the audit record. It must be a meaningful, stable identifier (typically the class name or a configured rule name) that an auditor can use to trace the decision back to its source. It must not be empty, and it should not change between calls on the same instance.

**Populate `reason` with a non-empty, human-readable explanation.** Reasons appear in `DecisionResponse.reason` and in audit records. They must describe what the rule evaluated and why the outcome was produced. Raw exception text, stack traces, or internal implementation details must not appear in `reason`.

### Determinism

A rule implementation must be **deterministic**: for the same `subject`, `action`, `resource_id`, and `context`, it must produce the same outcome on every call. The kernel does not enforce this — it cannot — but evaluation that depends on external mutable state, wall-clock time, random values, or network calls violates the audit guarantee that records accurately reflect the decision that was made.

The `context` parameter (from `DecisionRequest.context`) is the intended mechanism for passing request-scoped conditions like `{"maintenance_window": "true"}` or `{"site": "bldg-a"}` into rule evaluation. Rules that need deployment-time state (a role table, a resource allowlist) must load that state at construction time, not at evaluation time.

### Statefulness and thread safety

Rules must be **stateless at evaluation time**: `evaluate()` must not modify any instance attribute, write to external state, or produce side effects outside the returned `Decision`. State needed for evaluation (role tables, resource configurations, action allowlists) must be loaded at construction time and held as an immutable reference.

A `PolicyEngine` instance is designed to be shared across concurrent requests. Rules registered in the engine must also be safe for concurrent use — which follows naturally from the statelessness requirement.

### Forbidden side effects

During `evaluate()`, a rule implementation must not:

- Make network calls, database queries, or file I/O.
- Modify the `Subject`, `context`, or any other argument passed to it.
- Call `EnforcementPoint.evaluate()` recursively or invoke another `PolicyEngine`.
- Write to a log at a level that produces audit records (rules may log at DEBUG for diagnostics, but must not produce audit events from inside `evaluate()`).
- Sleep, block on a lock, or introduce latency beyond in-process computation.
- Import from `basis_core.enforcement` — this would violate import boundary rules.

### Exception behavior

If `evaluate()` raises an unhandled exception, the `PolicyEngine` catches it, logs it, and returns a DENY `Decision` with `is_error=True`. This DENY short-circuits remaining rules exactly as a normal DENY would. The `EnforcementPoint` then sets `failure_reason=POLICY_ERROR` on the `DecisionResponse` and records `AuditOutcome.ERROR`.

Individual rule implementations should catch exceptions from their own fallible operations (e.g., a lookup in a data structure that might be empty) and return a safe outcome — typically NOT_APPLICABLE or DENY with an appropriate reason — rather than letting exceptions propagate. The engine's catch is a last resort, not a design pattern for rule error handling.

### What rules may assume about inputs

- `subject` is a frozen, validated `Subject` instance. Its fields will not change during the call.
- `action` is a non-empty string. It will have been validated by `DecisionRequest` to match the `{verb}:{domain}[:{object}]` format.
- `resource_id`, when not None, will have been validated by `DecisionRequest` to match the `{type}:{qualifier}` format.
- `context`, when not None, is a plain `dict[str, str]`. Rules must treat it as read-only.
- The engine calls rules in registration order and never reorders them between calls.
- `identity_context`, when not None, is an `IdentityContext` carrying additional verified claims.

### What rules must not assume about inputs

- The transport that delivered the request. Rules do not know whether the request arrived over HTTP, MQTT, BACnet, or any other protocol. Rule evaluation is protocol-agnostic.
- The authentication mechanism used to verify the subject. The `Subject` has already been constructed from verified credentials; the rule receives the normalized result.
- Whether other rules in the engine returned ALLOW or DENY for this evaluation. Each rule evaluates independently; the engine aggregates outcomes.
- That `resource_id` is non-None. Resource-independent requests (policy and audit management) may have `resource_id=None`.

---

## AuditWriter contract

The `AuditWriter` interface has a single method. Any object that implements `write(event: AuditEvent) -> None` satisfies the interface.

### Required signature

```python
def write(self, event: AuditEvent) -> None: ...
```

### Purpose

Audit writers are evidence recorders, not authorization decision makers. The authorization decision is finalized by the `PolicyEngine` before `write()` is called. The `AuditWriter` receives the decision as a fait accompli; it has no mechanism to change it and must not attempt to.

### Required behavior

**Do not raise on failure.** `AuditWriter.write()` must not let exceptions propagate to the `EnforcementPoint`. The `EnforcementPoint` wraps `write()` in a try/except, so any exception will be caught — but implementations should swallow their own write failures, log them internally, and return normally. Propagating exceptions does not change the authorization outcome; it only causes the enforcement point to log an additional catch and may obscure the root cause.

**Do not modify the event.** The `AuditEvent` passed to `write()` is a frozen Pydantic model. Attempting to modify it will raise a validation error. Implementations that need to transform the event for storage should work on a copy or on the result of `event.model_dump()`, not on the event object itself.

**Write the event atomically where possible.** An event that is partially written to storage is worse than one that is not written at all: a partial record may be indistinguishable from a complete one and may produce incorrect audit queries. Implementations should use transactional or atomic write semantics appropriate to their backend.

### Ordering expectations

The `EnforcementPoint` calls `write()` once per evaluation, after the decision is finalized. There is no guaranteed ordering relationship between audit records for concurrent requests. Consumers that need to reconstruct the evaluation sequence across concurrent requests should use `timestamp`, `request_id`, and `correlation_id` rather than assuming write order.

### What AuditWriters may assume

- `event` is a complete, frozen `AuditEvent` with a non-empty `event_id`, a timezone-aware `timestamp`, and a non-empty `action`.
- `event.outcome` reflects the actual authorization outcome (ALLOWED, DENIED, or ERROR).
- `event.trace`, when present, is a complete `DecisionTrace` reflecting the rules that were evaluated.
- `write()` is called from the same execution path as the policy evaluation — not asynchronously, not on a different thread, unless the application explicitly wraps the `EnforcementPoint` with concurrency.

### What AuditWriters must not assume

- That the request arrived on any specific transport. Audit records are protocol-neutral.
- That `write()` will be called exactly once per process. The same writer instance may be called from multiple requests concurrently.
- That the `EnforcementPoint` will retry a failed write. A write that fails leaves an audit gap; it is the writer's responsibility to handle backend failures internally (retries, dead-letter queues, etc.).
- That `event.trace` is always present. When a policy rule fails to produce trace data, `trace` is `None`.
- That `event.resource_id` is always present. Resource-independent requests may have `resource_id=None`.

---

## AdapterBase contract

The `AdapterBase` protocol defines the lifecycle interface for protocol adapters. Adapters normalize field-protocol messages into the domain vocabulary; they do not evaluate authorization.

### Required attributes and methods

```python
adapter_id: str    # stable, unique identifier for this adapter instance
protocol:   str    # human-readable protocol name (e.g., "bacnet-ip", "modbus-tcp")

def start(self) -> None: ...
def stop(self) -> None: ...
```

### Required behavior

**`adapter_id` must be stable.** Once an adapter is deployed, its `adapter_id` appears in audit records under `AuditEventType.ADAPTER_EVENT`. Changing the `adapter_id` of a deployed adapter produces a discontinuity in audit records that cannot be resolved without explicit knowledge of the rename event. Treat `adapter_id` as an external identifier once deployed.

**`start()` and `stop()` are lifecycle hooks, not authorization paths.** The application calls these methods during startup and graceful shutdown. They must not perform authorization evaluation, submit `DecisionRequest` objects, or call `EnforcementPoint.evaluate()`.

**Adapters must not import from `basis_core.enforcement`.** The `EnforcementPoint` instance is provided to the adapter by the application layer (dependency injection at application construction time), not imported by the adapter. This is both an import boundary rule and a testability requirement: adapters must be testable without instantiating the enforcement layer.

### What `start()` and `stop()` may do

`start()` may: establish protocol connections, register message handlers, initialize normalization tables, acquire non-blocking resources. `stop()` may: close connections, flush buffered state, release resources.

`start()` and `stop()` must not: call `EnforcementPoint.evaluate()`, make authorization decisions, or block indefinitely.

---

## NormalizedEvent contract

`NormalizedEvent` is the output type that adapters produce when they receive and normalize a field-protocol message. It is the representation of a protocol operation in the domain vocabulary — stripped of all protocol-specific detail.

### Required fields

```python
adapter_id:  str             # identifies the adapter that produced this event
protocol:    str             # protocol name (for observability; not used by policy engine)
action:      str             # action name from the domain vocabulary
subject_id:  str | None      # authenticated subject, if available
resource_id: str | None      # normalized resource identifier, if applicable
context:     dict[str, str]  # policy evaluation context
payload:     dict[str, object]  # normalized original payload; not inspected by engine
```

### Normalization requirements

**`action` must be from the domain action vocabulary.** It must follow the `{verb}:{domain}[:{object}]` format and must represent the operational semantics of the protocol operation, not the protocol mechanism. `write:hvac:setpoint` is correct; `BACnet.WriteProperty.AI.3` is not.

**`resource_id`, when provided, must follow the `{type}:{qualifier}` format.** The normalized identifier must be stable: the same device point, presented by the same adapter, must always produce the same `resource_id`. Policy rules and audit records use `resource_id` as a stable reference; unstable identifiers produce inconsistent authorization decisions and audit records that cannot be correlated.

**Protocol-specific identifiers must not appear in `action` or `resource_id`.** BACnet object identifiers, Modbus register addresses, MQTT topic paths, and OPC-UA node IDs belong in `payload`, not in the authorization vocabulary fields. See `docs/adapter-contracts.md` and `docs/architecture/action-vocabulary.md` in basis-architecture.

**`payload` is for observability and audit detail, not for policy evaluation.** The `PolicyEngine` does not inspect `payload`. If a protocol-specific value needs to influence policy evaluation, the adapter must normalize it into the `context` dict using a domain-meaningful key (e.g., `{"override_priority": "8"}`), not expose the raw protocol representation.

**Normalization changes are compatibility-sensitive.** A change to an adapter's normalization mapping — a different `resource_id` for the same device point, or a different `action` for the same protocol operation — affects deployed policies (which reference the prior form) and historical audit records (which captured it). Treat normalization changes with the same discipline as action name changes: document them, version them, and account for the audit discontinuity. See `docs/adapter-contracts.md`.

---

## EnforcementPoint orchestration expectations

The `EnforcementPoint` is the only component authorized to call both the `PolicyEngine` and `AuditWriter` in the same execution path. Extension implementations must not replicate this orchestration.

### What the EnforcementPoint guarantees to callers

- `evaluate()` never raises. All failure paths return a `DecisionResponse` with `outcome=DENY`.
- Every evaluation that reaches policy evaluation produces an audit record attempt. Malformed requests that fail validation before policy evaluation do not produce audit records (no valid `action` field exists for the event).
- Raw exception text from policy rules, Pydantic validation errors, or internal errors never appears in `DecisionResponse.reason`. Callers receive a fixed, human-readable denial message.
- `DecisionResponse` fields are validated at construction. Treat the returned response as read-only; callers that need a different representation should work from `response.model_dump()`.

### What extensions must not do inside the EnforcementPoint path

- **Call `EnforcementPoint.evaluate()` from inside a policy rule.** Recursive enforcement calls are not supported.
- **Call `AuditWriter.write()` directly from a policy rule.** Audit writing belongs to the enforcement orchestration path, not to individual rules.
- **Modify the `DecisionRequest` or `Subject` between construction and `evaluate()`.** `Subject` is a frozen Pydantic model and will reject mutations. `DecisionRequest` fields are validated at construction; treat it as read-only by convention.

---

## DecisionRequest and DecisionResponse compatibility expectations

`DecisionRequest` and `DecisionResponse` are the data contracts at the enforcement boundary. Extension code that constructs, validates, or consumes these types must respect their stability.

### DecisionRequest construction

`DecisionRequest` validates its fields at construction time. Invalid inputs are rejected before reaching policy evaluation:
- `subject_id` must be non-empty.
- `action` must match `^[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)+$`.
- `resource_id`, when provided, must match `^[a-z][a-z0-9_-]*(:[a-z0-9][a-z0-9_:/-]*)$`.
- `timestamp` must be timezone-aware.
- `subject_roles` are normalized (sorted, deduplicated, whitespace-stripped) at construction.

Callers that pass invalid values receive a `ValidationError` from Pydantic. The `EnforcementPoint` catches this (for dict inputs) and returns `failure_reason=MALFORMED_REQUEST`.

### DecisionResponse field stability

`DecisionResponse` fields are validated at construction. Callers should treat the response as read-only by convention. Callers that need to transform the response for their transport layer should create a new representation from `response.model_dump()` rather than attempting field assignment.

### Field stability

Field names on `DecisionRequest` and `DecisionResponse` are compatibility surfaces. Code that references them by name — building requests, reading responses, serializing/deserializing — is coupled to those names. See `docs/schema-contracts.md` for the governing stability rules.

---

## Extension determinism expectations

Policy evaluation must be deterministic. For the same `DecisionRequest`, `Subject`, and policy configuration, the `PolicyEngine` must produce the same `Decision` outcome on every call.

This requirement applies recursively to extension implementations:

- **PolicyRule implementations must be deterministic.** The same inputs must produce the same outcome.
- **AuditWriter implementations need not be deterministic in their output** (they may buffer, batch, or retry), but they must not influence the authorization outcome.
- **Adapter normalization must be deterministic.** The same protocol message from the same source must always produce the same `NormalizedEvent`.

Non-deterministic evaluation produces audit records that cannot be interpreted as a reliable account of what happened. A decision that produces different outcomes on different calls — even for the same inputs — is not auditable.

---

## Extension failure behavior expectations

All extension failures must fail closed.

**PolicyRule failures:** An exception raised inside `evaluate()` causes the engine to return DENY with `is_error=True`. The `EnforcementPoint` records this as `AuditOutcome.ERROR` and sets `failure_reason=POLICY_ERROR`. The raw exception is logged; it does not reach the caller.

**AuditWriter failures:** An exception raised inside `write()` is caught by the `EnforcementPoint`. The `DecisionResponse` already returned is unchanged. The authorization outcome stands. The audit gap is logged as an error.

**AdapterBase failures:** Failures in `start()` or `stop()` are the application's responsibility to handle. The kernel does not define a recovery behavior for adapter lifecycle failures.

**Malformed `NormalizedEvent`:** Pydantic validates `NormalizedEvent` at construction time. Invalid inputs raise a `ValidationError` before the event reaches the `EnforcementPoint`. Applications that construct `NormalizedEvent` objects from untrusted protocol data must handle `ValidationError` and treat it as a malformed-request condition.

---

## Extension isolation expectations

Extension implementations must be isolated from the authorization decision path.

**Isolation from transport:** Extensions must not inspect, read, or modify any transport-layer state (HTTP headers, MQTT metadata, WebSocket context, connection identifiers). The only transport-adjacent information that may enter an extension is the `correlation_id` parameter on `EnforcementPoint.evaluate()`, which the application passes explicitly.

**Isolation from identity management:** Extensions must not call identity providers, validate tokens, or fetch JWKS endpoints. The `Subject` passed to a `PolicyRule` has already been constructed from verified credentials. Rules reason about the normalized subject; they do not verify it.

**Isolation from persistence:** Extensions must not perform database reads or writes during evaluation. Rule state is loaded at construction time. Audit writers interact with persistence backends, but must do so in a way that failures do not propagate to the authorization path.

**Isolation between instances:** Multiple `PolicyEngine` or `EnforcementPoint` instances in the same process must not share mutable state through their registered rules or writers. Each instance must be self-contained.

---

## What extensions may assume

- **The kernel's evaluation contract is stable.** DENY short-circuits; ALLOW does not. NOT_APPLICABLE passes through. The first ALLOW (in registration order) wins if no DENY is encountered. These behaviors are kernel contracts and will not change without a major version increment and documented migration.
- **`DecisionRequest` fields have been validated.** By the time a `PolicyRule.evaluate()` call receives a request via the `Subject` and `action` parameters, those values have passed validation.
- **`AuditEvent` is a complete, immutable record.** Writers receive the complete event; no fields will be added after `write()` is called.
- **The evaluation path is synchronous.** `PolicyEngine.evaluate()` is called synchronously. Rules and audit writers are called in-process, not through a message queue or RPC.

---

## What extensions must not assume

- **The transport protocol or deployment environment.** Extensions are embedded in whatever application hosts them. They must not assume HTTP, MQTT, WebSocket, or any other transport is present.
- **The identity provider in use.** The `Subject` has been constructed before the extension is called. Extensions cannot detect how the subject was authenticated.
- **The evaluation order of other rules.** Each rule evaluates independently. A rule must not assume that another rule in the engine has already evaluated (or not evaluated) the same request.
- **That `EnforcementPoint` will be called exactly once per request.** Applications may call `evaluate()` multiple times with the same or different requests. Rules and writers must behave correctly on any number of calls.
- **That `context` contains any particular key.** A rule that depends on a context key that is absent from the request must handle the absence gracefully (return NOT_APPLICABLE or a safe default, not raise).
- **That internal implementation details of the engine (such as `_policies`) will remain stable across versions.** The public interfaces defined in the protocol contracts are stable. Internal attributes are not.

---

## Breaking changes to extension contracts

The following changes to the extension interfaces are breaking changes that require a major version increment, an ADR, and a defined migration path. Invariants 7 (adapters normalize), 8 (audit records evidence), and 9 (compatibility is a public contract) in `docs/kernel-constitution.md` establish why extension interfaces are stability obligations, not implementation conveniences.

### Behavioral breakage

A behavioral change breaks extensions if it changes what the extension receives or what it must return:

- Changing the signature of `PolicyRule.evaluate()` — adding a required parameter or changing a parameter type — breaks all existing rule implementations.
- Changing the semantics of `PolicyOutcome.NOT_APPLICABLE` so that rules returning it must satisfy additional conditions.
- Changing the `AuditWriter.write()` signature — adding a required parameter or changing the `AuditEvent` parameter type in a non-additive way.
- Changing when `write()` is called (e.g., calling it before the decision is finalized, or calling it more than once per evaluation).
- Removing any field from `AdapterBase` or changing the semantics of `start()` and `stop()`.

### Semantic breakage

A semantic change breaks extensions if it changes the meaning of values they produce or consume, without changing the interface:

- Changing the meaning of `PolicyOutcome.ALLOW` so that an ALLOW from one rule in a chain no longer contributes to the final ALLOW decision.
- Changing how `evaluated_by` is used in audit records so that an existing naming convention produces incorrect audit attribution.
- Changing the `resource_id` validation pattern so that previously valid identifiers are rejected.
- Changing the `action` validation pattern so that previously valid action names are rejected.
- Redefining the meaning of an existing `AuditOutcome` value.

### Compatibility breakage

A compatibility change breaks extensions if it changes the data contract they interact with:

- Renaming any field on `DecisionRequest`, `DecisionResponse`, `AuditEvent`, `DecisionTrace`, or `RuleEvaluation`. Field names are compatibility surfaces for any code that references them by name.
- Removing any field from these types.
- Changing the type of any field in a way that is not backward-compatible.
- Changing the enum values of `DecisionOutcome`, `PolicyOutcome`, `AuditOutcome`, or `FailureReason`.
- Changing the `AuditEvent` frozen model configuration so that fields can be mutated after construction (would violate the immutability guarantee that writers and audit consumers depend on).

Adding new optional fields to any of these types, adding new enum values with defined semantics, and adding new optional `PolicyRule.evaluate()` parameters with defaults are additive changes. They do not break existing extension implementations provided they are introduced with defined absence semantics.

See `docs/architecture/compatibility-philosophy.md` in basis-architecture for the governing compatibility commitments.
