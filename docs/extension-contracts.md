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

---

## Operation-aware policy is structured data

This section records a conclusion, not a new contract: **the initial operation-aware authorization family (v0.2.0) does not introduce a new executable extension-point Protocol.** It exists so that a future contributor encountering `OperationAwarePolicyRule`, `PolicyBundle`, or the condition-operator implementation and wondering whether basis-core now has a second pluggable rule interface does not have to re-derive the answer from first principles. The answer is no, and this section explains why, what is actually customizable today, and what threshold a future executable extension point would have to clear.

This section is additive. It changes nothing about the three governed extension points documented above (`PolicyRule`, `AuditWriter`, `AdapterBase`) or about `NormalizedEvent`'s role as an adapter output contract rather than an independently executable plugin interface. Their signatures, behavioral requirements, determinism requirements, statefulness guidance, forbidden side effects, failure behavior, and compatibility commitments are unchanged and are not restated or reinterpreted here.

### The operation-aware policy family is authored data

The operation-aware Python package surface adds a family of validated, structured policy values to `basis_core.policy`: `PolicyBundle`, `PolicyBundleScope`, `OperationAwarePolicyRule`, `OperationAwarePolicyMatch`, `PolicyCondition`, and `RuleEffect`. The bundle, scope, rule, match, and condition types are validated Pydantic models; `RuleEffect` is a closed enum. They are structured data and vocabulary, not executable policy callbacks.

A `PolicyBundle` is authored by a bundle author—a human or an offline generation process. Its source representation may be YAML, JSON, or directly constructed Python data, but parsing and loading belong to the calling application or deployment layer. `basis-core` receives and validates the resulting typed `PolicyBundle`; it does not own YAML or JSON loading in the runtime evaluation path. Once constructed, a bundle is:

- **authored as data** — a bundle author fills in fields (rule identity, effect, match criteria, conditions), the same way a config file or a policy YAML document is written, not the way a Python class implementing an interface is written;
- **loaded or constructed outside evaluation** — bundle construction and validation happen before an `OperationAwareEvaluationEngine.evaluate()` call, not during it;
- **validated by basis-core** — structural shape, required fields, and enum membership are enforced by Pydantic validation and by `basis_core.policy.operation_aware.validation`'s semantic checks, during typed model construction and semantic bundle validation, before evaluation;
- **interpreted by deterministic kernel semantics** — the governed selector-matching, condition-evaluation, and aggregation logic in `policy/operation_aware/` reads the bundle's data and produces a result; the bundle itself contains no logic to invoke;
- **passed to `OperationAwareEnforcementPoint`** — the enforcement point (and the evaluation engine beneath it) receives the validated bundle as configuration, the same conceptual relationship `EnforcementPoint` has to its configured `PolicyEngine`;
- **not implemented by downstream consumers as Python callbacks** — a bundle author never writes a method the kernel calls back into. There is no `evaluate()`, `match()`, or `check()` method for a bundle author to implement anywhere in this family.

### `PolicyRule` versus `OperationAwarePolicyRule`: same-sounding names, different kinds of thing

The v0.1 `PolicyRule` extension point, documented in full at the top of this document, is **executable**: an object satisfies it by implementing

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

Downstream consumers may implement this `Protocol` today, subject to every behavioral requirement in the "PolicyRule contract" section above — determinism, statelessness, forbidden side effects, NOT_APPLICABLE-for-out-of-scope, and the rest. Nothing in the operation-aware release changes that.

`OperationAwarePolicyRule` is not a variant, extension, or successor of `PolicyRule`. It is a Pydantic `BaseModel` — a validated record containing an effect, match criteria, and conditions. A bundle author does not implement `OperationAwarePolicyRule.evaluate()`. No such method, and no such public protocol, exists anywhere in the v0.2.0 surface:

```text
PolicyBundle
    contains
OperationAwarePolicyRule records
    containing
structured match and condition data
```

To state the distinction plainly:

```text
PolicyRule
    remains the v0.1 executable extension protocol

OperationAwarePolicyRule
    is a validated operation-aware data model
```

The similar names — chosen because `PolicyRule` was already taken, per `docs/public-api.md`'s "Naming-collision note" — do not imply equivalent extension semantics. One is a code interface; the other is a record shape.

### Why no new executable extension point exists

The absence of an operation-aware `evaluate()`-style callback is a deliberate architectural position, not an oversight:

- **Deterministic behavior must remain centrally governed.** Selector matching, condition evaluation, and outcome aggregation for the operation-aware family are implemented once, in `policy/operation_aware/`, and reviewed as a unit. An executable per-rule callback would let each bundle author's code decide its own matching or aggregation behavior, fragmenting a semantic that `docs/kernel-constitution.md` Invariant 5 requires to be deterministic and centrally reasoned about.
- **Trace, response, and `AuditEvidence` semantics depend on a closed, reviewable evaluation pipeline.** `EvaluationTrace`, `OperationAwareDecisionResponse`, and `AuditEvidence` are assembled from the kernel's own bounded evaluation stages. A callback with unbounded behavior would make it impossible to guarantee the trace and audit-evidence artifacts faithfully and completely describe what happened.
- **Arbitrary callbacks would complicate reproducibility.** The determinism guarantee this document already states for `PolicyRule` — same inputs, same outcome, every call — is far harder to audit for third-party code invoked mid-pipeline than for structured data a validator can inspect once, statically.
- **Arbitrary callbacks could introduce hidden state or side effects.** A data model cannot make a network call, hold mutable state, or read a clock. A callback could, unless independently re-litigated against every forbidden-side-effect rule this document already establishes for `PolicyRule`.
- **Arbitrary callbacks could weaken bounded failure handling.** The six-value `OperationAwareFailureReason` vocabulary and the fail-closed guarantees of `OperationAwareEnforcementPoint` (ADR-0006, Decisions 7-9) are proven against a known, bounded set of failure modes. An arbitrary callback introduces failure modes the enforcement point cannot enumerate in advance.
- **Arbitrary callbacks could make canonical conformance difficult or impossible.** The canonical compatibility vectors (Milestone 12) assert that a given request and bundle produce an exact, reproducible response/trace/evidence shape. Executable per-bundle logic would make that assertion consumer-dependent rather than kernel-owned.
- **Arbitrary callbacks could bypass approved condition and aggregation semantics.** The ten-operator condition set and the deny-precedence/default-deny aggregation rules are the approved, reviewed authorization semantics for this family. A callback extension point would hand a bundle author a way to route around them entirely.
- **Public plugin interfaces create long-term compatibility obligations.** Per `docs/breaking-change-discipline.md`, an extension interface is a compatibility surface felt by every consumer simultaneously. Adding one is not free; it is a standing commitment.
- **No demonstrated requirement currently justifies that obligation.** Nothing in the accepted roadmap, the canonical vectors, or the merged operation-aware surface has identified a use case that structured data cannot already express.

None of this should be read as "executable extensibility is inherently bad" — `PolicyRule` itself is an executable extension point and remains fully supported. The correct framing is narrower: an executable operation-aware extension point has not been authorized for the initial v0.2.0 release because the need for one, and the compatibility contract it would require, have not been established.

### Supported customization today

A bundle author customizes operation-aware authorization entirely by authoring data within the governed model. This includes:

- bundle identity and version (`PolicyBundle`'s identity/version fields);
- bundle scope (`PolicyBundleScope`'s ten independently-optional selector categories);
- rule identity (`OperationAwarePolicyRule`'s identity field);
- rule effect (`RuleEffect`: `allow` / `deny`);
- selectors and match criteria (`OperationAwarePolicyMatch`'s twenty independently-optional selector categories);
- supported policy conditions (`PolicyCondition`'s field-path/operator/expected-value shape, using the currently-supported operator set — see below);
- rule ordering inputs where defined by the contract;
- evidence references and request context accepted by the public models (`IdentityEvidenceReference`, `AdapterEvidenceReference`, and the optional location/device/protocol/safety/environment/risk context objects on `OperationAwareDecisionRequest`).

This list tracks the merged model capabilities exactly, as inventoried in `docs/public-api.md`'s "Operation-aware public API (v0.2.0)" section. It does not extend to fields or semantics that do not exist in that inventory, and internal helper functions (next section) are never customization surfaces, however convenient a direct import might seem.

### Internal evaluation machinery is not an extension contract

The following are internal implementation detail, not extension contracts, regardless of the fact that they are implemented as importable Python functions and classes:

- `OperationAwareEvaluationEngine` (`evaluation/operation_aware/engine.py`);
- bundle-applicability helpers (`determine_applicability`, `ApplicabilityResult`, `policy/operation_aware/applicability.py`);
- selector helpers (`evaluate_rule_selectors`, `SelectorEvaluation`, `CandidateRuleEvaluation`, `policy/operation_aware/selector.py`);
- candidate-selection functions built on the above;
- condition evaluation functions (`evaluate_condition`, `ConditionEvaluation`, `RuleConditionEvaluation`, `policy/operation_aware/condition_eval.py`);
- the condition-operator implementation registry (`policy/operation_aware/operators.py`, including `SUPPORTED_OPERATORS` — see the dedicated treatment below);
- aggregation helpers (`aggregate_policy_outcome`, `OperationAwarePolicyOutcome`, `PolicyAggregationResult`, `policy/operation_aware/aggregation.py`);
- validation pipelines (`validate_policy_bundle`, `PolicyBundleValidationError` and its subtypes, `policy/operation_aware/validation.py`);
- trace assembly (`evaluation/operation_aware/trace_assembly.py`);
- response assembly (`assemble_operation_aware_decision_response`, `evaluation/operation_aware/response_assembly.py`);
- `AuditEvidence` assembly (`assemble_audit_evidence`, `evaluation/operation_aware/response_assembly.py`);
- private enforcement helpers inside `OperationAwareEnforcementPoint`.

`docs/public-api.md` already states this directly: these symbols are "reachable only via direct submodule import" and "not part of this documented public API," carrying "no compatibility guarantee." This section restates it here because the question this section exists to answer — "is there a second plugin interface?" — is exactly the question a contributor asks after finding one of these modules by grep. The fact that a function or class is importable, has a clear docstring, or is even convenient to call directly does not make it a supported plugin interface. Only the package surface and extension contracts actually documented in `docs/public-api.md` and in this document are supported contracts.

### Condition operators are governed semantics, not a plugin registry

`policy/operation_aware/operators.py` implements a fixed, ten-operator set (`SUPPORTED_OPERATORS`, an internal module-level immutable `frozenset[str]`) approved by the corresponding basis-architecture condition-operator-semantics clarification. This module must not be described, in this document or elsewhere, as:

- a plugin registry;
- a public registration API;
- dynamically extensible;
- an entry-point mechanism;
- a downstream callback interface.

`PolicyCondition.operator` is an open, structurally-validated string field — it does not reject an operator name the kernel does not implement at construction time — but this openness is a validation-shape decision, not an invitation for third parties to supply their own operator behavior. A structurally valid but unimplemented operator produces a governed, bounded outcome (a `no_match`/`error`-classified `ConditionEvaluation`, per `operators.py`'s own contract), never a callout to consumer-supplied code.

Adding a new built-in operator to this set is possible, and may be a purely additive semantic expansion, but it is not a matter of local convenience. It requires, at minimum: architecture review where required; contract and vocabulary review (the operator set is governed by a basis-architecture clarification, not solely by this repository); a deterministic implementation; compatibility analysis; exhaustive tests; documentation; and schema or shared-contract alignment where applicable. No mechanism exists, and none is proposed here, for a third party to register an arbitrary operator at runtime.

### The threshold for a future executable operation-aware extension point

Nothing in this section forecloses a future executable operation-aware extension mechanism. No such mechanism is part of the initial v0.2.0 surface, but the correct wording for that fact is bounded, not absolute:

No executable operation-aware policy extension point is part of the initial v0.2.0 surface. A future governed decision may add one if a real need is demonstrated. Until then, contributors must not introduce one informally.

A future decision to add one would be a new, separately governed architecture decision — an ADR in basis-architecture, following the same process `docs/breaking-change-discipline.md` requires for any new extension-interface surface — and would need to define, at minimum:

- demonstrated use cases;
- interface ownership;
- exact method signatures;
- input and output contracts;
- deterministic requirements;
- permitted and forbidden state;
- permitted and forbidden side effects;
- failure containment;
- timeout or resource-bound behavior, if applicable;
- trace and `AuditEvidence` integration;
- serialization and versioning;
- compatibility obligations;
- import boundaries;
- security implications;
- canonical conformance behavior;
- deprecation and breaking-change policy.

This section does not create that ADR, does not design the hypothetical protocol, and does not speculate about its shape. It states only the governance bar a future proposal would have to clear.

### What would count as an unauthorized informal extension point

The following changes — an illustrative list, not an exhaustive design specification — would introduce an executable operation-aware extension point and therefore require the governance described above before landing. None of them exist in the merged v0.2.0 surface:

- adding an `OperationAwarePolicyRuleProtocol`;
- adding `evaluate()` callbacks to operation-aware rules;
- accepting arbitrary Python callables as conditions;
- runtime operator registration;
- package entry-point discovery;
- dynamic module loading;
- user-supplied evaluator classes;
- arbitrary expression-language execution;
- adding a plugin object to `PolicyBundle`;
- allowing callbacks to directly construct authoritative traces, responses, or `AuditEvidence`.

A contributor proposing any of these — even framed as a small convenience, an internal helper, or a test-only mechanism that might later be exposed — should treat it as a new extension-point proposal subject to the threshold above, not as an implementation detail of the current roadmap.

### v0.1 contracts are preserved, unchanged, and not deprecated

`PolicyRule`, `AuditWriter`, and `AdapterBase` remain supported exactly as documented above. Their existing contracts are unchanged by anything in this section or by the operation-aware release generally. No migration is required for v0.1 consumers, and operation-aware additions do not deprecate the v0.1 extension points. The operation-aware data model (`PolicyBundle` and its nested shapes) is an additive parallel family, evaluated through its own `OperationAwareEnforcementPoint` alongside the existing `EnforcementPoint` — not a replacement for, and not implying any recommended rewrite of, v0.1 policies. Downstream consumers are not expected to migrate v0.1 `PolicyRule` implementations into operation-aware bundles unless a future, separately-scoped migration or adoption guide says otherwise.
