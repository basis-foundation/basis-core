# Public API Surface

This document is the authoritative inventory of what external consumers may import and depend on from basis-core. It classifies every symbol into one of three tiers and specifies the import path for each.

Cross-references: `docs/import-boundaries.md` defines the allowed dependency graph between subpackages. `docs/extension-contracts.md` specifies the behavioral contracts for extension-point interfaces. `docs/compatibility-testing.md` describes the test harness that protects the serialised shapes of public contracts. `docs/schema-versioning.md` governs schema evolution. `docs/kernel-constitution.md` states the invariants that constrain this surface. `docs/breaking-change-discipline.md` defines the required process for any change to this surface.

---

## Tiers

**Stable public API** — Types, functions, and constants that application code, gateways, and adapters may import and depend on. Symbols in this tier follow the compatibility rules in `docs/architecture/compatibility-philosophy.md` in basis-architecture: additive changes are allowed; breaking changes require an ADR.

**Extension API** — Interfaces (`Protocol` classes) and the supporting types extension implementations need to satisfy them. A subset of the stable public API, called out separately because implementors have different needs from callers. The same compatibility rules apply.

**Internal** — Implementation details. Prefixed with `_` by convention but listed here for clarity. Must not be imported by code outside `basis_core`. No compatibility guarantee.

---

## Stable public API

### `basis_core.domain`

Core domain types. No imports from any other `basis_core` subpackage. Immutable value objects only.

| Symbol | Import path | Description |
|---|---|---|
| `Subject` | `basis_core.domain` or `basis_core.domain.subject` | Frozen Pydantic model. Normalized identity of any entity performing an action. |
| `SubjectType` | `basis_core.domain` or `basis_core.domain.subject` | Enum: `HUMAN`, `DEVICE`, `SERVICE`, `GATEWAY`, `AGENT`. |
| `subject_from_jwt` | `basis_core.domain` or `basis_core.domain.subject` | **Deprecated** — see ADR-0005. Factory: constructs a `Subject` from a decoded OIDC/JWT payload. Assumes Keycloak/OIDC claim conventions; this is a kernel boundary violation. JWT normalization belongs at the gateway layer. Will be removed in a future release. Do not introduce new dependencies on this function. |
| `Resource` | `basis_core.domain` or `basis_core.domain.resource` | Frozen Pydantic model. Immutable descriptor for any OT resource. |
| `ResourceType` | `basis_core.domain` or `basis_core.domain.resource` | Enum: `HVAC`, `SENSOR`, `ZONE`, `DEVICE`, `GATEWAY`. |
| `build_resource_id` | `basis_core.domain` or `basis_core.domain.resource` | Utility: constructs a normalized `{type}:{qualifier}` resource identifier. |
| `parse_resource_id` | `basis_core.domain` or `basis_core.domain.resource` | Utility: splits a resource identifier into `(type_str, qualifiers)`. |
| `IdentityContext` | `basis_core.domain` or `basis_core.domain.identity` | Frozen Pydantic model. Verified identity context carried across trust boundaries. |
| `action` module | `basis_core.domain.action` | Module of action-name constants (`READ_SENSOR_TELEMETRY`, `WRITE_HVAC_SETPOINT`, etc.). Import the module directly. |

Preferred import style:

```python
from basis_core.domain import Subject, SubjectType, Resource, ResourceType, IdentityContext
from basis_core.domain import build_resource_id, parse_resource_id, subject_from_jwt
from basis_core.domain import action as actions   # access constants as actions.WRITE_HVAC_SETPOINT
```

### `basis_core.decisions`

Data contracts at the enforcement boundary. What goes in (`DecisionRequest`) and what comes out (`DecisionResponse`).

| Symbol | Import path | Description |
|---|---|---|
| `DecisionRequest` | `basis_core.decisions` or `basis_core.decisions.models` | Pydantic model. Normalized authorization request submitted to the `EnforcementPoint`. |
| `DecisionResponse` | `basis_core.decisions` or `basis_core.decisions.models` | Pydantic model. Result of an authorization evaluation. |
| `DecisionOutcome` | `basis_core.decisions` or `basis_core.decisions.models` | Enum: `ALLOW`, `DENY`, `NOT_APPLICABLE`. |
| `FailureReason` | `basis_core.decisions` or `basis_core.decisions.models` | Enum: `MALFORMED_REQUEST`, `POLICY_ERROR`, `AUDIT_ERROR`, `INTERNAL_ERROR`. Set on `DecisionResponse.failure_reason` for enforcement-boundary failures only. |

Preferred import style:

```python
from basis_core.decisions import DecisionRequest, DecisionResponse, DecisionOutcome, FailureReason
```

### `basis_core.policy`

Policy evaluation engine and built-in rule implementations.

| Symbol | Import path | Description |
|---|---|---|
| `PolicyEngine` | `basis_core.policy` or `basis_core.policy.engine` | Evaluates authorization requests against a list of `PolicyRule` implementations using deny-overrides semantics. |
| `PolicyRule` | `basis_core.policy` or `basis_core.policy.engine` | `@runtime_checkable Protocol`. The interface all policy rule implementations must satisfy. Also an extension-API symbol. |
| `Decision` | `basis_core.policy` or `basis_core.policy.engine` | Outcome of a single policy rule evaluation, with `reason` and `evaluated_by` fields for audit records. |
| `PolicyOutcome` | `basis_core.policy` or `basis_core.policy.engine` | Enum: `ALLOW`, `DENY`, `NOT_APPLICABLE`. Used by `Decision` and by rule implementations. |
| `RolePolicyRule` | `basis_core.policy` or `basis_core.policy.rules` | RBAC rule: maps action names to sets of permitted roles. |
| `ResourceTypePolicyRule` | `basis_core.policy` or `basis_core.policy.rules` | Constrains which `ResourceType` values are permitted targets. |
| `ActionPolicyRule` | `basis_core.policy` or `basis_core.policy.rules` | Assigns explicit `PolicyOutcome` values to named actions (allowlist or denylist). |

Preferred import style:

```python
from basis_core.policy import PolicyEngine, PolicyRule, Decision, PolicyOutcome
from basis_core.policy import RolePolicyRule, ResourceTypePolicyRule, ActionPolicyRule
```

### `basis_core.audit`

Audit event types, the `AuditWriter` protocol, and traceability structures.

| Symbol | Import path | Description |
|---|---|---|
| `AuditEvent` | `basis_core.audit` or `basis_core.audit.events` | Frozen Pydantic model. Canonical record of a security-relevant event. |
| `AuditEventType` | `basis_core.audit` or `basis_core.audit.events` | Enum: `AUTHORIZATION_DECISION`, `POLICY_CHANGE`, `IDENTITY_EVENT`, `EMERGENCY_OVERRIDE`, `ADAPTER_EVENT`, `SYSTEM_EVENT`. |
| `AuditOutcome` | `basis_core.audit` or `basis_core.audit.events` | Enum: `ALLOWED`, `DENIED`, `ERROR`. Recorded on authorization decision events. |
| `AUDIT_SCHEMA_VERSION` | `basis_core.audit` or `basis_core.audit.events` | String constant. Current `AuditEvent` schema revision (`"1.1"`). |
| `AuditWriter` | `basis_core.audit` or `basis_core.audit.writer` | `@runtime_checkable Protocol`. Interface for audit record persistence backends. Also an extension-API symbol. |
| `NullAuditWriter` | `basis_core.audit` or `basis_core.audit.writer` | Discards all events. For tests and unconfigured environments only. |
| `LogAuditWriter` | `basis_core.audit` or `basis_core.audit.writer` | Writes events as structured JSON to a Python logger. For development and log-pipeline environments. |
| `DecisionTrace` | `basis_core.audit` or `basis_core.audit.trace` | Frozen Pydantic model. Per-rule evaluation history that produced a final decision. |
| `RuleEvaluation` | `basis_core.audit` or `basis_core.audit.trace` | Frozen Pydantic model. Outcome produced by a single rule during trace collection. |

Preferred import style:

```python
from basis_core.audit import (
    AuditEvent, AuditEventType, AuditOutcome, AUDIT_SCHEMA_VERSION,
    AuditWriter, NullAuditWriter, LogAuditWriter,
    DecisionTrace, RuleEvaluation,
)
```

### `basis_core.enforcement`

The authorization boundary. Orchestrates policy evaluation and audit writing.

| Symbol | Import path | Description |
|---|---|---|
| `EnforcementPoint` | `basis_core.enforcement` or `basis_core.enforcement.enforcement` | The single component authorized to compose `PolicyEngine` evaluation and `AuditWriter` recording in one path. Never raises; all failure paths produce a safe `DENY`. |
| `EnforcementPoint.policy_version` | property on `EnforcementPoint` | Read-only. The policy version identifier supplied at construction (`policy_version` parameter), or `None` if not set. Propagated verbatim into every `DecisionResponse.policy_version` and `AuditEvent.policy_version` this instance produces. Provenance metadata only — does not affect evaluation semantics. |

Preferred import style:

```python
from basis_core.enforcement import EnforcementPoint
```

### `basis_core.adapters`

Protocol adapter contracts. Defines what adapters must produce; concrete adapter implementations live outside this repository.

| Symbol | Import path | Description |
|---|---|---|
| `AdapterBase` | `basis_core.adapters` or `basis_core.adapters.base` | `@runtime_checkable Protocol`. Lifecycle interface all protocol adapters implement (`adapter_id`, `protocol`, `start()`, `stop()`). Also an extension-API symbol. |
| `NormalizedEvent` | `basis_core.adapters` or `basis_core.adapters.base` | Pydantic model. Protocol-agnostic representation of a field-protocol message, as produced by adapter normalization. |

Preferred import style:

```python
from basis_core.adapters import AdapterBase, NormalizedEvent
```

---

## Extension API

The extension API is the subset of the stable public API used by implementors of custom policy rules, audit backends, and protocol adapters. All stability and compatibility guarantees of the stable public API apply here.

### Implementing a custom `PolicyRule`

Implement `evaluate()` with the required signature. No class inheritance is required.

Required imports:

```python
from basis_core.policy import PolicyRule, Decision, PolicyOutcome
from basis_core.domain import Subject, IdentityContext          # parameter types
```

Skeleton:

```python
class MyRule:
    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        ...
```

See `docs/extension-contracts.md` for the full behavioral contract.

### Implementing a custom `AuditWriter`

Implement `write(event: AuditEvent) -> None`. No class inheritance required.

Required imports:

```python
from basis_core.audit import AuditWriter, AuditEvent
```

`write()` must not raise, must not mutate `event`, and must not influence the authorization decision. See `docs/extension-contracts.md` for the full behavioral contract.

### Implementing a protocol `AdapterBase`

Expose `adapter_id: str`, `protocol: str`, `start() -> None`, and `stop() -> None`.

Required imports:

```python
from basis_core.adapters import AdapterBase, NormalizedEvent
from basis_core.decisions import DecisionRequest              # to construct requests
```

See `docs/extension-contracts.md` and `docs/adapter-contracts.md` for the full behavioral contract.

---

## Operation-aware public API (v0.2.0)

The following additive surface is stabilized on `main` for the forthcoming v0.2.0 release.

The operation-aware API is a purely additive family of typed models, sitting alongside the v0.1 stable public API documented above. Every existing v0.1 stable and extension symbol listed above remains supported, unmodified, and at its existing import path — nothing in this section renames, replaces, subclasses, or reinterprets any v0.1 symbol. `OperationAwareDecisionRequest` coexists with `DecisionRequest`; `OperationAwareEnforcementPoint` coexists with `EnforcementPoint`; `AuditEvidence`/`EvaluationTrace`/`TraceRuleEvidence` coexist with `AuditEvent`/`DecisionTrace`/`RuleEvaluation`. This is not a migration path and not a deprecation of v0.1 — both families are expected to be used, independently, for as long as their respective consumers need them.

Operation-aware policy (`PolicyCondition`, `OperationAwarePolicyRule`, `PolicyBundle`, and their nested shapes) is **structured data** — a bundle a policy author authors and a validator inspects — not executable code and not a new extension-point `Protocol`. This PR introduces no new extension API: implementors still satisfy exactly the three extension points documented above (`PolicyRule`, `AuditWriter`, `AdapterBase`). `docs/extension-contracts.md` will record this "policy is data, not a plugin interface" position explicitly in a later PR.

The evaluation-orchestration package (`basis_core.evaluation`, including `basis_core.evaluation.operation_aware`) remains internal. It has no `__all__`, no package-level export, and no entry in this document. `OperationAwareEvaluationEngine`, `OperationAwareDecisionResponse`, and every response/trace/audit-evidence assembly function are implementation details reached only indirectly, through `OperationAwareEnforcementResult.response` after calling `OperationAwareEnforcementPoint.evaluate()`. Whether and how to expose the evaluation package directly is a later, separately-scoped public-integration decision, not made by this PR.

Gateway- and runtime-enforcement concerns (`GatewayAuditEvent`, HTTP/routing behavior, retry/timeout policy) remain entirely outside `basis-core`, as before. Nothing in this section changes that boundary.

### `basis_core.domain` — operation-aware additions

Shared vocabulary, evidence-reference models, and context value objects consumed by `OperationAwareDecisionRequest` and by other operation-aware models throughout the kernel.

| Symbol | Import path | Category | Responsibility | Compatibility |
|---|---|---|---|---|
| `RedactionClassification` | `basis_core.domain` | Stable model — vocabulary | Closed, five-value enum classifying how a piece of evidence may appear in a trace/audit/explanation artifact. | New in v0.2.0 |
| `ReasonCode` | `basis_core.domain` | Stable model — vocabulary | Validated, machine-readable reason-code string token (lowercase snake_case format, open vocabulary). | New in v0.2.0 |
| `EvidenceDigest` | `basis_core.domain` | Stable model | Structural digest reference (algorithm label + hex value) nested inside both evidence-reference models. | New in v0.2.0 |
| `IdentityEvidenceReference` | `basis_core.domain` | Stable model | Safe reference to identity evidence produced outside the kernel (typically by basis-identity); never the evidence itself. | New in v0.2.0 |
| `AdapterEvidenceReference` | `basis_core.domain` | Stable model | Safe reference to normalized adapter evidence produced outside the kernel (typically by basis-adapters). | New in v0.2.0 |
| `OperationAwareLocation` | `basis_core.domain` | Stable model — context | Optional physical/logical location context (site, building, zone, area); no hierarchy enforcement. | New in v0.2.0 |
| `OperationAwareDevice` | `basis_core.domain` | Stable model — context | Optional device context (device identifier, device class). | New in v0.2.0 |
| `OperationAwareProtocolContext` | `basis_core.domain` | Stable model — context | Optional, protocol-neutral provenance context (protocol label, protocol-native operation name); evidence only. | New in v0.2.0 |
| `OperationAwareSafetyContext` | `basis_core.domain` | Stable model — context | Optional supplied safety-relevant context; no safety-state inference or calculation. | New in v0.2.0 |
| `OperationAwareEnvironmentContext` | `basis_core.domain` | Stable model — context | Optional supplied operational-environment context. | New in v0.2.0 |
| `OperationAwareRiskContext` | `basis_core.domain` | Stable model — context | Optional supplied risk context; no risk calculation or enforced numeric range. | New in v0.2.0 |

### `basis_core.decisions` — operation-aware additions

The operation-aware authorization request and its closed evaluation-result vocabularies.

| Symbol | Import path | Category | Responsibility | Compatibility |
|---|---|---|---|---|
| `OperationAwareDecisionRequest` | `basis_core.decisions` | Stable model | Typed, additive sibling of `DecisionRequest` carrying operational context (evidence references, location/device/protocol/safety/environment/risk context). | New in v0.2.0 |
| `OperationIntent` | `basis_core.decisions` | Stable model — vocabulary | Closed, three-value vocabulary (`read_only` / `state_changing` / `control_affecting`) for a request's `operation_intent` field. | New in v0.2.0 |
| `OperationAwareFailureReason` | `basis_core.decisions` | Stable model — vocabulary | Closed, six-value governed evaluator failure-category vocabulary, shared by policy/audit/evaluation. | New in v0.2.0 |
| `OperationAwareEvaluationStatus` | `basis_core.decisions` | Stable model — vocabulary | Closed, two-value vocabulary (`completed` / `failed`) for whether evaluation produced a valid authorization decision. | New in v0.2.0 |
| `OperationAwareDecisionOutcome` | `basis_core.decisions` | Stable model — vocabulary | Closed, three-value authorization-outcome vocabulary (`allow` / `deny` / `not_applicable`), matching the response/trace/policy-rule outcome vocabulary. | New in v0.2.0 |

### `basis_core.policy` — operation-aware additions

Structured operation-aware policy data models — data a bundle author authors, not a new extension point. `PolicyRule` (the v0.1.0 extension-point `Protocol`) is unaffected and unchanged.

| Symbol | Import path | Category | Responsibility | Compatibility |
|---|---|---|---|---|
| `PolicyCondition` | `basis_core.policy` | Stable model | A single, inert, data-only predicate (field-path, open operator, expected value). Structural shape only — no evaluation. | New in v0.2.0 |
| `OperationAwarePolicyRule` | `basis_core.policy` | Stable model | A single, inert, data-only unit of authorization evaluation (effect, match criteria, conditions). Distinct name from `PolicyRule` by design — see naming-collision note below. | New in v0.2.0 |
| `OperationAwarePolicyMatch` | `basis_core.policy` | Stable model | Structured, closed-shape nested match object (twenty independently-optional selector categories). | New in v0.2.0 |
| `RuleEffect` | `basis_core.policy` | Stable model — vocabulary | Closed, two-value vocabulary (`allow` / `deny`) for a rule's `effect` field. | New in v0.2.0 |
| `PolicyBundle` | `basis_core.policy` | Stable model | The unit of policy identity, versioning, ownership, provenance, optional scope, and rule grouping. | New in v0.2.0 |
| `PolicyBundleScope` | `basis_core.policy` | Stable model | Structured, closed-shape nested scope object (ten independently-optional selector categories). | New in v0.2.0 |

**Naming-collision note.** `basis_core.policy.engine.PolicyRule` is a v0.1.0 `Protocol` (a code interface), already re-exported from `basis_core.policy` and unchanged by this PR. `OperationAwarePolicyRule` is an unrelated v0.2.0 *data model* (a Pydantic `BaseModel`). `from basis_core.policy import PolicyRule` continues to resolve to the existing v0.1.0 `Protocol`; the operation-aware model is exported only under its distinct name, `OperationAwarePolicyRule`, never as `PolicyRule`.

**Internal — not exported.** Policy-owned bundle-applicability determination, rule-selector matching, condition operators/evaluation, aggregation, and structural/semantic bundle validation (`determine_applicability`, `ApplicabilityResult`, `evaluate_rule_selectors`, `SelectorEvaluation`, `CandidateRuleEvaluation`, condition operators, `ConditionEvaluation`, `RuleConditionEvaluation`, `aggregate_policy_outcome`, `OperationAwarePolicyOutcome`, `PolicyAggregationResult`, `validate_policy_bundle`, `PolicyBundleValidationError` and its subtypes) remain internal implementation detail. They are reachable only via direct submodule import, are not part of this documented public API, and carry no compatibility guarantee.

### `basis_core.audit` — operation-aware additions

Kernel-produced, bounded trace and audit evidence models. None of these extend, subclass, or alter `DecisionTrace`, `RuleEvaluation`, or `AuditEvent` above.

| Symbol | Import path | Category | Responsibility | Compatibility |
|---|---|---|---|---|
| `TraceRuleEvidence` | `basis_core.audit` | Stable evidence model | Bounded explanation record for one policy rule considered during one evaluation. | New in v0.2.0 |
| `TraceConditionEvidence` | `basis_core.audit` | Stable evidence model | Bounded per-condition entry nested inside `TraceRuleEvidence.condition_results`. | New in v0.2.0 |
| `TraceRuleEffect` | `basis_core.audit` | Stable model — vocabulary | Closed `allow`/`deny` vocabulary for trace-evidence purposes (parity-tested against `policy`'s `RuleEffect`, not imported from it). | New in v0.2.0 |
| `RuleResult` | `basis_core.audit` | Stable model — vocabulary | Closed `matched`/`not_matched`/`skipped`/`error` vocabulary. | New in v0.2.0 |
| `TraceConditionResult` | `basis_core.audit` | Stable model — vocabulary | Closed `matched`/`not_matched`/`error` vocabulary. | New in v0.2.0 |
| `EvaluationTrace` | `basis_core.audit` | Stable evidence model | Bounded, deterministic explanation of one kernel authorization evaluation. | New in v0.2.0 |
| `EvaluationStatus` | `basis_core.audit` | Stable model — vocabulary | Closed `completed`/`failed` vocabulary (audit's own local copy; parity-tested against `decisions`'s `OperationAwareEvaluationStatus`). | New in v0.2.0 |
| `TraceOutcome` | `basis_core.audit` | Stable model — vocabulary | Closed `allow`/`deny`/`not_applicable` vocabulary (audit's own local copy). | New in v0.2.0 |
| `TraceBundleApplicability` | `basis_core.audit` | Stable model — vocabulary | Closed bundle-applicability vocabulary (audit's own local copy; parity-tested against `policy`'s internal `ApplicabilityResult`). | New in v0.2.0 |
| `TraceFailureReason` | `basis_core.audit` | Stable model — vocabulary | Closed six-value governed failure-category vocabulary (audit's own local copy; parity-tested against `decisions`'s `OperationAwareFailureReason`). | New in v0.2.0 |
| `AuditEvidence` | `basis_core.audit` | Stable evidence model | Bounded, durable, kernel-side evidence record of one operation-aware authorization evaluation. Not persisted by `basis-core`. | New in v0.2.0 |
| `AUDIT_EVIDENCE_SCHEMA_VERSION` | `basis_core.audit` | Stable model — constant | String constant. Current `AuditEvidence` schema revision. | New in v0.2.0 |

### `basis_core.enforcement` — operation-aware additions

The operation-aware enforcement boundary. `EnforcementPoint` above is unaffected and unchanged; `OperationAwareEnforcementPoint` does not modify, subclass, or share implementation with it (ADR-0006 Decision 1).

| Symbol | Import path | Category | Responsibility | Compatibility |
|---|---|---|---|---|
| `OperationAwareEnforcementPoint` | `basis_core.enforcement` | Stable entry point | Fail-closed operation-aware enforcement orchestration; `evaluate()` never raises. Composes evaluation, response assembly, and audit-evidence assembly. | New in v0.2.0 |
| `OperationAwareEnforcementResult` | `basis_core.enforcement` | Stable enforcement result | Immutable carrier binding one evaluation's `OperationAwareDecisionResponse`, optional `AuditEvidence`, and `EnforcementDisposition` together. | New in v0.2.0 |
| `EnforcementDisposition` | `basis_core.enforcement` | Stable model — vocabulary | Closed, two-value (`allow`/`deny`) enforcement-only vocabulary. Distinct from the three-value kernel authorization outcome. | New in v0.2.0 |

Preferred import style:

```python
from basis_core.domain import (
    RedactionClassification, ReasonCode, EvidenceDigest,
    IdentityEvidenceReference, AdapterEvidenceReference,
    OperationAwareLocation, OperationAwareDevice, OperationAwareProtocolContext,
    OperationAwareSafetyContext, OperationAwareEnvironmentContext, OperationAwareRiskContext,
)
from basis_core.decisions import (
    OperationAwareDecisionRequest, OperationIntent,
    OperationAwareFailureReason, OperationAwareEvaluationStatus, OperationAwareDecisionOutcome,
)
from basis_core.policy import (
    PolicyCondition, OperationAwarePolicyRule, OperationAwarePolicyMatch,
    RuleEffect, PolicyBundle, PolicyBundleScope,
)
from basis_core.audit import (
    TraceRuleEvidence, TraceConditionEvidence, TraceRuleEffect, RuleResult, TraceConditionResult,
    EvaluationTrace, EvaluationStatus, TraceOutcome, TraceBundleApplicability, TraceFailureReason,
    AuditEvidence, AUDIT_EVIDENCE_SCHEMA_VERSION,
)
from basis_core.enforcement import (
    OperationAwareEnforcementPoint, OperationAwareEnforcementResult, EnforcementDisposition,
)
```

---

## Internal symbols

The following are implementation details. They must not be imported by code outside `basis_core`. No compatibility guarantee is made for any symbol beginning with `_`.

| Symbol | Location | Notes |
|---|---|---|
| `_RESOURCE_ID_RE` | `basis_core.domain.resource` | Compiled regex for resource ID validation. |
| `_ACTION_RE` | `basis_core.decisions.models` | Compiled regex for action name validation. |
| `_RESOURCE_ID_RE` | `basis_core.decisions.models` | Duplicate of the domain regex; kept local to avoid a cross-module dependency. |
| `_POLICY_OUTCOME_TO_DECISION_OUTCOME` | `basis_core.enforcement.enforcement` | Internal outcome mapping table. |
| `_DECISION_OUTCOME_TO_AUDIT_OUTCOME` | `basis_core.enforcement.enforcement` | Internal outcome mapping table. |
| `_REASON_MALFORMED`, `_REASON_POLICY_ERROR`, `_REASON_INTERNAL` | `basis_core.enforcement.enforcement` | Sanitised caller-visible reason strings for enforcement failures. |
| `EnforcementPoint._write_audit` | `basis_core.enforcement.enforcement` | Private method; not part of the `EnforcementPoint` public interface. |
| `EnforcementPoint._engine`, `._audit_writer` | `basis_core.enforcement.enforcement` | Private attributes. Access `policy_version` via the public property instead. |
| `log` (all packages) | various | Module-level Python loggers. Not exported. |

---

## Deprecated surface

### `basis_core.api`

`basis_core.api` and `basis_core.api.enforcement` are **deprecated stubs** scheduled for removal after v0.1. They were created during an internal refactor when `EnforcementPoint` lived in `api/` and was later moved to `enforcement/`. Importing from either path now emits a `DeprecationWarning`.

**Do not import from `basis_core.api`.** Use `basis_core.enforcement` instead:

```python
# Deprecated — emits DeprecationWarning, will be removed
from basis_core.api.enforcement import EnforcementPoint

# Correct
from basis_core.enforcement import EnforcementPoint
```

The `basis_core.api` package is not protected by the public API test suite and carries no compatibility guarantee. It will be removed in the release following v0.1.

---

## Package-level `__all__` exports

Each subpackage `__init__.py` declares an explicit `__all__` that mirrors the stable public API inventory above. This ensures that `from basis_core.<package> import *` exposes only the declared symbols, and that static analysis tools can enumerate the public surface without inspecting every submodule.

The `test_public_api.py` test suite verifies that:
1. Every symbol listed here is importable from its declared import path.
2. Each package's `__all__` exactly matches the inventory.
3. Internal symbols (those beginning with `_`) are not re-exported by any package `__init__.py`.

---

## Open API questions

The following questions are deferred to basis-architecture. They are tracked here to prevent accidental resolution through implementation choices.

**`basis_core.domain.action` module pattern** — The `action` module is a flat collection of string constants. It is currently re-exported as a module (not individual symbols). Whether to additionally export individual constants from `basis_core.domain` is an open question. The current approach (import the module) is consistent and avoids polluting the `domain` namespace with ~15 string constants. Track as `OPEN: action-module-export-pattern`.

**Top-level `basis_core` namespace** — `basis_core.__init__.py` currently exports nothing. Whether to provide a convenience namespace (`from basis_core import Subject, EnforcementPoint, ...`) is deliberately deferred. A flat top-level namespace is ergonomic but commits to a fixed shape that is harder to evolve. Track as `OPEN: top-level-namespace`.

**`subject_from_jwt` placement** — Resolved by ADR-0005. JWT/OIDC normalization belongs at the gateway layer, not in the kernel. `subject_from_jwt` is deprecated. It will be removed in a future release. New code should implement normalization in `basis-gateway` or an equivalent trusted runtime component. See `docs/adr/ADR-0005-move-jwt-normalization-outside-kernel.md`.
