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
| `subject_from_jwt` | `basis_core.domain` or `basis_core.domain.subject` | Factory: constructs a `Subject` from a decoded OIDC/JWT payload. |
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
| `EnforcementPoint._engine`, `._audit_writer`, `._policy_version` | `basis_core.enforcement.enforcement` | Private attributes. |
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

**`subject_from_jwt` placement** — `subject_from_jwt` is in `basis_core.domain.subject` but assumes a Keycloak/OIDC JWT structure. It is a convenience factory, not a core domain type. Whether it belongs in a future `basis_core.auth` helper module rather than `domain` is an open question. Track as `OPEN: subject-from-jwt-placement`.
