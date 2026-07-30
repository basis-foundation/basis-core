# Operation-Aware Model

This document is a public, implementation-level overview of the operation-aware authorization surface merged into `basis-core`. It describes the models, the policy data shape, and the enforcement entry point as they exist in the current codebase.

Cross-references: `docs/operation-aware-evaluation-semantics.md` covers how a request is actually evaluated. `docs/public-api.md` is the authoritative inventory of what is importable. `docs/extension-contracts.md` records that the operation-aware policy family is structured data, not a new extension point. `docs/import-boundaries.md` and `docs/kernel-constitution.md` state the layering this surface obeys. `docs/implementation/basis-core-v0.2-operation-aware-plan.md` is the roadmap that sequenced this work. Architectural authority for everything summarized here lives in `basis-architecture` — ADR-0001 through ADR-0006 and their companion documents, cited throughout.

---

## 1. Overview

The operation-aware surface adds richer OT authorization context alongside the existing v0.1 API. It is additive: it does not replace or deprecate v0.1. Existing `DecisionRequest`, `PolicyEngine`, `EnforcementPoint`, and `AuditEvent` behavior is unchanged by anything described here.

Operation-aware consumers use a separate request model, a separate structured policy model, a separate evaluator, a separate evidence family, and a separate enforcement point. `OperationAwareDecisionRequest` coexists with `DecisionRequest`; `OperationAwareEnforcementPoint` coexists with `EnforcementPoint`; `AuditEvidence`/`EvaluationTrace`/`TraceRuleEvidence` coexist with `AuditEvent`/`DecisionTrace`/`RuleEvaluation`. Nothing in this document should be read as recommending migration — v0.1 remains a fully supported public surface, and the two families are expected to be used independently, each for as long as their own consumers need them.

`basis-architecture` defines the semantics this surface implements. `basis-schemas` publishes the contract shapes the merged models were built against. `basis-core` implements deterministic evaluation over those contracts. This document explains the implementation; it is not a new architecture decision, not a replacement contract specification, and not a policy-language specification.

---

## 2. Model Map

### Domain and request vocabulary

| Symbol | Package | Role |
|---|---|---|
| `RedactionClassification` | `basis_core.domain` | Closed, five-value enum classifying how a piece of evidence may appear in a trace/audit/explanation artifact. |
| `ReasonCode` | `basis_core.domain` | Validated, machine-readable reason-code token (lowercase snake_case; open vocabulary — a format, not a closed enum). |
| `EvidenceDigest` | `basis_core.domain` | Structural digest reference (algorithm label + hex value) nested inside both evidence-reference models. |
| `IdentityEvidenceReference` | `basis_core.domain` | Bounded reference to identity evidence produced outside the kernel (typically by `basis-identity`). |
| `AdapterEvidenceReference` | `basis_core.domain` | Bounded reference to normalized adapter evidence produced outside the kernel (typically by `basis-adapters`). |
| `OperationAwareLocation` | `basis_core.domain` | Optional location context (site/building/zone/area); no hierarchy enforcement. |
| `OperationAwareDevice` | `basis_core.domain` | Optional device context (device identifier, device class). |
| `OperationAwareProtocolContext` | `basis_core.domain` | Optional, protocol-neutral provenance context (protocol label, protocol-native operation name); evidence only. |
| `OperationAwareSafetyContext` | `basis_core.domain` | Optional supplied safety-relevant context; no safety-state inference. |
| `OperationAwareEnvironmentContext` | `basis_core.domain` | Optional supplied operational-environment context. |
| `OperationAwareRiskContext` | `basis_core.domain` | Optional supplied risk context; no risk calculation or enforced numeric range. |
| `OperationIntent` | `basis_core.decisions` | Closed, three-value vocabulary (`read_only` / `state_changing` / `control_affecting`). |
| `OperationAwareDecisionRequest` | `basis_core.decisions` | The operation-aware request model itself (Section 3). |

`IdentityEvidenceReference` and `AdapterEvidenceReference` are bounded *references*, not trust proofs. Neither model retrieves the evidence it points to, verifies its source, or validates a cryptographic signature. Raw JWTs, passwords, credentials, complete claim sets, session secrets, and raw protocol payloads are not modeled as fields anywhere in this family — the shape simply does not admit such a value, and every model in this family rejects unknown fields at construction (`extra="forbid"`).

### Policy data model

| Symbol | Package | Role |
|---|---|---|
| `PolicyCondition` | `basis_core.policy` | A single, inert, data-only predicate: `condition_id`, a dotted `field_path`, an open `operator` string, and a scalar or homogeneous-array `expected_value`. |
| `OperationAwarePolicyRule` | `basis_core.policy` | A single, inert, data-only unit of authorization evaluation: `rule_id`, `effect`, optional `match`, optional `conditions`, optional `reason_code`/`explanation`. |
| `OperationAwarePolicyMatch` | `basis_core.policy` | Structured, closed-shape nested match object — twenty independently-optional selector categories. |
| `RuleEffect` | `basis_core.policy` | Closed, two-value vocabulary (`allow` / `deny`). |
| `PolicyBundle` | `basis_core.policy` | The unit of policy identity, versioning, ownership, provenance, optional scope, and rule grouping. |
| `PolicyBundleScope` | `basis_core.policy` | Structured, closed-shape nested scope object — ten independently-optional selector categories. |

These are structured, validated data — a bundle a policy author authors and a validator inspects. They are not executable extension-point objects, and they do not replace the v0.1 `PolicyRule` Protocol.

**Naming.** `basis_core.policy.engine.PolicyRule` (re-exported from `basis_core.policy`) remains the v0.1 executable `Protocol` — an interface a caller implements with a Python `evaluate()` method. `OperationAwarePolicyRule` is an unrelated v0.2.0 Pydantic data model with no `evaluate()` method and no execution behavior of any kind. The names are similar because `PolicyRule` was already taken; they do not imply equivalent extension semantics. `from basis_core.policy import PolicyRule` continues to resolve to the v0.1 Protocol unchanged.

A bundle validates before it can be evaluated (Section 4). A structurally or semantically invalid bundle can never reach evaluation, and can therefore never produce `ALLOW`.

### Trace and audit evidence

| Symbol | Package | Role |
|---|---|---|
| `TraceRuleEvidence` | `basis_core.audit` | Bounded explanation record for one policy rule considered during one evaluation. |
| `TraceConditionEvidence` | `basis_core.audit` | Bounded per-condition entry nested inside `TraceRuleEvidence.condition_results`. |
| `EvaluationTrace` | `basis_core.audit` | Bounded, deterministic explanation of one kernel authorization evaluation. |
| `AuditEvidence` | `basis_core.audit` | Bounded, durable, kernel-side evidence record of one operation-aware authorization evaluation. |

An `EvaluationTrace` explains how one evaluation reached its outcome: which rules were candidates, which matched, and what each condition resolved to. `AuditEvidence` is a separate, more bounded record — request identity, evaluation state, matched rule IDs, and evidence references — that references a trace by `trace_id` rather than embedding it. Neither is the v0.1 `AuditEvent`: `AuditEvidence`/`EvaluationTrace`/`TraceRuleEvidence` are a structurally distinct family that does not subclass, extend, or share fields with `AuditEvent`/`DecisionTrace`/`RuleEvaluation`.

```text
basis-core decides.
Enforcement boundaries enforce.
```

`basis-core` produces `AuditEvidence` as part of one evaluation's artifacts. It does not persist it — there is no `write`/`save`/`persist` method on `AuditEvidence`, and no writer protocol for it (the v0.1 `AuditWriter` protocol is shaped for `AuditEvent` and is never adapted or reused here). `GatewayAuditEvent` — the runtime record that combines this kernel-produced evidence with gateway-only enforcement facts (which route was called, what was returned to the caller, whether enforcement succeeded) — is not a `basis-core` runtime type. No `GatewayAuditEvent` type exists anywhere in this package.

### Enforcement result

| Symbol | Package | Role |
|---|---|---|
| `OperationAwareEnforcementPoint` | `basis_core.enforcement` | Fail-closed operation-aware enforcement entry point. |
| `OperationAwareEnforcementResult` | `basis_core.enforcement` | Immutable carrier binding one evaluation's response, optional audit evidence, and disposition together. |
| `EnforcementDisposition` | `basis_core.enforcement` | Closed, two-value (`allow`/`deny`) enforcement-only vocabulary. |

`OperationAwareEnforcementResult` is not itself a published `basis-schemas` contract; it exists only so a caller receives all three artifacts from one evaluation together, rather than reconstructing them from separate calls.

`OperationAwareDecisionResponse` — the authoritative per-evaluation result — lives at `basis_core.evaluation.operation_aware.response.OperationAwareDecisionResponse`. It is reached in practice through `OperationAwareEnforcementResult.response` after calling `OperationAwareEnforcementPoint.evaluate()`; it is not re-exported from any package `__init__.py` today (Section 5 covers why). `OperationAwareEnforcementPoint.evaluate()` is fail-closed: it never raises, and every failure path — including an unexpected internal exception — returns a `deny` disposition rather than propagating. It does not modify, subclass, or share implementation with the v0.1 `EnforcementPoint`.

---

## 3. Request Context

`OperationAwareDecisionRequest` groups its fields into the following categories. Every category beyond `request_id`/`subject_id`/`action` is optional — no decision requires every field to be populated, and a request carrying only its three required fields is valid.

- **Subject identity and attributes** — `subject_id` (required), `subject_roles`, `subject_attrs` (an ABAC attribute mapping).
- **Identity source and authority mode** — `identity_source`, `authority_mode` (both opaque, provider-neutral labels), `identity_evidence_reference`.
- **Action** — `action` (required), in the canonical `{verb}:{domain}[:{object}]` form.
- **Resource** — `resource` (canonical `{resource_type}:{local_resource_id}` form), `resource_type` (an open, normalized classification — not `basis_core.domain.resource.ResourceType`, and never derived from `resource`'s own prefix).
- **Location** — `location` (`OperationAwareLocation`).
- **Device** — `device` (`OperationAwareDevice`).
- **Protocol context** — `protocol_context` (`OperationAwareProtocolContext`), evidence only.
- **Operation intent** — `operation_intent` (`OperationIntent`).
- **Safety context** — `safety_context` (`OperationAwareSafetyContext`).
- **Environment context** — `environment_context` (`OperationAwareEnvironmentContext`).
- **Risk context** — `risk_context` (`OperationAwareRiskContext`).
- **Identity and adapter evidence references** — `identity_evidence_reference`, `adapter_evidence_reference`.
- **Correlation and policy-version expectations** — `request_id` (required, no default factory — the producer must supply it), `correlation_id`, `expected_policy_version`, `evaluation_time` (timezone-aware when present; never defaulted from the system clock).

This model implements structural validation only — field presence, type, and pattern/enum shape. It performs no evaluation, no cross-field reconciliation between `resource` and `resource_type`, and no interpretation of what any open label (`authority_mode`, `device_class`, safety/environment/risk labels) means beyond the pattern it validates against.

---

## 4. Policy Bundle Model

A `PolicyBundle` carries:

- **Bundle identity and version** — `bundle_id` (stable, opaque), `bundle_version` (this bundle's own `MAJOR.MINOR.PATCH` content version), `schema_version` (the contract shape version this instance was authored against — distinct from `bundle_version` and never compared against the installed `basis-schemas` package version).
- **Owner and provenance metadata** — `policy_owner` (an opaque accountability reference, never resolved through `basis-identity` and never itself an authorization subject), `description`, `source_ref`, `approval_ref`, `created_at`/`updated_at`, `compatibility_target`, `deprecated`, `replaced_by`.
- **Optional applicability scope** — `scope` (`PolicyBundleScope`).
- **Ordered rules** — `rules` (non-empty `list[OperationAwarePolicyRule]`).
- **Rule effects** — each rule's `effect` is `allow` or `deny` (`RuleEffect`); `not_applicable` is deliberately not a rule effect — it is a bundle-applicability outcome, never something one rule inside an applicable bundle produces.
- **Structural selectors** — `OperationAwarePolicyMatch`'s twenty independently-optional categories (subject, identity, action, resource, location, device, protocol, operation intent, safety, environment, risk). Within one populated selector, listed alternatives are any-of; across populated selectors, every one must match (all-of).
- **Policy conditions** — zero or more `PolicyCondition` per rule, evaluated only once structural `match` selectors are satisfied (Section 4 of `docs/operation-aware-evaluation-semantics.md`).
- **Reason codes and explanations** — `reason_code` (`ReasonCode`) and `explanation` (a static string) are optional per-rule authored fields, carried into trace evidence for a `matched` rule (see the evaluation-semantics document's trace-provenance section).
- **Semantic validation** — unique `rule_id` values across a bundle's `rules`, and unique `condition_id` values within one rule's `conditions`.

### Scope matching is exact-match only

The currently implemented scope-to-request applicability check compares every populated `PolicyBundleScope` selector against its request counterpart using exact equality (scalar fields) or exact membership (the request's value must appear in the selector's array). This implementation does **not** support wildcards, hierarchical location matching (site → building → zone → area inference), prefix matching, external directory lookups, or inferred topology relationships. A populated selector with no matching request value — including a request that carries no value at all for that dimension — resolves the bundle to `not_applicable` for that request; it is never treated as a wildcard. This is a conservative first implementation, flagged explicitly in the roadmap as a candidate for future, separately-reviewed broadening — not a permanent ceiling.

Bundle validation happens strictly before authorization evaluation. A bundle that fails structural construction, or that fails the semantic uniqueness checks above, never reaches applicability determination, selector matching, or aggregation — malformed or semantically invalid policy cannot produce `ALLOW`.

---

## 5. Public Versus Internal Components

Per `docs/public-api.md`'s "Operation-aware public API (v0.2.0)" section and the current `__all__` inventories:

**Public** — every symbol listed in Section 2 above, plus `OperationAwareFailureReason`, `OperationAwareEvaluationStatus`, and `OperationAwareDecisionOutcome` (`basis_core.decisions`), and `AUDIT_EVIDENCE_SCHEMA_VERSION` (`basis_core.audit`).

**Internal** — `basis_core.evaluation` (including `basis_core.evaluation.operation_aware`) remains internal in its entirety: no `__all__`, no package-level export, no entry in `docs/public-api.md`. This includes `OperationAwareEvaluationEngine`, `OperationAwareDecisionResponse`, and every response/trace/audit-evidence assembly function (`assemble_operation_aware_decision_response`, `assemble_audit_evidence`, `assemble_rule_evidence`, `assemble_evaluation_trace`). These are reached only indirectly, through `OperationAwareEnforcementResult.response` after calling `OperationAwareEnforcementPoint.evaluate()`. Whether and how to expose the evaluation package directly is a later, separately-scoped decision — not made by this document.

Also internal: bundle-applicability determination (`determine_applicability`, `ApplicabilityResult`), rule-selector matching (`evaluate_rule_selectors`, `select_candidate_rules`, `SelectorEvaluation`, `CandidateRuleEvaluation`), the condition-operator registry and evaluator (`evaluate_condition`, `ConditionEvaluation`, `SUPPORTED_OPERATORS`, `evaluate_rule_conditions`), policy-owned aggregation (`aggregate_policy_outcome`, `PolicyAggregationResult`, `OperationAwarePolicyOutcome`), and bundle validation (`validate_policy_bundle`, `PolicyBundleValidationError` and its subtypes). All of these are reachable only via direct submodule import, carry no compatibility guarantee, and are not supported API — do not import them as though they were.

---

## 6. Minimal Usage Example

```python
from datetime import datetime, timezone

from basis_core.decisions import OperationAwareDecisionRequest
from basis_core.enforcement import OperationAwareEnforcementPoint
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.policy import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
    PolicyBundle,
    RuleEffect,
)

request = OperationAwareDecisionRequest(
    request_id="req-0001",
    subject_id="operator-1",
    subject_roles=["operator"],
    action="write:hvac:setpoint",
    resource="hvac:zone-a",
)

rule = OperationAwarePolicyRule(
    rule_id="allow-operator-hvac-write",
    effect=RuleEffect.ALLOW,
    match=OperationAwarePolicyMatch(
        actions=["write:hvac:setpoint"],
        subject_roles=["operator"],
    ),
)

bundle = PolicyBundle(
    bundle_id="site-a-hvac-policy",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="ops-team",
    rules=[rule],
)

enforcement_point = OperationAwareEnforcementPoint(
    engine=OperationAwareEvaluationEngine(),
    bundle=bundle,
)

result = enforcement_point.evaluate(
    request=request,
    trace_id="trace-0001",
    evidence_id="evidence-0001",
    recorded_at=datetime.now(timezone.utc),
)

print(result.disposition)                    # EnforcementDisposition.ALLOW
print(result.response.outcome)                # OperationAwareDecisionOutcome.ALLOW
print(result.response.trace_id)                # "trace-0001"
print(result.audit_evidence.matched_rule_ids)   # ["allow-operator-hvac-write"]
```

`trace_id`, `evidence_id`, and `recorded_at` are caller-supplied and never generated by `basis-core` — the kernel reads no clock and no random source (`docs/operation-aware-evaluation-semantics.md`, Section 7). `OperationAwareEnforcementPoint.evaluate()` defaults `embed_evaluation_trace` to `False`, so `result.response.evaluation_trace` is `None` here; `result.response.trace_id` still identifies the trace by reference. This example was executed against the current checkout as part of validating this document; see the PR's final report for how.

---

## 7. Compatibility With v0.1

| v0.1 surface | Operation-aware sibling |
|---|---|
| `DecisionRequest` | `OperationAwareDecisionRequest` |
| `PolicyRule` Protocol and `PolicyEngine` | structured bundle/rule models and the internal `OperationAwareEvaluationEngine` |
| `DecisionResponse` | `OperationAwareDecisionResponse` |
| `DecisionTrace` | `EvaluationTrace` |
| `AuditEvent` | `AuditEvidence` |
| `EnforcementPoint` | `OperationAwareEnforcementPoint` |

Each row is a sibling relationship, not a subclass or an automatic replacement. A consumer may continue using v0.1 unchanged indefinitely, or independently adopt the operation-aware surface — see Section 10. Nothing in the merged surface deprecates, alters the behavior of, or requires migrating away from any v0.1 symbol.

---

## 8. Kernel Boundary and Non-Goals

`basis-core`, including the operation-aware surface, does not:

- authenticate tokens, perform OIDC discovery, or verify JWT signatures;
- call an identity provider;
- communicate with BACnet, Modbus, OPC UA, MQTT, DNP3, IEC 61850, KNX, or Niagara, or any other field or application protocol;
- perform HTTP routing or any transport-layer work;
- persist `AuditEvidence`, or persist anything else;
- create `GatewayAuditEvent`;
- call cloud services or query databases;
- enforce authorization outside its caller's own process or enforcement boundary.

These boundaries are unchanged from the v0.1 kernel (`docs/kernel-constitution.md`, `docs/kernel-boundary.md`) and apply identically to the operation-aware surface.

---

## 9. Adopting the Operation-Aware Surface

Adopting the operation-aware surface is independent of, and not a prerequisite for, continuing to use v0.1. A consumer that chooses to adopt it typically:

1. constructs normalized `OperationAwareDecisionRequest` instances from already-verified identity and already-normalized adapter context;
2. authors and validates `PolicyBundle` instances (`validate_policy_bundle`, reached via direct submodule import — see Section 5);
3. constructs one `OperationAwareEnforcementPoint` per configured bundle and invokes `evaluate()`;
4. enforces the returned `disposition` at the caller's own boundary;
5. retains or forwards the returned `AuditEvidence` according to the caller's or gateway's own audit policy.

This is adoption guidance, not a gateway integration specification. `basis-core` does not itself authenticate, persist audit evidence, or apply physical control — those remain the caller's, or `basis-gateway`'s, responsibility.

---

## 10. Further Reading

- `docs/operation-aware-evaluation-semantics.md` — how a request is actually evaluated.
- `docs/public-api.md` — the authoritative public API inventory.
- `docs/extension-contracts.md` — why the operation-aware policy family is not a new extension point.
- `docs/import-boundaries.md` — the kernel's dependency graph, including `evaluation/`'s place in it.
- `docs/kernel-constitution.md` — the invariants this surface inherits unchanged.
- `docs/implementation/basis-core-v0.2-operation-aware-plan.md` — the roadmap that sequenced this work.
- `docs/adr/ADR-0006-operation-aware-enforcement-point.md` — the repository-local design decision behind `OperationAwareEnforcementPoint`.
- `basis-architecture` ADR-0001 through ADR-0006 and their companion documents — the architectural authority for everything summarized here.
