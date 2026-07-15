# basis-core v0.2.0 — Operation-Aware Authorization Implementation Plan

**Status:** Planning only. No runtime behavior, domain models, dependencies, or
public APIs are implemented, added, or modified by this document.

**Branch:** `docs/operation-aware-v0.2-plan`

**Audience:** Future Claude sessions and human contributors implementing
`basis-core` v0.2.0, one narrow PR at a time, without rediscovering
architecture or inventing semantics.

---

## 1. Executive summary

`basis-core` v0.1.0 is a deterministic authorization kernel that evaluates a
flat `(subject, action, resource_id, context)` request against a chain of
`PolicyRule` implementations under deny-overrides semantics, and returns a
`DecisionResponse` plus an `AuditEvent`. It is released, public, and protected
by contract tests, a public API inventory (`docs/public-api.md`), and a
breaking-change governance process (`docs/breaking-change-discipline.md`).

`basis-core` v0.2.0 is intended to add **operation-aware evaluation**: the
ability to evaluate a request that carries the operational context real OT
authorization decisions depend on — resource type, site/building/zone,
device identity and class, protocol evidence, operation intent (read-only vs.
state-changing vs. control-affecting), safety/environment/risk context,
identity source and evidence, and a data-defined policy bundle/rule/condition
model — instead of only `(subject, action, resource_id)`. This is not a
rewrite. The v0.1.0 kernel — `DecisionRequest`, `DecisionResponse`,
`AuditEvent`, `PolicyEngine`, `EnforcementPoint`, the three built-in
`PolicyRule` implementations, and every symbol in `docs/public-api.md` —
remains published, supported, and behaviorally unchanged. v0.2.0 adds a
second, additive evaluation surface alongside it: new modules, new models, a
new engine, and (per the compatibility strategy in Section 5) a new
enforcement entry point, none of which alter what a v0.1.0 consumer already
depends on.

The operation-aware expansion does not originate in `basis-core`. It is the
implementation phase of a chain of decisions already made and published
upstream:

```text
basis-architecture          basis-schemas               basis-core
─────────────────           ─────────────                ──────────
ADR-0001..0005          →   20 published contracts   →   v0.2.0 (this plan)
defines WHAT the            (6 first-wave + 14           implements deterministic
kernel must be able          operation-aware, v0.2.0      evaluation against
to represent and             tag) publish the             those contracts
how it must reason           machine-readable SHAPE
about it                     of those concepts
```

Five ADRs in `basis-architecture` — 0001 (operation-aware authorization
model), 0002 (operation-aware evaluation semantics), 0003 (trace/audit
evidence), 0004 (policy bundle/rule model), and 0005 (schema readiness
plan) — define the conceptual categories and behavioral rules. `basis-schemas`
v0.2.0 (tag `v0.2.0`, commit `1d3af3cfd38686173980cfb47f8fa44659a4e1c4`) then
formalized fourteen of those categories as machine-readable YAML contracts,
on top of the six first-wave contracts (`vocabulary`, `action-string`,
`resource-identifier`, `decision-request`, `decision-response`,
`audit-event`) that already mirror `basis-core` v0.1.0 today. Five canonical
compatibility scenarios (`allow-basic`, `deny-precedence`, `default-deny`,
`not-applicable`, `invalid-policy-bundle`) were published alongside those
contracts as the first executable acceptance target for a future evaluator.

This plan takes the position, restated throughout the upstream documents and
adopted here without modification:

```text
Architecture defines.
Schemas publish.
Core implements deterministic evaluation.
```

`basis-core`'s job in v0.2.0 is exactly and only the third line: implement a
deterministic evaluator, typed domain models, and a trace/audit-evidence
pipeline that realize what ADR-0001 through ADR-0005 already decided and
`basis-schemas` v0.2.0 already published — not to invent new authorization
semantics, not to choose a policy language, and not to resolve the condition
operator question that ADR-0004 and the schema-readiness plan both explicitly
left open (see Section 8).

**What must remain compatible with v0.1.0**, restated from the kernel
constitution and re-derived in Section 5: every public symbol in
`docs/public-api.md` continues to resolve to the same behavior; `DecisionRequest`
and `DecisionResponse` field semantics are unchanged; `PolicyEngine` and
`EnforcementPoint` evaluation semantics (DENY short-circuits, ALLOW does not,
first-ALLOW wins, NOT_APPLICABLE resolves to DENY at the enforcement boundary,
exceptions fail closed) are unchanged; the `AuditEvent` schema and its
`schema_version` are unchanged; the `PolicyRule`, `AuditWriter`, and
`AdapterBase` extension contracts are unchanged; and the import-boundary graph
in `docs/import-boundaries.md` is preserved, extended only by adding new
leaf-safe modules that follow the same layering rules.

---

## 2. Current-state inventory

This section documents what exists in `basis-core` today, inspected directly
from the repository at commit `e567890` on `main` (the tip `docs/operation-aware-v0.2-plan`
was branched from). It is the baseline every later section in this plan
extends, not replaces.

### 2.1 Public domain models (`src/basis_core/domain/`)

Import direction: `domain/` imports nothing from `basis_core`. It is the
dependency sink for the whole kernel (`docs/import-boundaries.md`).

- `subject.py` — `Subject` (frozen Pydantic model: `id`, `name`, `type: SubjectType`,
  `roles: list[str]` normalized sorted/deduped/stripped, `attrs: dict[str, str]`),
  `SubjectType` enum (`HUMAN`, `DEVICE`, `SERVICE`, `GATEWAY`, `AGENT`), and
  `subject_from_jwt()` — **deprecated per ADR-0005 in `basis-core`**
  (`docs/adr/ADR-0005-move-jwt-normalization-outside-kernel.md`), scheduled
  for removal, not to be extended or newly depended upon.
- `resource.py` — `Resource` (frozen: `id`, `type: ResourceType`, `name`, `zone`,
  `description`, `attrs`), `ResourceType` enum (`HVAC`, `SENSOR`, `ZONE`,
  `DEVICE`, `GATEWAY` — a fixed, closed set today), `build_resource_id()`,
  `parse_resource_id()`. Resource identifier format:
  `^[a-z][a-z0-9_-]*(:[a-z0-9][a-z0-9_:/-]*)$`, duplicated (by design, per the
  module docstring) in `decisions/models.py`.
- `identity.py` — `IdentityContext` (frozen: `subject`, `token`, `issued_at`,
  `expires_at`, `propagated_from`) — the *wire-level* verified-identity
  carrier, distinct from `Subject`.
- `action.py` — a flat module of action-name string constants
  (`READ_SENSOR_TELEMETRY`, `WRITE_HVAC_SETPOINT`, etc.), following
  `{verb}:{domain}[:{object}]`.

**Verdict:** retained unchanged. `ResourceType` is a *closed* enum today;
operation-aware `resource_type` (per `basis-schemas`
`operation-aware-decision-request.md` §16) is an *open* normalized-string
classification, not a re-use of this enum — see Section 3, row
"resource_type".

### 2.2 DecisionRequest / DecisionResponse (`src/basis_core/decisions/models.py`)

`DecisionRequest`: `request_id` (auto UUID), `subject_id`, `subject_roles`
(normalized), `subject_attrs`, `resource_id: str | None` (validated
`{type}:{qualifier}` pattern), `action: str` (validated
`{verb}:{domain}[:{object}]` pattern), `context: dict[str, str]`, `timestamp`
(tz-aware, defaulted). `DecisionResponse`: `request_id`, `outcome:
DecisionOutcome` (`ALLOW`/`DENY`/`NOT_APPLICABLE`), `reason`, `evaluated_by`,
`policy_version: str | None`, `failure_reason: FailureReason | None`
(`MALFORMED_REQUEST`/`POLICY_ERROR`/`AUDIT_ERROR`/`INTERNAL_ERROR`),
`timestamp`. `FailureReason` here is a *v0.1-era enforcement-boundary*
concept and is **not** the same vocabulary as `basis-schemas`
`operation-aware-decision-response.md`'s six-value evaluator-failure
`failure_reason` (`invalid_request`, `unsupported_schema_version`, etc.) —
`basis-schemas` explicitly documents these as two unrelated, independently
versioned vocabularies that happen to share a field name (§14 of that
document). This plan preserves that separation; see Section 3, row
"failure_reason (response)".

**Verdict:** retained unchanged. `context: dict[str, str]` is the closest
v0.1.0 analog to operation-aware structured context, but the operation-aware
request does not reuse it — `operation-aware-decision-request.md` §33
("Legacy `context` field: not retained") is explicit that the richer request
replaces the flat context bag with named, typed fields (`location`, `device`,
`protocol_context`, etc.) instead of extending it.

### 2.3 PolicyEngine and PolicyRule (`src/basis_core/policy/`)

`PolicyEngine.evaluate()` walks a `list[PolicyRule]` in registration order:
first DENY short-circuits and returns; ALLOW does not short-circuit (all
rules still run); first ALLOW (by registration order) wins if no DENY
follows; NOT_APPLICABLE from all rules aggregates to engine-level
NOT_APPLICABLE. `PolicyRule` is a `@runtime_checkable Protocol` with one
method, `evaluate(subject, action, resource_id, identity_context, context) ->
Decision`. Three concrete rules ship: `RolePolicyRule`,
`ResourceTypePolicyRule`, `ActionPolicyRule`. `Decision` (not a Pydantic
model — a plain class with `__slots__`) carries `outcome`, `reason`,
`evaluated_by`, `evaluated_rules` (list of `(name, outcome_str, reason)`
tuples), `is_error`.

**Verdict:** the *shape* (deny-overrides, first-ALLOW, NOT_APPLICABLE
pass-through) is retained unchanged and is architecturally re-affirmed by
ADR-0002 §§4-7 for the operation-aware model. The *implementation* — a flat
list of `PolicyRule` objects evaluated imperatively — is **not** reused for
operation-aware evaluation. Operation-aware policy is a **data model**
(`PolicyBundle`/`PolicyRule`/`PolicyCondition` as Pydantic-validated data, not
code implementing a `evaluate()` protocol) per `basis-schemas`
`policy-rule.md` and ADR-0004. A new `OperationAwarePolicyEngine` implements
the same *combining semantics* (deny-precedence, default-deny,
not-applicable) over the new data model — see Section 6 and Milestone 9. The
v0.1.0 `PolicyEngine`/`PolicyRule` extension point is unaffected and is not
deprecated by this plan.

### 2.4 EnforcementPoint (`src/basis_core/enforcement/enforcement.py`)

`EnforcementPoint.evaluate()` validates/normalizes a `DecisionRequest` (or
raw dict), builds a `Subject`, calls `PolicyEngine.evaluate()`, maps the
outcome to a `DecisionResponse`, builds a `DecisionTrace` from
`Decision.evaluated_rules`, and writes an `AuditEvent` via `AuditWriter`.
Every failure path (malformed request, subject construction failure, policy
exception, unexpected internal exception) returns a `DecisionResponse` with
`outcome=DENY` and an appropriate `failure_reason`; `evaluate()` never
raises. `EnforcementPoint` is the *only* component permitted to call both the
policy engine and the audit writer in one path — the top of the import graph
(`enforcement/` may import from everything; nothing imports from
`enforcement/`).

**Verdict:** retained unchanged. Section 5 and Milestone 11 recommend a new,
separate `OperationAwareEnforcementPoint` class (not a modified `evaluate()`
signature on the existing class) as the operation-aware entry point, for the
compatibility reasons detailed there.

### 2.5 Audit model (`src/basis_core/audit/`)

`AuditEvent` (frozen, `AUDIT_SCHEMA_VERSION = "1.1"`): identification
(`event_id`, `event_type: AuditEventType`, `timestamp`, `schema_version`),
correlation (`request_id`, `decision_id`, `correlation_id`), subject fields,
resource/action fields, decision fields (`outcome: AuditOutcome`, `reason`,
`evaluated_by`, `policy_version`, `matched_rules`), `trace:
DecisionTrace | None`, `detail: dict[str, object]`. `DecisionTrace` /
`RuleEvaluation` (frozen): `final_outcome`, `evaluated_rules:
list[RuleEvaluation]`, `short_circuited`. `AuditWriter` is a
`@runtime_checkable Protocol` with `write(event) -> None`; `NullAuditWriter`
and `LogAuditWriter` ship as reference implementations.

**Verdict:** retained unchanged. The operation-aware model introduces a
structurally distinct evidence family — `EvaluationTrace`/`TraceRuleEvidence`
(explanatory, part of the response) and `AuditEvidence` (bounded, durable,
kernel-produced-but-not-persisted) — that is **not** a v2 of `AuditEvent` and
does not extend `DecisionTrace`/`RuleEvaluation`. `basis-schemas`
`audit-evidence.md` §11 ("Relationship to first-wave AuditEvent") is explicit
that the existing `AuditEvent` is unmodified. `basis_core.audit.writer`'s
`AuditWriter` protocol is unaffected: `basis-core` does not persist
`AuditEvidence` either (ADR-0003 §14 — "`basis-core` does not persist audit");
that responsibility, and any new writer-shaped protocol for it, belongs to
`basis-gateway`, not this repository.

### 2.6 Adapter contracts (`src/basis_core/adapters/base.py`)

`AdapterBase` (`@runtime_checkable Protocol`: `adapter_id`, `protocol`,
`start()`, `stop()`) and `NormalizedEvent` (adapter output:
`adapter_id`, `protocol`, `subject_id`, `resource_id`, `action`, `context`,
`payload`).

**Verdict:** retained unchanged. Nothing in the operation-aware model changes
what an adapter produces or how it is wired; `basis-adapters` is expected to
emit richer evidence *incrementally* (ADR-0005 §13) once `basis-core` v0.2.0
exists, not the reverse. This plan does not require any change to
`AdapterBase` or `NormalizedEvent`.

### 2.7 Failure handling, trace, and audit behavior

Every kernel failure path is fail-closed (Invariant 6,
`docs/kernel-constitution.md`): malformed requests, subject construction
errors, policy-rule exceptions, and unexpected internal errors all resolve to
`DecisionOutcome.DENY` with a `FailureReason`. This behavior is a governed
contract surface (`docs/breaking-change-discipline.md`, "Enforcement and
failure-mode contracts") and is preserved unchanged by this plan; the
operation-aware evaluator introduces its *own*, textually distinct failure
category (`evaluation_status: failed` with a six-value `failure_reason`) that
does not touch or extend `basis_core.decisions.models.FailureReason`.

### 2.8 Serialization, schema validation, and compatibility snapshots

`schemas/*.schema.json` (JSON Schema, `additionalProperties: false`) define
`DecisionRequest`, `DecisionResponse`, `AuditEvent`, and `Policy`.
`tests/test_schema_validation.py` verifies Pydantic-model-to-schema alignment.
`tests/test_contract_snapshots.py` and `tests/test_backward_compatibility.py`
protect serialized shapes against silent drift.
`tests/fixtures/contracts/*.json` hold the snapshot fixtures.
`docs/schema-versioning.md` and `docs/breaking-change-discipline.md` define
what is breaking vs. additive.

**Verdict:** retained unchanged. `basis-schemas` publishes contracts as YAML
with an informal, non-JSON-Schema structural-validation convention (see
Section 4) — the operation-aware model does **not** get JSON Schema files
under `basis-core/schemas/`; that would duplicate a contract this repository
does not own. New operation-aware fixtures live in a new,
clearly-separated location (Section 4, Section 7 Milestone 3) so the existing
`schemas/*.schema.json` set and its snapshot tests are never touched by
operation-aware work.

### 2.9 Extension contracts (`docs/extension-contracts.md`)

`PolicyRule`, `AuditWriter`, `AdapterBase` are the three governed extension
points, each with required signature, determinism, statefulness, forbidden
side effects, and breaking-change rules documented. Section 11 of this plan
assesses whether the operation-aware model introduces a fourth.

**Verdict:** retained unchanged. See Section 11 — the operation-aware policy
model is data, not an extension point with an `evaluate()` method, so no new
`PolicyRule`-shaped protocol is anticipated for the initial v0.2.0 scope.

### 2.10 Public exports and import-boundary protections

`docs/public-api.md` defines three tiers (stable public API, extension API,
internal) with `__all__` enforced per package and `test_public_api.py`
verifying the inventory matches. `docs/import-boundaries.md` defines the
allowed dependency graph (`domain` ← `decisions`/`policy`/`audit`/`adapters`
← `enforcement`), enforced statically by `tests/test_import_boundaries.py`
via `ast.parse()`.

**Verdict:** both extended additively — new packages/modules following the
same layering rules, new symbols added to `__all__`, no existing symbol
touched. See Section 11 and Section 6.

### 2.11 Existing deprecations

`subject_from_jwt()` (deprecated per ADR-0005) and the `basis_core.api` /
`basis_core.api.enforcement` stub package (deprecated, scheduled for removal
"after v0.1") are the two active deprecations. Neither interacts with the
operation-aware model; this plan does not extend, depend on, or accelerate
either deprecation.

### 2.12 Test organization

19 test modules under `tests/`, organized by concern rather than by package
(`test_models.py`, `test_policy_engine.py`, `test_policy_rules.py`,
`test_enforcement_point.py`, `test_audit.py`, `test_extension_contracts.py`,
`test_evaluation_semantics.py`, `test_import_boundaries.py`,
`test_public_api.py`, `test_governance_docs.py`, `test_schema_validation.py`,
`test_schema_versioning.py`, `test_contract_snapshots.py`,
`test_backward_compatibility.py`, `test_readiness.py`, plus fixtures/helpers).
`pyproject.toml` sets `testpaths = ["tests"]`, `pythonpath = ["src"]`. This
plan recommends operation-aware tests live under a new `tests/operation_aware/`
subpackage (Section 13, Milestone 1) rather than growing the flat top-level
list further, given the number of new modules Section 12's roadmap
introduces — a repository-structure choice, not an architecture requirement,
flagged for confirmation in Section 15.

### 2.13 Package and release versioning

`pyproject.toml`: `name = "basis-core"`, `version = "0.1.0"`, Python
`>=3.10`, one runtime dependency (`pydantic>=2.0`), dev extras (`pytest`,
`pytest-cov`, `ruff`, `mypy`, `jsonschema[format-nongpl]`). `src/basis_core/__init__.py`
exports `__version__ = "0.1.0"` and nothing else (no top-level namespace —
an explicitly open question in `docs/public-api.md`, unrelated to this plan).
Governance docs (`docs/breaking-change-discipline.md`,
`docs/v0.1-readiness-review.md`) describe the v0.1 release process this plan
mirrors in Section 14/Milestone 14 for v0.2.0 readiness, without performing
any of it here.

**Verdict:** version stays at `0.1.0` until the single, final roadmap PR
(Milestone 14, PR 44) bumps it — see Section 12 and Section 16.

---

## 2A. What is retained / extended / adapted / deferred / breaking-only

Summarizing 2.1–2.13 into the four categories this plan's brief requested:

- **Retained unchanged:** `domain/` (all four modules), `decisions/models.py`,
  `policy/engine.py` + `policy/rules.py`, `enforcement/enforcement.py`,
  `audit/events.py` + `audit/trace.py` + `audit/writer.py`,
  `adapters/base.py`, all `schemas/*.schema.json`, all existing `docs/*.md`,
  the entire v0.1 public API surface, both existing deprecations.
- **Extended additively:** `docs/public-api.md` (new tier for new symbols),
  `docs/import-boundaries.md` (new leaf-safe subpackages under the same
  rules), `docs/architecture-references.md` (new cross-references), `README.md`
  (documentation index), `tests/` (new subpackage), `pyproject.toml` (no
  change until Milestone 14, and even then additive: a version bump plus,
  possibly, new *dev-only* test dependencies — never a new runtime
  dependency).
- **Adapted behind compatibility layers:** none identified. Every operation-aware
  concept (Section 3) has either a direct new-module home or no v0.1.0
  analog; nothing requires wrapping or shimming existing v0.1.0 code.
- **Deprecated later:** none. This plan does not deprecate `PolicyEngine`,
  `PolicyRule`, `EnforcementPoint`, or any other v0.1.0 symbol. Whether the
  v0.1.0 surface is ever deprecated in favor of the operation-aware surface is
  explicitly out of scope and not implied by anything in this plan.
- **Replaceable only through a breaking-change process:** any change to the
  items in "retained unchanged" above. No item in this plan's Section 12
  roadmap proposes such a change; if a future PR discovers it needs one, it
  must stop and follow `docs/breaking-change-discipline.md` in full,
  including basis-architecture review, before proceeding.

---

## 3. Architecture-to-schema-to-core mapping

Columns: architectural concept · governing architecture document/ADR ·
`basis-schemas` v0.2.0 contract · proposed `basis-core` component · current
v0.1.0 equivalent, if any · implementation phase (milestone, Section 12) ·
compatibility concern · unresolved question.

| Architectural concept | Governing ADR/doc | basis-schemas v0.2.0 contract | Proposed basis-core component | Current v0.1.0 equivalent | Phase | Compatibility concern | Unresolved question |
|---|---|---|---|---|---|---|---|
| Operation-aware request | ADR-0001 §3; ADR-0005 §4 (PR C) | `operation-aware-decision-request` (0.1.0, experimental) | `OperationAwareDecisionRequest` — new, `src/basis_core/decisions/operation_aware.py` | `DecisionRequest` (v0.1.0, unchanged, coexists) | Milestone 2 (PR 8-9) | Additive sibling only; must not alter `DecisionRequest` | None — contract is published and stable enough to implement against |
| `identity_source` / `authority_mode` | ADR-0001 §3; `operation-aware-decision-request.md` §13 | same contract, fields on it | fields on `OperationAwareDecisionRequest` | none (v0.1.0 has no identity-source concept) | Milestone 2 (PR 8) | none | `authority_mode` is an open lowercase label, not a governed enum — basis-architecture has not published an authority-mode vocabulary contract (noted explicitly in the schema doc) |
| `IdentityEvidenceReference` | ADR-0003 §8 | `identity-evidence-reference` (PR B) | `IdentityEvidenceReference` — new, `src/basis_core/domain/evidence.py` | none | Milestone 2 (PR 6) | none — evidence-only, never raw credentials | Reference-only enforcement (no raw token ever accepted) needs a construction-time guard, not just documentation — track as an implementation-detail decision, not an architecture question |
| `AdapterEvidenceReference` | ADR-0003 §7 | `adapter-evidence-reference` (PR B) | `AdapterEvidenceReference` — new, `src/basis_core/domain/evidence.py` | none | Milestone 2 (PR 6) | none | Same reference-only guard question as identity evidence |
| Resource / resource type (operation-aware) | ADR-0001 §3 | fields on `operation-aware-decision-request` | `resource: str \| None`, `resource_type: str \| None` fields | `Resource`, `ResourceType` (closed enum) | Milestone 2 (PR 7-8) | `resource_type` here is an **open string**, not `basis_core.domain.resource.ResourceType` — must not silently coerce into the closed enum | Whether a future phase should validate `resource_type` against a governed vocabulary once one exists is explicitly deferred by the schema doc itself |
| Location context (site/building/zone/area) | ADR-0001 §3 | `location` object on `operation-aware-decision-request` | `OperationAwareLocation` value object | none | Milestone 2 (PR 7) | none | None — no hierarchy/parent-child enforcement is defined or expected |
| Device identity / class | ADR-0001 §3 | `device` object | `OperationAwareDevice` value object | none | Milestone 2 (PR 7) | none | None |
| Protocol / protocol operation | ADR-0001 §3 | `protocol_context` object | `OperationAwareProtocolContext` value object | `NormalizedEvent.protocol` (evidence-only today, different contract) | Milestone 2 (PR 7) | Must not make the kernel protocol-aware — field is opaque evidence only, never parsed | None |
| Operation intent | ADR-0001 §3 | `operation_intent` (closed: `read_only`/`state_changing`/`control_affecting`) | field on `OperationAwareDecisionRequest`, or small closed enum type | none | Milestone 2 (PR 8) | none | None — contract already closes the vocabulary |
| Safety / environment / risk context | ADR-0001 §3 | `safety_context` / `environment_context` / `risk_context` objects | `OperationAwareSafetyContext`, `OperationAwareEnvironmentContext`, `OperationAwareRiskContext` value objects | none | Milestone 2 (PR 7) | none | Whether/how these should feed condition evaluation is gated behind Section 8 |
| `PolicyCondition` | ADR-0004 §7 | `policy-condition` (PR D) | `PolicyCondition` — new, `src/basis_core/policy/operation_aware/condition.py` | none | Milestone 4 (PR 12); **execution** gated, Milestone 7 | Structural model only until Section 8's gate opens | **Blocked**: condition operator semantics — see Section 8 |
| `PolicyRule` (operation-aware) | ADR-0004 §4-5 | `policy-rule` (PR D) | `OperationAwarePolicyRule` — new data model, `src/basis_core/policy/operation_aware/rule.py` | `PolicyRule` Protocol (v0.1.0, unrelated — code interface vs. data shape) | Milestone 4 (PR 13) | Name collision with v0.1.0 `PolicyRule` — must use a distinct class name; see Section 11 | None on the shape; naming decision is this plan's to make (Section 5) |
| `PolicyBundle` | ADR-0004 §2-3 | `policy-bundle` (PR D) | `PolicyBundle` — new, `src/basis_core/policy/operation_aware/bundle.py` | none (v0.1.0 has no bundle concept — rules are just a Python list) | Milestone 4 (PR 14-15) | none | Scope-matching semantics beyond exact-match equality are not fully specified by ADR-0004 — implement the conservative exact-match reading first (Section 6, Milestone 5) and flag richer matching as a later, separately-reviewed capability |
| `TraceRuleEvidence` | ADR-0003 §5 | `trace-rule-evidence` (PR E) | `TraceRuleEvidence` — new, `src/basis_core/audit/operation_aware/trace_rule_evidence.py` | `RuleEvaluation` (v0.1.0, structurally simpler — no `rule_result` 4-value vocabulary, no `condition_results`) | Milestone 8 (PR 24) | Does not extend or alter `RuleEvaluation` | None |
| `EvaluationTrace` | ADR-0003 §4 | `evaluation-trace` (PR E) | `EvaluationTrace` — new, `src/basis_core/audit/operation_aware/evaluation_trace.py` | `DecisionTrace` (v0.1.0, structurally simpler) | Milestone 8 (PR 25) | Does not extend or alter `DecisionTrace` | None |
| `OperationAwareDecisionResponse` | ADR-0001 §4; ADR-0002 §4-5,14 | `operation-aware-decision-response` (PR E) | `OperationAwareDecisionResponse` — new, `src/basis_core/decisions/operation_aware.py` | `DecisionResponse` (v0.1.0, coexists unchanged) | Milestone 10 (PR 29) | Additive sibling only | None — the `evaluation_status`/`outcome`/`failure_reason` invariants are fully specified and directly testable |
| `AuditEvidence` | ADR-0003 §2,14 | `audit-evidence` (PR F) | `AuditEvidence` — new, `src/basis_core/audit/operation_aware/audit_evidence.py` | `AuditEvent` (v0.1.0, coexists unchanged, structurally distinct family) | Milestone 10 (PR 30) | `basis-core` **produces** this as part of its response; it must not persist it (no writer, no storage) | None on the shape; persistence ownership is explicitly the gateway's per ADR-0003 §14 |
| reason codes | ADR-0003 §12; ADR-0004 §13 | `reason-code` (PR A) — format only, open vocabulary | `ReasonCode` validated string type (regex, not enum) | none | Milestone 2 (PR 5) | none — contract is explicitly not a closed enum | Final reason-code *vocabulary* (which specific codes `basis-core` emits) is this repository's own decision to make incrementally as evaluation stages are implemented, not something to invent wholesale up front |
| redaction classification | ADR-0003 §10 | `redaction-classification` (PR A) — closed 5-value enum | `RedactionClassification` enum, `src/basis_core/domain/operation_aware_vocabulary.py` | none | Milestone 2 (PR 5) | Must be applied consistently wherever evidence-reference models are constructed | None — vocabulary is closed and stable |
| contract metadata | ADR-0005 §4 (PR A) | `contract-metadata` (PR A) | **not implemented as a basis-core runtime type** — informational only, used in fixture provenance (Section 4) | none | N/A | none | This is a `basis-schemas` publication-tooling concept, not a kernel runtime concept; `basis-core` does not need a `ContractMetadata` class |
| `GatewayAuditEvent` | ADR-0003 §9,14 | `gateway-audit-event` (PR F) | **not implemented in basis-core** | none | N/A | `basis-core` must never produce, consume, or validate this shape at runtime | Explicitly out of kernel scope — see below |

**`GatewayAuditEvent` is consumed or composed outside the kernel.** ADR-0003
§9 states this without qualification: *"basis-core decides. basis-gateway
enforces and records enforcement facts."* `GatewayAuditEvent` combines
kernel-produced evidence (`AuditEvidence`, `EvaluationTrace`) with facts the
kernel structurally cannot know — which route was called, what was returned
to the caller, whether enforcement succeeded, fail-closed behavior, timeout
behavior. None of that exists inside `EnforcementPoint.evaluate()` or its
operation-aware counterpart. This plan's roadmap (Section 12) contains **no
PR** that adds a `GatewayAuditEvent` model, a `GatewayAuditEvent`-shaped
writer protocol, or any gateway-enforcement-facts field to any `basis-core`
type. The canonical-vector test suite (Milestone 12) explicitly asserts only
the kernel-relevant subset of each scenario's fixtures and treats
`expected-gateway-audit-event.yaml` as out-of-scope reference material, never
as an assertion target.

---

## 4. Contract-consumption strategy

`basis-schemas` v0.2.0 deliberately does not package schema, example, or
documentation files into its PyPI wheel — confirmed directly in
`docs/release-notes.md`: *"`pip install basis-schemas` installs only the
small `basis_schemas` metadata package, not the schema, example, or
documentation files themselves."* The 20 published contracts are YAML files
with an informal `contract:`-block metadata convention (not JSON Schema — see
`docs/schemas/README.md` in that repository), validated by that repository's
own `_validate_object`-style test helpers, not a standard schema-validation
library. Adding `basis-schemas` as a runtime dependency of `basis-core` would
therefore buy nothing at runtime (no files ship) and would introduce exactly
the kind of higher-level dependency Invariant 10 in `docs/kernel-constitution.md`
forbids in spirit — `basis-schemas` is a peer publication repository, not a
runtime library `basis-core` should import.

### Options evaluated

- **Consume tagged repository fixtures during development** (clone/checkout
  `basis-schemas` locally, read files by relative path). Reproducible only if
  every contributor and CI runner has the exact same checkout; fragile across
  machines and impossible in an air-gapped CI runner without a pre-staged
  copy. Rejected as the primary mechanism, though useful as a *local*
  authoring aid.
- **Use source-distribution (`sdist`) contents.** The `sdist` on PyPI, if it
  includes `schemas/`/`examples/`/`docs/` (unconfirmed at plan time — `pip
  install` only installs the wheel's contents, and the release notes only
  describe the wheel), could be downloaded and inspected without a git
  checkout. Still an external network dependency at build/test time unless
  cached; does not solve air-gapped CI on its own.
- **Vendor immutable compatibility fixtures.** Copy the specific files
  `basis-core` needs — the fourteen operation-aware contract YAMLs and the
  five canonical-vector directories under
  `examples/operation-aware/compatibility/` — into `basis-core` at a pinned
  commit, with a manifest recording the exact `basis-schemas` tag and commit
  hash. **Recommended — see below.**
- **Use GitHub release archives or release assets.** Download the tagged
  source `.tar.gz`/`.zip` from the `v0.2.0` GitHub release at build/CI time.
  Reproducible if the archive is content-addressed (a checksum is pinned
  alongside the URL) but still a network dependency unless the archive is
  itself cached/vendored — converges on the vendoring option once made
  reproducible, so it is not a distinct recommendation, only a *fetch
  mechanism* for populating the vendored copy (see the update procedure
  below).
- **Introduce a future packaged-resource API in `basis-schemas`.** A future
  `basis-schemas` release could ship `importlib.resources`-accessible schema
  files in its wheel, letting `basis-core` add a *test-only* (never runtime)
  dependency and read fixtures programmatically. This is a `basis-schemas`
  packaging decision this plan cannot make; it is named in Section 15 as a
  cross-repository follow-up.
- **Duplicate only generated test snapshots, if governed.** Snapshotting only
  the five canonical vectors' *expected outputs* (not the full contract set)
  would under-serve Milestones 2-11, which need the full field-level contract
  text (required/optional/type/pattern) to build accurate Pydantic models,
  not just expected end-to-end outputs. Rejected as insufficient on its own,
  though the canonical vectors are a subset of what gets vendored either way.

### Recommendation

**Vendor immutable compatibility fixtures**, pinned to `basis-schemas` tag
`v0.2.0` (commit `1d3af3cfd38686173980cfb47f8fa44659a4e1c4`, as inspected at
plan-authoring time), under a new, clearly-provenanced path:

```text
tests/fixtures/basis-schemas/v0.2.0/
├── PROVENANCE.md              # tag, commit hash, fetch date, fetch command, update procedure
├── schemas/                   # the 14 operation-aware contract YAMLs, copied verbatim
│   ├── contract-metadata/contract-metadata.yaml
│   ├── redaction-classification/redaction-classification.yaml
│   ├── reason-code/reason-code.yaml
│   ├── identity-evidence-reference/identity-evidence-reference.yaml
│   ├── adapter-evidence-reference/adapter-evidence-reference.yaml
│   ├── operation-aware-decision-request/operation-aware-decision-request.yaml
│   ├── policy-condition/policy-condition.yaml
│   ├── policy-rule/policy-rule.yaml
│   ├── policy-bundle/policy-bundle.yaml
│   ├── trace-rule-evidence/trace-rule-evidence.yaml
│   ├── evaluation-trace/evaluation-trace.yaml
│   ├── operation-aware-decision-response/operation-aware-decision-response.yaml
│   ├── audit-evidence/audit-evidence.yaml
│   └── gateway-audit-event/gateway-audit-event.yaml
└── compatibility/              # the five canonical-vector directories, copied verbatim
    ├── allow-basic/…
    ├── deny-precedence/…
    ├── default-deny/…
    ├── not-applicable/…
    └── invalid-policy-bundle/…
```

This satisfies every requirement the brief poses:

- **Reproducibility** — every contributor and every CI run reads the same
  bytes, because they are committed to `basis-core`, not fetched at test
  time.
- **Offline development / air-gapped contributors** — no network access is
  needed to run the operation-aware test suite once the vendored copy
  exists.
- **CI reliability** — no dependency on `basis-schemas`' PyPI availability,
  GitHub availability, or network flakiness during CI.
- **Release immutability** — the vendored copy is pinned to an immutable tag
  and commit hash; it never silently drifts.
- **Drift detection** — `PROVENANCE.md` records the exact commit; a future PR
  that re-vendors against a newer `basis-schemas` tag is a visible,
  reviewable diff against the previous vendored copy, exactly like a
  dependency version bump.
- **Ownership of copied fixtures** — owned by `basis-core`, under
  `tests/fixtures/`, which this repository's own conventions
  (`docs/compatibility-testing.md`) already establish as the home for
  contract-shaped test fixtures; **not** treated as `basis-core`-authored
  content, and never edited by hand (a re-vendor is always a full-directory
  replacement, never a hand patch).
- **How updates are approved** — a deliberate, reviewable PR (Milestone 1,
  PR 2) that re-runs the vendoring copy, updates `PROVENANCE.md`, and lets
  every downstream conformance test (Milestone 12) confirm the new vendored
  contracts still produce the same canonical-vector outcomes, or surfaces
  exactly what changed if `basis-schemas` shipped a breaking or additive
  revision.
- **Runtime dependency: none.** `basis-schemas` is never added to
  `pyproject.toml` `dependencies` or `[project.optional-dependencies].dev`.
  The vendored files are read only by test code, never by `src/basis_core/`.
- **Build-time/test-time inputs only** — confirmed by the point above; this
  is the load-bearing constraint the rest of this plan (Sections 6, 7, 13)
  assumes.

This strategy is implemented, not designed, in **Milestone 1, PR 2** (see
Section 12). This plan does not implement it here.

---

## 5. Compatibility strategy

**First-wave models stay public, unchanged, and un-deprecated.** No item in
`docs/public-api.md`'s "Stable public API" or "Extension API" tiers is
removed, renamed, or redefined by this plan. `DecisionRequest`,
`DecisionResponse`, `PolicyEngine`, `PolicyRule`, `EnforcementPoint`,
`AuditEvent`, `AuditWriter`, `AdapterBase`, and every domain type keep their
current import paths, fields, and behavior for the entire duration of this
roadmap and beyond.

**New operation-aware models are additive**, following the "Additive
changes" list in `docs/breaking-change-discipline.md` throughout: every new
model is a *new* symbol at a *new* import path; nothing narrows or reinterprets
an existing symbol.

**Naming strategy.** Every operation-aware symbol is prefixed
`OperationAware*` where it directly parallels an existing v0.1.0 concept
(`OperationAwareDecisionRequest`, `OperationAwareDecisionResponse`,
`OperationAwarePolicyEngine`, `OperationAwareEnforcementPoint`), and left
unprefixed where the concept has no v0.1.0 analog and the `basis-schemas`
contract name is already unambiguous (`PolicyBundle`, `PolicyCondition`,
`TraceRuleEvidence`, `EvaluationTrace`, `AuditEvidence`,
`IdentityEvidenceReference`, `AdapterEvidenceReference`,
`RedactionClassification`). The one deliberate exception requiring care:
`basis-schemas`' `policy-rule` contract would naturally map to a class named
`PolicyRule` in Python, but `basis_core.policy.engine.PolicyRule` **already
exists** as the v0.1.0 extension-point Protocol. This plan resolves the
collision by naming the operation-aware data model `OperationAwarePolicyRule`
— not `PolicyRule` — even though every other operation-aware symbol in this
list is unprefixed for its category. This is called out explicitly because
it is the one place a mechanical "follow the contract name" rule would have
produced a breaking naming collision.

**Import paths.** All operation-aware code lives under a parallel module
tree, one new leaf module per existing subpackage plus new
subpackages-of-subpackages where the volume warrants it:

```text
src/basis_core/
├── domain/
│   ├── operation_aware_vocabulary.py   # RedactionClassification, ReasonCode
│   ├── evidence.py                     # IdentityEvidenceReference, AdapterEvidenceReference
│   └── operation_aware.py              # Location, Device, ProtocolContext, Safety/Environment/RiskContext
├── decisions/
│   └── operation_aware.py              # OperationAwareDecisionRequest, OperationAwareDecisionResponse
├── policy/
│   └── operation_aware/
│       ├── condition.py                # PolicyCondition
│       ├── rule.py                     # OperationAwarePolicyRule
│       ├── bundle.py                   # PolicyBundle
│       ├── validation.py               # bundle/rule structural + semantic validation
│       ├── applicability.py            # bundle-scope applicability
│       ├── selector.py                 # rule match-criteria evaluation
│       ├── operators.py                # condition operator registry — Milestone 7, gated
│       └── condition_eval.py           # condition evaluation integration — Milestone 7, gated
├── audit/
│   └── operation_aware/
│       ├── trace_rule_evidence.py      # TraceRuleEvidence
│       ├── evaluation_trace.py         # EvaluationTrace
│       └── audit_evidence.py           # AuditEvidence
├── evaluation/
│   ├── __init__.py
│   └── operation_aware/
│       ├── __init__.py
│       ├── trace_assembly.py           # rule evidence → EvaluationTrace (orchestration, not semantics)
│       ├── engine.py                   # sequences policy-owned applicability/selection/condition/effect-aggregation stages
│       └── response_assembly.py        # response + AuditEvidence assembly
└── enforcement/
    └── operation_aware.py              # OperationAwareEnforcementPoint
```

Per `basis-architecture` ADR-0006 ("Introduce a Pure Evaluation Orchestration
Layer"), `trace_assembly.py`, `engine.py`, and `response_assembly.py` are
**evaluation-owned orchestration**, not policy-owned semantics, and live
under `evaluation/operation_aware/` rather than `policy/operation_aware/`.
`policy/operation_aware/` retains every module that implements executable
authorization semantics: applicability, candidate selection, selector
matching, condition evaluation, and (added by the milestones after this one)
rule-effect aggregation, deny precedence, allow determination, default deny,
and `NOT_APPLICABLE`/final-outcome semantics. The evaluation engine invokes
those policy-owned operations; it does not reimplement them.

**Supersession note:** ADR-0006 supersedes the earlier draft placement of
`trace_assembly.py`, `engine.py`, and `response_assembly.py` under
`policy/operation_aware/`; these orchestration modules are now planned under
`evaluation/operation_aware/` (module tree above). Later PR entries in this
document (PR 26, PR 27, PR 31) reference this note rather than repeating the
move's rationale at each file listing.

This mirrors the existing `domain → {decisions, policy, audit, adapters} →
enforcement` import graph, extended per ADR-0006: `evaluation/` is a new
node in the dependency graph, sitting between `policy/`+`audit/` and
`enforcement/` — it does not add a new edge into `policy/` or `audit/` from
below, only a new node that legally imports both from above. See
`docs/import-boundaries.md` for the authoritative per-module permission
matrix (including the `policy/` architecture-ceiling-vs-legacy-local-rule
distinction), not repeated here.

**Serialization boundaries.** Every new model is a Pydantic `BaseModel`
(matching every existing kernel model), serialized with `model_dump(mode="json")`
the same way `AuditEvent`/`LogAuditWriter` already do. No new serialization
mechanism is introduced.

**Deprecation timing.** None. This plan deprecates nothing. If a future
architecture decision chooses to deprecate the v0.1.0 surface in favor of the
operation-aware one, that is a separate, later ADR-governed decision outside
this plan's scope (see Section 15).

**Migration documentation.** Not required by this plan, because nothing is
migrated — v0.1.0 consumers do not need to change anything. A future
*adoption guide* (not a migration guide) for consumers who want to *start*
using the operation-aware surface is scoped in Section 14, Milestone 14.

**Semantic-versioning expectations.** Per `docs/architecture/compatibility-philosophy.md`'s
semantic-versioning philosophy (adopted by `docs/schema-versioning.md`):
this is a **minor**-shaped expansion in spirit (purely additive), but the
package version increments to `0.2.0` (not `0.1.1`) because it introduces a
substantial new public surface, matching the precedent `basis-schemas` itself
set (`0.1.0` → `0.2.0` for its own purely-additive fourteen-contract
expansion, per its release notes). This is a naming/communication choice,
not a claim that anything breaking occurred.

**Compatibility snapshots.** New, separate fixtures and snapshot tests for
every new model (Milestone 3 forward), living in their own fixture directory
(e.g. `tests/fixtures/contracts/operation_aware/`), never mixed into the
existing `tests/fixtures/contracts/*.json` v0.1.0 fixture set.

**Behavioral regression testing.** Milestone 13 (Section 12) is dedicated
entirely to proving, with tests, that every v0.1.0 behavior — evaluation
semantics, failure modes, audit shape, public API — is unchanged after every
other milestone's additions land.

**Does `EnforcementPoint` gain new entry points, or accept multiple request
families?** **Recommendation: a new, separate `OperationAwareEnforcementPoint`
class — not a modified `EnforcementPoint.evaluate()`.** Reasons:

1. `EnforcementPoint.evaluate()`'s signature
   (`request: DecisionRequest | dict[str, object]`) accepting a *third*
   request type (`OperationAwareDecisionRequest`) would require runtime type
   dispatch inside a method whose current contract (`docs/extension-contracts.md`,
   "EnforcementPoint orchestration expectations") guarantees a single,
   simple failure/audit shape. Branching internal behavior on input type is
   exactly the kind of behavioral-breakage risk `docs/breaking-change-discipline.md`
   flags under "Changing the signature of a public function or method in an
   incompatible way."
2. `EnforcementPoint` composes a v0.1.0 `PolicyEngine`; an operation-aware
   evaluation composes an `OperationAwarePolicyEngine` operating over a
   `PolicyBundle`, not a `list[PolicyRule]`. These are different
   constructor-time dependencies — a single class cannot cleanly hold both
   without either making both optional (weakening the "always configured"
   guarantee) or overloading the constructor.
3. A separate class keeps the "single component authorized to call both
   policy evaluation and audit writing" invariant (Invariant 1 of
   `docs/extension-contracts.md`'s EnforcementPoint section) intact for
   *each* evaluation family independently, rather than requiring one class to
   reason about two unrelated evaluation and audit pipelines.
4. It is the same pattern this plan already uses for `PolicyEngine` →
   `OperationAwarePolicyEngine` and is therefore consistent, not a one-off.

This decision itself is recorded as **Milestone 11, PR 33** (a short design
note, not code) before PR 34 implements it, so it goes through the same
"decide before build" discipline as the rest of this plan.

**How old consumers remain functional.** By construction: nothing they
import, call, or depend on changes. No action is required of a v0.1.0
consumer at any point in this roadmap.

**What would require a future major release.** Per
`docs/architecture/compatibility-philosophy.md`'s semantic-versioning
philosophy and `docs/breaking-change-discipline.md`'s "Breaking changes"
list, applied to the *new* v0.2.0 surface once it exists: renaming or
removing any operation-aware symbol, narrowing `OperationAwareDecisionRequest`'s
optional-field set to required, changing the `evaluation_status`/`outcome`/
`failure_reason` invariants, changing deny-precedence or default-deny
behavior, or changing the `TraceRuleEvidence.rule_result` four-value
vocabulary. None of these are proposed by this plan; they are named here
only so a future contributor recognizes the bar.

---

## 6. Proposed internal architecture

No code is written in this plan. The layers below describe the intended
shape of Milestones 2-11 (Section 12) without prescribing function
signatures.

**Dependency direction** (extends, never contradicts,
`docs/import-boundaries.md`):

```text
tests/fixtures/basis-schemas/v0.2.0/   (vendored contract text, test-time only)
    ↓  (informs, does not runtime-import)
domain/operation_aware_vocabulary.py, domain/evidence.py, domain/operation_aware.py
    ↓
decisions/operation_aware.py  (OperationAwareDecisionRequest)
    ↓
policy/operation_aware/{condition,rule,bundle}.py         (typed immutable data model)
    ↓
policy/operation_aware/validation.py                       (structural + semantic bundle validation)
    ↓
policy/operation_aware/applicability.py                     (bundle scope vs. request)
    ↓
policy/operation_aware/selector.py                          (match-criteria evaluation)
    ↓
policy/operation_aware/{operators,condition_eval}.py         (condition evaluation — gated, Milestone 7)
    ↓
policy/operation_aware/{effect aggregation, deny precedence, default deny, NOT_APPLICABLE, final-outcome modules — Milestone 9-10, policy-owned}
    ↓                                        ↓
    ↓                          audit/operation_aware/{trace_rule_evidence,evaluation_trace,audit_evidence}.py
    ↓                                        ↓
    └──────────────→  evaluation/operation_aware/trace_assembly.py, engine.py, response_assembly.py
                       (orchestration only — invokes the policy-owned stages above and audit-owned
                        trace/evidence models; implements none of their semantics)
    ↓
decisions/operation_aware.py  (OperationAwareDecisionResponse — response assembly output)
    ↓
enforcement/operation_aware.py  (OperationAwareEnforcementPoint — public entry point)
```

Read this as: **policy-owned evaluation facts flow down into evaluation
orchestration, which flows down into decision/trace/response artifacts,
which flow down into enforcement.** `evaluation/operation_aware/engine.py`
invokes the policy-owned applicability, selection, condition-evaluation, and
effect-aggregation operations above it and carries their typed results into
trace assembly and response assembly — it does not reimplement selector
semantics, condition semantics, operator semantics, effect aggregation, deny
precedence, default deny, or applicability semantics. Ordering in this
diagram reflects data flow through orchestration stages, not authorization
precedence — deny-precedence itself is decided entirely within the
policy-owned effect-aggregation stage, before evaluation orchestration ever
runs.

This is the same shape the brief's template describes, instantiated against
this repository's actual package layout:

```text
serialized contract (vendored basis-schemas YAML, test-time reference only)
    ↓
structural validation (Pydantic field/type/pattern validation on construction)
    ↓
typed domain model (OperationAwareDecisionRequest, PolicyBundle, PolicyRule, PolicyCondition — frozen, immutable)
    ↓
semantic validation (bundle scope well-formed, rule_id/condition_id uniqueness, effect closed-vocabulary, at-least-one-of match/conditions)
    ↓
policy-owned deterministic evaluation (applicability → selection → condition evaluation → effect aggregation → deny-precedence/default-deny/NOT_APPLICABLE/final-outcome semantics)
    ↓
evaluation orchestration (evaluation/operation_aware/engine.py invokes the policy-owned stages above and carries their typed results forward — no semantic reimplementation)
    ↓
trace + decision + AuditEvidence (EvaluationTrace/TraceRuleEvidence, OperationAwareDecisionResponse, AuditEvidence — assembled by evaluation/operation_aware/{trace_assembly,response_assembly}.py, not mutated in place)
    ↓
serialization boundary (Pydantic model_dump(mode="json"), same convention as AuditEvent today)
```

**Import legality reminder:** `evaluation/` legally imports both `policy/`
and `audit/` (it is the one package permitted to sit above both — see
`docs/import-boundaries.md`). `policy/` and `audit/` remain mutually isolated
siblings; neither imports the other, and neither imports `evaluation/`.
`evaluation/` must not import `adapters/` or `enforcement/`.

**Raw YAML dictionaries never become the evaluator's primary internal
representation.** Every stage past "structural validation" operates on typed,
validated Pydantic models — `PolicyBundle.rules` is `list[OperationAwarePolicyRule]`,
never `list[dict]`; `OperationAwarePolicyRule.conditions` is
`list[PolicyCondition]`, never `list[dict]`. The vendored YAML fixtures
(Section 4) are loaded and parsed into these typed models exactly once, at
the test boundary (Milestone 1's fixture-loading helper), and never touched
again as raw dicts by evaluator code.

---

## 7. Deterministic evaluation pipeline

Sixteen stages, each with input, output, possible failure, whether the
failure is an authorization result or an evaluator failure, relevant reason
codes, expected test type, and governing source. This is the concrete
translation of ADR-0002 §3's nine-step conceptual sequence into the sixteen
stages the brief's template names — every ADR-0002 concept is covered; no
stage below introduces behavior ADR-0002 did not already require.

| # | Stage | Input | Output | Possible failure | Result vs. evaluator failure | Reason codes | Test type | Governing source |
|---|---|---|---|---|---|---|---|---|
| 1 | Structural request validation | raw input (dict or `OperationAwareDecisionRequest`) | validated `OperationAwareDecisionRequest` | missing required field (`request_id`/`subject_id`/`action`), wrong type, invalid `action`/`resource` pattern | **evaluator failure** — `evaluation_status: failed`, `failure_reason: invalid_request` | `invalid_request` | unit (Pydantic `ValidationError` cases) | ADR-0002 §3 step 1; `operation-aware-decision-request.md` §10 |
| 2 | Semantic request validation | validated request | request confirmed internally consistent (e.g. `identity_source` vs. `identity_evidence_reference.identity_source` per §26 general rule) | inconsistent cross-field state that structural validation cannot catch alone | **evaluator failure** — `invalid_request` | `invalid_request` | unit | `operation-aware-decision-request.md` §26 |
| 3 | Schema/version compatibility check | request's implicit contract version (this plan pins one version, so this stage is a no-op check in v0.2.0's initial scope) | pass, or failure | unsupported schema version (not reachable until multiple versions exist) | **evaluator failure** — `unsupported_schema_version` | `unsupported_schema_version` | unit (reserved case, exercised once versioning matters) | ADR-0002 §12 |
| 4 | Policy bundle structural validation | raw/loaded `PolicyBundle` candidate | validated `PolicyBundle` | missing required bundle field, malformed rule, malformed condition | **evaluator failure** — `invalid_policy_bundle` | `invalid_policy_bundle` | unit; canonical vector `invalid-policy-bundle` | ADR-0002 §3 step 2; `policy-bundle.md` §22 |
| 5 | Policy bundle semantic validation | validated `PolicyBundle` | confirmed internally consistent bundle | duplicate `rule_id` across bundle, duplicate `condition_id` within a rule, rule with neither `match` nor non-empty `conditions` | **evaluator failure** — `policy_validation_failure` | `policy_validation_failure` | unit; canonical vector `invalid-policy-bundle` | ADR-0004 §11; `policy-rule.md` §12; `policy-condition.md` §8 |
| 6 | Establish evaluation context | validated request | internal evaluation context (no new model — a function-local structure) | none (pure data assembly) | n/a | n/a | unit | ADR-0002 §3 step 3 |
| 7 | Bundle applicability determination | request + candidate bundles | `bundle_applicability: applicable \| not_applicable` per bundle | none (deterministic classification, not a failure) | **authorization result** — feeds `NOT_APPLICABLE` at stage 11 | n/a | unit; canonical vector `not-applicable` | ADR-0002 §5; `policy-rule-model.md` §3; `evaluation-trace.md` §11 |
| 8 | Candidate rule selection (match criteria) | applicable bundle(s) | ordered candidate rule list | none (a rule that doesn't match is `not_matched`, not a failure) | **authorization result** | n/a | unit; deterministic-ordering test | ADR-0002 §8; ADR-0004 §6,10 |
| 9 | Condition evaluation | candidate rule's `conditions` + evaluation context | per-condition match/no-match/error | unsupported operator, type mismatch, missing required context | **mixed** — a condition `error` result feeds `rule_result: error` for that rule (still an authorization-path outcome per ADR-0002 §9, not an `evaluation_status: failed`, unless it is a *policy bundle* validity problem caught upstream at stage 5) | rule/condition-level `reason_code`, e.g. `condition_evaluation_error` when it propagates to `failure_reason` (see Section 8 — **gated**) | unit (once Milestone 7 unblocks); canonical vectors do not currently exercise this path (deferred scenario) | ADR-0002 §9-11; `policy-condition.md` |
| 10 | Per-rule evidence creation | rule + its condition results | `TraceRuleEvidence` (`rule_result`: `matched`/`not_matched`/`skipped`/`error`) | none (assembly only) | n/a | rule's own `reason_code`, if authored | unit | ADR-0003 §5; `trace-rule-evidence.md` |
| 11 | Deny precedence | all rule evidence for applicable bundle(s) | `deny` if any `matched` DENY rule exists, else continue | none | **authorization result** | e.g. `deny_rule_matched` | unit; canonical vector `deny-precedence` | ADR-0002 §6-7; `policy-rule-model.md` §9 |
| 12 | Allow determination | rule evidence, given no deny matched | `allow` if any `matched` ALLOW rule exists | none | **authorization result** | e.g. `allow_rule_matched` | unit; canonical vector `allow-basic` | ADR-0002 §4,7 |
| 13 | Default deny | no matched ALLOW and no matched DENY, but an applicable bundle existed | `deny` | none | **authorization result** | e.g. `no_allow_rule_matched` | unit; canonical vector `default-deny` | ADR-0002 §4 |
| 14 | NOT_APPLICABLE | no bundle's scope covers the request at all (from stage 7) | `not_applicable` | none | **authorization result**, distinct from `deny` | n/a or a scope-gap reason code | unit; canonical vector `not-applicable` | ADR-0002 §5 |
| 15 | Trace assembly | all rule evidence + stages 7-14's outcome | `EvaluationTrace` (deterministic ordering, bounded) | none if stages 1-5 passed; an upstream stage 1/2/4/5 failure short-circuits straight to stage 16 with `evaluation_status: failed` and no trace content beyond identity fields | n/a | n/a | unit; determinism/ordering test; canonical vectors (all five) | ADR-0002 §13; ADR-0003 §4,13 |
| 16 | Response + AuditEvidence assembly | `EvaluationTrace` + outcome (or the stage 1/2/4/5 failure) | `OperationAwareDecisionResponse` + `AuditEvidence` | none (pure assembly; the failure itself was already classified upstream) | n/a | n/a | unit; response/trace/audit-evidence agreement invariant tests; canonical vectors (all five) | ADR-0002 §14; ADR-0003 §2,14; `operation-aware-decision-response.md` §16,21 |

**Invariant carried through every stage:** an evaluator failure at stages
1-5 (or an internal error at any stage — a sixth failure category, "internal
evaluation error," not separately numbered above because it is a catch-all
fail-closed path parallel to `EnforcementPoint`'s own `INTERNAL_ERROR`
handling) always produces `evaluation_status: failed`, `outcome: null`, and
never reaches stages 6-15's authorization logic at all. This is the same
"evaluator failure is fail-closed and distinct from a substantive decision"
guarantee `docs/kernel-constitution.md` Invariant 6 already requires of the
v0.1.0 kernel, applied unchanged to the operation-aware one.

---

## 8. Condition-operator decision gate

`basis-schemas` `policy-condition.md` §10-11 publishes `operator` as a
**structurally validated, open identifier** — a condition is well-formed if
`operator` matches an identifier pattern, but the contract explicitly does
not close the vocabulary or define what any specific operator *does* at
evaluation time. ADR-0004 §7 requires conditions to be deterministic, side-
effect-free, three-outcome (match/no-match/error), non-coercing, and to treat
missing context as non-truthy — but, like the schema, stops short of naming
an operator set. This is a deliberate, repeatedly-stated gap in the upstream
architecture (ADR-0001 §6, ADR-0002 §16, ADR-0004 §18, ADR-0005 §14 all name
"condition operator language" as explicitly deferred).

**This plan formalizes that gap as an implementation blocker, not a
`basis-core` design decision.** `basis-core` must not invent condition
operator semantics inside an implementation PR — doing so would let a single
kernel PR silently settle an ecosystem-wide semantic question that
`basis-architecture` itself has repeatedly declined to settle.

### Inventory of what remains unresolved

At minimum, the following require an explicit operator-registry decision
before Milestone 7 (Section 12) can proceed past its first, blocked PR:

- **Supported operator registry** — the closed (or intentionally open) list
  of operator identifiers `basis-core` v0.2.0 will implement in its first
  release (e.g. `eq`, `ne`, `in`, `not_in`, `gt`/`gte`/`lt`/`lte`, `exists`,
  `not_exists`, or some different naming/set entirely).
- **Equality / inequality** — exact semantics for `eq`/`ne` across the
  scalar types `policy-condition.md` allows (`string`/`number`/`boolean`/`null`).
- **Membership** — `in`/`not_in` semantics against `expected_value`'s
  "homogeneous array of scalars" shape.
- **List semantics** — whether a condition can test list-shaped *request*
  context (e.g. `subject_roles`) against a scalar or list `expected_value`,
  and if so, whether it means "any of" or "all of."
- **Booleans** — whether boolean context values participate in
  ordering/comparison operators or only equality.
- **Numeric comparison** — `gt`/`gte`/`lt`/`lte` semantics, and whether
  numeric strings are ever compared numerically (they should not be, per the
  no-silent-coercion rule, but this needs an explicit statement).
- **Time comparison** — whether/how ISO 8601 timestamp context (e.g.
  `evaluation_time`) participates in ordering operators, and timezone-
  normalization rules if so.
- **Absent values** — confirmed by ADR-0002 §10/§9 as "does not match, not an
  error" for a rule condition referencing context the request does not
  carry, but the exact operator-by-operator behavior (does `not_exists`
  match an absent field? does `ne` match against an absent field?) needs
  enumeration per operator.
- **Null values** — whether an explicitly-present `null` in either the
  request context or `expected_value` behaves like "absent" or like a
  distinct comparable value.
- **Type mismatches** — confirmed by ADR-0002 §9 as "evaluation error or
  defined no-match, never implicit coercion," but which of the two (error vs.
  no-match) applies to which operator/type-pair combination needs
  enumeration.
- **Unsupported operators** — an `operator` string that is structurally
  valid (passes `policy-condition.md`'s pattern) but not implemented by this
  kernel version: must be a defined evaluation error, never a silent
  no-match or silent match.
- **Unknown field paths** — a `field_path` that structurally validates
  (per `operation-aware-decision-request.md` §9's dotted-path rules) but does
  not resolve to any field this kernel version's request model defines.
- **Coercion** — the general no-silent-coercion rule needs a specific,
  written statement of what "coercion" means operator-by-operator (e.g. is
  comparing `"3"` against `3` an error, a no-match, or — forbidden —
  a silent match?).
- **Nested context lookup** — `field_path`'s dotted-path resolution against
  nested optional objects (`location.site_id`, `device.device_class`, etc.)
  needs a defined resolution algorithm, including what happens when an
  intermediate object (e.g. `location`) is itself absent.
- **Deterministic ordering** — condition evaluation order within a rule's
  `conditions` array (already required to be array-order, per the general
  determinism requirement, but needs to be stated as this kernel's specific
  behavior, not inferred).
- **Error versus non-match behavior** — the overarching distinction the
  bullets above all instantiate: this needs one governing statement, not
  sixteen independent judgment calls made rule-by-rule during
  implementation.

### Recommendation

This requires **a narrow architecture clarification document** in
`basis-architecture` — not a full new ADR, and not an amendment to an
existing ADR-0004 (which already correctly scoped condition semantics out).
A clarification document is the right weight because: the *shape* question
(is `operator` open or closed) is already answered by the published schema;
what remains is an *operational semantics* question — the specific
operator-by-operator behavior table above — that is naturally scoped to
"first implementable subset for `basis-core` v0.2.0," not a permanent,
ecosystem-wide closed vocabulary decision. A full ADR is more appropriate if
`basis-architecture` decides the operator registry should be a governed,
versioned vocabulary from day one (analogous to the reason-code and action-
vocabulary treatment); a narrower clarification is more appropriate if the
first implementable subset is understood as a `basis-core`-scoped starting
point that a future `basis-schemas` contract can later formalize once
exercised by a real consumer (the same "experimental → candidate → stable"
path every other operation-aware contract already follows, per
`docs/contract-governance.md` in `basis-schemas`). This plan recommends the
narrower path — propose the operator table above as a `basis-architecture`
clarification PR, informed by (but not overriding) ADR-0004 — because it
matches the incremental, evidence-before-commitment posture the rest of the
operation-aware architecture work has followed throughout (every ADR
explicitly defers what it is not ready to decide, rather than deciding it
provisionally).

**All condition-evaluation implementation is blocked until this
clarification is approved.** Milestone 7 (Section 12) is scoped as exactly
one blocked PR (opening the clarification request) followed by two PRs whose
entire dependency is "the clarification above is approved" — no
condition-operator code is written in any earlier milestone, and
Milestones 1-6, 8-11 (Section 12) are explicitly scoped so that they do not
require condition evaluation to function: bundle/rule/condition *shape*
validation, applicability, and rule *selection by structural match criteria*
(the `match` object, not `conditions`) are all independent of the operator
question and can proceed unblocked. The `OperationAwarePolicyEngine`'s
Milestone 9-10 aggregation logic (deny-precedence, default-deny) operates
correctly on `rule_result: matched/not_matched` values that, ahead of
Milestone 7, are produced entirely by `match`-criteria evaluation (Milestone
6) with `conditions` treated as present-but-not-yet-evaluated — the plan
explicitly notes at Milestone 8/PR 26 that `condition_results` will be empty
until Milestone 7 lands, so the kernel remains honest about what it has and
has not evaluated at every intermediate milestone rather than silently
skipping conditions without saying so.

---

## 9. Trace and audit design plan

**`TraceRuleEvidence`** (Milestone 8, PR 24) records, per candidate rule:
`rule_id` + `effect` (reused unchanged from `PolicyRule`), `rule_result`
(`matched`/`not_matched`/`skipped`/`error` — closed, per ADR-0003 §5),
optional `condition_results` (bounded, per-condition match/no-match/error —
populated only once Milestone 7 unblocks), optional `reason_code`, optional
`explanation`. It does **not** copy the rule's own `match`/`conditions`
authored content — a consumer that needs the rule's authored shape
dereferences the bundle by `rule_id`, per `trace-rule-evidence.md` §8. This
keeps trace records bounded regardless of how elaborate a rule's authored
match criteria are.

**`EvaluationTrace`** (Milestone 8, PR 25) is the per-request explanatory
record: `trace_id`, `request_id`, `correlation_id`, `evaluation_status`,
`outcome`, `bundle_applicability`, `bundle_id`/`bundle_version`,
`failure_reason`, `rule_evidence: list[TraceRuleEvidence]`, `reason_code`,
`explanation`. It is produced by `basis-core` as part of the response, never
persisted by `basis-core` itself.

**`OperationAwareDecisionResponse`** (Milestone 10, PR 29) is the
authoritative kernel result. `evaluation_trace`, when embedded, is the
explanatory record that must *agree with* — never override — the response's
own `request_id`/`evaluation_status`/`outcome`/`failure_reason` (the
"Response/trace authority" invariant, `operation-aware-decision-response.md`
§21, tested directly in Milestone 10, PR 32).

**`AuditEvidence`** (Milestone 10, PR 30) is bounded, durable, kernel-side
evidence, structurally distinct from `EvaluationTrace`: it references
`trace_id` rather than duplicating trace content, carries `matched_rule_ids`
(bounded list, not full rule evidence), and carries `identity_evidence_reference`/
`adapter_evidence_reference` (references, never raw evidence) alongside
`recorded_at` and `schema_version`. **`basis-core` produces `AuditEvidence` as
part of its response and never persists it** — no `AuditWriter`-shaped
protocol is introduced for it in this plan, because there is nothing for
`basis-core` to write to; persistence is `basis-gateway`'s responsibility
(ADR-0003 §14), realized when `basis-gateway` assembles a `GatewayAuditEvent`
that this repository never constructs, validates, or imports.

**`GatewayAuditEvent` belongs to the gateway boundary.** Confirmed in
Section 3's mapping table and restated here for emphasis: no `basis-core`
module in this plan's roadmap (Section 12) imports, constructs, or asserts
against a `GatewayAuditEvent`-shaped value at any point.

**Redaction classifications constrain handling but do not themselves perform
redaction.** `RedactionClassification` (Milestone 2, PR 5) is a five-value
closed enum (`safe_to_expose`, `safe_after_redaction`, `reference_only`,
`never_store`, `never_display`) that this plan's evidence-reference models
(`IdentityEvidenceReference`, `AdapterEvidenceReference` — Milestone 2, PR 6)
carry as a field. **No PR in this roadmap implements a redaction function.**
Applying the classification (masking, hashing, minimizing) is future work,
explicitly out of scope for the models this plan defines, consistent with
`redaction-classification.md`'s own "carries vocabulary only" framing.

**Evidence references point to evidence but do not establish trust.**
`IdentityEvidenceReference`/`AdapterEvidenceReference` carry a structural
digest and a redaction classification — never a raw token, credential,
claim set, or protocol payload. This plan's models enforce the *shape*
constraint (no raw-evidence-shaped field exists on these types at all — see
Milestone 2, PR 6's non-goals) but make **no claim about cryptographic trust,
signature verification, or non-repudiation** of the referenced evidence,
exactly matching `basis-schemas`' own explicit disclaimer in
`docs/release-notes.md` ("does not verify evidence trust, authenticity,
signatures, or non-repudiation").

**Raw JWTs, credentials, protocol payloads, and unsafe identity claims must
not enter these artifacts.** Enforced structurally: no field on any
operation-aware model in this plan's roadmap is typed to hold a raw
token/credential/claim-set/protocol-payload. This is a modeling constraint
(the field simply does not exist), not a runtime filter — there is nothing
to filter because the shape never admits the value.

**Determinism, ordering, stable rule IDs, bounded output.** `rule_evidence`
ordering in `EvaluationTrace` must not depend on Python dict iteration order
or set ordering at any stage; Milestone 6 (selector) and Milestone 8 (trace
assembly) both carry explicit deterministic-ordering tests (sorted by
`rule_id` as the stable tie-breaker, per ADR-0004 §10, when no other
ordering signal is defined). `rule_id`/`condition_id`/`trace_id`/`bundle_id`/
`evidence_id` are all treated as stable identifiers, never regenerated or
recomputed between evaluations of the same request against the same bundle
version — the determinism guarantee Invariant 5 in `docs/kernel-constitution.md`
already requires of the v0.1.0 kernel, extended unchanged to every new model.
"Bounded output" (Milestone 8) means `EvaluationTrace`/`AuditEvidence` never
grow unbounded with the number of *candidate* rules considered in a large
bundle beyond what the contract's own field shapes already bound (e.g.
`matched_rule_ids` is a list of stable identifiers, not full rule content).

---

## 10. Canonical-vector adoption plan

The five `basis-schemas` v0.2.0 canonical scenarios, and the first
`basis-core` phase expected to make each pass, distinguishing schema
validation from domain-model round trip from semantic validation from
evaluator behavior from trace equality from response equality from
`AuditEvidence` equality from gateway-only assertions this repository must
never make.

| Scenario | First phase it becomes *loadable* (schema validation, domain-model round trip) | First phase it becomes *evaluable* (semantic validation, evaluator behavior) | First phase its *trace* is asserted | First phase its *response* is asserted | First phase its *AuditEvidence* is asserted | Gateway-only assertions this repo makes |
|---|---|---|---|---|---|---|
| `allow-basic` | Milestone 3 (PR 10-11): request + bundle load and round-trip against vendored fixtures | Milestone 9 (PR 27-28): unit-level combining logic reaches `allow` | Milestone 12 (PR 37): full canonical-vector wiring | Milestone 12 (PR 37) | Milestone 12 (PR 37) | **none** — `expected-gateway-audit-event.yaml` is reference-only (Milestone 12, PR 38) |
| `deny-precedence` | Milestone 3 | Milestone 9 (PR 27-28) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | none |
| `default-deny` | Milestone 3 | Milestone 9 (PR 27-28) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | none |
| `not-applicable` | Milestone 3 | Milestone 5 (PR 17-18): applicability alone already determines this outcome, ahead of full rule aggregation | Milestone 12 (PR 37) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | none |
| `invalid-policy-bundle` | Milestone 3 (loads as YAML; fails *validation*, which is the point) | Milestone 4 (PR 15-16): bundle semantic validation rejects the duplicate `rule_id` and produces `evaluation_status: failed` | Milestone 12 (PR 37) | Milestone 12 (PR 37) | Milestone 12 (PR 37) | none |

**Comparison strategy.** Field-by-field structural comparison against the
vendored `expected-*.yaml` fixtures (Section 4), using exact equality for
closed-vocabulary and identifier fields (`outcome`, `evaluation_status`,
`rule_result`, `bundle_id`, `rule_id`) and normalized comparison for
timestamp fields (compare parsed `datetime` values, not raw strings, to
avoid brittleness to timezone-offset formatting differences) — mirroring
`basis-schemas`' own test suite's stated approach
(`operation-aware-compatibility-vectors.md` §11's determinism guarantees make
this safe: every fixture value is fixed and synthetic, so exact comparison is
the default, with normalization reserved only for genuinely
format-equivalent representations). No test in this plan re-implements
evaluation to check the fixtures are "correct" independently — Milestone 12
proves `basis-core`'s evaluator *reaches* the vendored expected outputs, the
same "future basis-core conformance question" framing
`operation-aware-compatibility-vectors.md` §9-10 already anticipates.

---

## 11. Public API impact assessment

**Model exports.** Every new type named in Section 5's module tree becomes a
new `__all__` entry on its owning package (`basis_core.domain`,
`basis_core.decisions`, `basis_core.policy`, `basis_core.audit`,
`basis_core.enforcement`), added additively — no existing `__all__` entry is
removed or reordered in a way that changes meaning. `docs/public-api.md`
gains a new top-level section, "Operation-aware public API (v0.2.0)",
parallel in structure to the existing "Stable public API" section, added at
Milestone 11 (PR 35) once the shape has stabilized through Milestones 2-10,
not speculatively at Milestone 2.

**Evaluator entry points.** `OperationAwarePolicyEngine.evaluate(...)` —
signature to be finalized during Milestone 9 implementation, but expected to
mirror `PolicyEngine.evaluate()`'s shape (bundle/request in, aggregated
result out) closely enough that a `basis-core` contributor already familiar
with `PolicyEngine` recognizes the pattern immediately.

**`EnforcementPoint` responsibilities.** Unchanged (Section 5). A new,
separate `OperationAwareEnforcementPoint` gains the equivalent
responsibilities for the operation-aware family only.

**`PolicyEngine` responsibilities.** Unchanged. `OperationAwarePolicyEngine`
is a new, separate class with its own responsibilities, not a modification
or subclass of `PolicyEngine` (subclassing would create an implicit
compatibility coupling between two evaluators this plan treats as
independent).

**Result types.** `OperationAwareDecisionResponse` (Section 3, Section 9)
becomes the operation-aware result type; `DecisionResponse` is unchanged and
remains the v0.1.0 result type. Both exist simultaneously; no shared base
class is introduced unless a future PR discovers a genuine need and gets it
reviewed on its own terms — this plan does not presuppose one.

**Trace access.** `OperationAwareDecisionResponse.evaluation_trace` (optional,
embedded) and `.trace_id` (optional, reference) — mirrors the contract
exactly (Section 3). `DecisionResponse` gains no new field; its existing
(indirect, via `AuditEvent.trace`) trace-access path is unchanged.

**`AuditEvidence` access.** Returned as part of the operation-aware
evaluation result (exact carrier type — e.g. a small result tuple/dataclass
from `OperationAwareEnforcementPoint.evaluate()`, or a field directly on
`OperationAwareDecisionResponse` — is an implementation-architecture decision
Milestone 10 makes, not this plan). Not written anywhere by `basis-core`
(Section 9).

**Exception and failure representation.** `OperationAwareEnforcementPoint.evaluate()`
never raises, matching `EnforcementPoint`'s guarantee exactly — every failure
path (Section 7, stages 1-5, plus an internal-error catch-all) resolves to a
`OperationAwareDecisionResponse` with `evaluation_status: failed`, never a
raised exception reaching the caller.

**Async versus sync behavior.** Synchronous throughout, matching every
existing kernel entry point. No async variant is proposed by this plan; if a
future need arises it is a separate, explicitly-scoped decision.

**Extension contracts.** No new extension point (Protocol interface with an
`evaluate()`-style method) is introduced by this plan. The operation-aware
policy model is **data** (`PolicyBundle`/`OperationAwarePolicyRule`/
`PolicyCondition` as validated Pydantic models a bundle author *authors*, not
code a bundle author *implements*), consistent with `basis-schemas`
`release-notes.md`'s explicit framing ("a structured policy data model, not a
policy language"). `docs/extension-contracts.md` therefore gains **no new
section** for a custom-rule-type extension point in this plan's scope; if a
future phase decides operation-aware evaluation needs a pluggable
rule/condition-evaluator extension point analogous to `PolicyRule`, that is
a new architecture question for `basis-architecture`, not something this
plan pre-authorizes. This is recorded explicitly in Milestone 11 (PR 36) as
a documentation addition stating the current (no-new-extension-point)
position, so a future contributor does not have to re-derive it.

**Naming collisions with first-wave models.** Identified and resolved in
Section 5: `OperationAwarePolicyRule` (not `PolicyRule`) is the one
deliberate rename-from-contract-name-convention needed to avoid colliding
with `basis_core.policy.engine.PolicyRule`. No other collision was found
during this plan's inventory (Section 2) — every other operation-aware
contract name (`PolicyBundle`, `PolicyCondition`, `TraceRuleEvidence`,
`EvaluationTrace`, `AuditEvidence`, `IdentityEvidenceReference`,
`AdapterEvidenceReference`, `RedactionClassification`) has no existing
`basis_core` symbol of the same name.

**Compatibility aliases.** None proposed. No v0.1.0 symbol is renamed, so no
alias is needed to preserve an old import path.

**Deprecation policy.** Unaffected — no deprecation is introduced or
accelerated by this plan (Section 5).

**Documentation requirements.** Enumerated in full in Section 14.

**Every existing public symbol likely to be affected:** **none.** This is
the deliberate, load-bearing conclusion of this section: a full pass over
`docs/public-api.md`'s inventory against every model this plan proposes
(Section 3, Section 5) found zero existing stable-tier or extension-tier
symbol whose signature, behavior, or meaning changes. The only *documentation*
file touched pre-emptively by this plan (Section "Additional repository
updates," below) is `docs/public-api.md` itself, and only to append a new
section — never to edit an existing one.

---

## 12. Detailed phased implementation roadmap

44 PRs across 15 milestones (0-14). PR numbers are sequence-within-plan, not
final PR numbers in the repository's history — later re-sequencing during
actual implementation is expected and fine, provided the dependency
relationships stated below are preserved.

### Milestone 0 — Planning and prerequisites

**PR 1 — This planning document.**
Objective: establish the roadmap itself.
Files: `docs/implementation/basis-core-v0.2-operation-aware-plan.md`,
`README.md`, `docs/architecture-references.md`.
Non-goals: no code, no models, no dependency changes.
Dependencies: none.
Architecture/schema references: ADR-0001 through ADR-0005; `basis-schemas`
v0.2.0 (all 20 contracts).
Required tests: none beyond existing quality gates (this PR is
documentation-only).
Completion criteria: this document merged on `docs/operation-aware-v0.2-plan`.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 2 — Vendor pinned `basis-schemas` v0.2.0 compatibility fixtures.**

**Status: implemented** (`feature/oa-schema-fixture-foundation`, "PR 1:
Schema and Compatibility Fixture Foundation" in the implementation
tracker — a distinct numbering scheme from this document's roadmap
sequence, since this document's own PR 1 was the planning PR above, already
merged). Delivered as one PR that folds this PR's scope together with the
fixture-*discovery* half of PR 4 (parsing/validation into a generic
required/optional/pattern/enum view is explicitly deferred — see below),
because the completion criteria for a governed, drift-checked snapshot were
judged to require the loader helpers and inventory/integrity tests in the
same reviewable change, not a separate follow-up PR. PR 3's
`tests/operation_aware/` subpackage scaffold was not created by this PR —
the new tests were added as flat `tests/test_basis_schemas_snapshot*.py`
modules, matching this repository's existing flat `tests/*.py` convention
(`test_contract_snapshots.py`, `test_schema_validation.py`, etc.); PR 3 was
open and unstarted at the time this PR merged (see PR 3's own status note
above — since implemented) and PR 4 was open and unstarted at the time this
PR merged (see PR 4's own status note below — since implemented).

Two deviations from the sketch below, both strictly additive:

- `manifest.json` (JSON, machine-readable) was used instead of a prose
  `PROVENANCE.md`, so that a per-file SHA-256 digest could be recorded and
  mechanically verified — `PROVENANCE.md`'s tag/commit/date/procedure
  content is instead carried by the snapshot's `README.md` plus
  `manifest.json`'s structured fields.
- A test-only discovery/integrity helper module
  (`tests/helpers/basis_schemas_snapshot.py`) and a controlled offline
  refresh tool (`scripts/update_basis_schemas_snapshot.py`) were added
  alongside the vendored tree, rather than deferred to PR 4, since a vendored
  snapshot without a governed update mechanism and discovery helpers is not
  usefully "complete" on its own.

What remained for PR 4 at the time this PR merged (now delivered — see PR
4's own status note below): YAML *parsing* into a generic
required/optional/pattern/enum policy view (the `_validate_object`-style
helper), and the PyYAML dev dependency that requires. This PR's helpers
resolve paths, load `manifest.json`, and enumerate inventory only — they
never parse the vendored YAML content.

Objective: implement the Section 4 recommendation.
Files: new `tests/fixtures/basis-schemas/v0.2.0/` tree (14 contract YAMLs +
5 canonical-vector directories + `PROVENANCE.md`); no `src/` changes.
Non-goals: no parsing/validation code yet (that is PR 4); no `pyproject.toml`
change.
Dependencies: PR 1.
Architecture/schema references: Section 4 of this plan.
Required tests: a trivial "fixture tree exists and `PROVENANCE.md` records a
real commit hash" sanity test.
Completion criteria: vendored tree present, byte-identical to the source
commit, provenance recorded.
Compatibility risk: none (test-fixtures-only change).
Blocked by architecture decision: no.

**PR 3 — Operation-aware test scaffolding.**

**Status: implemented** (`test/oa-test-scaffold`). Delivers the
`tests/operation_aware/` test package: `__init__.py` (docstring-only marker,
no `sys.path` manipulation, no production imports, no side effects),
`README.md` (scope boundaries and the anticipated-but-not-yet-implemented
future test file list), and `test_scaffold.py` (8 tests covering package
discovery, fixture-foundation accessibility through the existing
`tests/helpers/basis_schemas_snapshot.py` helper, isolation from a
nonexistent `basis_core.operation_aware` production package, and confirming
`import basis_core` exposes neither the scaffold nor the fixture helpers).
No configuration change was needed — `pyproject.toml`'s existing
`testpaths = ["tests"]` already discovers the subpackage. This PR adds no
YAML parsing, no fixture-loading behavior beyond what PR 2 already
established, and no `src/basis_core/` changes; the remaining portion of PR 4
(generic YAML contract-loading and structural-validation helpers) is still
open.

Objective: create `tests/operation_aware/__init__.py` and confirm
`pytest`/`pythonpath` discovery works for the new subpackage; no assertions
beyond a placeholder.
Files: `tests/operation_aware/__init__.py`,
`tests/operation_aware/test_scaffold.py` (one trivial passing test).
Non-goals: no real test content yet.
Dependencies: PR 1.
Architecture/schema references: Section 2.12 of this plan.
Required tests: the scaffold test itself.
Completion criteria: `pytest` discovers and runs the new subpackage
alongside the existing flat `tests/*.py` modules without conflict.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 1 — Schema/fixture consumption

**PR 4 — Fixture-loading test utilities.**

**Status: implemented** (`test/oa-contract-loading`). Delivers the
remaining generic YAML-parsing and structural-validation half of this PR —
the fixture-*discovery* half (path resolution, manifest loading, inventory
enumeration) was already delivered by PR 2's
`tests/helpers/basis_schemas_snapshot.py`. Adds
`tests/helpers/operation_aware_contracts.py`: a safe test-only YAML loader
(`load_yaml_document`, built on `yaml.SafeLoader` with an added
duplicate-mapping-key check via a small `_StrictSafeLoader` subclass — no
unsafe tag construction, no multi-document input, no empty documents),
snapshot-boundary-aware wrappers (`load_contract`, `load_scenario_artifact`)
that reuse PR 2's discovery helpers, a concise test-helper exception
hierarchy (`FixtureLoadError` and 6 focused subtypes distinguishing missing
file / unsafe path / invalid YAML / empty document / multi-document /
unexpected root type), generic structural-validation helpers
(`require_mapping`, `require_sequence`, `require_string_field`,
`require_mapping_field`, `require_sequence_field`, `require_optional_field`,
`reject_unknown_fields`), and `validate_contract_metadata`, which checks
only the structural presence and type of `contract`, `contract.name`,
`contract.version`, `contract.lifecycle`, and `contract.depends_on` — not
their patterns, enums, or any other field the `contract-metadata` contract
itself already governs.

Adds three new `tests/operation_aware/` modules: `test_contract_loading.py`
(all 14 pinned contracts load, have mapping roots, structurally valid
metadata, a `name` matching their own inventory entry, structurally valid
`depends_on`, deterministic repeated loads, and no helper mutates loaded
data), `test_compatibility_fixture_loading.py` (all 5 scenarios' artifacts
load and have mapping roots, artifact discovery matches the existing helper
inventory, the gateway-only artifact still loads but stays labeled
reference-only, and the intentionally-invalid `invalid-policy-bundle`
scenario still parses as plain YAML without asserting the business rule
that makes it semantically invalid), and `test_yaml_loader_negative.py` (16
focused negative cases against temporary files outside the pinned snapshot:
missing path, directory-as-file, empty/whitespace/explicit-null documents,
malformed YAML, multi-document YAML, an unsafe `!!python/object/apply` tag,
duplicate top-level and nested mapping keys, invalid UTF-8, an unexpected
scalar root via `require_mapping`, and absolute/`..`-traversal/symlink
boundary escapes). Also extends
`tests/test_basis_schemas_snapshot_boundaries.py` with a check that no
`src/basis_core/` file imports `yaml`.

Adds `PyYAML>=6.0` to `pyproject.toml`'s `[project.optional-dependencies].dev`
— no runtime dependency change.

161 new tests (862 total, up from 701 after PR 3); all 4 quality gates
(`pytest`, `ruff check`, `ruff format --check`, `mypy src`) green. No
`src/basis_core/` change, no operation-aware domain model, no semantic
policy or request validation, no public API change. **Milestone 0 and
Milestone 1 are both now complete.**

Objective: a test-only helper module that loads a vendored contract YAML and
exposes its `required`/`optional`/`fields`/pattern/enum policy generically,
reusing the same approach `basis-schemas`' own tests use
(`operation-aware-compatibility-vectors.md` §6's `_validate_object` pattern),
so later milestones can validate models against vendored fixtures without
each writing bespoke parsing.
Files: `tests/helpers/operation_aware_contracts.py`.
Non-goals: no `src/` changes; no PyYAML added as a *runtime* dependency —
added under `[project.optional-dependencies].dev` only, since the vendored
fixtures are YAML and `pyproject.toml`'s existing dev extras do not include a
YAML parser.
Dependencies: PR 2, PR 3.
Architecture/schema references: Section 4, Section 6.
Required tests: unit tests for the helper itself, loading each of the 14
vendored contract YAMLs and asserting the parsed shape matches what Section 3
documents.
Completion criteria: every vendored contract YAML loads and parses without
error; helper functions are exercised against at least one contract each.
Compatibility risk: none (test-only; the one new dev dependency, PyYAML, is
explicitly test-scope, never imported by `src/basis_core/`).
Blocked by architecture decision: no.

### Milestone 2 — Operation-aware domain models

**PR 5 — Shared vocabulary value objects.**

**Status: implemented** (`feature/oa-request-primitives`). Delivers exactly
the scope named below — `RedactionClassification` (a closed, five-value
`str, Enum` matching the existing repo convention for
`SubjectType`/`ResourceType`/`DecisionOutcome`/`FailureReason`) and
`ReasonCode` (a validated, open-format `str` subclass — not a closed
enum) — in a new module, `src/basis_core/domain/operation_aware_vocabulary.py`.
This is the **first PR to add a module under `src/basis_core/`** for the
operation-aware surface; Milestone 0 and Milestone 1 (PR 1-4) were
documentation- and test-infrastructure-only.

Scope note: this PR's branch name and originating brief anticipated a
broader "request primitives" grouping (request identifier, correlation
identifier, policy version expectation, evaluation timestamp, authority
mode, operation intent, protocol context, resource/device/location
references). Inspecting this roadmap directly at implementation time showed
Milestone 0 and Milestone 1 already complete and the next unstarted roadmap
PR to be exactly PR 5 as specified below — a materially smaller scope than
the anticipated list, and one that does not yet touch
`OperationAwareDecisionRequest`, evidence references, or any context value
object. Per this plan's own instruction to implement only what the roadmap
assigns to the next PR rather than a guessed list, this PR delivers PR 5
only. The broader "request primitives" the brief anticipated are PR 6
(evidence-reference models), PR 7 (context value objects), and PR 8-9 (the
request model itself and its round-trip tests) — all still open, and all
depend on this PR.

The full `PolicyBundle`/`PolicyRule`/`PolicyCondition`/`OperationAwareDecisionRequest`
model remains unimplemented; no evaluator behavior of any kind was added.

`tests/operation_aware/test_vocabulary.py` (78 tests) covers: enum
exhaustiveness and member-ID alignment with the vendored
`redaction-classification` contract; valid/invalid construction for both
types, parametrized directly and cross-checked against every vendored
`valid`/`invalid` example in the `redaction-classification` and
`reason-code` contracts; `ReasonCode`'s compiled pattern checked
byte-identical to the contract's published `pattern` string; immutability
(enum singleton identity; `str`-subclass immutability); equality and
hashing (`str` mixin equality, dict/set usability); and deterministic
`repr()` for both types. `tests/operation_aware/test_vocabulary_boundaries.py`
additionally confirms the new module imports only the standard library
(`re`, `enum` — no YAML, no `pydantic`, no gateway/adapter/identity-provider
library, no test helper), is not re-exported from `basis_core.domain` or
any package `__init__.py`, is not yet listed in `docs/public-api.md`'s
stable public API table, and is not imported by any existing v0.1.0 module.

940 tests total (up from 862 after PR 4; 78 new); all 4 quality gates
(`pytest`, `ruff check`, `ruff format --check`, `mypy src`) green.

Objective: `RedactionClassification` (closed 5-value enum) and `ReasonCode`
(validated string type, regex `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`, not a closed
enum) in a new module.
Files: `src/basis_core/domain/operation_aware_vocabulary.py`; test:
`tests/operation_aware/test_vocabulary.py`.
Non-goals: no reason-code *vocabulary* (specific codes) defined yet — format
only, per `reason-code.md`.
Dependencies: PR 4.
Architecture/schema references: `redaction-classification.md`,
`reason-code.md` (basis-schemas PR A).
Required tests: enum exhaustiveness; `ReasonCode` pattern acceptance/rejection
cases, cross-checked against vendored fixture examples (PR 4's helper).
Completion criteria: both types importable, validated against vendored
fixtures.
Compatibility risk: none — wholly new module, no existing import touched.
Blocked by architecture decision: no. **Milestone 2's PR 5 is now complete;
PR 6 (evidence-reference models) is next.**

**PR 6 — Evidence-reference models.**

**Status: implemented** (`feature/oa-evidence-references`). Delivers
`IdentityEvidenceReference` and `AdapterEvidenceReference` — frozen Pydantic
models (`model_config = {"frozen": True, "extra": "forbid"}`, matching the
existing `Subject`/`Resource`/`AuditEvent` convention) mirroring the two
published `identity-evidence-reference` and `adapter-evidence-reference`
contracts (PR B) field-for-field, plus a small internal `EvidenceDigest`
nested value object for the two contracts' byte-identical
`evidence_digest_shape`. All three types live in the new
`src/basis_core/domain/evidence.py`, the second production module added
under `src/basis_core/` for the operation-aware surface (after PR 5's
`operation_aware_vocabulary.py`, which this module depends on for
`RedactionClassification`).

`IdentityEvidenceReference` fields: `reference_id`, `evidence_digest`,
`identity_source`, `redaction_classification` (required); `normalization_version`,
`mapping_version`, `request_id`, `correlation_id` (optional, default `None`).
`AdapterEvidenceReference` fields: `reference_id`, `evidence_digest`,
`adapter_source`, `redaction_classification` (required); `normalization_version`,
`mapping_version`, `protocol`, `request_id`, `correlation_id` (optional,
default `None`). Field names, required/optional status, and validation
(non-empty identifiers, `request_id` non-empty when present, digest
algorithm/value patterns, `protocol`'s open lowercase pattern, closed
`redaction_classification` vocabulary) are taken directly from the vendored
contract YAMLs — no field was added, renamed, or guessed beyond what the
schemas publish. Neither the identity nor the adapter contract, nor this
roadmap's own PR 6 entry, defines a timestamp/capture-time field, so none was
added.

Evidence references remain structurally bounded: no raw token, credential,
claim set, or protocol payload field exists on either type, unknown fields
are rejected at construction (`extra="forbid"`, matching each contract's
`additional_properties: false`), and no trust, verification, signature-
checking, or digest-authenticity logic was added — `EvidenceDigest` carries a
structurally well-formed algorithm label and hex value only, per this
module's own docstring's explicit "reference, not proof" framing. The models
remain internal (not re-exported from `basis_core.domain`, not listed in
`docs/public-api.md`), exactly like PR 5's vocabulary types. The full
`OperationAwareDecisionRequest` and the six context value objects (PR 7)
remain unimplemented; no evaluator behavior of any kind was added.

`tests/operation_aware/test_evidence.py` (102 tests) covers: digest
algorithm/value pattern alignment with both vendored contracts (and
confirms the two contracts' `evidence_digest_shape` blocks are
byte-identical); required/optional field-name alignment with each
contract's `required`/`optional` lists; valid/invalid construction,
parametrized directly and cross-checked against every vendored `valid`/
`invalid` example in both contracts; each required field individually
enforced; empty-string rejection for required and optional-but-non-empty-
when-present identifiers; unsupported `redaction_classification` and
malformed `protocol`/digest values rejected; all nine currently published
adapter protocol labels accepted as opaque strings (proving the model
stays protocol-agnostic); immutability, equality, and hashing; and a
dedicated security/data-minimization class per model parametrized over
`access_token`, `refresh_token`, `id_token`, `authorization_header`,
`password`, `client_secret`, `private_key`, `raw_claims`, `raw_token`,
`raw_protocol_payload`, and `unredacted_device_secret` — all rejected, both
because no such field is declared on the model and because unknown fields
are structurally rejected. `tests/operation_aware/test_evidence_boundaries.py`
(11 tests) confirms the new module imports only the standard library,
`pydantic`, and its sibling `operation_aware_vocabulary` module; is not
re-exported from `basis_core.domain` or any package `__init__.py`; is not
listed in `docs/public-api.md`'s stable public API table; is not imported by
any existing v0.1.0 module; and defines no generic public `EvidenceReference`
base type. PR 5's own `test_vocabulary_boundaries.py` needed one narrow,
anticipated update: its "no module imports operation_aware_vocabulary"
check now excludes other operation-aware modules (starting with
`evidence.py`) via an explicit, documented allowlist, since PR 5's own
docstring already named evidence references as an expected future consumer.

1053 tests total (up from 940 after PR 5; 113 new); all 4 quality gates
(`pytest`, `ruff check`, `ruff format --check`, `mypy src`, including a
`--strict` pass on `evidence.py` alone) green.

Objective: `IdentityEvidenceReference`, `AdapterEvidenceReference` — frozen
Pydantic models mirroring the two PR B contracts, carrying a structural
digest and a `RedactionClassification`, never a raw token/credential/claim/
payload field.
Files: `src/basis_core/domain/evidence.py`; test:
`tests/operation_aware/test_evidence.py`.
Non-goals: no trust/signature verification logic (explicitly out of scope
per `basis-schemas` itself); no runtime enforcement mechanism beyond "the
field does not exist on the model."
Dependencies: PR 5.
Architecture/schema references: `identity-evidence-reference.md`,
`adapter-evidence-reference.md` (PR B); ADR-0003 §7-8.
Required tests: fixture conformance against vendored PR B examples (valid +
invalid); a negative test confirming no raw-token-shaped field can be
constructed (i.e. the model rejects unknown fields, per `additionalProperties:
false` parity).
Completion criteria: both models pass every vendored valid/invalid example.
Compatibility risk: none.
Blocked by architecture decision: no. **Milestone 2's PR 6 is now complete;
PR 7 (operation-aware context value objects) is next.**

**PR 7 — Operation-aware context value objects.**

**Status: implemented** (`feature/oa-context-objects`). Delivers exactly the
six frozen Pydantic models named below in a new module,
`src/basis_core/domain/operation_aware.py` — the third production module
added under `src/basis_core/` for the operation-aware surface (after PR 5's
`operation_aware_vocabulary.py` and PR 6's `evidence.py`). Field names,
optional status (every field on every one of these six objects is
individually optional — none has a "required" list at all), and validation
(non-empty-when-present identifiers, the shared open-identifier pattern
`^[a-z][a-z0-9_-]*$` for `device_class`/`protocol`/safety
`mode`/`classification`/environment `mode`/risk `classification`, no
pattern for free-form `operation` or numeric `score`) are taken directly
from the vendored `operation-aware-decision-request` contract's six
`*_shape` blocks (`location_shape`, `device_shape`,
`protocol_context_shape`, `safety_context_shape`,
`environment_context_shape`, `risk_context_shape`) — no field was added,
renamed, or guessed beyond what the schema publishes.

Unlike PR 6, none of these six objects nests a PR 5 vocabulary type or a PR
6 evidence-reference type: the published contract keeps
`identity_evidence_reference` and `adapter_evidence_reference` as separate,
sibling fields on the future request itself, not nested inside these six
shapes. This module therefore has no import dependency on either sibling
operation-aware module, and neither existing sibling-module boundary test
(`test_vocabulary_boundaries.py`, `test_evidence_boundaries.py`) needed an
allowlist update.

`OperationAwareSafetyContext.constraint_ids` and
`OperationAwareEnvironmentContext.condition_ids` are typed `tuple[str, ...]`
(default `()`), not `list[str]` — a caller-supplied list is accepted and
converted at construction, then stored immutably; mutating the caller's
original list afterward has no effect on the constructed model, and the
stored tuple itself has no `.append`. `OperationAwareRiskContext.score` is
validated to reject `bool` (a `bool` is not a risk score, even though
`bool` is a Python `int` subtype) and non-finite (`NaN`/`Infinity`) values,
per this roadmap's general Section 11 validation guidance; the contract
itself defines no bounds, scale, or calculation method, and none is
implemented here.

`tests/operation_aware/test_context_objects.py` (99 tests) covers: optional
field-name alignment with each of the six vendored `*_shape` blocks;
pattern alignment for every pattern-constrained field; valid/invalid
construction, parametrized directly and cross-checked against the two
vendored `operation-aware-decision-request` request examples that cleanly
isolate these six objects without alteration (the "OT operation-rich"
example for `location`/`device`/`protocol_context`, the "full contextual"
example for `safety_context`/`environment_context`/`risk_context`) and the
one vendored nested-object invalid example the contract publishes (an
unknown `country` key under `location`); immutability, equality, and
hashing; defensive-copy behavior for both tuple-typed collection fields;
and boolean/non-finite rejection for `risk_context.score`.
`tests/operation_aware/test_context_boundaries.py` (16 tests) confirms the
new module imports only the standard library and `pydantic` (no sibling
operation-aware module); is not re-exported from `basis_core.domain` or any
other package `__init__.py`; is not listed in `docs/public-api.md`'s stable
public API table; is not imported by any existing v0.1.0 module; and
declares no field name from the prohibited raw-security-artifact list
(`access_token`, `password`, `raw_claims`, `raw_protocol_payload`, and
others).

1168 tests total (up from 1053 after PR 6; 115 new); all 4 quality gates
(`pytest`, `ruff check`, `ruff format --check`, `mypy src`, including a
`--strict` pass on `operation_aware.py` alone) green.

Objective: `OperationAwareLocation`, `OperationAwareDevice`,
`OperationAwareProtocolContext`, `OperationAwareSafetyContext`,
`OperationAwareEnvironmentContext`, `OperationAwareRiskContext` — frozen
Pydantic models for the six optional nested-object categories on
`operation-aware-decision-request`.
Files: `src/basis_core/domain/operation_aware.py`; test:
`tests/operation_aware/test_context_objects.py`.
Non-goals: none of these participate in evaluation yet (that begins
Milestone 6). No inference, calculation, protocol parsing, or trust
establishment of any kind. `OperationAwareDecisionRequest` itself (with its
flat `resource`, `resource_type`, and `operation_intent` fields) remains
unimplemented — that is PR 8.
Dependencies: PR 5.
Architecture/schema references: `operation-aware-decision-request.md` §17-25
(PR C).
Required tests: each object's optional-subfield combinations, matching the
contract's "each independently optional" rule exactly.
Completion criteria: all six objects pass vendored fixture conformance.
Compatibility risk: none.
Blocked by architecture decision: no. **Milestone 2's PR 7 is now complete;
PR 8 (`OperationAwareDecisionRequest` value object) is next.**

**PR 8 — `OperationAwareDecisionRequest` value object.**
Objective: the full request model (Section 3's field table), composing PR
6/PR 7's nested objects plus flat scalar fields (`request_id`, `subject_id`,
`subject_roles`, `subject_attrs`, `identity_source`, `authority_mode`,
`action`, `resource`, `resource_type`, `operation_intent`,
`evaluation_time`, `expected_policy_version`, `correlation_id`).
Files: `src/basis_core/decisions/operation_aware.py` (new file — does not
modify `decisions/models.py`); test:
`tests/operation_aware/test_decision_request.py`.
Non-goals: no changes whatsoever to `DecisionRequest` in
`decisions/models.py`.
Dependencies: PR 6, PR 7.
Architecture/schema references: `operation-aware-decision-request.md` (PR C)
in full; ADR-0001 §3.
Required tests: required-field enforcement (`request_id`/`subject_id`/
`action` only); `action`/`resource` pattern reuse from existing
`action-string`/`resource-identifier` validation logic (reusing
`decisions/models.py`'s existing compiled regexes where the pattern is
identical, per `operation-aware-decision-request.md` §15-16's explicit
"reuses unchanged" language).
Completion criteria: model round-trips every vendored PR C valid/invalid
example.
Compatibility risk: none — new file, new class.
Blocked by architecture decision: no.

**PR 9 — Request-level structural validation & serialization round-trip
tests.**
Objective: close out Milestone 2 with exhaustive fixture-conformance and
`model_dump(mode="json")` round-trip tests for PR 8's model.
Files: `tests/operation_aware/test_decision_request_roundtrip.py`.
Non-goals: no new model code.
Dependencies: PR 8.
Architecture/schema references: same as PR 8.
Required tests: serialize → deserialize → equality, for every vendored PR C
example and every canonical-vector request fixture.
Completion criteria: 100% of vendored request fixtures round-trip correctly.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 3 — Serialization and structural validation

**PR 10 — Contract-fixture conformance test suite.**
Objective: a dedicated, exhaustive test module that validates every
operation-aware model built so far (PRs 5-9) against every vendored `valid`/
`invalid` example in the 14 contract YAMLs, using PR 4's generic helper.
Files: `tests/operation_aware/test_contract_conformance.py`.
Non-goals: no models not yet implemented (policy bundle/rule/condition
begins Milestone 4).
Dependencies: PR 9.
Architecture/schema references: all vendored PR A-C contracts.
Required tests: parametrized over every vendored example.
Completion criteria: green for every currently-implemented model; explicitly
`xfail`/skipped (not silently omitted) for models not yet implemented, with a
comment naming the milestone that will implement them.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 11 — Compatibility-snapshot scaffolding for operation-aware models.**
Objective: establish `tests/fixtures/contracts/operation_aware/` as a new,
clearly-separated snapshot fixture directory (never mixed with the existing
v0.1.0 `tests/fixtures/contracts/*.json`), and a
`test_operation_aware_contract_snapshots.py` module mirroring the existing
`test_contract_snapshots.py` pattern.
Files: `tests/fixtures/contracts/operation_aware/*.json`,
`tests/operation_aware/test_contract_snapshots.py`.
Non-goals: no v0.1.0 fixture touched.
Dependencies: PR 9.
Architecture/schema references: `docs/compatibility-testing.md` (pattern
reused, not modified).
Required tests: snapshot serialization test for `OperationAwareDecisionRequest`.
Completion criteria: snapshot fixture committed and passing.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 4 — Policy domain model and semantic validation

**PR 12 — `PolicyCondition` model.**
Objective: `condition_id`, `field_path` (validated dotted path per
`policy-condition.md` §9), `operator` (validated open identifier — structural
only, no evaluation), `expected_value` (scalar/homogeneous-array union).
Files: `src/basis_core/policy/operation_aware/condition.py` (new package);
test: `tests/operation_aware/test_policy_condition.py`.
Non-goals: **no operator evaluation logic** — this model only validates that
`operator` is a well-formed identifier string, per Section 8's gate.
Dependencies: PR 9.
Architecture/schema references: `policy-condition.md` (PR D); ADR-0004 §7.
Required tests: fixture conformance against vendored PR D condition
examples; explicit test asserting the model accepts a structurally-valid but
semantically-unimplemented `operator` string (proving no premature operator
whitelist exists).
Completion criteria: model passes every vendored valid/invalid example.
Compatibility risk: none.
Blocked by architecture decision: no (the *model* is unblocked; only
*evaluating* conditions, Milestone 7, is blocked).

**PR 13 — `OperationAwarePolicyRule` model.**
Objective: `rule_id`, `effect` (closed `allow`/`deny`), `match` (structured
dict), `conditions` (list of `PolicyCondition`), `reason_code`,
`explanation`; validation: at least one of `match`/`conditions` non-empty;
`condition_id` uniqueness within the rule.
Files: `src/basis_core/policy/operation_aware/rule.py`; test:
`tests/operation_aware/test_policy_rule.py`.
Non-goals: no bundle-level uniqueness check (that is bundle's job, PR 14);
no rule *evaluation* logic (that is Milestone 6/7).
Dependencies: PR 12.
Architecture/schema references: `policy-rule.md` (PR D); ADR-0004 §4-5.
Required tests: fixture conformance; the "at least one of match/conditions"
invariant; the naming-collision regression test (`from basis_core.policy import
PolicyRule` still resolves to the v0.1.0 Protocol, unaffected by this new
class).
Completion criteria: model passes every vendored valid/invalid example;
naming-collision regression test passes.
Compatibility risk: **naming collision risk, mitigated** — see Section 5 and
Section 11. This PR is the concrete point where that mitigation is verified
by a test, not just documented.
Blocked by architecture decision: no.

**PR 14 — `PolicyBundle` model.**
Objective: `bundle_id`, `bundle_version`, `schema_version`, `policy_owner`,
`scope` (optional), `rules` (non-empty list of `OperationAwarePolicyRule`),
plus metadata/provenance fields (`description`, `source_ref`, `approval_ref`,
`created_at`/`updated_at`, `compatibility_target`, `deprecated`,
`replaced_by`).
Files: `src/basis_core/policy/operation_aware/bundle.py`; test:
`tests/operation_aware/test_policy_bundle.py`.
Non-goals: no `validation_status` field (per `policy-bundle.md` §17 — derived
state, not a stored field); no evaluation logic.
Dependencies: PR 13.
Architecture/schema references: `policy-bundle.md` (PR D); ADR-0004 §2-3.
Required tests: fixture conformance; non-empty `rules` enforcement.
Completion criteria: model passes every vendored valid/invalid example.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 15 — Policy bundle structural + semantic validation pipeline.**
Objective: a `PolicyBundleValidationError` hierarchy distinguishing
structural failures (malformed shape — pydantic-level) from semantic
failures (duplicate `rule_id` across a bundle's `rules`, duplicate
`condition_id` within a rule — cross-object checks pydantic alone cannot
express), realized as an explicit validation function invoked *before* any
evaluation entry point exists, so "invalid policy must never produce ALLOW"
is true by construction (there is no code path yet that could produce
`ALLOW` from an unvalidated bundle).
Files: `src/basis_core/policy/operation_aware/validation.py`; test:
`tests/operation_aware/test_policy_validation.py`.
Non-goals: no evaluation.
Dependencies: PR 14.
Architecture/schema references: `policy-bundle.md` §18 (duplicate rule-ID
validation); ADR-0004 §11; ADR-0002 §14.
Required tests: duplicate-`rule_id` rejection (using the vendored
`invalid-policy-bundle` canonical-vector fixture directly); duplicate-
`condition_id`-within-rule rejection.
Completion criteria: the vendored `invalid-policy-bundle.yaml` fixture is
rejected for exactly its documented reason (duplicate `rule_id`), not an
incidental one.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 16 — Bundle/rule contract-fixture conformance tests (canonical
vectors).**
Objective: extend PR 10's conformance suite to cover all five canonical
vectors' `policy-bundle.yaml`/`invalid-policy-bundle.yaml` fixtures.
Files: `tests/operation_aware/test_canonical_vector_bundles.py`.
Non-goals: no response/trace assertions yet (Milestone 12).
Dependencies: PR 15.
Architecture/schema references: `operation-aware-compatibility-vectors.md`.
Required tests: all five vectors' bundle fixtures load and validate (four
valid, one — `invalid-policy-bundle` — correctly rejected).
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 5 — Bundle applicability

**PR 17 — Bundle scope model + applicability determination.**
Objective: a `scope` sub-model on `PolicyBundle` (domain, action-vocabulary
scope, resource-type scope, site/building/zone scope, device-class scope,
environment scope, identity-authority-mode scope — per ADR-0004 §3) and a
pure function `determine_applicability(bundle, request) ->
applicable | not_applicable`, implementing the exact-match reading flagged in
Section 3's mapping table (absence of a scope dimension on the bundle means
that dimension does not constrain applicability; presence must match the
request's corresponding field exactly).
Files: `src/basis_core/policy/operation_aware/applicability.py`; test:
`tests/operation_aware/test_applicability.py`.
Non-goals: no *richer* scope-matching (prefix matching, hierarchy-aware zone
matching, wildcard scope) — flagged in Section 15 as a future capability
requiring its own review, not implemented here.
Dependencies: PR 14.
Architecture/schema references: ADR-0004 §3; ADR-0002 §5.
Required tests: every scope dimension's applicable/not-applicable cases; the
vendored `not-applicable` canonical vector.
Completion criteria: `not-applicable` canonical vector's bundle correctly
classified as not applicable to its paired request.
Compatibility risk: none.
Blocked by architecture decision: no — the exact-match reading is a
conservative, clearly-flagged implementation choice within what ADR-0004
already permits (Section 3, Section 15 track the *richer*-matching question
separately as an implementation choice, not an architecture blocker).

**PR 18 — Applicability unit tests (exhaustive).**
Objective: close out Milestone 5 with exhaustive per-dimension and
combined-dimension test coverage.
Files: extends `tests/operation_aware/test_applicability.py`.
Non-goals: none.
Dependencies: PR 17.
Architecture/schema references: same as PR 17.
Required tests: cartesian coverage of scope-dimension-present ×
request-field-present combinations.
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 6 — Selector matching

**PR 19 — Rule match-criteria evaluator.**
Objective: deterministic evaluation of a rule's `match` object (structural,
equality/membership only — the categories named in ADR-0004 §6: subject
identity/attributes, action, resource/resource_type, location, device,
protocol, operation intent, safety/environment/risk context) against an
applicable request, producing `matched`/`not_matched` — explicitly **not**
the `conditions` array (that is Milestone 7, gated).
Files: `src/basis_core/policy/operation_aware/selector.py`; test:
`tests/operation_aware/test_selector.py`.
Non-goals: no `conditions` evaluation; no operator registry.
Dependencies: PR 17.
Architecture/schema references: ADR-0004 §6; `policy-rule.md` §11,14.
Required tests: match-criteria coverage per category; a request that matches
`match` but whose rule also carries unevaluated `conditions` is explicitly
tested to produce a `not_matched`-pending-conditions state (not a premature
`matched`) once Milestone 8's trace assembly represents it, per the
Section 8 gate's stated behavior.
Completion criteria: match-only evaluation is deterministic and covers every
match-criteria category the contract lists.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 20 — Selector determinism/ordering tests.**
Objective: prove candidate-rule iteration order does not depend on Python
dict/set iteration order; sort by `rule_id` as the stable tie-breaker per
ADR-0004 §10 when no other ordering signal is defined.
Files: extends `tests/operation_aware/test_selector.py`.
Non-goals: none.
Dependencies: PR 19.
Architecture/schema references: ADR-0002 §8; ADR-0004 §10.
Required tests: same bundle constructed via two different, deliberately
reordered in-memory rule lists produces identical candidate-selection output.
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 7 — Condition semantics (architecture-gated)

**PR 21 — [BLOCKED] Open a `basis-architecture` condition-operator
clarification request.**
Objective: file the clarification document proposed in Section 8 (operator
registry table) as a PR/discussion in `basis-architecture`. **No
`basis-core` code in this PR.**
Files: none in `basis-core` beyond a short note in this plan's "Risks and
open decisions" register confirming the request was filed (link/reference
only — this plan does not pre-author the architecture document itself).
Non-goals: no condition-evaluation code anywhere in `basis-core`.
Dependencies: PR 12 (the `PolicyCondition` model must exist to motivate the
concrete question).
Architecture/schema references: Section 8 of this plan in full.
Required tests: none (not a code PR).
Completion criteria: clarification request filed and acknowledged in
`basis-architecture`.
Compatibility risk: none.
**Blocked by architecture decision: this PR *is* the unblocking action for
PR 22/23** — it does not itself require a prior decision, but everything
after it does.

**PR 22 — [BLOCKED on PR 21's clarification being approved] Condition
operator registry implementation.**
Objective: implement exactly the operator set the approved clarification
defines — no more, no less — with deterministic match/no-match/error
three-outcome semantics, no silent coercion, no external data fetching, no
side effects.
Files: `src/basis_core/policy/operation_aware/operators.py`.
Non-goals: no operator not named in the approved clarification.
Dependencies: PR 21 (approved), PR 20.
Architecture/schema references: the approved clarification document; ADR-0004
§7; ADR-0002 §9.
Required tests: exhaustive per-operator match/no-match/error cases, type-
mismatch cases, missing-context cases, unsupported-operator cases.
Completion criteria: 100% of the approved operator table is implemented and
tested.
Compatibility risk: none (net-new module).
Blocked by architecture decision: **yes — cannot start until PR 21's
clarification is approved.**

**PR 23 — [BLOCKED on PR 22] Condition evaluation integration.**
Objective: wire `PolicyCondition` evaluation into rule evidence, populating
`TraceRuleEvidence.condition_results` (previously always empty/absent per
Milestone 8's PR 26 caveat) and folding condition outcomes into
`rule_result` (`matched` requires all conditions to match; any condition
`error` makes the rule `error`).
Files: `src/basis_core/policy/operation_aware/condition_eval.py`.
Non-goals: none beyond what PR 22 already scoped.
Dependencies: PR 22.
Architecture/schema references: ADR-0002 §9-11; ADR-0003 §5.
Required tests: rule-level aggregation of multiple conditions; the
condition-evaluation-error deferred scenario (named but not covered by the
five canonical vectors — Section 10 — becomes a first-class test case here,
independent of the vendored fixtures).
Completion criteria: green; `TraceRuleEvidence.condition_results` populated
correctly.
Compatibility risk: none.
Blocked by architecture decision: **yes — inherits PR 22's block.**

### Milestone 8 — Trace evidence

**PR 24 — `TraceRuleEvidence` model.**
Objective: implement the model exactly as specified in Section 9.
Files: `src/basis_core/audit/operation_aware/trace_rule_evidence.py` (new
package); test: `tests/operation_aware/test_trace_rule_evidence.py`.
Non-goals: no assembly logic yet.
Dependencies: PR 13 (reuses `rule_id`/`effect` shape).
Architecture/schema references: `trace-rule-evidence.md` (PR E); ADR-0003
§5.
Required tests: fixture conformance against vendored PR E examples.
Completion criteria: model passes every vendored valid/invalid example.
Compatibility risk: none — does not touch `audit/trace.py`'s
`RuleEvaluation`.
Blocked by architecture decision: no.

**PR 25 — `EvaluationTrace` model.**
Objective: implement the model exactly as specified in Section 9, including
the `evaluation_status`/`outcome`/`bundle_applicability`/`failure_reason`
required-key shape.
Files: `src/basis_core/audit/operation_aware/evaluation_trace.py`; test:
`tests/operation_aware/test_evaluation_trace.py`.
Non-goals: no assembly logic yet.
Dependencies: PR 24.
Architecture/schema references: `evaluation-trace.md` (PR E); ADR-0003 §4,13.
Required tests: fixture conformance; deterministic-ordering test for
`rule_evidence`.
Completion criteria: model passes every vendored valid/invalid example.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 26 — Trace assembly function.**
Objective: a pure function, owned by the `evaluation/` orchestration layer
(ADR-0006), assembling `EvaluationTrace` from Milestone 6's selector output
and Milestone 7's condition evidence. **PR 23 (condition evaluation
integration) is merged and on `main`** — `TraceRuleEvidence.condition_results`
is no longer a future capability at this point in the roadmap. PR 26 must use
the current ordered condition-evaluation results whenever conditions were
actually evaluated:

- conditions evaluated → include bounded, ordered condition evidence in the
  assembled `TraceRuleEvidence`.
- selector mismatch (conditions were never reached) → `condition_results` is
  absent; do not invent condition evidence for a rule whose conditions were
  never evaluated.
- rule authored with no `conditions` → `condition_results` is absent; do not
  invent condition evidence for a rule that has none to evaluate.

Do not introduce temporary fallback behavior (e.g. `unknown`,
`not_evaluated`, or a synthetic "skipped condition" value) for a milestone
gap that no longer exists — PR 23 already closed it. The stale "empty/absent
until Milestone 7" framing that appeared in earlier drafts of this PR is
superseded by PR 23's merge and must not appear in the current acceptance
criteria.

PR 26's operational acceptance criteria (ownership rationale is Section
5/6's, not repeated here):

- **Input:** already-evaluated policy facts (Milestone 6 selector output,
  Milestone 7 condition-evaluation results) — never re-derives them.
- **Output:** actual `TraceRuleEvidence` and `EvaluationTrace` instances,
  preserving rule and condition ordering exactly as produced upstream, using
  explicit source-to-trace enum mappings and bounded reason
  codes/explanations.
- **Condition evidence:** uses the current ordered condition-evaluation
  results per the objective above (evaluated → included; not reached or
  absent → omitted, never invented).
- **No authorization outcome derived:** does not evaluate selectors or
  conditions, determine applicability, aggregate effects, apply deny
  precedence/default deny/`NOT_APPLICABLE`, or choose final decision reasons
  — a complete `EvaluationTrace` requires `evaluation_status`, `outcome`,
  `bundle_applicability`, and `failure_reason`, which PR 26 receives as
  already-determined trace-level state through a narrow typed assembly
  input, never derives itself.
- **No policy semantics implemented:** all combining/precedence/outcome
  logic remains policy-owned (see the module-tree note above); PR 26 is not
  the place it's added even provisionally.
- **Out of scope entirely:** response assembly, audit-evidence persistence,
  enforcement.
- **Purity:** copies no raw request/policy/condition/evidence values;
  performs no I/O; uses no clock or randomness; generates no identifiers.

(This plan does not define the assembly input's concrete function
signature — see Section 6's note on not prescribing signatures.)

Files: `src/basis_core/evaluation/__init__.py` (new package);
`src/basis_core/evaluation/operation_aware/__init__.py` (new package);
`src/basis_core/evaluation/operation_aware/trace_assembly.py` (see Section 5
for this module's superseded earlier placement); test:
`tests/operation_aware/test_trace_assembly.py`.
Non-goals: no response assembly yet (Milestone 10).
Dependencies: PR 20, PR 23, PR 25.
Architecture/schema references: ADR-0002 §13; ADR-0003 §4; basis-architecture
ADR-0006.
Required tests: assembly from selector output (with and without evaluated
conditions) produces a valid, honest `EvaluationTrace`; a recursive
import-boundary test for `src/basis_core/evaluation/operation_aware/`
(mirroring `tests/test_import_boundaries.py`'s existing recursive guard for
`audit/operation_aware/`) asserting it imports only from `basis_core.domain`,
`basis_core.decisions`, `basis_core.policy`, and `basis_core.audit`, and
never from `basis_core.adapters` or `basis_core.enforcement`. This PR is the
first to create `src/basis_core/evaluation/`, so it is also the first PR
that can add this guard — no earlier PR could have.
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no (this PR is explicitly designed to be
unblocked; PR 22/23 unblocked and merged during Milestone 7).

### Milestone 9 — Decision aggregation

**PR 27 — Effect aggregation and final-outcome semantics (policy-owned) +
evaluation engine orchestration.**
Objective: two ownership-separated pieces, per ADR-0006:

1. **Policy-owned** (`policy/operation_aware/`): implement deny-precedence,
   default-deny, `NOT_APPLICABLE`, allow determination, and final
   authorization-outcome semantics as pure, executable rule-effect
   combination logic over rule evidence — mirroring `PolicyEngine`'s
   deny-overrides *shape* (Section 2.3) but operating over the new data
   model. Use the roadmap's existing filenames for this logic; this plan
   does not rename them.
2. **Evaluation-owned** (`evaluation/operation_aware/engine.py`): the
   orchestration engine that invokes policy-owned applicability, candidate
   selection, selector evaluation, condition evaluation, and effect
   aggregation, in sequence, carrying each stage's typed result into the
   next and into trace assembly (PR 26). The evaluation engine invokes the
   policy-owned effect-combination operation and carries its typed result
   into subsequent stages — it does not itself combine rule effects.

Files: policy-owned aggregation/precedence/outcome modules under
`src/basis_core/policy/operation_aware/` (filenames as this plan already
establishes elsewhere in this section — no new filenames invented here);
`src/basis_core/evaluation/operation_aware/engine.py` (see Section 5 for this
module's superseded earlier placement).
Non-goals: no `EnforcementPoint` integration yet (Milestone 11). The
evaluation engine must not reimplement selector semantics, condition
semantics, operator semantics, effect aggregation, deny precedence, default
deny, or applicability semantics — it invokes the policy-owned operations
above and carries their typed results forward.
Dependencies: PR 15 (bundle validation), PR 26 (trace assembly).
Architecture/schema references: ADR-0002 §4-7,14; `policy-rule-model.md` §9;
basis-architecture ADR-0006.
Required tests: deny-precedence beats allow; default-deny when no allow
matches; not-applicable when no bundle scope covers the request; invalid
bundle never reaches an `ALLOW`/`DENY` outcome; the evaluation engine's
recursive import-boundary test (established by PR 26) continues to pass with
`engine.py` added to `evaluation/operation_aware/`.
Completion criteria: unit-level correctness for all four logical categories.
Compatibility risk: **naming/behavioral collision risk with `PolicyEngine` —
mitigated by keeping the classes fully independent**, per Section 5; this
PR's tests include an explicit regression check that constructing the new
evaluation engine has no observable effect on any existing `PolicyEngine`
instance (no shared mutable state).
Blocked by architecture decision: no.

**Naming note (not resolved by this PR):** the roadmap's Section 5 naming
strategy names this evaluator `OperationAwarePolicyEngine` and, before this
alignment pass, planned to implement it at `policy/operation_aware/engine.py`
— a location where a class named `*PolicyEngine` matched its package. Moving
`engine.py` to `evaluation/operation_aware/` (this update) creates a naming
tension: `OperationAwarePolicyEngine` would now be implemented inside the
`evaluation/` package, which does not match ADR-0006's `evaluation/`-invokes-
`policy/` ownership split as cleanly as the pre-ADR-0006 name suggests. Every
occurrence of `OperationAwarePolicyEngine` in this document (Section 5,
Section 6, Section 11, this milestone) is left unrenamed here — this is a
documentation/roadmap-alignment PR, not an API-naming decision, and the type
does not yet exist in code. A future naming decision (analogous to Milestone
11 PR 33's short design-note treatment of `OperationAwareEnforcementPoint`)
should resolve whether the orchestration class keeps the `*PolicyEngine`
name, is renamed to something evaluation-scoped (e.g. an
`*EvaluationEngine`-shaped name), or is split into a thin evaluation-owned
orchestrator plus a policy-owned aggregator with two distinct names. That
decision belongs to whoever implements PR 27, not to this alignment PR.

**PR 28 — Combining-algorithm canonical-vector-shaped unit tests.**
Objective: unit-level (not yet fixture-wired — that is Milestone 12)
coverage of all five canonical vectors' *logical* shape, using
hand-constructed `PolicyBundle`/`OperationAwareDecisionRequest` objects that
mirror each vector's structure.
Files: `tests/operation_aware/test_engine_canonical_shapes.py`.
Non-goals: not yet reading the vendored fixture files directly (Milestone
12 does that).
Dependencies: PR 27.
Architecture/schema references: `operation-aware-compatibility-vectors.md`
§5.
Required tests: one test per canonical scenario, hand-constructed.
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 10 — Response and AuditEvidence

**PR 29 — `OperationAwareDecisionResponse` model.**
Objective: implement the model exactly as specified in Section 3/Section 9,
including the `evaluation_status`/`outcome`/`failure_reason` mutual-exclusion
invariants (Section 3's mapping-table row).
Files: extends `src/basis_core/decisions/operation_aware.py` (from PR 8).
Non-goals: none.
Dependencies: PR 8, PR 25.
Architecture/schema references: `operation-aware-decision-response.md` (PR
E) in full; ADR-0002 §4-5,14.
Required tests: the four required outcome/status/failure-reason invariant
combinations (`completed+allow/deny/not_applicable` valid;
`failed+null-outcome` valid and required; every other combination invalid),
tested directly as Pydantic validator cases.
Completion criteria: model passes every vendored PR E valid/invalid example.
Compatibility risk: none — new file addition, does not touch
`decisions/models.py`.
Blocked by architecture decision: no.

**PR 30 — `AuditEvidence` model.**
Objective: implement the model exactly as specified in Section 3/Section 9.
Files: `src/basis_core/audit/operation_aware/audit_evidence.py`; test:
`tests/operation_aware/test_audit_evidence.py`.
Non-goals: **no persistence mechanism, no `AuditWriter`-shaped protocol for
this type** — explicitly out of scope per Section 9.
Dependencies: PR 25, PR 29.
Architecture/schema references: `audit-evidence.md` (PR F); ADR-0003 §2,14.
Required tests: fixture conformance against vendored PR F examples.
Completion criteria: model passes every vendored valid/invalid example.
Compatibility risk: none — does not touch `audit/events.py`'s `AuditEvent`.
Blocked by architecture decision: no.

**PR 31 — Response + AuditEvidence assembly.**
Objective: pure functions, owned by the `evaluation/` orchestration layer
(ADR-0006), wiring the policy-owned aggregation result (PR 27) and
`EvaluationTrace` (PR 26) into a `(OperationAwareDecisionResponse,
AuditEvidence)` pair — no I/O, no persistence. Response assembly consumes
already-determined evaluation results and an already-assembled
`EvaluationTrace`; it constructs the operation-aware response contract,
preserves response/trace agreement, and may construct bounded kernel audit
evidence now that `AuditEvidence` (PR 30) exists. It performs no audit
persistence, records no gateway-only enforcement facts (`GatewayAuditEvent`
remains the gateway's, per ADR-0003 and Section 9), and performs no runtime
enforcement.
Files: `src/basis_core/evaluation/operation_aware/response_assembly.py` (see
Section 5 for this module's superseded earlier placement).
Non-goals: none.
Dependencies: PR 27, PR 29, PR 30.
Architecture/schema references: ADR-0002 §14-15; ADR-0003 §2,14; basis-architecture
ADR-0006.
Required tests: assembly correctness for all four combining categories
(allow/deny/not-applicable/failed); the `evaluation/operation_aware/`
recursive import-boundary test (established by PR 26) continues to pass with
`response_assembly.py` added.
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 32 — Response/trace/AuditEvidence agreement invariant tests.**
Objective: implement and test the "Response/trace authority" cross-field
rules from `operation-aware-decision-response.md` §21 (Section 9 of this
plan) — request_id/evaluation_status/outcome/failure_reason equality between
response and embedded trace; bundle_id/version agreement; one-sided
correlation_id/reason_code is not a mismatch.
Files: `tests/operation_aware/test_response_trace_audit_agreement.py`.
Non-goals: none.
Dependencies: PR 31.
Architecture/schema references: `operation-aware-decision-response.md` §21.
Required tests: every stated invariant, both positive (agreement holds) and
negative (deliberately constructed disagreement is caught).
Completion criteria: green.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 11 — EnforcementPoint/public API integration

**PR 33 — `OperationAwareEnforcementPoint` design decision record.**
Objective: a short, docs-only note in `basis-core` (not a `basis-architecture`
ADR — this is an additive, non-breaking design choice within `basis-core`'s
own discretion, per Section 5's analysis) recording the "new class, not a
modified `evaluate()` signature" decision and its four supporting reasons
from Section 5, so the implementation PR that follows has a settled target.
Files: `docs/implementation/operation-aware-enforcement-point-decision.md`
(or folded into this plan's own text if a future session judges a separate
file unnecessary — see Section 15 for this as an open repository-convention
question).
Non-goals: no code.
Dependencies: PR 27, PR 31.
Architecture/schema references: Section 5 of this plan.
Required tests: none (docs-only).
Completion criteria: decision recorded.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 34 — `OperationAwareEnforcementPoint` implementation.**
Objective: compose the `evaluation/operation_aware/` orchestration engine
(PR 27, which itself invokes policy-owned bundle validation from PR 15 and
every other policy-owned semantic stage) into a fail-closed `evaluate()`
that never raises, returning `OperationAwareDecisionResponse` (+ trace +
`AuditEvidence`, per PR 33's recorded shape decision). `enforcement/`
imports `evaluation/` directly for this composition — it does not reach past
`evaluation/` into `policy/`'s semantic modules itself.
Files: `src/basis_core/enforcement/operation_aware.py`.
Non-goals: no audit *persistence* (Section 9 — `basis-core` does not write
`AuditEvidence` anywhere); no shared state with `EnforcementPoint`.
Dependencies: PR 33.
Architecture/schema references: Section 5, Section 7 (all 16 pipeline
stages), ADR-0002, ADR-0003.
Required tests: fail-closed behavior for every Section 7 stage-1-5 failure
category; never-raises guarantee (exception-injection tests analogous to
`test_enforcement_point.py`'s existing coverage of `EnforcementPoint`).
Completion criteria: green; `EnforcementPoint`'s own existing test suite
still passes unmodified (proving no shared-state regression).
Compatibility risk: none — new file, new class, verified independent of
`EnforcementPoint` by test.
Blocked by architecture decision: no.

**PR 35 — Public API surface update.**
Objective: add the new "Operation-aware public API (v0.2.0)" section to
`docs/public-api.md` (Section 11 of this plan), update `__all__` on every
touched package, extend `test_public_api.py`.
Files: `docs/public-api.md`, `src/basis_core/{domain,decisions,policy,audit,
enforcement}/__init__.py`, `tests/test_public_api.py` (extended, not
replaced).
Non-goals: no existing `__all__` entry removed or reordered in a
meaning-changing way. `evaluation/` and `evaluation/operation_aware/` are
deliberately excluded from this list — the evaluation package remains
internal for the implementation milestones this plan scopes; it gains no
`__all__`, no public export, and no `docs/public-api.md` entry here. Whether
and how to expose it is a later public-integration milestone's decision, not
this PR's.
Dependencies: PR 34.
Architecture/schema references: Section 11 of this plan;
`docs/breaking-change-discipline.md`'s "Additive changes" list.
Required tests: `test_public_api.py`'s existing invariants (every symbol
importable from its declared path; `__all__` matches the documented
inventory; no internal symbol re-exported) extended to cover every new
symbol.
Completion criteria: green; the existing v0.1.0 portion of `test_public_api.py`
unchanged in outcome.
Compatibility risk: none (purely additive).
Blocked by architecture decision: no.

**PR 36 — Extension-contracts.md addition.**
Objective: document, in `docs/extension-contracts.md`, that the
operation-aware policy model is data (not a new extension-point Protocol),
per Section 11's conclusion — so a future contributor does not have to
re-derive the "no new extension point" finding.
Files: `docs/extension-contracts.md` (new section appended, existing
sections unchanged).
Non-goals: no new Protocol, no code.
Dependencies: PR 35.
Architecture/schema references: Section 11 of this plan.
Required tests: `test_extension_contracts.py`'s existing assertions
unaffected (docs-only change).
Completion criteria: merged.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 12 — Canonical compatibility vectors

**PR 37 — Wire the five canonical scenarios end-to-end.**
Objective: load each vendored canonical-vector directory (Section 4), run
`OperationAwareEnforcementPoint.evaluate()` against its request + bundle, and
assert the result matches the vendored `expected-operation-aware-decision-
response.yaml` / `expected-evaluation-trace.yaml` / `expected-audit-
evidence.yaml`, using the comparison strategy from Section 10.
Files: `tests/operation_aware/test_canonical_vectors.py`.
Non-goals: no `expected-gateway-audit-event.yaml` assertions (PR 38 makes
this explicit).
Dependencies: PR 32, PR 34.
Architecture/schema references: `operation-aware-compatibility-vectors.md`
in full; Section 10 of this plan.
Required tests: all five scenarios, response + trace + AuditEvidence
equality.
Completion criteria: all five canonical vectors pass.
Compatibility risk: none.
Blocked by architecture decision: no (Milestone 7's gate only affects
scenarios that require condition evaluation — none of the five canonical
vectors do, per Section 10's phase table, so this milestone is fully
unblocked regardless of Milestone 7's status).

**PR 38 — Document gateway-audit-event exclusion.**
Objective: a short, explicit docstring/comment in PR 37's test module (and a
cross-reference in this plan, already present in Section 3) stating that
`expected-gateway-audit-event.yaml` is loaded for completeness but never
asserted against, because `GatewayAuditEvent` is out of kernel scope.
Files: extends `tests/operation_aware/test_canonical_vectors.py`.
Non-goals: none.
Dependencies: PR 37.
Architecture/schema references: ADR-0003 §9,14; Section 3 of this plan.
Required tests: none beyond PR 37's (this PR is a clarity/documentation
pass).
Completion criteria: merged.
Compatibility risk: none.
Blocked by architecture decision: no.

### Milestone 13 — Regression and backward compatibility

**PR 39 — v0.1 regression fixture pass.**
Objective: extend `test_backward_compatibility.py` and
`test_contract_snapshots.py` with an explicit "no drift after operation-aware
additions" checkpoint — re-running every existing v0.1.0 fixture and
snapshot after all of Milestones 1-12 have landed.
Files: `tests/test_backward_compatibility.py`,
`tests/test_contract_snapshots.py` (both extended, not rewritten).
Non-goals: no new v0.1.0 behavior.
Dependencies: PR 38 (i.e., all prior milestones complete).
Architecture/schema references: `docs/breaking-change-discipline.md`;
`docs/compatibility-testing.md`.
Required tests: full existing v0.1.0 suite re-run and re-asserted green.
Completion criteria: zero regressions in any v0.1.0 fixture/snapshot.
Compatibility risk: this PR's entire purpose is to *detect* risk, not
introduce it.
Blocked by architecture decision: no.

**PR 40 — Import-boundary and kernel-constitution regression tests for new
subpackages.**
Objective: extend `test_import_boundaries.py` to statically verify every new
`operation_aware/` module obeys the same layering rules as its
non-operation-aware sibling package (Section 5's dependency-graph diagram),
and add a `docs/kernel-constitution.md` cross-check confirming no
Invariant (1-10) was violated by any Milestone 1-12 addition. Recursive
per-package boundary state entering this PR, and this PR's job for each:

- `audit/operation_aware/` — already has a dedicated recursive guard
  (`tests/test_import_boundaries.py::test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters`),
  added ahead of this milestone. This PR confirms it stays current as later
  audit-owned modules (e.g. `audit_evidence.py`, Milestone 10) are added, but
  does not need to create it.
- `policy/operation_aware/` — **no recursive guard exists yet.** This PR adds
  one, asserting every module under `src/basis_core/policy/operation_aware/`
  (recursively) imports only from `basis_core.domain`, `basis_core.decisions`,
  and its own `policy/operation_aware/` siblings, and never from
  `basis_core.audit`, `basis_core.evaluation`, `basis_core.adapters`, or
  `basis_core.enforcement`. This guard uses the operation-aware ceiling
  (`domain` + `decisions`), not the stricter legacy rule
  `tests/test_models.py::test_policy_does_not_import_from_decisions` enforces
  for `policy/engine.py`/`policy/rules.py` — the two rules are intentionally
  different in scope and this PR must not collapse them into one.
- `evaluation/operation_aware/` — already has a dedicated recursive guard,
  required as part of PR 26 (Milestone 8) when that PR first creates
  `src/basis_core/evaluation/`. This PR confirms it stays current as later
  evaluation-owned modules (`engine.py` at PR 27, `response_assembly.py` at
  PR 31) are added, but does not need to create it.

Files: `tests/test_import_boundaries.py` (extended).
Non-goals: no relaxation of any existing boundary rule.
Dependencies: PR 39.
Architecture/schema references: `docs/import-boundaries.md`,
`docs/kernel-constitution.md`; basis-architecture ADR-0006.
Required tests: AST-level import checks for every new module, mirroring the
existing test's methodology exactly, including the `policy/operation_aware/`
recursive guard this PR adds.
Completion criteria: green; zero new edges in the dependency graph beyond
those Section 5 pre-declared.
Compatibility risk: none (verification-only).
Blocked by architecture decision: no.

### Milestone 14 — Documentation, hardening, and release readiness

**PR 41 — Operation-aware model and evaluation-semantics documentation.**
Objective: `docs/operation-aware-model.md` (public overview, mirroring
`docs/core-domain.md`'s style) and `docs/operation-aware-evaluation-semantics.md`
(implementation-level mirror of ADR-0002, in this repository's own
documentation voice, cross-referencing the architecture original rather than
duplicating its authority).
Files: two new docs; `README.md` documentation index updated.
Non-goals: no redefinition of anything ADR-0002 already states — this is an
implementation-level companion, not a competing authority.
Dependencies: PR 40.
Architecture/schema references: ADR-0002 in full.
Required tests: `test_governance_docs.py`-style cross-reference check, if
that test's pattern extends naturally; otherwise a manual review checklist
item.
Completion criteria: both docs merged, cross-referenced from `README.md`.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 42 — Governance doc cross-references.**
Objective: add the fourteen new operation-aware contract surfaces to the
governed-surfaces table in `docs/breaking-change-discipline.md` and the
schema-versioning discussion in `docs/schema-versioning.md`, so future
breaking-change classification automatically considers them.
Files: `docs/breaking-change-discipline.md`, `docs/schema-versioning.md`
(both extended, existing rows unchanged).
Non-goals: none.
Dependencies: PR 41.
Architecture/schema references: same docs, extended in place.
Required tests: `test_governance_docs.py` extended if it parses these
tables programmatically; otherwise a manual completeness check.
Completion criteria: merged.
Compatibility risk: none.
Blocked by architecture decision: no.

**PR 43 — v0.2.0 release-readiness review document.**
Objective: `docs/v0.2-readiness-review.md`, mirroring
`docs/v0.1-readiness-review.md`'s structure, checked directly against
Section 16 (Definition of Done) of this plan.
Files: `docs/v0.2-readiness-review.md`.
Non-goals: no version bump yet.
Dependencies: PR 42.
Architecture/schema references: Section 16 of this plan;
`docs/v0.1-readiness-review.md` (structural precedent).
Required tests: every Section 16 checklist item addressed with a concrete
pointer to the PR/test that satisfies it.
Completion criteria: every checklist item accounted for (satisfied, or
explicitly deferred with a named reason).
Compatibility risk: none.
Blocked by architecture decision: no, unless the readiness review itself
surfaces one — in which case that decision blocks PR 44, not this PR.

**PR 44 — Version bump and release preparation.**
Objective: the single PR in this roadmap that touches `pyproject.toml`'s
`version` field (`0.1.0` → `0.2.0`) and `src/basis_core/__init__.py`'s
`__version__`; adds a `CHANGELOG.md` if the readiness review (PR 43)
recommends introducing one (none exists today — Section 2.13), or a release
notes document following whatever convention PR 43 established.
Files: `pyproject.toml`, `src/basis_core/__init__.py`, possibly
`CHANGELOG.md`.
Non-goals: no new runtime dependency (the version bump itself does not
require one — Section 4 confirmed `basis-schemas` is never a runtime
dependency).
Dependencies: PR 43, and implicitly every prior PR in this roadmap.
Architecture/schema references: `docs/architecture/compatibility-philosophy.md`'s
semantic-versioning philosophy; Section 5 of this plan.
Required tests: full test suite green; `test_readiness.py`-style final gate,
extended if that test currently only covers v0.1.0 readiness.
Completion criteria: all Section 16 Definition-of-Done items satisfied;
version bumped; release tag prepared (tagging itself is a repository-owner
action, not something this plan performs).
Compatibility risk: this is the release boundary — by construction, no
compatibility risk should remain unaddressed at this point, because every
prior milestone was scoped specifically to avoid introducing any.
Blocked by architecture decision: no, provided every prior milestone's
architecture dependency (Milestone 7's gate, principally) is already
resolved.

---

## 13. Testing strategy

**Value-object unit tests.** Every model in Milestones 2, 4, 8, 10 gets a
dedicated test module asserting field validation, required/optional
enforcement, and rejection of unknown fields (`additionalProperties: false`
parity), mirroring the existing `tests/test_models.py` pattern.

**Serialization round-trip tests.** Every model: `model_dump(mode="json")` →
re-parse → equality, per PR 9's pattern, extended to every subsequent model.

**Schema fixture validation.** Every model validated against its vendored
`basis-schemas` contract's `valid`/`invalid` examples (PR 4's helper, reused
throughout Milestones 2-10).

**Semantic validation tests.** Bundle/rule/condition uniqueness and
consistency checks (PR 15), response/trace/audit-evidence agreement
invariants (PR 32).

**Property-based or generative tests where appropriate.** Recommended for
the condition operator registry (Milestone 7, once unblocked) — an operator's
match/no-match/error behavior is a natural fit for property-based testing
(e.g. "for any two values of incompatible type, the result is never `matched`").
Not recommended elsewhere in this roadmap, where fixture-driven and
invariant-driven testing already gives strong, example-grounded coverage
without the added complexity a generative framework would introduce for
comparatively simple value objects.

**Deterministic ordering tests.** PR 20 (selector), PR 25 (trace evidence
ordering) — explicit reordering-input-produces-identical-output tests.

**Evaluator unit tests.** PR 27-28 (`OperationAwarePolicyEngine`),
PR 34 (`OperationAwareEnforcementPoint`).

**Canonical vector tests.** Milestone 12 (PR 37-38) — the terminal proof
that the whole pipeline reaches the architecture-and-schema-defined expected
outputs.

**Compatibility snapshot tests.** PR 11 (new operation-aware snapshot
fixtures, kept structurally separate from v0.1.0's).

**Public API tests.** PR 35 (extends `test_public_api.py`).

**Import-boundary tests.** PR 40 (extends `test_import_boundaries.py`).

**Mutation or negative tests.** Every "invalid" vendored fixture (Milestones
2-10) is a mutation/negative test by construction — this repository does not
need a separate mutation-testing framework given how thoroughly the vendored
contracts already enumerate invalid shapes.

**Performance guardrails.** Not scoped as a dedicated milestone in this
plan — flagged in Section 15 as an open question (bundle size /
rule-count scaling is untested by this roadmap) rather than silently
assumed adequate.

**Security/redaction tests.** PR 6 (evidence-reference models reject
raw-evidence-shaped fields structurally); no dedicated redaction-*function*
tests exist because no redaction function is implemented by this plan
(Section 9) — this is stated explicitly here so it is not mistaken for an
oversight.

### Preventing specific failure classes

- **Evaluator nondeterminism** — PR 20/25 ordering tests; PR 27's
  "same inputs, same outputs" unit tests; the Invariant-5 regression check in
  PR 40.
- **Unordered trace output** — PR 25/26's deterministic-ordering tests.
- **Accidental ALLOW on malformed policy** — PR 15's validation-before-
  evaluation architecture makes this structurally impossible, verified by
  PR 16/28's explicit `invalid-policy-bundle` never-produces-ALLOW tests.
- **Semantic drift from `basis-architecture`** — every PR in Milestones 2-12
  cites its governing ADR section directly (Section 12's per-PR "Architecture/
  schema references" field); PR 39/40 are the terminal regression check.
- **Contract drift from `basis-schemas`** — PR 2's pinned vendoring + PR 4's
  fixture-conformance helper, re-run by every subsequent milestone.
- **Regression of first-wave behavior** — Milestone 13 in full.
- **Leakage of raw evidence** — PR 6's structural-shape guarantee (no
  raw-evidence field exists on any model in this roadmap).

---

## 14. Documentation and migration plan

Future documentation required, beyond what Milestone 14 (Section 12)
already schedules:

- **Operation-aware model overview** — PR 41 (`docs/operation-aware-model.md`).
- **Public API** — PR 35 (`docs/public-api.md` addition).
- **Policy bundle format** — a `docs/operation-aware-policy-model.md`
  companion to PR 41, documenting the *implemented* subset (structural match
  only, until Milestone 7 unblocks conditions) so `basis-core`'s own docs
  never overclaim relative to what is actually evaluable at any given point
  in the rollout — recommended as part of PR 41's scope rather than a
  separate PR, to avoid drift between the two documents.
- **Evaluation semantics** — PR 41
  (`docs/operation-aware-evaluation-semantics.md`).
- **Reason codes** — deferred until Milestone 9-10 produce the first concrete
  reason codes `basis-core` actually emits; documented as part of PR 41 once
  those exist, not speculatively earlier.
- **Trace interpretation** — folded into PR 41.
- **AuditEvidence** — folded into PR 41.
- **Migration from first-wave requests** — explicitly **not needed**, per
  Section 5 ("Migration documentation. Not required by this plan, because
  nothing is migrated"); an *adoption* guide (how to start using the
  operation-aware surface, for a consumer who chooses to) is a reasonable
  PR 41 addition, but framed as adoption, never as migration.
- **Compatibility policy** — PR 42 (governance doc cross-references).
- **Extension-author guidance** — PR 36 (documents that there is currently no
  new extension point).
- **Canonical vector usage** — folded into PR 38's documentation and PR 41's
  overview.
- **Gateway integration guidance** — explicitly out of scope for this plan
  (`basis-core` does not describe how `basis-gateway` should integrate;
  that guidance belongs in `basis-gateway`'s own repository once it begins
  consuming this surface — named here only so its absence is not mistaken
  for an oversight, mirroring the same caution ADR-0005 §14 applies to
  audit storage backend and deployment packaging).
- **Release notes** — PR 44.

---

## 15. Risks and open decisions

Classified per the brief's taxonomy: implementation choice within
`basis-core` · `basis-architecture` decision required · `basis-schemas`
follow-up required · cross-repository integration decision · release-
governance decision.

| Item | Classification | Notes |
|---|---|---|
| Condition operator semantics | **`basis-architecture` decision required** | Section 8 in full; blocks Milestone 7 (PR 22-23) only. |
| Schema/fixture distribution mechanism | Implementation choice within `basis-core` | Resolved by this plan (Section 4); implemented in Milestone 1, PR 2. |
| Naming of operation-aware public models | Implementation choice within `basis-core` | Resolved by this plan (Section 5, Section 11); the one collision (`OperationAwarePolicyRule`) is explicitly documented. |
| Coexistence of request families | Implementation choice within `basis-core` | Resolved (Section 5) — two independent classes/entry points, no shared dispatch. |
| Evaluation-time handling of `conditions` ahead of Milestone 7 | Implementation choice within `basis-core` | Resolved (Section 8, Section 12 PR 19/26) — structural `match` evaluated first; `conditions` explicitly and visibly deferred, never silently skipped. |
| Policy version matching (`expected_policy_version` vs. `bundle_version`) | **`basis-schemas` follow-up required** | `operation-aware-decision-response.md` §17 states no negotiation/resolution behavior is defined by the contract itself; `basis-core` implements "no negotiation, publish what was evaluated" per that same section — but a real negotiation policy, if ever needed, is a `basis-schemas`/`basis-architecture` question, not `basis-core`'s to invent. |
| Evidence reference validation versus trust | Implementation choice within `basis-core`, with a noted limit | This plan enforces *shape* (no raw-evidence field exists) but explicitly makes no trust/signature claim (Section 9) — matches upstream's own disclaimer; not a gap this plan is responsible for closing. |
| Field-path resolution (nested dotted paths) | **`basis-architecture` decision required**, folded into Section 8's gate | `operation-aware-decision-request.md` §9's dotted-path rules define the *syntax*; the *resolution algorithm* against optional nested objects is named explicitly in Section 8's inventory and is part of the same clarification request (PR 21). |
| Reason-code registry openness | Implementation choice within `basis-core` | The *format* is closed by contract (Section 3); the *vocabulary* `basis-core` emits is this repository's own incremental decision, made PR-by-PR as each evaluation stage is implemented (Section 14), not invented wholesale up front. |
| Trace size bounds | Implementation choice within `basis-core` | No explicit numeric bound is defined by any upstream document; this plan does not invent one — flagged here as untested by Section 13's "Performance guardrails" gap, worth a future, separately-scoped PR if large bundles become a real deployment concern. |
| `AuditEvidence` retention assumptions | **Cross-repository integration decision** | `basis-core` produces but never persists `AuditEvidence` (Section 9); retention is entirely `basis-gateway`'s concern, not resolved here or blocking anything in this roadmap. |
| Policy bundle ordering (multi-bundle) | **`basis-architecture` decision required** (narrow) | ADR-0004 does not fully specify combining behavior when *multiple* bundles are simultaneously applicable to one request beyond "candidate rules are selected from applicable bundles" (§9) — this plan's Milestone 9 implementation treats multi-bundle candidate-rule pooling as a straightforward union (all applicable bundles' rules become candidates together, deny-precedence applies across the pooled set), which is the most conservative reading consistent with ADR-0004 §9, but is flagged here in case a future architecture clarification narrows or changes it. |
| Multi-bundle behavior | See above row | Same item; not double-counted, cross-referenced for visibility under both headings the brief names. |
| Performance expectations | Implementation choice within `basis-core`, currently undefined | No upstream document states a latency/throughput target for operation-aware evaluation; this plan does not invent one. Named as an open question rather than silently assumed. |
| Extension contract compatibility | Resolved — no impact | Section 11's conclusion: no new extension point is introduced, so no existing extension contract (`PolicyRule`, `AuditWriter`, `AdapterBase`) is affected by anything in this roadmap. |
| `tests/operation_aware/` as a new top-level test-organization convention | Implementation choice within `basis-core`, flagged for confirmation | Section 2.12 notes this departs from the existing flat `tests/*.py` convention; recommended because of the sheer number of new modules, but a future session/reviewer may prefer flattening it back into `tests/test_operation_aware_*.py` to match the existing convention exactly — either is compatible with this plan's roadmap, and the choice does not affect any dependency or architecture question. |
| Whether PR 33's design-decision note is a standalone doc or folded into this plan | Implementation choice within `basis-core` | Named explicitly in PR 33's own entry (Section 12) as still open at plan-authoring time. |
| Richer bundle-scope matching (beyond exact-match) | **`basis-architecture` decision required**, if/when needed | Section 3 and PR 17 flag this as a conservative first implementation, not a permanent ceiling; broadening it (prefix matching, zone hierarchy awareness) should get its own review rather than being added informally to Milestone 5's PRs after the fact. |
| CHANGELOG.md introduction | Release-governance decision | No `CHANGELOG.md` exists in `basis-core` today (Section 2.13); PR 43/44 (Milestone 14) is where this plan recommends deciding whether to introduce one, not earlier. |

---

## 16. Definition of done for basis-core v0.2.0

- All fourteen operation-aware `basis-schemas` v0.2.0 contracts that are
  kernel-owned (i.e., every contract in Section 3's table except
  `contract-metadata` and `gateway-audit-event`, which are explicitly not
  kernel runtime types) have typed, validated `basis-core` representations.
- Deterministic operation-aware evaluation is implemented
  (`OperationAwarePolicyEngine` + `OperationAwareEnforcementPoint`), covering
  every stage of Section 7's sixteen-stage pipeline.
- Condition semantics are architecture-approved (Section 8's clarification,
  PR 21, approved) **before** any condition-evaluation code (PR 22-23) is
  merged — and if, at release time, that approval has not occurred, v0.2.0
  ships with structural `match`-only rule evaluation and *conditions
  present-but-not-yet-evaluated*, explicitly documented as such, rather than
  blocking the entire release on an external architecture dependency. This
  is a deliberate release-scoping option this plan authorizes in advance:
  Milestones 1-6 and 8-13 do not depend on Milestone 7, so a v0.2.0 release
  without condition evaluation is a coherent, honestly-documented partial
  release if the architecture clarification is not resolved in time — not a
  failure of this plan.
- All five applicable canonical scenarios (`allow-basic`, `deny-precedence`,
  `default-deny`, `not-applicable`, `invalid-policy-bundle`) pass at the
  kernel boundary (Milestone 12) — none of the five require condition
  evaluation (Section 10), so this criterion is independent of the previous
  bullet's conditional scope.
- Invalid policy can never produce ALLOW (PR 15/16/28, verified structurally
  and by test).
- DENY precedence is enforced (PR 27-28).
- Default DENY is enforced (PR 27-28).
- NOT_APPLICABLE remains distinct from DENY (PR 17-18, PR 27-28).
- Evaluator failure remains distinct from DENY (Section 7's stage-1-5
  category; PR 29's invariant tests).
- `EvaluationTrace` is deterministic and bounded (PR 20, PR 25).
- `AuditEvidence` is produced separately from any gateway event, and is
  never persisted by `basis-core` (PR 30, Section 9).
- First-wave (v0.1.0) compatibility is preserved — not formally deprecated,
  not silently altered (Milestone 13 in full).
- Public APIs are documented (PR 35, PR 41).
- Quality gates pass: `pytest`, `ruff check`, `ruff format --check`, `mypy
  src` (matching the commands in `README.md`'s "Development" section), for
  every PR in this roadmap, not only at the end.
- Compatibility snapshots are established for the new surface (PR 11).
- Release-readiness review is complete (PR 43), directly checked against
  this section.

---

## Additional repository updates

Made in this PR (planning-only, per the scope restrictions below) to make
this plan discoverable:

- `README.md` — one new bullet in the "Documentation" section pointing to
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md`.
- `docs/architecture-references.md` — one new section, "Operation-aware
  authorization model," pointing to ADR-0001 through ADR-0005 in
  `basis-architecture` and to this plan, following the existing section
  format exactly (Document / Governs / Why it matters / Relevant for).

No `CHANGELOG.md` entry is added because `basis-core` does not currently
have a `CHANGELOG.md` (Section 2.13); introducing one is deferred to Section
15's release-governance row and, if adopted, executed in Milestone 14 (PR
43-44), not here. This plan uses `docs/implementation/` as its home
directory because no existing phase-plan convention exists elsewhere in this
repository (Section 2.13 confirms no `ROADMAP.md` and no prior
`docs/implementation/` directory existed before this PR) — the location is
chosen to read naturally next to the other `docs/*.md` governance and
reference documents, and is flagged here, as the task brief requires, for
explicit confirmation rather than silent adoption.

---

## Scope compliance

This PR contains: planning documentation, repository inventory findings
(Section 2), architecture/schema mapping (Section 3), proposed future API
sketches in documentation form only (Section 6, Section 11), diagrams in
ASCII form (Sections 1, 6, 7), risk and decision registers (Section 15), a
detailed 44-PR roadmap (Section 12), the two documentation-index updates
listed immediately above.

This PR contains no production Python implementation, no new runtime
dependencies, no `basis-schemas` dependency changes, no copied schema files
under `basis-core/schemas/` (Section 4's vendored fixtures live under
`tests/fixtures/`, are not implemented in this PR, and are documentation of
a *future* PR's scope, not an action taken here), no copied compatibility
fixtures (same point), no evaluator changes, no model changes, no public
export changes, no test changes for unimplemented behavior, no version
changes, no deprecations, no release preparation, and no changes to
`basis-architecture` or `basis-schemas`.
