# Operation-Aware Evaluation Semantics

This document is the implementation-level companion to `basis-architecture`'s operation-aware evaluation semantics. It explains how the merged `basis-core` implementation evaluates one `OperationAwareDecisionRequest` against one `PolicyBundle`: stage ownership, outcomes, failure handling, trace provenance, and enforcement disposition.

Cross-references: `docs/operation-aware-model.md` covers the model families this document assumes. `docs/import-boundaries.md` and `docs/kernel-constitution.md` state the layering this document's stage-ownership sections rely on. `docs/adr/ADR-0006-operation-aware-enforcement-point.md` is the repository-local design decision behind the enforcement mapping in Section 6. Architectural authority is `basis-architecture` ADR-0002 ("Operation-Aware Evaluation Semantics") and its companion document of the same name, ADR-0003 ("Operation-Aware Trace and Audit Evidence") and its companion document, and ADR-0006 ("Introduce a Pure Evaluation Orchestration Layer") and its companion document — cited throughout by section number.

This document does not introduce new policy semantics. Where it restates an architecture rule, the restatement describes how the merged code implements that rule, not an independent decision.

---

## 1. Scope and Authority

`basis-architecture` owns the ecosystem-level evaluation semantics — default deny, `NOT_APPLICABLE`, deny precedence, condition-evaluation requirements, safe error handling, and the rest, defined in `basis-architecture`'s `docs/architecture/operation-aware-evaluation-semantics.md`. This document explains the `basis-core` implementation of those semantics; it is not a competing authority.

`basis-schemas` contract fixtures (the vendored `tests/fixtures/basis-schemas/` snapshot) are conformance inputs used by this repository's own test suite — never a runtime dependency. `basis-core` does not import, parse, or depend on `basis-schemas` at runtime.

The operation-aware evaluator is deterministic and synchronous: `OperationAwareEvaluationEngine.evaluate()` and `OperationAwareEnforcementPoint.evaluate()` are both ordinary, blocking Python method calls. Neither performs I/O, network access, filesystem access, database access, or reads a clock or a random-value source; every identifier and timestamp that would otherwise require one (`trace_id`, `evidence_id`, `recorded_at`) is supplied by the caller.

---

## 2. Evaluation Layers

Three kernel subpackages divide ownership of the pipeline described in Section 3.

```text
policy/operation_aware/
```

owns executable authorization *semantics*: bundle structural and semantic validation, bundle-scope applicability, rule-selector matching, condition evaluation, condition-result aggregation, rule-effect aggregation, deny precedence, default deny, and `NOT_APPLICABLE` determination. Every decision about what a request/bundle pair *means* is made here.

```text
evaluation/operation_aware/
```

owns orchestration and artifact assembly: sequencing the policy-owned stages in the required order, carrying their typed results forward, and assembling `TraceRuleEvidence`/`EvaluationTrace` (trace assembly), `OperationAwareDecisionResponse` (response assembly), and `AuditEvidence` (audit-evidence assembly). It reimplements none of `policy/`'s semantics — every authorization-meaning decision `evaluation/` reports was already made by a `policy/`-owned function it called.

```text
enforcement/operation_aware.py
```

owns the public, fail-closed composition boundary: invoking the evaluation engine, composing response and audit-evidence assembly, and mapping the result to the enforcement-only `EnforcementDisposition` vocabulary (Section 6).

Evaluation orchestration does not redefine policy semantics. If `evaluation/` needed a new authorization rule, that rule would belong in `policy/`, not be improvised in the orchestration layer.

---

## 3. Evaluation Pipeline

`OperationAwareEvaluationEngine.evaluate(request=..., bundle=..., trace_id=...)` runs the following stages, in this order, as implemented in `src/basis_core/evaluation/operation_aware/engine.py`:

1. **Typed request and policy-bundle acceptance.** `request` and `bundle` are already-constructed, already-validated `OperationAwareDecisionRequest`/`PolicyBundle` instances by the time the engine receives them — construction-time Pydantic validation (field presence, type, pattern/enum shape) has already run. The engine performs no raw-mapping parsing of its own.
2. **Policy-bundle semantic validation** — `policy.operation_aware.validation.validate_policy_bundle(bundle)`. Only `SemanticPolicyValidationError` is caught (duplicate `rule_id`/`condition_id`); `StructuralPolicyValidationError` is unreachable through this typed entry point, because the engine never receives a raw mapping. A semantic-validation failure short-circuits the pipeline immediately: it produces a failed `EvaluationTrace` (`failure_reason=policy_validation_failure`) and none of stages 3–7 below runs.
3. **Bundle applicability** — `policy.operation_aware.applicability.determine_applicability(bundle, request)`. A `not_applicable` result also short-circuits: stages 4–5 do not run, and stage 6 (aggregation) is still invoked, with zero evaluated rules, so that the `NOT_APPLICABLE` outcome comes from the same policy-owned aggregation function every other path uses.
4. **Deterministic candidate selection** — `policy.operation_aware.selector.select_candidate_rules(bundle.rules, request)`. Returns every rule's `CandidateRuleEvaluation`, sorted by ascending `rule_id` (a determinism tie-breaker only, never authorization precedence).
5. **Selector and condition evaluation** — one call to `policy.operation_aware.condition_eval.evaluate_rule_conditions(rule, request)` per candidate, in the order stage 4 produced. This integrates structural `match` evaluation with condition evaluation (Section 4).
6. **Policy-owned aggregation** — `policy.operation_aware.aggregation.aggregate_policy_outcome(applicability, evaluated_rules)`. Accepted as authoritative for completed/failed status, outcome, failure reason, and final reason code (Section 5).
7. **Per-rule evidence assembly** — `evaluation.operation_aware.trace_assembly.assemble_rule_evidence(rule, evaluation)`, once per candidate, preserving stage 4's order.
8. **Trace assembly** — `evaluation.operation_aware.trace_assembly.assemble_evaluation_trace(...)`, composing the ordered rule evidence with stage 6's aggregated state (mapped through the explicit vocabulary tables in Section 5) into one `EvaluationTrace`.
9. **Return.** `OperationAwareEvaluationEngine.evaluate()` returns the assembled `EvaluationTrace` directly — there is no separate engine-specific result wrapper.

Two further stages happen outside the engine, inside `OperationAwareEnforcementPoint.evaluate()` (`src/basis_core/enforcement/operation_aware.py`):

10. **Response assembly** — `evaluation.operation_aware.response_assembly.assemble_operation_aware_decision_response(trace=..., embed_evaluation_trace=...)`, producing `OperationAwareDecisionResponse` from the trace alone.
11. **`AuditEvidence` assembly** — `evaluation.operation_aware.response_assembly.assemble_audit_evidence(request=..., trace=..., evidence_id=..., recorded_at=...)`, after verifying `request`/`trace` identify the same evaluation.
12. **Enforcement disposition mapping** — Section 6.

No stage above reimplements a decision another stage already made. The engine's own docstring states this directly: where it "decides," it decides which already-implemented operation to call next and how to carry its typed result forward — never what that operation's own answer means.

---

## 4. Applicability, Matching, and Conditions

The pipeline distinguishes several states that must not be conflated:

| State | Meaning | Produced by |
|---|---|---|
| Bundle not applicable | The bundle's declared scope does not cover this request at all. | `determine_applicability` |
| Rule selector not matched | The rule's structural `match` criteria did not select this request. | `evaluate_rule_selectors` (via `evaluate_rule_conditions`) |
| Condition not matched | A condition evaluated to `no_match`. | `evaluate_condition` |
| Condition evaluation error | A condition could not be evaluated at all (unsupported operator, unknown field path, type mismatch). | `evaluate_condition` |
| Rule matched | Structural selectors matched and every declared condition matched. | `evaluate_rule_conditions` |
| Rule error | Any one of the rule's conditions errored. | `evaluate_rule_conditions` |

### Condition operator registry

`policy/operation_aware/operators.py` implements a fixed, ten-operator set, exposed as the immutable `SUPPORTED_OPERATORS` frozenset. There is no registration API, no plugin loading, and no dynamic import — adding an operator requires editing the literal registry in a reviewed change.

| Operator | Accepted actual-value family | Behavior |
|---|---|---|
| `equals` | string, number, boolean | Match iff present, family-matched, and equal. |
| `not_equals` | string, number, boolean | Match iff present, family-matched, and unequal. |
| `in` | string, number, boolean | Match iff present, family-matched, and a member of the expected array. |
| `not_in` | string, number, boolean | Match iff present, family-matched, and not a member of the expected array. |
| `greater_than` | number | Match iff present, both operands number-family, and ordered. |
| `greater_than_or_equal` | number | As above. |
| `less_than` | number | As above. |
| `less_than_or_equal` | number | As above. |
| `exists` | any | Match iff the field path resolves to a present value. |
| `not_exists` | any | Match iff the field path resolves to absent. |

**Field-path resolution** is bounded, typed traversal against a hardcoded set of known fields on `OperationAwareDecisionRequest` and its six nested context objects — never generic `getattr`/reflection, never `eval`. `subject_attrs` is the one exception, resolved as a bounded, one-level string-keyed lookup. `identity_evidence_reference` and `adapter_evidence_reference` are excluded from the addressable field-path surface at any depth.

**Missing-field behavior.** Resolution distinguishes two non-present states, never conflated: **absent** (a known, declared field or `subject_attrs` key this particular request did not populate) and **unknown** (a field path this kernel version's request model does not declare at all, or one that reaches past a scalar leaf, or that names an excluded evidence-reference field). An absent field feeds each operator's own absence rule — `equals`/`not_equals`/`in`/`not_in`/the four ordering operators all resolve to `no_match` on an absent field; `exists` resolves to `no_match`; `not_exists` resolves to `match`. An unknown path always produces `error`, independent of which operator was named.

**No silent coercion.** Every comparison operator classifies the actual value and the expected value into a family (`string`, `number` — int and float unified, never boolean — `boolean`, `array`, `timestamp`, or `structured_object`) and requires the operator's accepted families to match before comparing. A family mismatch is always `error`, never an implicit string/int/float/bool conversion and never a silent `no_match` standing in for "could not be compared."

**Condition order.** Every condition in a rule's `conditions` is evaluated exactly once, in authored order, with no short-circuiting after a `no_match` or an `error` — the full, ordered per-condition result sequence is always retained.

**Rule-level condition aggregation** (`evaluate_rule_conditions`): a structural selector mismatch is reported `not_matched` without evaluating any condition. A structural match with no declared conditions is reported `matched` immediately. Otherwise, every condition is evaluated; any condition `error` makes the rule `error` (dominating `no_match`); otherwise, if every condition `match`, the rule is `matched`; otherwise `not_matched`.

**Unsupported-operator handling.** `PolicyCondition.operator` is an open, structurally validated string — it is not rejected at bundle-construction time merely because this kernel version does not implement it. An operator name absent from `SUPPORTED_OPERATORS` always evaluates to `error`, never a silent `no_match` or `match`.

---

## 5. Policy Aggregation

`aggregate_policy_outcome(bundle_applicability, evaluated_rules)` implements the following, checked in this order:

1. **Evaluator failure dominates.** If any evaluated rule's condition result is `error`, the aggregation result is `failed` with `failure_reason=condition_evaluation_error` — regardless of whether a matched `deny` or matched `allow` rule is also present.
2. **Not applicable.** If the bundle's applicability is `not_applicable`, the result is `completed` with `outcome=not_applicable` and `reason_code=no_applicable_bundle`.
3. **Matched `deny` takes precedence over matched `allow`.** For an applicable bundle, if any evaluated rule has `result=matched` and `effect=deny`, the outcome is `deny` with `reason_code=deny_rule_matched` — independent of how many matched `allow` rules are also present, and independent of the evaluated-rules sequence order (both dominance checks are order-independent `any()` scans).
4. **Matched `allow` produces allow only when no deny matched.** For an applicable bundle with no matched `deny` and at least one matched `allow`, the outcome is `allow` with `reason_code=allow_rule_matched`.
5. **Default deny.** An applicable bundle with no matched `deny` and no matched `allow` — including the case of zero evaluated rules — produces `outcome=deny` with `reason_code=no_allow_rule_matched`, deliberately a different code from explicit deny precedence's `deny_rule_matched`.
6. **Ordering is evidence ordering, not authorization precedence.** The order rules appear in `evaluated_rules` (and therefore in trace evidence) never affects the aggregated outcome — both the deny-dominance and allow-dominance checks scan the full set.

### Reason codes currently emitted

`aggregate_policy_outcome` constructs exactly four fixed `ReasonCode` values — the only reason codes the merged implementation currently emits:

| Reason code | Emitted when |
|---|---|
| `allow_rule_matched` | Matched allow (Semantics 4). |
| `deny_rule_matched` | Matched deny — deny precedence (Semantics 3). |
| `no_allow_rule_matched` | Default deny — no matched rule of either effect (Semantics 5). |
| `no_applicable_bundle` | Bundle applicability is `not_applicable` (Semantics 2). |

A `reason_code` is present only on a `completed` aggregation result; a `failed` result always carries `reason_code=None`. This is not a complete ecosystem reason-code registry — `ReasonCode` itself remains an open, validated string format (`docs/operation-aware-model.md`, Section 2) — it is the exhaustive list of codes this repository's implementation constructs today. A rule's own authored `reason_code`/`explanation` (distinct from the aggregate reason code above) may still appear in that rule's own `TraceRuleEvidence` entry, per Section 8.

---

## 6. Completed Outcomes Versus Evaluator Failures

`EvaluationTrace.evaluation_status`, `OperationAwareDecisionResponse.evaluation_status`, and `AuditEvidence.evaluation_status` each take one of two values: `completed` or `failed`. Every one of the three artifact models enforces the same construction-time invariant pair:

- `outcome` is non-`None` if and only if `evaluation_status` is `completed`.
- `failure_reason` is non-`None` if and only if `evaluation_status` is `failed`.

A `failed` result therefore can never carry a substantive `allow`/`deny`/`not_applicable` outcome, and a `completed` result can never carry a failure reason. An evaluator failure is not silently rewritten into an authorization `DENY` anywhere in these three models.

### Governed failure reasons implemented by the code

`OperationAwareFailureReason` (`basis_core.decisions`) is a closed, six-value vocabulary. The merged implementation constructs three of the six members; the other three are defined in the vocabulary but not currently constructed anywhere in this evaluator, because the conditions that would produce them are request-shape/structural concerns resolved before a typed request or bundle ever reaches the engine:

| Member | Constructed by this implementation? | Where |
|---|---|---|
| `policy_validation_failure` | Yes | `OperationAwareEvaluationEngine`, stage 2, on `SemanticPolicyValidationError` (duplicate `rule_id`/`condition_id`). |
| `condition_evaluation_error` | Yes | `aggregate_policy_outcome`, when any evaluated rule's condition result is `error`. |
| `internal_evaluation_error` | Yes | `OperationAwareEnforcementPoint`, only on an unexpected exception anywhere in its own composition (Section 10). |
| `invalid_request` | No | Request-shape validation happens at `OperationAwareDecisionRequest` construction time, upstream of this evaluator's typed entry point. |
| `unsupported_schema_version` | No | No schema-version negotiation is implemented by this evaluator. |
| `invalid_policy_bundle` | No | `StructuralPolicyValidationError` — a raw-mapping shape failure — is unreachable through the engine's typed `bundle: PolicyBundle` parameter; a caller that parses raw policy data is responsible for this category. |

### Enforcement disposition mapping

`OperationAwareEnforcementPoint._derive_disposition()` maps the assembled response to the closed, two-value `EnforcementDisposition` (`allow`/`deny`):

- `disposition=allow` only when `evaluation_status=completed` **and** `outcome=allow`.
- `disposition=deny` for every other case: explicit `deny`, default deny, `not_applicable`, any of the three governed failure reasons above, or an unexpected internal failure.

The response itself is never rewritten to match the disposition — `not_applicable` stays `not_applicable`, and a failed evaluation keeps `evaluation_status=failed`/`outcome=None`. `disposition` collapses three non-allow kernel states into one caller-facing "do not proceed" signal; it does not alter what the kernel artifacts themselves report.

---

## 7. Determinism

The evaluator's determinism rests on:

- no network, filesystem, database, or other external-state access anywhere in `policy/operation_aware/` or `evaluation/operation_aware/`;
- caller-supplied identifiers and timestamps everywhere one would otherwise require a clock or randomness (`trace_id`, `evidence_id`, `recorded_at`);
- deterministic rule ordering (`select_candidate_rules` sorts by ascending `rule_id`) and deterministic, authored-order condition evaluation;
- explicit, exhaustive enum-to-enum mapping tables at every vocabulary boundary (for example `ApplicabilityResult → TraceBundleApplicability`, `TraceOutcome → OperationAwareDecisionOutcome`) — never `.value`-string coercion and never a fallback branch, so an enum member added to one vocabulary without a matching table update fails a completeness test rather than mapping through a coincidental string match;
- pure response and evidence assembly functions that read their arguments only and mutate nothing;
- no clock, UUID, or random-value generation inside any pure assembly function.

This does not claim byte-for-byte determinism for values the caller intentionally varies — a different `trace_id`, `evidence_id`, or `recorded_at` on an otherwise-identical evaluation produces a different (but equally valid) artifact set. What is guaranteed is that identical typed inputs, including identical caller-supplied facts, always produce an equal result.

---

## 8. Trace Evidence and Provenance

`TraceRuleEvidence` (per rule) nests `TraceConditionEvidence` (per condition); `EvaluationTrace` carries an ordered `rule_evidence: list[TraceRuleEvidence]`; the top-level response and `AuditEvidence` are each assembled from one `EvaluationTrace` (Section 3, stages 10–11).

### Governed rationale projection

`assemble_rule_evidence` does not copy a rule's authored `reason_code`/`explanation` unconditionally. It projects them by the rule's own `rule_result`:

- **`matched`** — the rule's authored `reason_code`/`explanation` are preserved verbatim, never rewritten and never suppressed merely because another rule was decisive under deny precedence.
- **`not_matched`** — omitted (`null`/`null`). A rule that did not match emitted no rationale for this evaluation.
- **`skipped`** — omitted (`null`/`null`), for the same reason. `RuleResult.SKIPPED` is not currently producible by this pipeline (every candidate rule the engine considers is evaluated, never skipped), but the projection remains total over all four `RuleResult` members.
- **`error`** — omitted (`null`/`null`). No governed evaluation-error `reason_code`/`explanation` exists anywhere in this pipeline; an errored rule's evidence never substitutes the rule's authored success/deny rationale for one.

Matched-but-non-decisive evidence remains visible: a rule that matched with effect `allow` still appears in `rule_evidence` with `rule_result=matched` and its authored rationale intact even when a different rule's matched `deny` determines the final outcome. The top-level `EvaluationTrace.explanation` and `OperationAwareDecisionResponse.explanation` remain `null` whenever no governed stage supplies one — assembly never synthesizes prose. The reason code (Section 5) remains the authoritative machine-readable explanation; explanation text, when present, is a static, non-generated string only.

### Bundle identity preservation

`bundle_id`/`bundle_version` remain present on the trace whenever a trustworthy typed `PolicyBundle` exists — including the `not-applicable` path (sourced from the already-validated bundle) and the typed semantic-validation-failure path (sourced from the original `bundle` parameter, which is itself a successfully constructed `PolicyBundle` even though its semantic validation failed). They are omitted only when no trustworthy typed bundle exists at all — the unexpected-internal-failure path (Section 10) still supplies both from the enforcement point's own configured bundle, since the bundle itself was never in question.

Evidence is never silently summarized or "improved" beyond what the code above actually emits — a not-matched or skipped rule's absent rationale is not backfilled from the bundle's authored data, and an errored condition's evidence carries only its `condition_id` and `result`, never the raw compared values.

---

## 9. Response, Trace, and Audit-Evidence Agreement

`OperationAwareDecisionResponse` enforces a narrow, fixture-driven subset of full response/trace agreement when `evaluation_trace` is embedded — deliberately not the complete agreement matrix, which remains a later, separately-scoped concern:

**Enforced by `OperationAwareDecisionResponse`'s own model validators:**

- `request_id` — the embedded trace's `request_id` must equal the response's own.
- `correlation_id` — must agree when *both* are non-null.
- `failure_reason` — must agree (both may be `None`, which trivially agrees).
- `reason_code` — must agree when *both* are non-null.

**Not separately re-validated by this model** (true by construction, because response assembly copies every field directly from the trace — see Section 3, stage 10): `evaluation_status` agreement, `outcome` agreement, `bundle_id`/`bundle_version` agreement, and `trace_id` vs. `evaluation_trace.trace_id` agreement.

`AuditEvidence` references the trace by `trace_id` rather than duplicating trace content — it carries no embedded `EvaluationTrace` and no per-rule or per-condition evidence. `assemble_audit_evidence` additionally verifies, before combining request-owned evidence references with trace-owned facts, that `request.request_id == trace.request_id` and `request.correlation_id == trace.correlation_id`, raising `EvaluationArtifactIdentityMismatchError` if either disagrees.

**Trace presentation.** Whether the full `EvaluationTrace` is embedded on the response (`response.evaluation_trace`) or only referenced by identifier (`response.trace_id`) is controlled by `OperationAwareEnforcementPoint.evaluate()`'s `embed_evaluation_trace` keyword argument (default `False`) — never inferred from environment or trace content.

**`matched_rule_ids` projection.** `AuditEvidence.matched_rule_ids` is derived, not caller-supplied: it is the `rule_id` of every `rule_evidence` entry whose `rule_result` is `matched`, in the trace's own already-established order. A `deny` outcome reached through deny precedence may still carry both a matched allow and a matched deny rule in this list — both are reported honestly; the list is never inferred from `trace.outcome` alone.

`basis-core` produces `AuditEvidence` as one of an evaluation's three artifacts. It does not persist it — there is no writer protocol, no storage backend, and no `write`/`save`/`persist` method anywhere in this family.

---

## 10. Enforcement Boundary

`OperationAwareEnforcementPoint.evaluate()`:

- invokes `OperationAwareEvaluationEngine.evaluate()` with the caller's request, its own configured bundle, and the caller-supplied `trace_id`;
- composes `assemble_operation_aware_decision_response()` and `assemble_audit_evidence()` from the resulting trace;
- maps the assembled response to `EnforcementDisposition` (Section 6);
- catches any unexpected exception raised anywhere in that composition (engine invocation, response assembly, audit-evidence assembly, or disposition derivation) and converts it into a fixed internal-error result (`failure_reason=internal_evaluation_error`, `disposition=deny`) rather than propagating it — `evaluate()` never raises;
- fails closed: every reachable path, expected or unexpected, produces `disposition=deny` except the single completed-and-allowed case;
- never persists `AuditEvidence`;
- never constructs `GatewayAuditEvent` — no such type exists anywhere in `basis_core`;
- never performs gateway transport, HTTP routing, or any caller-response duty of its own.

The result carrier, `OperationAwareEnforcementResult`, is an immutable, frozen dataclass binding exactly three fields together — `response`, `audit_evidence` (`None` only when it could not be trustworthily assembled during an unexpected-failure path), and `disposition` — with no gateway, persistence, or execution-success field of any kind.

---

## 11. Canonical Conformance

The five canonical scenarios — `allow-basic`, `deny-precedence`, `default-deny`, `not-applicable`, and `invalid-policy-bundle` — are exercised through the real `OperationAwareEnforcementPoint.evaluate()` path (`tests/operation_aware/test_canonical_vectors.py`), using real typed requests and bundles loaded from the vendored `basis-schemas` fixture snapshot — never a hand-typed expected value and never a test double for the engine, the bundle, or any assembler.

Kernel conformance asserts complete semantic equality against the vendored expected artifacts for exactly three kernel-owned types: `OperationAwareDecisionResponse`, `EvaluationTrace`, and `AuditEvidence`.

Each canonical scenario directory also vendors `expected-gateway-audit-event.yaml`, part of the complete cross-repository fixture set `basis-schemas` publishes. This suite intentionally never loads, constructs, or asserts against that artifact, and no `GatewayAuditEvent` production type exists anywhere in `basis_core` to assert against — `basis-core`'s conformance boundary is the three kernel-owned artifacts above; `basis-gateway` owns conformance for the artifact that combines this kernel's evidence with gateway-only enforcement facts.

---

## 12. Failure and Error Boundaries

| Failure | Kernel representation | Owner |
|---|---|---|
| Semantic policy validation failure (duplicate `rule_id`/`condition_id`) | Failed evaluation, `failure_reason=policy_validation_failure`, valid `AuditEvidence` still assembled, `disposition=deny`. | `policy/` (detection) / `evaluation/` (mapping into the trace) |
| Rule condition evaluation error | Failed evaluation, `failure_reason=condition_evaluation_error`, valid `AuditEvidence` still assembled, `disposition=deny`. | `policy/` (aggregation) |
| Unsupported condition operator | The single condition evaluates to `error`; if that condition is the rule's only defect, the rule is `error`, which dominates aggregation into `condition_evaluation_error` above. | `policy/` |
| Unexpected exception anywhere in engine/assembly composition | Failed evaluation, `failure_reason=internal_evaluation_error`, `audit_evidence` may be `None` (Section 10), `disposition=deny`. | `enforcement/` |
| Token verification failure | Not represented by the kernel evaluator at all. | `basis-gateway` / caller (upstream of the typed request) |
| HTTP delivery failure | Not represented by the kernel evaluator. | `basis-gateway` |
| `AuditEvidence` persistence failure | Not performed by `basis-core` — there is nothing here to fail. | `basis-gateway` or caller |
| Raw/unparsed policy-bundle shape failure (`StructuralPolicyValidationError`) | Not reachable through the engine's typed `bundle: PolicyBundle` entry point. | Whatever caller parses raw policy data before constructing a `PolicyBundle` |

---

## 13. Non-Goals

The evaluator does not:

- authenticate a subject or verify any credential;
- fetch identity, protocol, topology, safety, environment, or risk context from any external system — every context field is caller-supplied, already-normalized data;
- infer missing operational facts, or treat a missing request value as a wildcard;
- perform topology discovery or location-hierarchy inference (Section 4 of `docs/operation-aware-model.md`);
- persist any evidence it produces;
- emit `GatewayAuditEvent`;
- negotiate policy versions — `expected_policy_version` on the request is carried through as data; this evaluator implements no comparison or negotiation behavior against it;
- implement an open-ended policy language — the condition-operator set is closed and finite (Section 4);
- expose any internal evaluation helper (`OperationAwareEvaluationEngine`, the applicability/selector/condition/aggregation functions, the response/trace/audit-evidence assembly functions) as a supported public extension point (`docs/operation-aware-model.md`, Section 5).

---

## 14. Further Reading

- `docs/operation-aware-model.md` — the model families this document assumes.
- `docs/public-api.md` — what is importable and supported.
- `docs/extension-contracts.md` — why the operation-aware policy family is not an executable extension point.
- `docs/kernel-constitution.md`, `docs/import-boundaries.md` — the invariants and layering this document's Section 2 restates against the merged code.
- `docs/adr/ADR-0006-operation-aware-enforcement-point.md` — the repository-local design decision behind Section 6 and Section 10.
- `basis-architecture` `docs/architecture/operation-aware-evaluation-semantics.md` (ADR-0002) — the ecosystem-level authority for Sections 3–7 of this document.
- `basis-architecture` `docs/architecture/operation-aware-trace-audit-evidence.md` (ADR-0003) — the ecosystem-level authority for Sections 8–9 and 11 of this document.
- `basis-architecture` `docs/architecture/operation-aware-evaluation-orchestration.md` (ADR-0006) — the ecosystem-level authority for Section 2 of this document.
