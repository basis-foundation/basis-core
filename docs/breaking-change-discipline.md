# Breaking-Change Discipline

This document is the single reference for how public contract changes in basis-core are classified, governed, and executed. It covers every contract surface the kernel exposes to external consumers. Per-surface documents (listed below) provide deeper detail; this document provides the unified process.

Cross-references: `docs/kernel-constitution.md` Invariant 9 states the constitutional commitment. `docs/schema-versioning.md` details schema-specific rules, including the operation-aware serialized-artifact rules in that document's own "Operation-Aware Contract Families" section. `docs/extension-contracts.md` details interface behavioral rules, including why the operation-aware policy family is structured data rather than a new extension point. `docs/compatibility-testing.md` describes the test harness and how test failures signal a contract change, including the vendored `basis-schemas` operation-aware snapshot harness. `docs/public-api.md` inventories the stable public API surface, including the "Operation-aware public API (v0.2.0)" section. `docs/operation-aware-model.md` and `docs/operation-aware-evaluation-semantics.md` describe the operation-aware models and evaluation pipeline this document's "Operation-Aware Governed Surfaces" section classifies for compatibility purposes. `docs/architecture/compatibility-philosophy.md` in basis-architecture is the governing architectural rationale.

---

## Contract surfaces

All of the following are external compatibility surfaces. A change to any of them is felt by consumers simultaneously — including audit consumers that must interpret stored records retroactively.

| Surface | Canonical reference |
|---|---|
| JSON schemas (`schemas/*.schema.json`) | `docs/schema-versioning.md` |
| Contract fixtures (`tests/fixtures/contracts/*.json`) | `docs/compatibility-testing.md` |
| Public API exports (`__all__` per package) | `docs/public-api.md` |
| Evaluation semantics (DENY short-circuit, first-ALLOW, NOT_APPLICABLE) | `docs/evaluation-semantics.md` |
| Enforcement fail-closed behavior and failure-reason codes | `docs/enforcement-boundary.md`, `docs/failure-modes.md` |
| Audit event shape and immutability semantics | `docs/audit-model.md` |
| Extension interface signatures and behavioral contracts | `docs/extension-contracts.md` |
| Action vocabulary (names and meanings in `basis_core.domain.action`) | `docs/architecture/action-vocabulary.md` (basis-architecture) |
| Adapter normalization contracts (`NormalizedEvent` field semantics) | `docs/adapter-contracts.md` |
| Operation-aware governed surfaces (v0.2.0): shared vocabulary, evidence references, request/context models, structured policy data, trace/evidence artifacts, response/enforcement surface | "Operation-Aware Governed Surfaces (v0.2.0)" section below; `docs/operation-aware-model.md`; `docs/operation-aware-evaluation-semantics.md`; `docs/schema-versioning.md` |

If you are unsure whether something you are changing is on this list, assume it is.

---

## Operation-Aware Governed Surfaces (v0.2.0)

The operation-aware authorization surface (`OperationAwareDecisionRequest`, the structured policy data model, the trace/evidence family, `OperationAwareDecisionResponse`, and `OperationAwareEnforcementPoint`) was merged as a purely additive expansion of the v0.1 public API — see `docs/implementation/basis-core-v0.2-operation-aware-plan.md` and `docs/operation-aware-model.md`. Being additive at merge time does not make it exempt from compatibility discipline going forward. Once published, every governed surface below is a compatibility commitment under this document exactly as the v0.1 surfaces are: "new" is not a synonym for "casually changeable." The [Breaking changes](#breaking-changes) and [Additive changes](#additive-changes) sections below apply to these surfaces the same way they apply to the v0.1 surfaces; this section identifies what they are and adds concrete operation-aware examples.

### Authority boundaries for this section

Per the cross-repository authority model (`docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 1): `basis-architecture` defines operation-aware semantics; `basis-schemas` publishes the contract shapes; `basis-core` implements and governs compatibility of its own implementation surface. This section classifies changes to what `basis-core` implements or consumes. It does not, and must not be read to, claim authority over ecosystem-wide architecture semantics (owned by `basis-architecture`), `basis-schemas`' own release governance, gateway enforcement facts, `GatewayAuditEvent`, or schema-publication metadata used only by `basis-schemas`' own tooling.

When a change to one of the surfaces below is proposed, identify which of the three lines it falls on before classifying it:

1. **The upstream contract** — the `basis-schemas` YAML contract or the `basis-architecture` ADR that defines the concept.
2. **The corresponding `basis-core` implementation surface** — the Python model, vocabulary, or evaluator behavior listed below.
3. **Whether that surface is runtime-owned, test-only, or outside kernel scope** — see "Classification of the fourteen upstream contract surfaces" below; not every upstream contract has a runtime counterpart in this repository.

### Shared vocabulary and evidence references

Governed surface: `RedactionClassification` (closed, five-value enum), `ReasonCode` (validated format, open vocabulary), `EvidenceDigest`, `IdentityEvidenceReference`, `AdapterEvidenceReference` — all in `basis_core.domain`.

**Breaking** — removing or renaming a `RedactionClassification` value; changing what an existing `RedactionClassification` value means (e.g., redefining `NEVER_STORE` to permit redacted storage); narrowing the `ReasonCode` format pattern (`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`) so previously valid codes are rejected; changing the meaning of an *existing, currently-emitted* reason code (`allow_rule_matched`, `deny_rule_matched`, `no_allow_rule_matched`, `no_applicable_bundle` — see `docs/operation-aware-evaluation-semantics.md` Section 5) so it is emitted under different conditions than before; changing `EvidenceDigest`'s field names or required fields; admitting a raw token, raw credential, or raw protocol payload field to `IdentityEvidenceReference` or `AdapterEvidenceReference`; changing a currently-required evidence-reference field to optional or vice versa; changing these models' unknown-field rejection (`extra="forbid"`) to permit unknown fields.

**Additive, subject to compatibility review** — adding a new emitted reason code without changing what any existing emitted code means; adding a new optional field to an evidence-reference model with defined absence semantics.

`ReasonCode`'s open vocabulary is a deliberate design point, not a loophole: the *format* is governed (pattern-validated, closed to non-conforming strings) even though the *set of codes* is not closed. A future PR that adds a new code the evaluator emits is a smaller-review additive change; a PR that changes what one of the four codes currently emitted by `aggregate_policy_outcome` means, or under what condition it is produced, is a behavioral change requiring the same review as any other semantic redefinition.

### Operation-aware request and context models

Governed surface: `OperationAwareDecisionRequest`, `OperationIntent` (closed, three-value: `read_only`/`state_changing`/`control_affecting`), and the six context value objects — `OperationAwareLocation`, `OperationAwareDevice`, `OperationAwareProtocolContext`, `OperationAwareSafetyContext`, `OperationAwareEnvironmentContext`, `OperationAwareRiskContext` — all in `basis_core.decisions`/`basis_core.domain`.

**Breaking** — renaming or removing any field on `OperationAwareDecisionRequest` or any of the six context objects; making a currently-optional field required (every field beyond `request_id`/`subject_id`/`action` is optional today — see `docs/operation-aware-model.md` Section 3); narrowing the open-identifier pattern used by `resource_type` and `authority_mode`, or the non-empty check on `identity_source`, so previously valid values are rejected; changing `action`/`resource` validation patterns; changing how `subject_roles`/`subject_attrs` are normalized; changing the `evaluation_time` timezone-aware requirement; changing the model's unknown-field rejection; changing what `operation_intent` means for any of its three values, or removing/renaming a value; introducing a cross-field invariant between `resource` and `resource_type` where none exists today (or removing one that has been added); changing the requirement that `request_id` has no default factory (the producer must supply it).

**Additive, subject to compatibility review** — adding a new optional field to `OperationAwareDecisionRequest` or a context object with defined absence semantics. This is not automatically risk-free: a strict downstream consumer that rejects unknown fields, or a policy condition's field-path resolution (`docs/operation-aware-evaluation-semantics.md` Section 4) that would need to recognize the new path, are both compatibility-relevant even for an additive field. Treat the existing document's general "additive changes still need review for strict consumers" position (see [Additive changes](#additive-changes) below) as fully applicable here.

### Structured policy data model

Governed surface: `PolicyCondition`, `OperationAwarePolicyMatch`, `OperationAwarePolicyRule`, `RuleEffect` (closed, two-value: `allow`/`deny`), `PolicyBundleScope`, `PolicyBundle` — all in `basis_core.policy`.

This model is **structured data that a policy author authors**, not a public executable extension-point `Protocol` — `docs/extension-contracts.md`'s "Operation-aware policy is structured data" section is the authority for that distinction and is unchanged by this document. Changing an internal helper's signature (`determine_applicability`, `evaluate_rule_selectors`, `aggregate_policy_outcome`, and the rest of `docs/public-api.md`'s "Internal — not exported" list) is not automatically a public API break, because none of those symbols are part of the documented public surface. Changing what a bundle author observes — the shape a bundle must have, or what effect a given bundle produces on evaluation — is governed behavior regardless of which internal function implements it.

**Breaking** — altering the `allow`/`deny` `RuleEffect` vocabulary (adding, removing, or redefining a value; `not_applicable` is deliberately not a rule effect and must not become one without architecture review); changing `PolicyCondition.field_path`'s dotted-identifier syntax or `operator`'s snake-case identifier pattern; changing what an existing, currently-implemented operator (the ten in `SUPPORTED_OPERATORS` — `docs/operation-aware-evaluation-semantics.md` Section 4) does, including its family-matching or absent/missing-field rule; removing an operator from `SUPPORTED_OPERATORS`; changing the no-silent-coercion guarantee (family classification before comparison) to permit implicit type conversion; changing `rule_id`/`condition_id` uniqueness requirements (currently: unique `rule_id` across a bundle, unique `condition_id` within a rule); changing the "rule must have `match` or non-empty `conditions`" validity rule; changing `PolicyBundleScope`'s exact-match-only applicability semantics to introduce wildcard, hierarchical, or prefix matching without a governed decision (`docs/operation-aware-model.md` Section 4 documents the current exact-match-only limitation explicitly as a conservative starting point, not a permanent guarantee, but broadening it is still a behavioral change subject to review, not a silent fix); changing `PolicyBundle`'s required metadata fields (`bundle_id`, `bundle_version`, `schema_version`, `policy_owner`, non-empty `rules`); changing how a semantic-validation failure (duplicate `rule_id`/`condition_id`) is classified (currently `evaluation_status: failed`, `failure_reason=policy_validation_failure`).

**Additive, subject to compatibility review** — adding a new operator to `SUPPORTED_OPERATORS` under an approved architecture/schema clarification (not a local convenience decision — see `docs/extension-contracts.md`'s "Condition operators are governed semantics, not a plugin registry"); adding a new optional selector category to `OperationAwarePolicyMatch` or `PolicyBundleScope`; adding a new optional `PolicyBundle` metadata field.

### Trace and evidence artifacts

Governed surface: `TraceRuleEvidence`, `TraceConditionEvidence`, `TraceRuleEffect`, `RuleResult` (closed, four-value: `matched`/`not_matched`/`skipped`/`error`), `TraceConditionResult` (closed, three-value: `matched`/`not_matched`/`error`), `EvaluationTrace`, `EvaluationStatus`, `TraceOutcome`, `TraceBundleApplicability`, `TraceFailureReason`, `AuditEvidence` — in `basis_core.audit`.

**Breaking** — changing any of the closed `RuleResult`/`TraceConditionResult`/`EvaluationStatus`/`TraceOutcome`/`TraceBundleApplicability`/`TraceFailureReason` vocabularies (removal or semantic redefinition); changing the ordering guarantee for `EvaluationTrace.rule_evidence` (currently: candidate order from `select_candidate_rules`, sorted by ascending `rule_id` as a determinism tie-breaker, and condition order is authored order with no short-circuiting — `docs/operation-aware-evaluation-semantics.md` Sections 3-4); dropping a `matched`-but-non-decisive rule's evidence from `rule_evidence` (a matched `allow` rule that lost to a matched `deny` under deny precedence must remain visible — Section 8 of the evaluation-semantics document); projecting an authored `reason_code`/`explanation` onto a `not_matched`, `skipped`, or `error` `TraceRuleEvidence` entry (the current, governed rule is: preserved verbatim only for `matched`, omitted for the other three results — changing this projection rule is a behavioral change, not a bug fix, unless the current behavior is first shown to be a defect against the upstream contract); synthesizing top-level `EvaluationTrace.explanation`/`OperationAwareDecisionResponse.explanation` prose where the governed pipeline currently leaves it `null`; changing `bundle_id`/`bundle_version` preservation on the trace (currently preserved whenever a trustworthy typed `PolicyBundle` exists, including on the `not-applicable` and semantic-validation-failure paths — Section 8); changing which fields are required-nullable versus optional (see `docs/schema-versioning.md`'s "Required-Nullable Fields" section for the general rule, applied to these models); changing `AuditEvidence.matched_rule_ids`' derivation (currently: every `rule_evidence` entry with `rule_result=matched`, in trace order — never inferred from `outcome` alone); embedding raw policy content, raw credentials, raw identity claims, or raw protocol payloads in any of these evidence models (none do today; introducing one would violate the redaction-classification discipline these models were built to honor); changing response/trace/audit-evidence agreement (`docs/operation-aware-evaluation-semantics.md` Section 9's four enforced fields — `request_id`, `correlation_id`-when-both-present, `failure_reason`, `reason_code`-when-both-present).

**Additive, subject to compatibility review** — adding a new optional field to `TraceRuleEvidence`, `TraceConditionEvidence`, `EvaluationTrace`, or `AuditEvidence` with defined absence semantics; extending the response/trace/audit-evidence agreement matrix to cover a currently-unvalidated field (this is additive to consumers but should still be reviewed, since it adds a new construction-time validation failure mode that did not exist before).

`AuditEvidence` is kernel-produced but **not kernel-persisted** — `basis-core` has no writer, storage backend, or `write`/`save`/`persist` method for it (`docs/operation-aware-evaluation-semantics.md` Sections 5, 9-10). Do not conflate `AuditEvidence` with the v0.1 `AuditEvent` (a structurally distinct, unrelated family — `docs/operation-aware-model.md` Section 2) or with `GatewayAuditEvent` (see "Classification of the fourteen upstream contract surfaces" below — `GatewayAuditEvent` is not implemented in `basis-core` and is not a kernel-produced artifact).

### Operation-aware response and enforcement surface

Governed surface: `OperationAwareDecisionResponse` (internal — reached via `OperationAwareEnforcementResult.response`), `OperationAwareEvaluationStatus` (closed, two-value: `completed`/`failed`), `OperationAwareDecisionOutcome` (closed, three-value: `allow`/`deny`/`not_applicable`), `OperationAwareFailureReason` (closed, six-value), `OperationAwareEnforcementPoint`, `OperationAwareEnforcementResult`, `EnforcementDisposition` (closed, two-value: `allow`/`deny`).

**Breaking** — changing the completed-versus-failed invariant (`outcome` non-`None` iff `evaluation_status=completed`; `failure_reason` non-`None` iff `evaluation_status=failed` — `docs/operation-aware-evaluation-semantics.md` Section 6); changing which of the six `OperationAwareFailureReason` members this evaluator constructs, or under what condition (currently three are reachable — `policy_validation_failure`, `condition_evaluation_error`, `internal_evaluation_error` — and three are not yet constructed by this implementation — `invalid_request`, `unsupported_schema_version`, `invalid_policy_bundle` — changing which set is reachable, without changing the six-value vocabulary itself, is still a behavioral change worth documenting deliberately, not a silent drift); changing fail-closed behavior (every non-`completed`-`allow` outcome must map to `disposition=deny`); changing the disposition-mapping rule itself; changing whether `OperationAwareEnforcementPoint.evaluate()` can raise (it must not — every unexpected exception must be caught and converted to `internal_evaluation_error`/`disposition=deny`); changing `OperationAwareEnforcementResult`'s three-field carrier shape (`response`, `audit_evidence`, `disposition`); changing whether `evaluation_trace` is embedded on the response by default versus referenced only by `trace_id` (currently `embed_evaluation_trace` defaults to `False`, controlled only by explicit caller argument, never inferred); changing how caller-supplied `trace_id`/`evidence_id`/`recorded_at` are handled (the kernel must continue to read no clock and no random source — `docs/operation-aware-evaluation-semantics.md` Section 7); modifying, subclassing, or sharing implementation between `OperationAwareEnforcementPoint` and the v0.1 `EnforcementPoint` (ADR-0006 Decision 1 requires them to remain separate classes).

**Additive, subject to compatibility review** — adding a new optional keyword argument to `OperationAwareEnforcementPoint.evaluate()` with a default that preserves current behavior.

### Canonical operation-aware scenarios

The five canonical scenarios — `allow-basic`, `deny-precedence`, `default-deny`, `not-applicable`, `invalid-policy-bundle` — are the terminal conformance target for the whole pipeline (`docs/operation-aware-evaluation-semantics.md` Section 11; `tests/operation_aware/test_canonical_vectors.py`). A change to the output any one of these scenarios produces for `OperationAwareDecisionResponse`, `EvaluationTrace`, or `AuditEvidence` is **not an ordinary snapshot refresh** — updating the assertion to match new output without first determining why the output changed is exactly the anti-pattern `docs/compatibility-testing.md` already warns against for the v0.1 fixtures. A canonical-vector output change must be investigated and classified as one of:

- **implementation defect** — the current code diverges from the vendored `basis-schemas` expected artifacts; fix the code, not the fixture;
- **upstream schema correction** — the vendored snapshot itself was corrected (as `v0.2.2` did for three evidence-provenance disagreements present in `v0.2.1` — `docs/compatibility-testing.md`'s "Operation-aware `basis-schemas` fixture snapshot" section); re-vendor deliberately through `scripts/update_basis_schemas_snapshot.py`, never by hand-editing expected artifacts;
- **architecture clarification** — `basis-architecture` resolved an open question (e.g., a future condition-operator or scope-matching decision) that changes expected behavior; requires the same upstream-first review as any other architecture-driven change;
- **deliberate breaking or behavioral change** — requires the full breaking-change process below, exactly as any other breaking change to a governed surface would.

Canonical fixtures — the vendored `expected-*.yaml` artifacts under `tests/fixtures/basis-schemas/<version>/compatibility/` — must never be silently rewritten to match whatever the current implementation happens to produce. Silently "fixing" a fixture to match code output defeats the purpose of a conformance target.

### Classification of the fourteen upstream contract surfaces

`basis-schemas` v0.2.x publishes fourteen operation-aware contracts. Not all fourteen have a `basis-core` runtime counterpart, and this document must not be read to imply otherwise.

**Kernel runtime or compatibility surfaces** — the twelve contracts corresponding to models or behavior `basis-core` implements, each governed by one of the subsections above:

| Upstream contract | `basis-core` surface |
|---|---|
| `redaction-classification` | `RedactionClassification` |
| `reason-code` | `ReasonCode` |
| `identity-evidence-reference` | `IdentityEvidenceReference` |
| `adapter-evidence-reference` | `AdapterEvidenceReference` |
| `operation-aware-decision-request` | `OperationAwareDecisionRequest` and its context objects |
| `policy-condition` | `PolicyCondition` |
| `policy-rule` | `OperationAwarePolicyRule`, `OperationAwarePolicyMatch`, `RuleEffect` |
| `policy-bundle` | `PolicyBundle`, `PolicyBundleScope` |
| `trace-rule-evidence` | `TraceRuleEvidence`, `TraceConditionEvidence` and their vocabularies |
| `evaluation-trace` | `EvaluationTrace` and its vocabularies |
| `operation-aware-decision-response` | `OperationAwareDecisionResponse` and its vocabularies |
| `audit-evidence` | `AuditEvidence` |

**Test/provenance-only surface** — `contract-metadata`. This contract is consumed only as part of the vendored `basis-schemas` snapshot's provenance record (`tests/fixtures/basis-schemas/<version>/PROVENANCE.md` and the snapshot manifest tooling). It is **not a `basis-core` runtime model** — there is no `ContractMetadata` class anywhere in `src/basis_core/`. A change to its upstream shape may affect fixture-loading or provenance tests (`tests/test_basis_schemas_snapshot_provenance.py`); it does not affect kernel runtime serialization and must not be classified as though it did.

**Explicitly outside kernel ownership** — `gateway-audit-event`. `GatewayAuditEvent` is part of the complete cross-repository compatibility fixture family — each canonical scenario directory vendors an `expected-gateway-audit-event.yaml` — but it **remains outside `basis-core` runtime ownership and kernel conformance assertions**. No `GatewayAuditEvent` type exists anywhere in `basis_core`; kernel conformance (`docs/operation-aware-evaluation-semantics.md` Section 11) asserts complete semantic equality for exactly three kernel-owned types (`OperationAwareDecisionResponse`, `EvaluationTrace`, `AuditEvidence`) and intentionally never loads, constructs, or asserts against the gateway artifact. A change to `gateway-audit-event` is primarily a `basis-gateway` governance matter — it is `basis-gateway` that decides and records enforcement facts, per `basis-architecture` ADR-0003 §9 ("`basis-core` decides. `basis-gateway` enforces and records enforcement facts."). Such a change may still require a fixture-inventory update or cross-repository compatibility review in `basis-core` (the vendored snapshot includes the file even though nothing in this repository asserts against it), but it must never be listed as a kernel-produced artifact, and no future PR may add a `GatewayAuditEvent` model, a `GatewayAuditEvent`-shaped writer protocol, or any gateway-enforcement-facts field to any `basis-core` type without a separate, explicit architecture decision overturning this boundary.

### Required review path

A proposed change affecting an operation-aware governed surface may require coordination among `basis-architecture`, `basis-schemas`, `basis-core`, and `basis-gateway`, depending on which surface it touches — not all four for every change:

- **A semantic change** (what a concept means, e.g. redefining deny precedence or `NOT_APPLICABLE`) requires `basis-architecture` review first, per the existing ADR process this document already requires for breaking changes.
- **A serialized-contract change** (a field, pattern, or required/optional shift in a `basis-schemas`-published contract) requires `basis-schemas` review and versioning before `basis-core` can safely implement against the new shape.
- **An evaluator-implementation change** (how `basis-core` computes an already-defined semantic) requires `basis-core` review and re-validation against canonical conformance (the previous subsection).
- **A `GatewayAuditEvent`/gateway-enforcement-facts change** is owned by `basis-gateway`, with cross-repository compatibility review where it touches the shared fixture family.

Identify the surface, identify its owner from the list above, and follow that owner's process — do not default to requiring sign-off from all four repositories when only one owns the surface being changed.

---

## Breaking changes

The following changes are breaking, regardless of how they are described or motivated. They require the full process described below.

### Schema and fixture surfaces

- Removing or renaming any field in a JSON schema or a contract fixture.
- Changing the type of any field.
- Adding a new required field.
- Removing an enum value.
- Redefining the semantic meaning of an existing enum value (e.g., changing what `"deny"` means in `DecisionOutcome`).
- Tightening a `pattern` constraint so that previously valid values are now rejected.
- Changing `additionalProperties` from `false` to `true`.
- Incrementing `schema_version` on `AuditEvent` without a corresponding doc and fixture update.

### Public API surfaces

- Removing a symbol from any package's `__all__`.
- Renaming a public symbol (class, function, or constant) in the stable public API.
- Changing a public import path so that a previously valid `from basis_core.X import Y` no longer works.
- Changing the signature of a public function or method in an incompatible way (adding required parameters, removing parameters, changing types).
- Removing a field from a public Pydantic model (`DecisionRequest`, `DecisionResponse`, `AuditEvent`, `DecisionTrace`, `RuleEvaluation`).

### Evaluation semantics

- Changing whether DENY short-circuits (it must; removing short-circuit is breaking).
- Changing whether ALLOW short-circuits (it must not; adding short-circuit is breaking).
- Changing the first-ALLOW semantics (the first ALLOW in registration order wins if no DENY).
- Changing how NOT_APPLICABLE is resolved at the enforcement boundary (must remain DENY).
- Changing what exception behavior produces (must remain DENY with `is_error=True`).
- Changing the order in which per-rule evaluation records are collected.

### Enforcement and failure-mode contracts

- Changing any `FailureReason` enum value name or serialized string.
- Changing which failure paths set `failure_reason` (adding or removing cases).
- Changing `EnforcementPoint.evaluate()` so that it can raise.
- Allowing raw exception text to reach the caller in `DecisionResponse.reason`.
- Changing the audit coverage guarantees (e.g., making malformed-request paths write an audit event, or removing audit writes for covered paths).

### Audit immutability and failure behavior

- Making `AuditEvent` mutable (removing `frozen=True`).
- Changing `AuditWriter.write()` so that it may raise and propagate to the enforcement path.
- Changing when `write()` is called relative to the decision being finalized.
- Calling `write()` more than once per evaluation for the same request.

### Extension interface contracts

- Changing the signature of `PolicyRule.evaluate()` in a non-additive way.
- Changing the semantics of any `PolicyOutcome` value.
- Changing the signature of `AuditWriter.write()` in a non-additive way.
- Removing any field or method from `AdapterBase` or changing the semantics of `start()`/`stop()`.
- Changing the `resource_id` or `action` validation patterns so previously valid values are now rejected.

### Action vocabulary and normalization

- Removing or renaming any constant in `basis_core.domain.action`.
- Changing the string value of an action constant (the value appears verbatim in audit records and policies).
- Narrowing or broadening an established action name's scope so that requests that previously matched (or did not match) now behave differently.
- Changing the `NormalizedEvent` field semantics in a way that alters how enforcement points or adapters interpret events.

### Operation-aware surfaces (v0.2.0)

See "Operation-Aware Governed Surfaces (v0.2.0)" above for the full, per-surface classification. Concise cross-cutting examples of likely breaking or governed behavioral changes:

- Removing a public operation-aware symbol from `docs/public-api.md`'s "Operation-aware public API (v0.2.0)" inventory.
- Renaming a serialized field on any operation-aware model.
- Narrowing an operation-aware request or policy-bundle accepted shape (a pattern, an enum, a required/optional flip).
- Changing deny precedence, default-deny behavior, or `NOT_APPLICABLE` semantics for operation-aware evaluation.
- Changing an existing condition operator's meaning, or introducing implicit type coercion into condition comparison.
- Reordering `EvaluationTrace.rule_evidence` where the current ordering is governed (candidate order, then authored condition order).
- Removing matched-but-non-decisive rule evidence from a trace.
- Changing `OperationAwareFailureReason` classification for a case this evaluator already constructs.
- Changing `EnforcementDisposition` mapping.
- Changing required-nullable serialization on any operation-aware response, trace, or audit-evidence field.
- Adding persistence or gateway behavior to the kernel (e.g., a writer for `AuditEvidence`, or a `GatewayAuditEvent` model).
- Changing a canonical scenario's expected output without going through the upstream-first investigation the "Canonical operation-aware scenarios" subsection above requires.

No category above is automatically safe merely because it involves the operation-aware surface rather than the v0.1 surface — the same review, ADR, and migration-path requirements in "Required process for breaking changes" below apply.

---

## Additive changes

The following changes are additive and do not require the breaking-change process. They require a changelog entry and, if they touch a contract fixture, a deliberate fixture update visible in code review.

- Adding a new optional field to any public Pydantic model (with defined absence semantics: consumers that receive a record without the field must not fail).
- Adding a new enum value where consumers are expected to handle unknown values gracefully.
- Adding a new symbol to a package's `__all__` without removing existing symbols.
- Adding a new public import path (alias) while keeping the old path working.
- Adding a new contract fixture for a scenario not previously covered.
- Adding a new policy rule type (`RolePolicyRule`, `ResourceTypePolicyRule`, etc.) without changing existing rule semantics.
- Adding a new `AuditEventType` or `AuditOutcome` value (consumers must tolerate unknown values).
- Adding an optional parameter with a default to `PolicyRule.evaluate()` (does not break existing implementations).
- Adding a new action constant to `basis_core.domain.action`.
- Loosening a schema `pattern` constraint to accept values previously rejected (review the semantic coherence; this is additive but not always safe).

### Operation-aware surfaces (v0.2.0)

Concise cross-cutting examples that may be additive, still subject to compatibility review — see "Operation-Aware Governed Surfaces (v0.2.0)" above for the full, per-surface classification:

- Adding a new public sibling type to the operation-aware family (following the existing `OperationAware*`/unprefixed naming convention in `docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 5).
- Adding a new optional field to an operation-aware model whose absence preserves current behavior.
- Adding a new condition operator to `SUPPORTED_OPERATORS` under an approved architecture/schema clarification process (not a local implementation convenience).
- Adding a new emitted `ReasonCode` value without changing what any existing emitted code means.
- Adding a new canonical scenario while preserving the existing five scenarios' outputs unchanged.
- Adding a new internal helper function with no public or observable effect (internal operation-aware helpers carry no compatibility guarantee at all — see `docs/public-api.md`'s "Internal — not exported" list).

As with the v0.1 examples above, none of these categories is automatically safe. A strict downstream consumer, a policy condition's field-path resolution, or the canonical-conformance suite can all be affected by a change that is additive in the narrow "did not remove or rename anything" sense. Apply the same fixture-visibility and changelog requirements in "Required process for additive changes" below.

---

## Required process for breaking changes

When a proposed change is breaking:

### 1. Identify the affected surfaces

Before writing any code, enumerate every contract surface the change touches. Use the table in [Contract surfaces](#contract-surfaces) as the checklist. A single change can affect multiple surfaces simultaneously (e.g., renaming a field touches the JSON schema, the Python model, the contract fixture, and any audit records that contain the field).

### 2. Raise for architecture review in basis-architecture

Breaking changes to kernel contracts are cross-component compatibility events. Open a discussion or pull request in basis-architecture before applying the change in basis-core. Do not merge a breaking change without documented architecture review. The governing rationale is in `docs/architecture/compatibility-philosophy.md` in basis-architecture.

### 3. File an ADR in basis-architecture

Per `docs/adr/README.md` in basis-architecture, breaking changes require an Architecture Decision Record that documents: what is changing, why, what alternatives were considered, and what the migration path is. The ADR must be accepted before the basis-core change is merged.

### 4. Define the migration path before merge

A breaking change without a defined migration path is not mergeable. The migration path describes how existing consumers, deployed configurations, and stored audit records are handled under the new contract. "We will update all consumers" is not a migration path; "consumers may receive records without field X and must treat absence as Y, with a transition period of Z" is.

### 5. Update the compatibility tests

The failing test is the signal. Contract snapshot tests and backward compatibility tests will fail when a breaking change is introduced. Do not silence these failures before the governance steps (architecture review, ADR, migration path) are complete. Once governance is complete, update the affected fixtures and snapshots deliberately — one commit, visible in code review — and add a changelog entry.

See `docs/compatibility-testing.md` for the update procedure.

### 6. Update documentation

Update every doc that describes the surface being changed. At minimum: the per-surface reference doc (see the table above), `docs/public-api.md` if an API symbol is affected, and this document if a new surface category is introduced.

---

## Required process for additive changes

When a proposed change is additive:

1. Confirm the change satisfies the additive criteria above (new optional field, new enum value, etc.).
2. Update the affected fixture file if the serialized shape changes — make the update visible in code review.
3. Add a changelog entry.
4. Update any affected documentation.
5. No architecture review or ADR is required for purely additive changes.

---

## Signals that a breaking change occurred

The following test failures are diagnostic signals that a contract surface has changed. Before updating any fixture or snapshot, determine whether the change is intentional, review the governance checklist below, and complete the required process.

| Test file | What it signals |
|---|---|
| `test_contract_snapshots.py` | A public model's serialized shape differs from the stored fixture. |
| `test_backward_compatibility.py` | A stored fixture (representing a prior version's output) can no longer be deserialized by the current code. |
| `test_schema_versioning.py` | A JSON schema's required fields, enum values, or structural requirements changed. |
| `test_public_api.py` | A symbol was added to or removed from a package's `__all__`, or an `__all__` diverges from the documented inventory. |
| `test_extension_contracts.py` | An extension interface signature or behavioral contract changed. |
| `test_evaluation_semantics.py` | An evaluation algorithm contract changed. |
| `test_import_boundaries.py` | An import boundary rule was violated. |
| `tests/operation_aware/test_canonical_vectors.py` | One of the five canonical operation-aware scenarios no longer produces the vendored expected `OperationAwareDecisionResponse`/`EvaluationTrace`/`AuditEvidence` shape — see "Canonical operation-aware scenarios" above before touching any fixture. |
| `tests/test_basis_schemas_snapshot*.py` | The vendored `basis-schemas` snapshot's inventory, integrity, or provenance no longer matches what the test suite expects — investigate before re-vendoring. |
| `test_public_api.py` (operation-aware section) | A symbol was added to or removed from the "Operation-aware public API (v0.2.0)" inventory in `docs/public-api.md`, or an operation-aware package `__all__` diverges from it. |

---

## PR checklist

This checklist is reproduced in `.github/pull_request_template.md`. Every pull request that touches a public contract surface must complete it.

**Contract surface impact**

- [ ] I have identified every contract surface this change touches (schemas, fixtures, public API exports, evaluation semantics, enforcement behavior, audit behavior, extension interfaces, action vocabulary, adapter normalization).
- [ ] This change is: ☐ additive only  ☐ breaking  ☐ no contract surface affected.

**If additive**

- [ ] Compatibility tests pass without modification, or fixture updates are deliberate and visible in this PR.
- [ ] Documentation updated.
- [ ] Changelog entry added.

**If breaking**

- [ ] Architecture review opened in basis-architecture before this PR was written.
- [ ] ADR filed and accepted in basis-architecture. ADR reference: ___
- [ ] Migration path defined and documented. Migration path reference: ___
- [ ] Compatibility tests updated deliberately (not silenced) in this PR.
- [ ] Documentation updated in this PR.

---

## Relationship to other documents

This document establishes the process for contract changes. The documents below establish the substance — what the contracts say and why.

| Document | Role |
|---|---|
| `docs/kernel-constitution.md` | Constitutional invariants; Invariant 9 establishes compatibility as a governance obligation |
| `docs/schema-versioning.md` | Schema evolution rules; breaking vs. additive schema changes; open versioning questions |
| `docs/extension-contracts.md` | PolicyRule, AuditWriter, AdapterBase behavioral contracts; breaking-change definitions for interfaces |
| `docs/compatibility-testing.md` | Test harness; what each test failure signals; how to update fixtures deliberately |
| `docs/evaluation-semantics.md` | Evaluation algorithm contract; DENY/ALLOW/NOT_APPLICABLE semantics |
| `docs/enforcement-boundary.md` | Enforcement point guarantees; fail-closed behavior; audit resilience |
| `docs/failure-modes.md` | Concrete failure scenarios and what the library does in each case |
| `docs/audit-model.md` | Audit record model; append-only semantics; AuditWriter protocol |
| `docs/adapter-contracts.md` | Normalization requirements; NormalizedEvent contract |
| `docs/public-api.md` | Public API surface inventory; stable vs. extension vs. internal classification, including the operation-aware (v0.2.0) additions |
| `docs/operation-aware-model.md` | Operation-aware model families, public-vs-internal component classification, v0.1 compatibility table |
| `docs/operation-aware-evaluation-semantics.md` | Operation-aware evaluation pipeline, stage ownership, reason codes actually emitted, canonical conformance |
| `docs/architecture/compatibility-philosophy.md` (basis-architecture) | Governing rationale; why compatibility matters in OT infrastructure |
| `docs/adr/README.md` (basis-architecture) | ADR process; when an ADR is required; lifecycle and numbering |
