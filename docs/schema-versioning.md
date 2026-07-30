# Schema Versioning

This document establishes the minimum safe compatibility discipline for schema evolution in basis-core. It defines which schema changes are breaking, which are additive, and what process is required before a breaking change can proceed.

This is **not** a full migration framework, a schema registry service, or a finalized versioning scheme. It captures the baseline rules that protect external consumers from accidental incompatible schema changes while those larger questions remain open.

Cross-references: `docs/schema-contracts.md` documents the stability rules and open questions for each schema. `docs/architecture/compatibility-philosophy.md` in basis-architecture establishes the governing rationale — this document operationalizes that rationale for the schemas in this repository. `docs/audit-model.md` and `docs/core-domain.md` describe the semantic context these schemas encode. Invariant 9 in `docs/kernel-constitution.md` states the constitutional commitment that makes schema evolution a governance concern rather than a purely local coding decision. `docs/breaking-change-discipline.md` is the unified process document that covers all contract surfaces, including schemas — its own "Operation-Aware Governed Surfaces (v0.2.0)" section is the companion classification to this document's "Operation-Aware Contract Families" section below; the breaking-change process section in that document supersedes the process section in this file where they differ. `docs/operation-aware-model.md` and `docs/operation-aware-evaluation-semantics.md` describe the operation-aware models this document's operation-aware sections version.

This document covers both the four v0.1 JSON-Schema-backed contracts in `schemas/` and, in its own dedicated sections below, the operation-aware (v0.2.0) serialized artifacts. The two families are versioned under the same rules stated here; the operation-aware sections apply those rules rather than introducing a separate, conflicting policy.

---

## What these rules protect

The four schemas in `schemas/` define external compatibility contracts:

| Schema | File | External consumers |
|---|---|---|
| DecisionRequest | `schemas/decision-request.schema.json` | Gateways, adapters, enforcement points submitting requests |
| DecisionResponse | `schemas/decision-response.schema.json` | Callers reading authorization decisions |
| AuditEvent | `schemas/audit-event.schema.json` | Audit pipeline, compliance reporters, forensic tools, stored records |
| Policy | `schemas/policy.schema.json` | Policy authoring systems, configuration loaders |

Changes to these schemas are felt by all consumers simultaneously. For `AuditEvent`, changes are also felt _retroactively_: stored records carry no mechanism for post-hoc field addition or renaming. A field rename produces a structural discontinuity in the audit record that no documentation fully resolves.

---

## Schema structure requirements

Every schema in `schemas/` must include the following top-level fields:

- `$schema` — declares the JSON Schema draft in use
- `$id` — opaque namespace identifier (see open questions)
- `title` — human-readable schema name
- `type` — the JSON type of the root object
- `additionalProperties: false` — the schema surface is explicit; unknown fields are rejected

`additionalProperties: false` is intentional. It ensures that every field that crosses the kernel boundary is declared explicitly, and that accidental or undeclared extension is caught at validation time rather than silently passed through.

The `tests/test_schema_versioning.py` test suite verifies these structural requirements and the required-field and enum snapshots described below.

---

## Breaking changes

The following changes to any schema in `schemas/` are breaking. They require architecture review and, except in unusual circumstances, an ADR in basis-architecture before proceeding.

**Field removal** — Removing a required or optional field that consumers depend on is always breaking. Required fields encode invariants; optional fields encode behaviors that consumers may have adopted.

**Field renaming** — Renaming a field is a breaking change to every consumer that references the old name, regardless of how the rename is documented. Audit records containing the old name are structurally incompatible with tooling that expects the new name.

**Field semantic change** — Changing what a field means — redefining `evaluated_by` from "rule that produced the decision" to "rule that was first evaluated," for example — is a breaking change even if the field name and type are unchanged. Semantic changes produce audit records that look correct but are not.

**Required field addition** — Adding a new required field breaks every producer that does not know about the new field. This is only safe if a compatibility default exists and all producers can be updated simultaneously — conditions that are rarely met in field deployments.

**Enum value removal** — Removing an enum value is breaking. Any record or payload that carried the removed value is now invalid against the new schema, and any consumer that handled the value by name is broken.

**Enum semantic redefinition** — Changing what an existing enum value means is breaking. The enum string `"denied"` must mean the same thing in every schema version.

**Pattern tightening** — Narrowing a `pattern` constraint to reject values that the prior pattern accepted is breaking. Any record or payload produced under the prior constraint may now fail validation.

**`additionalProperties` from `false` to `true`** — This loosens the contract: payloads that were previously rejected are now accepted. Consumers that rely on the strict rejection invariant are broken by this change.

---

## Additive changes

The following changes are generally additive and do not require a breaking-change review. They should still be accompanied by a changelog entry.

**New optional field** — Adding a field with defined absence semantics (consumers that receive a record without the field must not fail) is additive, provided the field is not required and the schema continues to accept payloads without it.

**New enum value** — Adding an enum value is additive, provided consumers that encounter an unrecognized value can handle it gracefully. Forward compatibility — tolerating unknown enum values without failure — is the producer's responsibility to design for and the consumer's responsibility to implement.

**Pattern loosening** — Accepting values that were previously rejected is loosening, which is additive in the sense that it does not break existing producers. However, loosening can weaken invariants that consumers rely on. Review whether the loosened pattern expands the accepted vocabulary in ways that are semantically coherent before treating it as purely additive.

---

## Schema version fields

### `AuditEvent.schema_version`

`AuditEvent` carries a `schema_version` field that identifies the schema revision in effect when the record was written. The current value is `"1.1"`. Consumers use this field to determine which optional fields are present in a record.

`schema_version` must always be populated when writing an `AuditEvent`. A record without `schema_version` is ambiguous for consumers that need to handle records from multiple schema revisions.

### Schema-level version annotation (open question)

The schemas themselves do not currently carry a version annotation (distinct from `AuditEvent.schema_version`). There is no mechanism for a tooling consumer to determine which revision of `decision-request.schema.json` is in use without inspecting the repository.

This is tracked as an open question below.

---

## Examples must stay valid

The `schemas/examples/` directory contains schema-valid reference examples for each schema. These files are validated by the test suite (`tests/test_schema_versioning.py` and `tests/test_schema_validation.py`) without modification.

Any schema change that causes a canonical example to fail validation is a signal that either the schema change is breaking, or the example needs to be updated to reflect the new schema's intended usage. Updating examples is not a substitute for documenting a breaking change.

---

## Breaking change process

When a breaking schema change is necessary:

1. **Raise for architecture review.** Breaking schema changes are cross-component compatibility events. They must be reviewed in basis-architecture before being applied in basis-core. Do not make breaking changes to `schemas/` without a corresponding architectural decision.

2. **File an ADR.** Per `docs/adr/README.md` in basis-architecture, a change that affects a compatibility surface requires an ADR documenting the rationale, the alternatives considered, and the migration path.

3. **Define the migration path before deploying.** A breaking schema change without a defined migration path is not deployable in an ecosystem where components update at different speeds. The migration path — how existing consumers and stored records are handled under the new schema — must be specified before the change is merged.

4. **Update the test snapshots deliberately.** The required-field and enum snapshots in `tests/test_schema_versioning.py` will need to be updated for a breaking change. This is intentional: the test failure is the signal. Update the snapshots as part of the breaking change, not as a cleanup step.

---

## Open questions

The following questions remain deliberately unresolved. They are tracked here and in basis-architecture to prevent accidental resolution through implementation choices.

### Schema `$id` namespace

All four schemas use `$id` values of the form `https://basis-core/schemas/{name}.schema.json`. This is not a resolvable URL — `basis-core` is not a registered domain. These values function as opaque namespace identifiers for JSON Schema tooling.

**Open question**: Should the `$id` values migrate to a stable, resolvable namespace such as `https://schemas.basis-foundation.org/core/v1/{name}.schema.json`?

`$id` migration would affect any tooling or schema that uses `$ref` pointers to these identifiers. It should happen once, before external consumers establish dependencies on the current placeholder values. **Do not change the `$id` values in this repository** until the canonical schema registry question is resolved in basis-architecture. Track this as `OPEN: schema-id-namespace`.

### Schema-level version annotation

The schemas do not carry a version annotation that lets a tooling consumer identify which schema revision is in use. `AuditEvent.schema_version` covers the record-level case; there is no equivalent for the schema files themselves.

**Open question**: Should a `version` or `x-schema-version` annotation be added to the schema files?

This is not urgent while schemas are pre-1.0. It becomes important once external consumers begin pinning to specific schema revisions. Track this as `OPEN: schema-file-version-annotation`.

### Semantic versioning operationalization

The basis-architecture compatibility philosophy describes how semantic versioning should work conceptually (major = breaking, minor = additive, patch = correction). The schemas in this repository do not yet carry version numbers, and there is no defined process for incrementing them when changes are made.

**Open question**: How are schema versions operationalized — how are they incremented, communicated, and enforced across the ecosystem?

This is not yet a blocking concern for basis-core while the ecosystem is pre-release. Track this as `OPEN: schema-semver-operationalization`.

### `AuditEvent.subject_type` model/schema alignment

The `audit-event.schema.json` restricts `subject_type` to the enum `[human, device, service, gateway, agent, null]`. The `AuditEvent` Python model accepts any string to remain forward-compatible with subject types not yet listed in the schema.

**Open question**: Should the model be tightened to mirror the schema enum, or should the schema be loosened to `type: ["string", "null"]` to match the model's open-string behavior?

See `docs/schema-contracts.md` for the full discussion. Track this as `OPEN: audit-subject-type-alignment`.

---

## Operation-Aware Contract Families (v0.2.0)

This section extends the rules above to the operation-aware serialized artifacts merged for v0.2.0. It does not create a second versioning policy — "Breaking changes," "Additive changes," and the general discipline above apply to these artifacts exactly as they apply to the four v0.1 schemas; this section identifies the artifacts, states which of them carry an explicit `schema_version` field, and adds the operation-aware-specific detail the brief-level rules above don't spell out.

The governed operation-aware serialized families, matched to their actual current implementation (`docs/breaking-change-discipline.md`'s "Operation-Aware Governed Surfaces" section is the companion compatibility classification for the same list):

| Family | Models |
|---|---|
| Request | `OperationAwareDecisionRequest` and its six context objects (`OperationAwareLocation`, `OperationAwareDevice`, `OperationAwareProtocolContext`, `OperationAwareSafetyContext`, `OperationAwareEnvironmentContext`, `OperationAwareRiskContext`) |
| Policy condition, rule, match, scope, and bundle | `PolicyCondition`, `OperationAwarePolicyRule`, `OperationAwarePolicyMatch`, `PolicyBundleScope`, `PolicyBundle` |
| Trace condition and rule evidence | `TraceConditionEvidence`, `TraceRuleEvidence` |
| Evaluation trace | `EvaluationTrace` |
| Decision response | `OperationAwareDecisionResponse` (internal — see `docs/public-api.md`) |
| Audit evidence | `AuditEvidence` |
| Shared vocabularies and evidence references | `RedactionClassification`, `ReasonCode`, `EvidenceDigest`, `IdentityEvidenceReference`, `AdapterEvidenceReference` |

### Which artifacts carry an explicit `schema_version` field

Inspected directly against the merged implementation — do not assume a model has a version field merely because it is part of a governed family:

| Model | Carries `schema_version`? | Detail |
|---|---|---|
| `PolicyBundle` | **Yes** — required, no default | `MAJOR.MINOR.PATCH` pattern (`src/basis_core/policy/operation_aware/bundle.py`). Identifies the `policy-bundle` contract *shape* a given bundle instance was authored against — distinct from `PolicyBundle.bundle_version` (the bundle's own content version) and never compared against the installed `basis-schemas` package version. |
| `AuditEvidence` | **Yes** — defaults to `AUDIT_EVIDENCE_SCHEMA_VERSION` | Currently `"0.1.0"`, semver-pattern validated (`src/basis_core/audit/operation_aware/audit_evidence.py`). Exported as `basis_core.audit.AUDIT_EVIDENCE_SCHEMA_VERSION`. |
| `OperationAwareDecisionRequest` | No | Relies on model/package compatibility — the field set and `docs/public-api.md`'s inventory are the compatibility surface, not a runtime version token on the instance itself. |
| `EvaluationTrace` | No | Same as above. |
| `TraceRuleEvidence` / `TraceConditionEvidence` | No | Same as above. |
| `OperationAwareDecisionResponse` | No | Same as above; also internal (not re-exported — see `docs/public-api.md`). |
| `PolicyCondition` / `OperationAwarePolicyRule` / `OperationAwarePolicyMatch` / `PolicyBundleScope` | No | Versioned as part of the `PolicyBundle` they are nested in, via `PolicyBundle.schema_version`; they carry no independent version field of their own. |
| `RedactionClassification` / `ReasonCode` / `EvidenceDigest` / `IdentityEvidenceReference` / `AdapterEvidenceReference` | No | Same as `OperationAwareDecisionRequest` — model/package compatibility only. |

Do not invent a version field for a model that does not have one. A model without `schema_version` is versioned by the same mechanism the v0.1 `DecisionRequest`/`DecisionResponse`/`Policy` schemas already use today: field-level compatibility discipline (this document's "Breaking changes"/"Additive changes" rules) plus the public API inventory in `docs/public-api.md`, not a value carried on the instance.

### Upstream snapshot version versus runtime version

Five separate version domains exist. Changing one does not automatically change any other:

1. **The `basis-schemas` release snapshot vendored for test conformance** — currently `v0.2.2` (commit `da7832972dad36dea6ef2796161a1990fbbe6a05`), tracked as `SNAPSHOT_RELEASE` in `tests/helpers/basis_schemas_snapshot.py`. This identifies which upstream `basis-schemas` tag the vendored fixtures under `tests/fixtures/basis-schemas/` were copied from.
2. **Individual contract versions contained in those YAML contracts** — each of the fourteen vendored contract files carries its own version metadata as part of its upstream `contract:` block; that metadata is `basis-schemas`' own, not renumbered or reinterpreted by this repository.
3. **Model-level `schema_version` fields, where implemented** — `PolicyBundle.schema_version` (author-supplied, `MAJOR.MINOR.PATCH`) and `AuditEvidence.schema_version` (defaults to `AUDIT_EVIDENCE_SCHEMA_VERSION = "0.1.0"`). See the table above for which models have one.
4. **The `basis-core` package version** — `0.1.0` in `pyproject.toml` today. Vendoring `basis-schemas` v0.2.2, or adding new operation-aware models, does not itself change this. Only PR 44 (Milestone 14) changes it, per `docs/implementation/basis-core-v0.2-operation-aware-plan.md`.
5. **v0.1 `AuditEvent.schema_version`** — currently `"1.1"` (`AUDIT_SCHEMA_VERSION`). Wholly unrelated to `AuditEvidence.schema_version`; these are two different models in two different families with two different version tracks that happen to share a field name.

For example: vendoring `basis-schemas` v0.2.2 (domain 1) did not change `basis-core`'s package version (domain 4), did not change `PolicyBundle.schema_version` or `AuditEvidence.schema_version`'s currently-in-use values (domain 3), and did not touch `AuditEvent.schema_version` (domain 5) at all. Treat these as five independently-governed numbers, not as facets of one version.

### Vendored snapshot governance

The vendored `basis-schemas` compatibility fixtures live at:

```text
tests/fixtures/basis-schemas/v0.2.0/
tests/fixtures/basis-schemas/v0.2.1/
tests/fixtures/basis-schemas/v0.2.2/
```

`v0.2.2` is the active snapshot (`SNAPSHOT_RELEASE` in `tests/helpers/basis_schemas_snapshot.py`); `v0.2.0` and `v0.2.1` remain immutable historical snapshots, kept on disk for reference and never modified. Governance rules, stated in full in `docs/compatibility-testing.md`'s "Operation-aware `basis-schemas` fixture snapshot" section and in each snapshot directory's own `README.md` (not repeated here):

- historical snapshots are immutable — never hand-edited, never deleted;
- the active snapshot pointer is one explicit constant (`SNAPSHOT_RELEASE`), not inferred from directory contents;
- snapshot updates happen only through `scripts/update_basis_schemas_snapshot.py`, a deliberate, reviewed PR — never a hand patch to vendored files;
- source tag, commit, and per-file SHA-256 integrity are recorded in each snapshot's manifest and `PROVENANCE.md`;
- a snapshot update must rerun both the canonical-vector suite (`tests/operation_aware/test_canonical_vectors.py`) and the contract/scenario-inventory and integrity suites (`tests/test_basis_schemas_snapshot*.py`) before merge;
- changing the active snapshot is governed the same way a dependency version bump is governed — a visible, reviewable diff, not a silent refresh — even though `basis-schemas` is never an actual runtime or test-time package dependency (it is copied, not installed; see `docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 4).

### Additive and breaking shape changes (operation-aware)

The general rules in "Breaking changes" and "Additive changes" above apply verbatim to every model in the family table. Restated against operation-aware specifics, and see `docs/breaking-change-discipline.md`'s "Operation-Aware Governed Surfaces" section for concrete per-surface examples:

- adding an optional field — additive, provided absence semantics are defined and consumers that omit it are unaffected;
- adding a required field — breaking, for the same reason it is breaking on the v0.1 schemas: every producer that does not know about the field is now non-conformant;
- removing or renaming a field — breaking;
- narrowing a pattern (e.g. `ReasonCode`'s format, `PolicyCondition.field_path`/`operator`'s structural patterns, the open-identifier pattern shared by `resource_type`/`authority_mode`/`device_class`/`protocol_context.protocol`) — breaking;
- widening an enum (adding a member to a closed vocabulary) — additive for producers, potentially breaking for an exhaustive consumer (see "Open Versus Closed Vocabularies" below);
- changing what an existing enum member means — breaking, regardless of whether the member's name or the field's type changed;
- changing required-nullable behavior (a field's presence-with-`null` versus absence) — breaking; see the dedicated subsection below;
- changing unknown-field rejection (every operation-aware model uses `extra="forbid"` today) — breaking if loosened to accept unknown fields;
- changing ordering guarantees where ordering is governed (`EvaluationTrace.rule_evidence`'s candidate-then-authored-condition order) — breaking;
- changing a nested-object shape (any of the six context objects, `OperationAwarePolicyMatch`, `PolicyBundleScope`) — governed by the same field-level rules as a top-level model;
- changing reason-code or operator semantics without changing their format/pattern — still breaking, because the *shape* staying the same does not mean the *behavior* it triggers stayed the same;
- changing a cross-artifact agreement invariant (the response/trace/audit-evidence agreement fields in `docs/operation-aware-evaluation-semantics.md` Section 9) — breaking.

**A shape change and a semantic change are different dimensions.** A YAML/JSON shape can stay byte-identical while the behavior it produces changes — for example, if `aggregate_policy_outcome` started emitting `deny_rule_matched` under a different condition than it does today, no field, pattern, or enum would need to change for that to be a breaking behavioral change. Conversely, a field can be added (additive by the shape rules above) while still requiring compatibility review because a strict consumer or a condition field-path resolution depends on the field set being exactly what it was. Classify shape and semantics independently; do not assume one dimension being additive implies the other is too.

### Required-Nullable Fields

The v0.1 rule already established by this document's governing rationale — a field can be **absent**, **present with `null`**, or **present with a value**, and these are three distinct, independently governed states — applies to the operation-aware response, trace, and audit-evidence models. Concretely:

- `OperationAwareDecisionResponse`/`EvaluationTrace`/`AuditEvidence`'s `outcome`/`failure_reason` pair is a required-nullable pair by construction: `outcome` is required-nullable (must be present, `null` only when `evaluation_status=failed`) and `failure_reason` is required-nullable (must be present, `null` only when `evaluation_status=completed`) — see `docs/operation-aware-evaluation-semantics.md` Section 6. Serializers must not omit either field merely because its value is `None` for a given evaluation.
- `TraceRuleEvidence`'s `reason_code`/`explanation` pair is nullable by the governed rationale-projection rule (`docs/operation-aware-evaluation-semantics.md` Section 8): both are `null` for `not_matched`/`skipped`/`error` results, and both are present when the rule's `rule_result` is `matched` and the rule author supplied them. This is a *projection* rule, not a general "omit when absent" rule — the field itself must still be present (as `null` or as a value) in the serialized shape.
- `OperationAwareDecisionResponse.reason_code`/`correlation_id` follow the same must-agree-when-both-non-null rule stated in `docs/operation-aware-evaluation-semantics.md` Section 9, rather than an absence rule.

**This rule does not apply to every optional field.** A genuinely optional field with no required-nullable invariant attached to it (e.g. `OperationAwareDecisionRequest.location`, or any of the other five context objects) may be legitimately absent from a serialized payload with no `null` placeholder required. Consult the specific model's field documentation (`docs/operation-aware-model.md` Section 3) before assuming a required-nullable rule applies — the distinction is per-field, not a package-wide default.

### Open Versus Closed Vocabularies

**Closed vocabularies** (confirmed against the current implementation — each is a `(str, Enum)` subclass with a fixed member set):

| Vocabulary | Members |
|---|---|
| `OperationIntent` | `read_only`, `state_changing`, `control_affecting` |
| `RuleEffect` | `allow`, `deny` |
| `OperationAwareEvaluationStatus` / `EvaluationStatus` | `completed`, `failed` |
| `OperationAwareDecisionOutcome` / `TraceOutcome` | `allow`, `deny`, `not_applicable` |
| `OperationAwareFailureReason` / `TraceFailureReason` | six members: `invalid_request`, `unsupported_schema_version`, `invalid_policy_bundle`, `policy_validation_failure`, `condition_evaluation_error`, `internal_evaluation_error` |
| `RuleResult` | `matched`, `not_matched`, `skipped`, `error` |
| `TraceConditionResult` | `matched`, `not_matched`, `error` |
| `TraceRuleEffect` | `allow`, `deny` (trace's own local copy, parity-tested against `RuleEffect`) |
| `TraceBundleApplicability` | `applicable`, `not_applicable` |
| `EnforcementDisposition` | `allow`, `deny` |
| `RedactionClassification` | `safe_to_expose`, `safe_after_redaction`, `reference_only`, `never_store`, `never_display` |

**Open validated vocabularies** — format/pattern-validated but not closed to a fixed member set:

| Field | Validation |
|---|---|
| `ReasonCode` | `^[a-z][a-z0-9]*(_[a-z0-9]+)*$` — structural format only; only four values are currently emitted by `aggregate_policy_outcome` (`allow_rule_matched`, `deny_rule_matched`, `no_allow_rule_matched`, `no_applicable_bundle`), but the type itself does not close the vocabulary. |
| `OperationAwareDecisionRequest.authority_mode`, `.resource_type`; `OperationAwareDevice.device_class`; `OperationAwareProtocolContext.protocol` | the contract's shared `open_identifier_pattern`, non-empty when present — an open, provider/protocol-neutral label pattern, not a closed enum. |
| `OperationAwareDecisionRequest.identity_source` | non-empty-when-present only; no pattern beyond that. |
| `PolicyCondition.field_path` | `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$` — structurally well-formed dotted path; does not enumerate which paths this kernel version actually resolves. |
| `PolicyCondition.operator` | `^[a-z][a-z0-9]*(_[a-z0-9]+)*$` — structurally well-formed identifier; does not enumerate which operators this kernel version actually implements (`SUPPORTED_OPERATORS` is the separate, internal, closed-in-practice-but-not-in-the-type ten-operator implementation registry — `docs/operation-aware-evaluation-semantics.md` Section 4). |

Versioning consequences:

- adding a value to a closed enum may be additive for producers but breaking for a consumer that exhaustively matches on every member (an exhaustiveness check that does not account for unknown values will fail closed or throw on the new member — review both directions before treating an enum addition as risk-free);
- changing an existing enum value's name or meaning is breaking, full stop;
- narrowing an open pattern (`ReasonCode`, the open-identifier pattern, `field_path`, `operator`) is potentially breaking — any previously-valid instance in a stored bundle, request, or evidence record may become invalid;
- adding a new emitted value to an open vocabulary (a new `ReasonCode` the evaluator constructs, or a newly-supported `operator`) still requires behavioral and consumer review even though the type-level pattern does not change — the type staying the same says nothing about whether the new value is used correctly or expected by every consumer.

### Semantic Versioning and Package Release

The operation-aware expansion is additive to the v0.1 public surface (per `docs/breaking-change-discipline.md` and `docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 5's semantic-versioning-expectations subsection) but substantial enough to be released as `basis-core` v0.2.0 rather than a patch release, mirroring the precedent `basis-schemas` itself set for its own purely-additive fourteen-contract expansion. This is a naming/communication choice about release cadence, not a claim that anything breaking occurred. **This PR does not perform the version bump.** `pyproject.toml`'s `version` field and `src/basis_core/__init__.py`'s `__version__` remain `0.1.0`; PR 44 (Milestone 14) is the single roadmap PR that changes them, per `docs/implementation/basis-core-v0.2-operation-aware-plan.md`. No release notes are written here either — that is also PR 43/44 scope.

### Gateway Audit Event Boundary

`GatewayAuditEvent` is represented in the upstream `basis-schemas` compatibility fixture family — each canonical scenario directory vendors an `expected-gateway-audit-event.yaml` — but it is **not a `basis-core` runtime schema**. No `GatewayAuditEvent` Python model exists anywhere in `src/basis_core/`, and none of the runtime schema-versioning rules in this document (schema families, `schema_version` fields, snapshot governance, required-nullable rules) apply to it, because there is no `basis-core`-owned artifact for them to apply to. Its schema evolution is owned outside the kernel, per `basis-architecture` ADR-0003 §9 and `docs/breaking-change-discipline.md`'s "Classification of the fourteen upstream contract surfaces" section. `basis-core` may inventory the vendored `expected-gateway-audit-event.yaml` file as part of keeping the fixture family complete for cross-repository compatibility, but its canonical conformance tests (`tests/operation_aware/test_canonical_vectors.py`) do not assert against it, and it must never appear in a list of kernel-produced schemas in this document or any other.

---

## Relationship to other documents

This document establishes the what and when of schema change discipline. For the why, see `docs/architecture/compatibility-philosophy.md` in basis-architecture — the governing rationale is documented there.

For the current state of each schema's stability, known model/schema misalignments, and open compatibility questions, see `docs/schema-contracts.md`.

For the evaluation semantics that the schemas encode, see `docs/evaluation-semantics.md`. Changes to evaluation semantics that require schema changes are doubly breaking: they affect both the behavioral contract and the data contract simultaneously.

For the operation-aware (v0.2.0) contract families versioned in this document's "Operation-Aware Contract Families" section, see `docs/breaking-change-discipline.md`'s companion "Operation-Aware Governed Surfaces (v0.2.0)" section for the compatibility classification, `docs/operation-aware-model.md` for the model inventory, and `docs/operation-aware-evaluation-semantics.md` for the evaluation semantics those models encode.
