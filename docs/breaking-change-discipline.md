# Breaking-Change Discipline

This document is the single reference for how public contract changes in basis-core are classified, governed, and executed. It covers every contract surface the kernel exposes to external consumers. Per-surface documents (listed below) provide deeper detail; this document provides the unified process.

Cross-references: `docs/kernel-constitution.md` Invariant 9 states the constitutional commitment. `docs/schema-versioning.md` details schema-specific rules. `docs/extension-contracts.md` details interface behavioral rules. `docs/compatibility-testing.md` describes the test harness and how test failures signal a contract change. `docs/public-api.md` inventories the stable public API surface. `docs/architecture/compatibility-philosophy.md` in basis-architecture is the governing architectural rationale.

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

If you are unsure whether something you are changing is on this list, assume it is.

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
| `docs/public-api.md` | Public API surface inventory; stable vs. extension vs. internal classification |
| `docs/architecture/compatibility-philosophy.md` (basis-architecture) | Governing rationale; why compatibility matters in OT infrastructure |
| `docs/adr/README.md` (basis-architecture) | ADR process; when an ADR is required; lifecycle and numbering |
