# Compatibility Testing

This document describes the backward compatibility and contract snapshot testing harness for basis-core. The harness provides executable regression protection for the public kernel contracts — the serialized shapes and behavioral contracts that external consumers depend on.

Cross-references: `docs/schema-versioning.md` defines what counts as a breaking vs. additive change. `docs/kernel-constitution.md` Invariant 9 establishes why compatibility is a governance concern. `docs/extension-contracts.md` documents the behavioral contracts the tests enforce. `docs/breaking-change-discipline.md` defines the unified process for classifying and executing contract changes across all surfaces — including what a test failure here signals and what governance steps must complete before a fixture may be updated.

---

## What the harness protects

The public kernel contracts that have external consumers are:

| Contract | Coverage |
|---|---|
| `DecisionRequest` serialization shape | `test_contract_snapshots.py`, `test_backward_compatibility.py` |
| `DecisionResponse` serialization shape | `test_contract_snapshots.py`, `test_backward_compatibility.py` |
| `AuditEvent` serialization shape | `test_contract_snapshots.py`, `test_backward_compatibility.py` |
| `DecisionTrace` serialization shape | `test_contract_snapshots.py`, `test_backward_compatibility.py` |
| JSON Schema structural requirements | `test_schema_versioning.py` |
| JSON Schema required fields (snapshot) | `test_schema_versioning.py` |
| JSON Schema enum values (snapshot) | `test_schema_versioning.py` |
| Schema example file validity | `test_schema_validation.py`, `test_schema_versioning.py` |
| Model-to-schema alignment | `test_schema_validation.py` |
| Evaluation semantics behavioral contract | `test_evaluation_semantics.py` |
| Extension interface contracts | `test_extension_contracts.py` |

The harness deliberately does not snapshot internal implementation details — function call counts, internal state, or algorithm internals that are not part of the external contract.

---

## File structure

```
tests/
  fixtures/
    contracts/                   Stable JSON fixtures for contract snapshot tests
      decision_request.allow.json
      decision_request.deny.json
      decision_response.allow.json
      decision_response.deny.json
      decision_response.fail_closed.json
      audit_event.allow.json
      audit_event.deny.json
      evaluation_trace.allow.json
      evaluation_trace.deny.json
  helpers/
    contracts.py                 Fixture loading, normalization, and comparison utilities
  test_contract_snapshots.py     Model serialization shape vs. stored fixtures
  test_backward_compatibility.py Old records → current schemas and models
  test_schema_versioning.py      Schema structure and enum/field snapshots
  test_schema_validation.py      Payload validation and model-to-schema alignment
  test_evaluation_semantics.py   Evaluation algorithm behavioral contract
  test_extension_contracts.py    PolicyRule, AuditWriter, AdapterBase contracts
```

---

## Two test categories

### Contract snapshot tests (`test_contract_snapshots.py`)

Snapshot tests construct model instances with fully deterministic values, serialize them, and compare the result against stored JSON fixtures in `tests/fixtures/contracts/`. If the serialized shape of a model differs from the stored fixture — a field renamed, a type serialized differently, a field added or removed — the test fails with a field-level diff.

These tests catch drift between the model code and the declared contract. They are the first line of defence against accidental breaking changes.

### Backward compatibility tests (`test_backward_compatibility.py`)

Backward compatibility tests work in the opposite direction: they load stored JSON fixtures (representing records produced by earlier versions of the code) and verify that the current code can still process them.

Three guarantees are tested for each fixture:

**Schema validity.** The stored fixture is still valid against the current JSON Schema. If schema evolution has made a previously-valid record invalid, this test fails. (Requires `jsonschema`; skipped otherwise.)

**Model deserialization.** `Model.model_validate(fixture)` succeeds without error. If a required field was removed or renamed, deserialization fails with a validation error.

**Round-trip stability.** Deserializing the fixture and re-serializing produces JSON that preserves the semantically critical fields. Silent coercion — where a field value is quietly transformed on load — is caught here.

Additionally, the `schemas/examples/` canonical examples are tested for round-trip stability through the Python models. These are the reference examples shipped with the schemas; their ability to round-trip is a primary consumer guarantee.

---

## Fixtures

The fixtures in `tests/fixtures/contracts/` are stable JSON files that represent the expected serialized shape of each public model. They use fixed values shared with `schemas/examples/`:

- `request_id` (allow): `a1b2c3d4-0001-0000-0000-000000000001`
- `request_id` (deny): `a1b2c3d4-0002-0000-0000-000000000002`
- `subject_id`: `a7b8c9d0-1234-5678-abcd-ef0123456789`
- `event_id` (allow): `e1000000-0000-0000-0000-000000000001`
- `event_id` (deny): `e1000000-0000-0000-0000-000000000002`
- `timestamp`: `2026-05-22T14:30:00Z`
- `schema_version`: `1.1`

The `evaluation_trace` fixtures represent two canonical evaluation shapes: an allow outcome where ALLOW did not short-circuit (two rules evaluated: one allow, one not_applicable), and a deny outcome where DENY short-circuited after the first rule because a second rule was registered but never called. Note that `short_circuited` is not simply True for every DENY — it is True only when `len(evaluated_rules) < total rules registered`. If the denying rule is the last (or only) registered rule, `short_circuited` is False.

The `decision_response.fail_closed` fixture captures the distinct shape of an enforcement boundary failure: `outcome="deny"` with a non-null `failure_reason`. This is structurally different from `decision_response.deny` (a policy-produced refusal) because consumers use `failure_reason` to distinguish enforcement failures from normal policy decisions. `failure_reason` serializes as a plain lowercase string (e.g., `"policy_error"`, not `"POLICY_ERROR"`); this value is a contract.

---

## Running the harness

Run all compatibility and contract tests:

```bash
pytest tests/test_contract_snapshots.py tests/test_backward_compatibility.py -v
```

Run the full test suite including schema and extension contract coverage:

```bash
pytest -v
```

The backward compatibility schema-validation tests require `jsonschema`:

```bash
pip install "jsonschema[format-nongpl]>=4.18"
```

If `jsonschema` is not installed, the schema-validation tests are skipped with an informative message. All model deserialization and round-trip tests run regardless.

---

## Helpers

`tests/helpers/contracts.py` provides three utilities used by the test files:

**`load_fixture(name)`** — loads a fixture JSON file by stem name (e.g., `"decision_request.allow"`). Raises `FileNotFoundError` if the fixture does not exist.

**`assert_matches_fixture(model, fixture_name)`** — serializes a model instance and compares it against a stored fixture. Fails with a field-level diff listing each field that differs. This is the primary assertion in `test_contract_snapshots.py`.

**`normalize(data)`** — converts a dict or JSON string to a canonical sorted-key JSON string. Used internally to make comparisons insensitive to key insertion order.

---

## What a test failure means

### In `test_contract_snapshots.py`

A snapshot test failure means the serialized shape of a model no longer matches the stored fixture. Before updating the fixture, determine whether the change is:

**Additive** — a new optional field with defined absence semantics, or a new enum value. Update the fixture to include the new field or value. Add a changelog entry. No architecture review or ADR is required, but the fixture commit must be visible in code review so that the contract change is explicit.

**Breaking** — any of the following require architecture review in basis-architecture and an ADR before the fixture may be updated:
- Field renamed or removed
- Field type changed (including serialization format changes)
- Required field added
- Enum value removed or semantically redefined
- `failure_reason` string value changed

The failing test is the signal that the breaking change has occurred. It must not be silenced until the governance steps — architecture review, ADR, defined migration path — are complete per `docs/schema-versioning.md`.

### In `test_backward_compatibility.py`

A backward compatibility failure means a stored fixture — representing a record that was previously valid — can no longer be processed by the current code. This is evidence of a breaking change regardless of how it was introduced. The fixture may only be retired (not merely updated) after confirming that no production records carry the old shape, or that a migration path exists.

---

## Updating fixtures deliberately

When you have made an intentional, reviewed change and need to update a fixture:

1. Run the failing test to see the exact field diff.
2. Confirm the change is additive and has been reviewed.
3. Update the fixture file manually in `tests/fixtures/contracts/`.
4. Re-run the tests to confirm they pass.
5. Commit the fixture change alongside the model change so the diff is visible in code review.
6. Add a changelog entry for the additive change.

For breaking changes, complete the process in `docs/schema-versioning.md` — architecture review, ADR, defined migration path — before updating any fixture.

The `TestFixtureInventory` test in `test_contract_snapshots.py` also enforces that the fixture set is exactly the expected set. If you add a new fixture file, update the `EXPECTED_FIXTURES` frozenset in that test class.

---

## Relationship to other test files

This harness complements rather than replaces the existing test suite:

`test_schema_versioning.py` — tests JSON Schema *structure* (required fields, enum values, structural requirements). The compatibility harness tests model *instances* (serialized Python objects). Both are needed.

`test_schema_validation.py` — tests that known-valid payloads pass schema validation and known-invalid ones fail. The compatibility harness tests that stored records survive round-trips. Both are needed.

`test_evaluation_semantics.py` — tests the DENY/ALLOW/NOT_APPLICABLE evaluation algorithm in detail. The compatibility harness captures the *serialized shape* of evaluation traces but does not re-test the algorithm.

`test_extension_contracts.py` — tests the behavioral contracts of the extension interfaces. The compatibility harness captures the serialized representation of the records those interfaces produce.

Extension interface method names (`AuditWriter.write`, `PolicyRule.evaluate`, `AdapterBase.start`/`stop`) are not protected by JSON snapshots — they are protected by the `isinstance` checks in `test_extension_contracts.py`. Because `AuditWriter`, `PolicyRule`, and `AdapterBase` are `@runtime_checkable` Protocols, renaming a method on the Protocol causes existing implementations to fail the `isinstance` check in that file. This is the correct protection mechanism: interface contracts are behavioral, not serialized.
