# `tests/operation_aware/`

This directory holds tests for the **additive** `basis-core` v0.2.0
operation-aware surface (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`). It is a
dedicated subpackage, distinct from the repository's existing flat
`tests/*.py` convention, because the operation-aware surface is large enough
(models, policy, trace, audit, evaluator) to warrant its own namespace.

Existing v0.1.0 tests are unaffected and remain exactly where they are —
`tests/test_models.py`, `tests/test_policy_engine.py`,
`tests/test_evaluation_semantics.py`, and the rest of the flat `tests/*.py`
modules are not moved, renamed, or duplicated here.

## Scope boundaries

- **Contracts are owned by `basis-schemas`, not redefined here.** Tests in
  this package validate that `basis-core` behavior matches the pinned
  `basis-schemas` v0.2.0 contracts; they must never restate, fork, or
  loosen a contract's shape.
- **Vendored contracts and compatibility scenarios live in the pinned
  fixture tree**, `tests/fixtures/basis-schemas/v0.2.0/` (see that
  directory's own `README.md`). Tests here consume that snapshot through
  the existing test-only helper, `tests/helpers/basis_schemas_snapshot.py`
  — they do not add a second copy of contract data.
- **Test-only fixture helpers stay outside the runtime package.** Nothing
  under `tests/` is imported by `src/basis_core/`, and nothing in this
  package is, or becomes, part of the `basis_core` public API
  (`docs/public-api.md`).
- **Gateway-only fixture artifacts are reference data, not kernel
  outputs.** `expected-gateway-audit-event.yaml` (per scenario) documents
  what `basis-gateway` assembles downstream; it is never asserted here as
  something `basis-core` produces.
- **Each implementation PR adds its own focused tests here** as the
  corresponding operation-aware model, policy, trace, audit, or evaluator
  work lands — this package grows incrementally alongside the roadmap, not
  all at once.
- **Tests must remain deterministic and independent of network access.**
  No test in this package may reach out to `basis-schemas`, `PyPI`,
  GitHub, or any other network resource.
- **No test may mutate the vendored schema snapshot.** The snapshot under
  `tests/fixtures/basis-schemas/v0.2.0/` is immutable, governed input (see
  its own `README.md`); this package only reads it.
- **This package is not a second implementation of authorization
  semantics.** It tests `basis-core`'s operation-aware behavior; it must
  never grow its own parallel policy-evaluation, matching, or precedence
  logic used to "check" the kernel from the outside.

## YAML contract loading (Milestone 1, PR 4)

`test_scaffold.py` (Milestone 0, PR 3) proved this package could *locate*
pinned snapshot content through `tests/helpers/basis_schemas_snapshot.py`,
without parsing any of it. Milestone 1, PR 4 adds the remaining
YAML-*parsing* half:

- **Where the helpers live** — `tests/helpers/operation_aware_contracts.py`.
  It provides `load_yaml_document` (a safe, `yaml.SafeLoader`-based loader
  with an added duplicate-mapping-key check), `load_contract` and
  `load_scenario_artifact` (snapshot-boundary-aware wrappers over the
  existing discovery helpers), generic structural assertions
  (`require_mapping`, `require_sequence`, `require_string_field`,
  `require_mapping_field`, `require_sequence_field`, `require_optional_field`,
  `reject_unknown_fields`), and `validate_contract_metadata` (structural
  presence/type checks for the shared `contract:` block only).
- **What they validate** — that a fixture file is well-formed, safe YAML
  (single document, no unsafe tags, no duplicate keys, valid UTF-8) and has
  the broad container shape (mapping vs. sequence vs. scalar) a caller
  expects; and, for contract metadata specifically, that `contract`,
  `contract.name`, `contract.version`, `contract.lifecycle`, and
  `contract.depends_on` are present with the right structural type.
- **What they intentionally do not validate** — any contract's business
  semantics: field patterns (e.g. kebab-case `name`, semver `version`),
  enum membership (e.g. `lifecycle`'s three values), cross-field
  constraints, condition-operator behavior, selector matching, evaluation
  outcomes, or trace/audit content. Those are `basis-schemas`' own
  contracts to define and later, separate roadmap work (domain models,
  policy, evaluator) to implement and test.
- **Reuse, don't re-parse** — future test files below should call
  `load_contract` / `load_scenario_artifact` / the `require_*` helpers
  rather than opening and parsing vendored YAML themselves. This keeps
  exactly one place that knows how to safely read the snapshot.
- **Test-only, always** — like `basis_schemas_snapshot.py`, this helper
  module is never imported by `src/basis_core/` and exposes no
  `basis_core` public API; see `tests/test_basis_schemas_snapshot_boundaries.py`.

Its own tests live in `test_contract_loading.py` (all 14 pinned contracts),
`test_compatibility_fixture_loading.py` (all 5 pinned scenarios), and
`test_yaml_loader_negative.py` (malformed/unsafe input, exercised against
temporary files outside the pinned snapshot).

## Shared vocabulary value objects (Milestone 2, PR 5)

`test_vocabulary.py` and `test_vocabulary_boundaries.py` test the first
production code added under `src/basis_core/` for the operation-aware
surface: `basis_core.domain.operation_aware_vocabulary`, which implements
`RedactionClassification` (a closed, five-value enum) and `ReasonCode` (a
validated, open-format string token) — the two shared vocabulary primitives
every later evidence-reference, request, trace, and policy model is expected
to depend on. `test_vocabulary.py` covers construction (valid/invalid,
vendored-fixture-conformant and directly-parametrized), enum exhaustiveness,
immutability, equality, hashing, and deterministic representation.
`test_vocabulary_boundaries.py` confirms the new module imports only the
standard library, is not yet re-exported as public API, and is not imported
by any existing v0.1.0 module. No evidence-reference, context-object,
request/response, policy, or evaluator code is implemented or tested here —
those remain later, separately-scoped roadmap PRs (Milestone 2, PR 6
onward).

## Anticipated future test files

The files below are **anticipated, not yet implemented**. Each is added by
its own focused roadmap PR as the corresponding production surface lands.

```text
test_evidence_references.py
test_context_objects.py
test_decision_request.py
test_decision_request_roundtrip.py
test_policy_condition.py
test_policy_rule.py
test_policy_bundle.py
test_evaluation_trace.py
test_operation_aware_response.py
test_audit_evidence.py
test_operation_aware_engine.py
test_canonical_vectors.py
```

`test_scaffold.py` (PR 3) is infrastructure-only: it proves the package is
discovered by pytest and can reach the pinned fixture foundation.
`test_contract_loading.py`, `test_compatibility_fixture_loading.py`, and
`test_yaml_loader_negative.py` (PR 4, described above) are generic
loading/structural-validation tests, not domain-model or evaluation tests.
`test_vocabulary.py` and `test_vocabulary_boundaries.py` (PR 5, described
above) are implemented. None of the files in the list above exist yet.
