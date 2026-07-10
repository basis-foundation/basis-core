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

## Anticipated future test files

The files below are **anticipated, not yet implemented**. Each is added by
its own focused roadmap PR as the corresponding production surface lands;
none of them exist yet as of this scaffold.

```text
test_vocabulary.py
test_evidence_references.py
test_operation_aware_request.py
test_policy_condition.py
test_policy_rule.py
test_policy_bundle.py
test_evaluation_trace.py
test_operation_aware_response.py
test_audit_evidence.py
test_operation_aware_engine.py
test_canonical_vectors.py
```

`test_scaffold.py`, added by this PR, is infrastructure-only: it proves the
package is discovered by pytest and can reach the pinned fixture foundation.
It is not one of the files above and carries no domain-model or evaluation
assertions.
