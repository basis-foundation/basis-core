## Summary

_Describe what this PR changes and why._

---

## Contract surface checklist

Complete this section for every PR. If you are unsure whether a change touches a contract surface, assume it does.

**Step 1 — Identify affected surfaces**

Check every surface this PR touches:

- [ ] JSON schemas (`schemas/*.schema.json`)
- [ ] Contract fixtures (`tests/fixtures/contracts/*.json`)
- [ ] Public API exports (`__all__` in any package `__init__.py`)
- [ ] Evaluation semantics (DENY short-circuit, first-ALLOW, NOT_APPLICABLE resolution)
- [ ] Enforcement fail-closed behavior or `FailureReason` codes
- [ ] Audit event shape, fields, or immutability semantics
- [ ] Extension interface signatures or behavioral contracts (`PolicyRule`, `AuditWriter`, `AdapterBase`)
- [ ] Action vocabulary (constants in `basis_core.domain.action`)
- [ ] Adapter normalization contracts (`NormalizedEvent` field semantics)
- [ ] None of the above — this PR does not touch any contract surface

**Step 2 — Classify the change**

- [ ] Additive only (new optional field, new enum value, new export, new rule type — existing consumers unaffected)
- [ ] Breaking (see `docs/breaking-change-discipline.md` for the full list)
- [ ] Not applicable (no contract surface affected)

---

## If additive

- [ ] All compatibility tests pass, or fixture/snapshot updates are deliberate and explained in this PR description.
- [ ] Affected documentation updated.
- [ ] Changelog entry added (if a changelog exists).

---

## If breaking

A breaking change may not be merged without completing all of the following. See `docs/breaking-change-discipline.md` for the full required process.

- [ ] Architecture review opened in basis-architecture **before** this PR was written.
- [ ] ADR filed and accepted in basis-architecture.
  - ADR reference: ___
- [ ] Migration path defined and documented.
  - Migration path reference: ___
- [ ] Compatibility tests updated deliberately in this PR (not silenced pending governance).
- [ ] All affected documentation updated in this PR.

---

## Tests

_Describe what tests cover this change, or explain why no new tests are needed._

- [ ] `pytest` passes locally
- [ ] `ruff check` passes
- [ ] `ruff format --check` passes
- [ ] `mypy` passes
