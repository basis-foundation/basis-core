"""
basis_core.policy.operation_aware — operation-aware policy data models.

This package holds the operation-aware v0.2.0 policy *data* models
(`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4:
"Policy Domain Model and Semantic Validation"). It is a sibling to the
existing v0.1.0 `basis_core.policy` package (`engine.py`, `rules.py`), not a
replacement for it — the v0.1.0 `PolicyEngine`/`PolicyRule` Protocol/rule
implementations are unaffected by anything added here.

Contents
────────
  condition.py   `PolicyCondition` — the operation-aware condition data
                 model published by `basis-schemas` v0.2.0's
                 `policy-condition` contract (PR 12). Inert structural data
                 only: no condition evaluation, no operator registry, no
                 operator whitelist, no field-path resolution.

These models are policy *data*, not policy *evaluation*. Condition,
rule, and bundle evaluation semantics remain blocked pending the
architecture clarification named in Section 8 of the roadmap plan
(Milestone 7).

Public API status: internal for now, exactly like every other
operation-aware module added so far (`domain.operation_aware_vocabulary`,
`domain.evidence`, `domain.operation_aware`, `decisions.operation_aware`).
Not re-exported from `basis_core.policy` or any other package
`__init__.py`; see `docs/public-api.md`'s "Open API questions" convention
and Section 6 of the roadmap plan for when operation-aware symbols are
expected to graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations
