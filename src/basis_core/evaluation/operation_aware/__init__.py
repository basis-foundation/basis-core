"""
basis_core.evaluation.operation_aware — operation-aware evaluation
orchestration (v0.2.0).

Contains `trace_assembly.py` — pure, deterministic assembly of
`basis_core.audit.operation_aware`'s `TraceRuleEvidence` and
`EvaluationTrace` from already-evaluated `policy/`-owned facts
(`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 8,
PR 26). It implements no rule matching, condition evaluation, applicability
determination, effect aggregation, deny precedence, default-deny, or
`NOT_APPLICABLE`/final-outcome semantics — those remain `policy/`'s
responsibility.

Per `docs/import-boundaries.md`, this package may import from `domain/`,
`decisions/`, `policy/`, and `audit/`, and must not import from `adapters/`
or `enforcement/` — enforced recursively by
`tests/test_import_boundaries.py`.

This package is internal; nothing here is re-exported from
`basis_core.evaluation`, `basis_core`, or any other package `__init__.py`.
"""

from __future__ import annotations
