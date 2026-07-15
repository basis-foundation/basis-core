"""
basis_core.evaluation — pure evaluation orchestration layer (v0.2.0).

Introduced by `basis-architecture` ADR-0006 ("Introduce a Pure Evaluation
Orchestration Layer") and reflected in
`docs/implementation/basis-core-v0.2-operation-aware-plan.md` (Section 5's
supersession note, Section 6's module tree). `evaluation/` sequences and
composes typed results produced by `policy/`-owned semantic operations and
`audit/`-owned trace/evidence contracts into bounded decision, trace,
response, and kernel audit-evidence artifacts. It implements no
authorization semantics of its own — every combining, precedence, or
outcome rule remains `policy/`'s responsibility.

Per `docs/import-boundaries.md`, `evaluation/` may import from `domain/`,
`decisions/`, `policy/`, and `audit/`, and must not import from `adapters/`
or `enforcement/`. It inherits every kernel invariant in
`docs/kernel-constitution.md` (deterministic, synchronous, offline, no
clocks, no randomness, no I/O, no persistence, no runtime enforcement).

Contains `operation_aware/` — the operation-aware (v0.2.0) evaluation
orchestration surface. This package is internal; nothing here is
re-exported from `basis_core` or any other package `__init__.py`.
"""

from __future__ import annotations
