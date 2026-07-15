"""
basis_core.audit.operation_aware — operation-aware trace/audit data models.

Additive alongside the existing v0.1 `basis_core.audit` package
(`events.py`, `trace.py`, `writer.py`); nothing here modifies `AuditEvent`,
`DecisionTrace`, or `RuleEvaluation`.

Contains `trace_rule_evidence.py` — the bounded, frozen `TraceRuleEvidence`
per-rule trace-evidence model.

Symbols in this package are not re-exported from `basis_core.audit` or any
other package `__init__.py`.
"""

from __future__ import annotations
