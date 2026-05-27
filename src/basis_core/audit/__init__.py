"""
basis_core.audit — audit event types and the AuditWriter protocol.

The audit package defines what gets recorded (AuditEvent) and the interface
for recording it (AuditWriter). Concrete storage backends are not defined here;
they are provided by adapter implementations or application configuration.

Contents
────────
  events.py    AuditEvent, AuditEventType, AuditOutcome, AUDIT_SCHEMA_VERSION.
               The normalized record of every security-relevant system event.

  writer.py    AuditWriter (Protocol), NullAuditWriter, LogAuditWriter.
               AuditWriter is the interface storage backends implement.

  trace.py     DecisionTrace, RuleEvaluation.
               Per-rule evaluation history included in authorization events.

Design principles
─────────────────
- Audit records are append-only. No record is modified after it is written.
- The audit pipeline is independent of the operational data path. A failure
  to write an audit record should not prevent an authorized operation from
  completing — but the failure must itself be recorded and surfaced.
- Every authorization decision produces an audit record, whether the decision
  is ALLOW or DENY. Silence in the audit log is not evidence of absence.

Public API
──────────
All stable public symbols are available directly from this package.
See ``docs/public-api.md`` for the full inventory and stability tiers.
"""

from basis_core.audit.events import (
    AUDIT_SCHEMA_VERSION,
    AuditEvent,
    AuditEventType,
    AuditOutcome,
)
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.audit.writer import AuditWriter, LogAuditWriter, NullAuditWriter

__all__ = [
    # events
    "AuditEvent",
    "AuditEventType",
    "AuditOutcome",
    "AUDIT_SCHEMA_VERSION",
    # writer
    "AuditWriter",
    "NullAuditWriter",
    "LogAuditWriter",
    # trace
    "DecisionTrace",
    "RuleEvaluation",
]
