"""
basis_core.audit — audit event types and the AuditWriter protocol.

The audit package defines what gets recorded (AuditEvent) and the interface
for recording it (AuditWriter). Concrete storage backends are not defined here;
they are provided by adapter implementations or application configuration.

Contents
────────
  events.py    AuditEvent — the normalized record of every authorization
               decision, policy change, or security-relevant system event.

  writer.py    AuditWriter protocol — the interface that storage backends
               implement. Enforcement points and the policy engine call
               AuditWriter.write(); they do not depend on the backend.

Design principles
─────────────────
- Audit records are append-only. No record is modified after it is written.
- The audit pipeline is independent of the operational data path. A failure
  to write an audit record should not prevent an authorized operation from
  completing — but the failure must itself be recorded and surfaced.
- Every authorization decision produces an audit record, whether the decision
  is ALLOW or DENY. Silence in the audit log is not evidence of absence.
"""
