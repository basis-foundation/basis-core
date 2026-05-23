"""
basis_core.api.enforcement — EnforcementPoint: the authorization boundary.

An EnforcementPoint connects an incoming normalized request to the policy
engine, records the decision in the audit log, and returns the result to
the caller. It is the only component that is allowed to call both the policy
engine and the audit writer in the same execution path.

The EnforcementPoint does not know:
  - What transport the request arrived on (HTTP, MQTT, WebSocket, …).
  - What field protocol the adapter normalized.
  - How the audit writer persists the record.

Those concerns belong to the callers (API handlers, adapters) and to the
implementations (storage backends). The EnforcementPoint is the seam where
the core authorization logic runs.

Usage
─────
    from basis_core.api.enforcement import EnforcementPoint
    from basis_core.policy.engine import PolicyEngine
    from basis_core.policy.rules import RolePolicy
    from basis_core.audit.writer import LogAuditWriter

    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    writer = LogAuditWriter()
    ep = EnforcementPoint(engine=engine, audit_writer=writer)

    response = ep.evaluate(request)
    if not response.allowed:
        raise Forbidden(response.reason)
"""

from __future__ import annotations

import logging

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.writer import AuditWriter
from basis_core.decisions.models import DecisionOutcome, DecisionRequest, DecisionResponse
from basis_core.domain.subject import Subject
from basis_core.policy.engine import PolicyEngine

log = logging.getLogger("basis_core.api.enforcement")


class EnforcementPoint:
    """
    The authorization boundary.

    Submits a DecisionRequest to the PolicyEngine, records the decision
    in the audit log, and returns a DecisionResponse to the caller.

    Parameters
    ──────────
    engine          PolicyEngine configured with the active policy chain.
    audit_writer    AuditWriter backend for persisting decision records.
    policy_version  Optional version identifier included in audit records.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        audit_writer: AuditWriter,
        policy_version: str | None = None,
    ) -> None:
        self._engine         = engine
        self._audit_writer   = audit_writer
        self._policy_version = policy_version

    def evaluate(
        self,
        request: DecisionRequest,
        subject: Subject | None = None,
    ) -> DecisionResponse:
        """
        Evaluate an authorization request and record the decision.

        Parameters
        ──────────
        request   The normalized DecisionRequest.
        subject   The verified Subject, if available (used to populate audit
                  fields). If None, subject fields are taken from the request.

        Returns a DecisionResponse. Never raises — failures produce a DENY
        response with the error recorded in the audit trail.
        """
        try:
            # Build a Subject for policy evaluation from the request if not supplied.
            eval_subject = subject or Subject(
                id=request.subject_id,
                name=request.subject_id,
                roles=request.subject_roles,
                attrs=request.subject_attrs,
            )

            decision = self._engine.evaluate(
                eval_subject,
                request.action,
                request.resource_id,
            )

            outcome = DecisionOutcome.ALLOW if decision.allowed else DecisionOutcome.DENY

            response = DecisionResponse(
                request_id=request.request_id,
                outcome=outcome,
                reason=decision.reason,
                evaluated_by=decision.evaluated_by,
                policy_version=self._policy_version,
            )

        except Exception as exc:
            log.exception(
                "EnforcementPoint: error evaluating request_id=%s",
                request.request_id,
            )
            response = DecisionResponse(
                request_id=request.request_id,
                outcome=DecisionOutcome.DENY,
                reason=f"Evaluation error: {exc}",
                evaluated_by="EnforcementPoint",
                policy_version=self._policy_version,
            )

        self._write_audit(request, response, subject)
        return response

    def _write_audit(
        self,
        request: DecisionRequest,
        response: DecisionResponse,
        subject: Subject | None,
    ) -> None:
        """Write an audit record for the decision. Does not raise."""
        try:
            outcome_map = {
                DecisionOutcome.ALLOW:          AuditOutcome.ALLOWED,
                DecisionOutcome.DENY:           AuditOutcome.DENIED,
                DecisionOutcome.NOT_APPLICABLE: AuditOutcome.DENIED,
            }
            event = AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_DECISION,
                subject_id=subject.id if subject else request.subject_id,
                subject_name=subject.name if subject else request.subject_id,
                subject_type=subject.type.value if subject else None,
                subject_roles=subject.roles if subject else request.subject_roles,
                action=request.action,
                resource_id=request.resource_id,
                outcome=outcome_map.get(response.outcome, AuditOutcome.ERROR),
                reason=response.reason,
                evaluated_by=response.evaluated_by,
                policy_version=response.policy_version,
                request_id=request.request_id,
            )
            self._audit_writer.write(event)
        except Exception:
            log.exception(
                "EnforcementPoint: failed to write audit record for request_id=%s",
                request.request_id,
            )
