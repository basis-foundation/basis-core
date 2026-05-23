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

Decision paths and audit coverage
──────────────────────────────────
Every evaluation path produces an AuditEvent:

  ALLOW          Rule explicitly permits the request.
  DENY           Rule explicitly denies the request.
  NOT_APPLICABLE All rules returned NOT_APPLICABLE — default deny applied.
  ERROR          Unexpected exception during evaluation — DENY returned.

Audit failures do not reverse authorization decisions. If AuditWriter.write()
raises, the exception is caught and logged. The DecisionResponse is returned
unchanged. This trade-off is intentional and documented in failure-modes.md.

Usage
─────
    from basis_core.api.enforcement import EnforcementPoint
    from basis_core.policy.engine import PolicyEngine
    from basis_core.policy.rules import RolePolicyRule
    from basis_core.audit.writer import LogAuditWriter

    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    writer = LogAuditWriter()
    ep = EnforcementPoint(engine=engine, audit_writer=writer, policy_version="v1.1.0")

    response = ep.evaluate(request)
    if not response.allowed:
        raise Forbidden(response.reason)
"""

from __future__ import annotations

import logging

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.audit.writer import AuditWriter
from basis_core.decisions.models import DecisionOutcome, DecisionRequest, DecisionResponse
from basis_core.domain.identity import IdentityContext
from basis_core.domain.subject import Subject
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome

log = logging.getLogger("basis_core.api.enforcement")

_POLICY_OUTCOME_TO_DECISION_OUTCOME: dict[PolicyOutcome, DecisionOutcome] = {
    PolicyOutcome.ALLOW:          DecisionOutcome.ALLOW,
    PolicyOutcome.DENY:           DecisionOutcome.DENY,
    PolicyOutcome.NOT_APPLICABLE: DecisionOutcome.NOT_APPLICABLE,
}

_DECISION_OUTCOME_TO_AUDIT_OUTCOME: dict[DecisionOutcome, AuditOutcome] = {
    DecisionOutcome.ALLOW:          AuditOutcome.ALLOWED,
    DecisionOutcome.DENY:           AuditOutcome.DENIED,
    DecisionOutcome.NOT_APPLICABLE: AuditOutcome.DENIED,  # default deny = denied in audit
}


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
        identity_context: IdentityContext | None = None,
        correlation_id: str | None = None,
    ) -> DecisionResponse:
        """
        Evaluate an authorization request and record the decision.

        Parameters
        ──────────
        request          The normalized DecisionRequest.
        subject          The verified Subject, if available (used to populate
                         audit fields). If None, fields come from the request.
        identity_context Verified identity context for policy evaluation.
        correlation_id   Optional caller-provided trace ID for cross-system
                         correlation (e.g., HTTP request ID, batch job ID).
                         Passed through to the AuditEvent verbatim.

        Returns a DecisionResponse. Never raises — failures produce a DENY
        response with the error recorded in the audit trail.
        """
        decision: Decision | None = None

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
                resource_id=request.resource_id,
                identity_context=identity_context,
                context=dict(request.context) if request.context else None,
            )

            outcome = _POLICY_OUTCOME_TO_DECISION_OUTCOME.get(
                decision.outcome, DecisionOutcome.DENY
            )

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

        self._write_audit(request, response, subject, decision, correlation_id)
        return response

    def _write_audit(
        self,
        request: DecisionRequest,
        response: DecisionResponse,
        subject: Subject | None,
        decision: Decision | None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Write an audit record for the decision. Does not raise.

        Constructs a DecisionTrace from the engine's per-rule evaluation data
        (when available) and embeds it in the AuditEvent. If AuditWriter.write()
        raises, the exception is caught and logged — the decision is not reversed.
        """
        try:
            audit_outcome = _DECISION_OUTCOME_TO_AUDIT_OUTCOME.get(
                response.outcome, AuditOutcome.ERROR
            )

            # Build the decision trace from the engine's evaluation record.
            trace: DecisionTrace | None = None
            matched_rules: list[str] = []

            if decision is not None and decision.evaluated_rules:
                rule_evals = [
                    RuleEvaluation(
                        rule_name=name,
                        outcome=outcome_val,
                        reason=reason,
                    )
                    for name, outcome_val, reason in decision.evaluated_rules
                ]
                # short_circuited = engine stopped early because a DENY was found,
                # meaning the DENY is the last entry and the outcome is DENY.
                short_circuited = (
                    decision.outcome == PolicyOutcome.DENY
                    and len(rule_evals) < len(self._engine._policies)
                )
                trace = DecisionTrace(
                    final_outcome=decision.outcome.value,
                    evaluated_rules=rule_evals,
                    short_circuited=short_circuited,
                )
                matched_rules = trace.matched_rule_names

            event = AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_DECISION,
                # Correlation
                request_id=request.request_id,
                decision_id=request.request_id,   # same unless separately assigned
                correlation_id=correlation_id,
                # Subject
                subject_id=subject.id   if subject else request.subject_id,
                subject_name=subject.name if subject else request.subject_id,
                subject_type=subject.type.value if subject else None,
                subject_roles=list(subject.roles) if subject else list(request.subject_roles),
                # Resource and action
                action=request.action,
                resource_id=request.resource_id,
                # Decision
                outcome=audit_outcome,
                reason=response.reason,
                evaluated_by=response.evaluated_by,
                policy_version=response.policy_version,
                matched_rules=matched_rules,
                # Traceability
                trace=trace,
            )
            self._audit_writer.write(event)

        except Exception:
            log.exception(
                "EnforcementPoint: failed to write audit record for request_id=%s",
                request.request_id,
            )
