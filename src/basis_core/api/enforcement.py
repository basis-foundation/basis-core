"""
basis_core.api.enforcement — EnforcementPoint: the authorization boundary.

The EnforcementPoint is the single component authorized to call both the policy
engine and the audit writer in the same execution path. It translates a
DecisionRequest into a DecisionResponse and records the outcome.

What the EnforcementPoint knows
────────────────────────────────
  - How to submit a normalized DecisionRequest to the PolicyEngine.
  - How to build a Subject for policy evaluation from request fields.
  - How to record the decision in the audit log.
  - How to produce a safe deny when any step fails.

What the EnforcementPoint does not know
────────────────────────────────────────
  - What transport the request arrived on (HTTP, MQTT, WebSocket, …).
  - What field protocol the adapter normalized from.
  - How the audit writer persists records or where they go.
  - Any protocol-specific package (BACnet, Modbus, OPC-UA, …).

Enforcement guarantees
──────────────────────
  Fail closed.     Every failure path returns DENY. The enforcement point
                   never permits an action it cannot safely evaluate.
  No raw leakage.  Raw exception strings are logged but never returned to
                   the caller as decision reasons.
  Audit resilience. Audit write failures are caught and logged. They do not
                   reverse the authorization decision.
  Always returns.  evaluate() never raises. All failure paths are caught
                   and produce a DecisionResponse with outcome=DENY.

Decision paths and audit coverage
──────────────────────────────────
Every evaluation path produces a DecisionResponse. Audit coverage:

  ALLOW          Rule explicitly permits the request.     → AuditOutcome.ALLOWED
  DENY           Rule explicitly denies the request.      → AuditOutcome.DENIED
  NOT_APPLICABLE All rules returned NOT_APPLICABLE.       → AuditOutcome.DENIED
  POLICY_ERROR   Exception during rule evaluation.        → AuditOutcome.ERROR
  INTERNAL_ERROR Unexpected exception in EP.              → AuditOutcome.ERROR
  MALFORMED_REQ  Request failed validation.               (logged; no audit write)

Audit failures do not reverse authorization decisions. If AuditWriter.write()
raises, the exception is caught and logged. The DecisionResponse is returned
unchanged. See docs/failure-modes.md.

FailureReason codes
───────────────────
DecisionResponse.failure_reason is None for decisions produced by normal policy
evaluation. For enforcement-boundary failures:

  MALFORMED_REQUEST   Request did not pass validation — EP never reached policy.
  POLICY_ERROR        Exception raised during policy engine evaluation.
  INTERNAL_ERROR      Unexpected exception inside the enforcement point.

Usage
─────
    from basis_core.api.enforcement import EnforcementPoint
    from basis_core.policy.engine import PolicyEngine
    from basis_core.policy.rules import RolePolicyRule
    from basis_core.audit.writer import LogAuditWriter

    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    ep = EnforcementPoint(engine=engine, audit_writer=LogAuditWriter(), policy_version="v1")

    response = ep.evaluate(request)
    if not response.allowed:
        raise Forbidden(response.reason)
"""

from __future__ import annotations

import logging
import uuid

from pydantic import ValidationError

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.audit.writer import AuditWriter
from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
    FailureReason,
)
from basis_core.domain.identity import IdentityContext
from basis_core.domain.subject import Subject
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome

log = logging.getLogger("basis_core.api.enforcement")

_POLICY_OUTCOME_TO_DECISION_OUTCOME: dict[PolicyOutcome, DecisionOutcome] = {
    PolicyOutcome.ALLOW: DecisionOutcome.ALLOW,
    PolicyOutcome.DENY: DecisionOutcome.DENY,
    PolicyOutcome.NOT_APPLICABLE: DecisionOutcome.NOT_APPLICABLE,
}

_DECISION_OUTCOME_TO_AUDIT_OUTCOME: dict[DecisionOutcome, AuditOutcome] = {
    DecisionOutcome.ALLOW: AuditOutcome.ALLOWED,
    DecisionOutcome.DENY: AuditOutcome.DENIED,
    DecisionOutcome.NOT_APPLICABLE: AuditOutcome.DENIED,  # default deny = denied in audit
}

# Safe, caller-visible reason strings for enforcement failures.
# Raw exception text is logged but never returned to callers.
_REASON_MALFORMED = (
    "The request could not be validated. Check subject_id, action format, and required fields."
)
_REASON_POLICY_ERROR = (
    "Policy evaluation encountered an internal error. The request has been denied."
)
_REASON_INTERNAL = "An internal error occurred during evaluation. The request has been denied."


class EnforcementPoint:
    """
    The authorization boundary for basis_core.

    Accepts a DecisionRequest (or a raw dict that will be validated), submits
    it to the PolicyEngine, records the outcome in the audit log, and returns
    a DecisionResponse. Never raises — all failure paths produce a DENY.

    Parameters
    ──────────
    engine          PolicyEngine configured with the active policy chain.
    audit_writer    AuditWriter backend for persisting decision records.
    policy_version  Optional version identifier included in responses and
                    audit records.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        audit_writer: AuditWriter,
        policy_version: str | None = None,
    ) -> None:
        self._engine = engine
        self._audit_writer = audit_writer
        self._policy_version = policy_version

    def evaluate(
        self,
        request: DecisionRequest | dict[str, object],
        subject: Subject | None = None,
        identity_context: IdentityContext | None = None,
        correlation_id: str | None = None,
    ) -> DecisionResponse:
        """
        Evaluate an authorization request and record the decision.

        Parameters
        ──────────
        request          A DecisionRequest, or a raw dict that will be validated
                         into one. A dict that fails validation produces a safe
                         DENY with failure_reason=MALFORMED_REQUEST.
        subject          Pre-constructed Subject, if the caller has already
                         resolved identity. If None, Subject is built from
                         request.subject_id and request.subject_roles.
        identity_context Verified identity context for policy evaluation.
        correlation_id   Optional caller-provided trace ID (e.g., HTTP request
                         ID) forwarded verbatim to the AuditEvent.

        Returns a DecisionResponse. Never raises.
        """
        # ── Step 1: Validate and normalize the request ───────────────────────
        if isinstance(request, dict):
            raw = request  # keep a typed reference for the except block
            try:
                request = DecisionRequest.model_validate(raw)
            except ValidationError as exc:
                request_id = str(raw.get("request_id") or uuid.uuid4())
                log.warning(
                    "EnforcementPoint: malformed request request_id=%s — %s",
                    request_id,
                    exc,
                )
                # Cannot construct a valid AuditEvent without a valid action;
                # log the failure and return a safe deny without an audit write.
                return DecisionResponse(
                    request_id=request_id,
                    outcome=DecisionOutcome.DENY,
                    reason=_REASON_MALFORMED,
                    evaluated_by="EnforcementPoint",
                    policy_version=self._policy_version,
                    failure_reason=FailureReason.MALFORMED_REQUEST,
                )

        # From this point request is a validated DecisionRequest.
        decision: Decision | None = None

        try:
            # ── Step 2: Build the evaluation subject ─────────────────────────
            try:
                eval_subject = subject or Subject(
                    id=request.subject_id,
                    name=request.subject_id,
                    roles=request.subject_roles,
                    attrs=request.subject_attrs,
                )
            except (ValidationError, ValueError) as exc:
                log.warning(
                    "EnforcementPoint: subject construction failed request_id=%s — %s",
                    request.request_id,
                    exc,
                )
                response = DecisionResponse(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.DENY,
                    reason=_REASON_MALFORMED,
                    evaluated_by="EnforcementPoint",
                    policy_version=self._policy_version,
                    failure_reason=FailureReason.MALFORMED_REQUEST,
                )
                self._write_audit(request, response, subject, decision, correlation_id)
                return response

            # ── Step 3: Run policy evaluation ────────────────────────────────
            try:
                decision = self._engine.evaluate(
                    eval_subject,
                    request.action,
                    resource_id=request.resource_id,
                    identity_context=identity_context,
                    context=dict(request.context) if request.context else None,
                )
            except Exception:
                log.exception(
                    "EnforcementPoint: policy evaluation error request_id=%s",
                    request.request_id,
                )
                response = DecisionResponse(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.DENY,
                    reason=_REASON_POLICY_ERROR,
                    evaluated_by="EnforcementPoint",
                    policy_version=self._policy_version,
                    failure_reason=FailureReason.POLICY_ERROR,
                )
                self._write_audit(request, response, subject, decision, correlation_id)
                return response

            # ── Step 4: Map policy outcome to decision outcome ────────────────
            # If the engine caught an exception inside a rule it returns a DENY
            # with is_error=True. Sanitize the reason before surfacing to callers.
            if decision.is_error:
                log.error(
                    "EnforcementPoint: policy rule error for request_id=%s — %s",
                    request.request_id,
                    decision.reason,
                )
                response = DecisionResponse(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.DENY,
                    reason=_REASON_POLICY_ERROR,
                    evaluated_by=decision.evaluated_by,
                    policy_version=self._policy_version,
                    failure_reason=FailureReason.POLICY_ERROR,
                )
            else:
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

        except Exception:
            # Catch-all: unexpected internal failure. Fail closed.
            log.exception(
                "EnforcementPoint: unexpected internal error request_id=%s",
                getattr(request, "request_id", "unknown"),
            )
            response = DecisionResponse(
                request_id=getattr(request, "request_id", str(uuid.uuid4())),
                outcome=DecisionOutcome.DENY,
                reason=_REASON_INTERNAL,
                evaluated_by="EnforcementPoint",
                policy_version=self._policy_version,
                failure_reason=FailureReason.INTERNAL_ERROR,
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
        when available. If AuditWriter.write() raises, the exception is caught
        and logged — the decision is not reversed.
        """
        try:
            audit_outcome = _DECISION_OUTCOME_TO_AUDIT_OUTCOME.get(
                response.outcome, AuditOutcome.ERROR
            )
            # Error outcomes from enforcement failures map to AuditOutcome.ERROR.
            if response.failure_reason in (
                FailureReason.POLICY_ERROR,
                FailureReason.INTERNAL_ERROR,
            ):
                audit_outcome = AuditOutcome.ERROR

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
                short_circuited = decision.outcome == PolicyOutcome.DENY and len(rule_evals) < len(
                    self._engine._policies
                )
                trace = DecisionTrace(
                    final_outcome=decision.outcome.value,
                    evaluated_rules=rule_evals,
                    short_circuited=short_circuited,
                )
                matched_rules = trace.matched_rule_names

            detail: dict[str, object] = {}
            if response.failure_reason is not None:
                detail["failure_reason"] = response.failure_reason.value

            event = AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_DECISION,
                # Correlation
                request_id=request.request_id,
                decision_id=request.request_id,
                correlation_id=correlation_id,
                # Subject
                subject_id=subject.id if subject else request.subject_id,
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
                detail=detail,
            )
            self._audit_writer.write(event)

        except Exception:
            log.exception(
                "EnforcementPoint: failed to write audit record for request_id=%s",
                request.request_id,
            )
