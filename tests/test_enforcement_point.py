"""
Tests for basis_core.api.enforcement — EnforcementPoint.

Verifies that the EnforcementPoint correctly connects the policy engine
to the audit writer, and that both ALLOW and DENY decisions are recorded.
"""

from __future__ import annotations

from basis_core.api.enforcement import EnforcementPoint
from basis_core.audit.events import AuditOutcome
from basis_core.audit.writer import AuditEvent, AuditWriter, NullAuditWriter
from basis_core.decisions.models import DecisionOutcome, DecisionRequest
from basis_core.domain.subject import Subject
from basis_core.policy.engine import PolicyEngine
from basis_core.policy.rules import RolePolicy


ROLE_TABLE: dict[str, set[str]] = {
    "write:hvac:setpoint": {"operator", "admin"},
}


def make_ep(captured: list[AuditEvent] | None = None) -> EnforcementPoint:
    """Build an EnforcementPoint with a capturing audit writer."""

    class CapturingWriter:
        def write(self, event: AuditEvent) -> None:
            if captured is not None:
                captured.append(event)

    return EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicy(ROLE_TABLE)]),
        audit_writer=CapturingWriter(),
        policy_version="test-v1",
    )


def make_request(action: str = "write:hvac:setpoint") -> DecisionRequest:
    return DecisionRequest(
        subject_id="test-user",
        subject_roles=["operator"],
        resource_id="hvac:zone-a",
        action=action,
    )


# ── Core behavior ──────────────────────────────────────────────────────────────

def test_allowed_request_returns_allow_outcome() -> None:
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request("write:hvac:setpoint")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.ALLOW
    assert response.allowed is True


def test_denied_request_returns_deny_outcome() -> None:
    ep = make_ep()
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    request = make_request("write:hvac:setpoint")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False


def test_decision_is_recorded_in_audit_log() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request()
    ep.evaluate(request, subject=subject)
    assert len(captured) == 1
    assert captured[0].outcome == AuditOutcome.ALLOWED


def test_denial_is_also_recorded_in_audit_log() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    request = make_request()
    ep.evaluate(request, subject=subject)
    assert len(captured) == 1
    assert captured[0].outcome == AuditOutcome.DENIED


def test_request_id_is_echoed_in_response() -> None:
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request()
    response = ep.evaluate(request, subject=subject)
    assert response.request_id == request.request_id


def test_policy_version_appears_in_response() -> None:
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request()
    response = ep.evaluate(request, subject=subject)
    assert response.policy_version == "test-v1"
