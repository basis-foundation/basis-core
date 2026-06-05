"""
Tests for basis_core.enforcement.enforcement — EnforcementPoint.

Covers:
  - Core allow / deny / default-deny / deny-overrides behavior.
  - Audit write coverage for every decision path.
  - Fail-closed behavior: malformed request, policy exception, internal error.
  - Audit writer exceptions do not reverse authorization decisions.
  - Error responses never expose raw exception details to the caller.
  - Import boundary: enforcement module must not import protocol packages.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

import pytest

from basis_core.audit.events import AuditEvent, AuditOutcome
from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    FailureReason,
)
from basis_core.domain.subject import Subject
from basis_core.enforcement.enforcement import EnforcementPoint
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome
from basis_core.policy.rules import RolePolicyRule

ROLE_TABLE: dict[str, set[str]] = {
    "write:hvac:setpoint": {"operator", "admin"},
}

# A second role table used for deny-overrides tests.
DENY_TABLE: dict[str, set[str]] = {}  # denies everything it matches

# ── Helpers ────────────────────────────────────────────────────────────────────


def make_ep(
    captured: list[AuditEvent] | None = None,
    policies: list[Any] | None = None,
) -> EnforcementPoint:
    """Build an EnforcementPoint with a capturing audit writer."""

    class CapturingWriter:
        def write(self, event: AuditEvent) -> None:
            if captured is not None:
                captured.append(event)

    return EnforcementPoint(
        engine=PolicyEngine(policies=policies or [RolePolicyRule(ROLE_TABLE)]),
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


class ExplodingWriter:
    """Audit writer that always raises."""

    def write(self, event: AuditEvent) -> None:
        raise RuntimeError("audit pipeline failure")


class ExplodingRule:
    """Policy rule that always raises an unhandled exception."""

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: Any = None,
        context: Any = None,
    ) -> Decision:
        raise RuntimeError("rule internal failure")


class ExplicitDenyRule:
    """Policy rule that explicitly denies every request it receives."""

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: Any = None,
        context: Any = None,
    ) -> Decision:
        return Decision(
            outcome=PolicyOutcome.DENY,
            reason="explicit deny from test rule",
            evaluated_by="ExplicitDenyRule",
        )


class ExplicitAllowRule:
    """Policy rule that explicitly allows every request it receives."""

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: Any = None,
        context: Any = None,
    ) -> Decision:
        return Decision(
            outcome=PolicyOutcome.ALLOW,
            reason="explicit allow from test rule",
            evaluated_by="ExplicitAllowRule",
        )


# ── Core behavior ──────────────────────────────────────────────────────────────


def test_allowed_request_returns_allow_outcome() -> None:
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request("write:hvac:setpoint")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.ALLOW
    assert response.allowed is True
    assert response.failure_reason is None


def test_denied_request_returns_deny_outcome() -> None:
    ep = make_ep()
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    request = make_request("write:hvac:setpoint")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False
    assert response.failure_reason is None


def test_default_deny_when_no_rule_covers_action() -> None:
    """NOT_APPLICABLE from all rules → default deny at the enforcement point."""
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    # Use an action not in the role table so all rules return NOT_APPLICABLE.
    request = make_request("read:sensor:temperature")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.NOT_APPLICABLE
    assert response.allowed is False
    assert response.failure_reason is None


def test_deny_overrides_allow_when_both_rules_evaluate() -> None:
    """A single DENY overrides any number of ALLOWs (deny-overrides semantics)."""
    ep = make_ep(policies=[ExplicitAllowRule(), ExplicitDenyRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request("write:hvac:setpoint")
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False
    assert response.failure_reason is None


# ── Audit coverage ─────────────────────────────────────────────────────────────


def test_allow_decision_is_recorded_in_audit_log() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request(), subject=subject)
    assert len(captured) == 1
    assert captured[0].outcome == AuditOutcome.ALLOWED


def test_deny_decision_is_recorded_in_audit_log() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    ep.evaluate(make_request(), subject=subject)
    assert len(captured) == 1
    assert captured[0].outcome == AuditOutcome.DENIED


def test_default_deny_is_recorded_as_denied_in_audit() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request("read:sensor:temperature"), subject=subject)
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
    response = ep.evaluate(make_request(), subject=subject)
    assert response.policy_version == "test-v1"


# ── Fail-closed: malformed request ────────────────────────────────────────────


def test_malformed_request_dict_fails_closed() -> None:
    """A raw dict with invalid fields produces a safe DENY, not an exception."""
    ep = make_ep()
    # Missing required 'action'; subject_id is empty (also invalid).
    bad_dict: dict[str, object] = {"subject_id": "", "resource_id": "hvac:zone-a"}
    response = ep.evaluate(bad_dict)  # type: ignore[arg-type]
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False
    assert response.failure_reason == FailureReason.MALFORMED_REQUEST


def test_valid_dict_request_is_accepted() -> None:
    """A raw dict that passes validation produces a normal decision."""
    ep = make_ep()
    good_dict: dict[str, object] = {
        "subject_id": "u1",
        "subject_roles": ["operator"],
        "resource_id": "hvac:zone-a",
        "action": "write:hvac:setpoint",
    }
    response = ep.evaluate(good_dict)  # type: ignore[arg-type]
    assert response.outcome == DecisionOutcome.ALLOW
    assert response.failure_reason is None


def test_malformed_request_reason_does_not_leak_internals() -> None:
    """The reason returned to the caller must not contain raw exception text."""
    ep = make_ep()
    bad_dict: dict[str, object] = {"subject_id": "x"}
    response = ep.evaluate(bad_dict)  # type: ignore[arg-type]
    # Should be the safe, human-readable string — not a traceback or Pydantic dump.
    assert "ValidationError" not in response.reason
    assert "traceback" not in response.reason.lower()
    assert len(response.reason) < 300  # sanity: not a raw exception dump


# ── Fail-closed: policy evaluation errors ─────────────────────────────────────


def test_policy_exception_fails_closed() -> None:
    """An unhandled exception inside a policy rule produces a safe DENY."""
    captured: list[AuditEvent] = []
    ep = make_ep(captured=captured, policies=[ExplodingRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request()
    response = ep.evaluate(request, subject=subject)
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False
    assert response.failure_reason == FailureReason.POLICY_ERROR


def test_policy_exception_is_recorded_as_error_in_audit() -> None:
    """A policy evaluation error produces an AuditOutcome.ERROR record."""
    captured: list[AuditEvent] = []
    ep = make_ep(captured=captured, policies=[ExplodingRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request(), subject=subject)
    assert len(captured) == 1
    assert captured[0].outcome == AuditOutcome.ERROR


def test_policy_exception_reason_does_not_leak_internals() -> None:
    """Raw exception text from a failing rule must not reach the caller."""
    ep = make_ep(policies=[ExplodingRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    # The rule raised RuntimeError("rule internal failure") — that text must
    # not appear in the caller-visible reason string.
    assert "rule internal failure" not in response.reason
    assert "RuntimeError" not in response.reason


# ── Audit writer resilience ────────────────────────────────────────────────────


def test_audit_writer_exception_does_not_reverse_allow_decision() -> None:
    """If the audit writer raises, the ALLOW decision stands."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=ExplodingWriter(),
        policy_version="test-v1",
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.outcome == DecisionOutcome.ALLOW
    assert response.allowed is True


def test_audit_writer_exception_does_not_reverse_deny_decision() -> None:
    """If the audit writer raises, the DENY decision stands."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=ExplodingWriter(),
        policy_version="test-v1",
    )
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.outcome == DecisionOutcome.DENY
    assert response.allowed is False


def test_audit_writer_exception_does_not_raise_to_caller() -> None:
    """An audit write failure must never propagate as an exception to the caller."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=ExplodingWriter(),
        policy_version="test-v1",
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    # This must not raise:
    response = ep.evaluate(make_request(), subject=subject)
    assert response is not None


# ── Correlation fields ─────────────────────────────────────────────────────────


def test_correlation_id_is_forwarded_to_audit_event() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request(), subject=subject, correlation_id="trace-abc-123")
    assert captured[0].correlation_id == "trace-abc-123"


def test_decision_id_matches_request_id_in_audit_event() -> None:
    captured: list[AuditEvent] = []
    ep = make_ep(captured)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    request = make_request()
    ep.evaluate(request, subject=subject)
    assert captured[0].decision_id == request.request_id


# ── Import boundary ────────────────────────────────────────────────────────────


def test_enforcement_module_does_not_import_protocol_packages() -> None:
    """
    The enforcement module must not directly import protocol-specific packages.
    Importing bacnet, modbus, mqtt, opcua, or similar would violate the
    protocol-neutrality constraint on the enforcement boundary.
    """
    # Reload to ensure we see the current import state, not a cached module.
    module = importlib.import_module("basis_core.enforcement.enforcement")
    # Collect all modules imported by the enforcement module itself.
    enforcement_file = getattr(module, "__file__", "")
    forbidden_prefixes = ("bacnet", "modbus", "mqtt", "opcua", "pymodbus", "pybacnet")

    for name in sys.modules:
        for prefix in forbidden_prefixes:
            assert not name.startswith(prefix), (
                f"enforcement module imported protocol package: {name!r}"
            )

    # Also assert the enforcement module itself doesn't reference these names
    # in its source, as a belt-and-suspenders check.
    if enforcement_file:
        with open(enforcement_file) as f:
            source = f.read()
        for prefix in forbidden_prefixes:
            assert prefix not in source, (
                f"enforcement source references forbidden package: {prefix!r}"
            )


# ── Failure reason is absent for normal decisions ──────────────────────────────


def test_successful_allow_has_no_failure_reason() -> None:
    ep = make_ep()
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.failure_reason is None


def test_successful_deny_has_no_failure_reason() -> None:
    ep = make_ep()
    subject = Subject(id="u2", name="bob", roles=["viewer"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.failure_reason is None


# ── Deny-overrides: single DENY in a multi-rule chain ─────────────────────────


def test_deny_overrides_when_deny_comes_before_allow() -> None:
    ep = make_ep(policies=[ExplicitDenyRule(), ExplicitAllowRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.outcome == DecisionOutcome.DENY


def test_deny_overrides_when_deny_comes_after_allow() -> None:
    ep = make_ep(policies=[ExplicitAllowRule(), ExplicitDenyRule()])
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.outcome == DecisionOutcome.DENY


@pytest.mark.parametrize("n_allows", [1, 3, 5])
def test_deny_overrides_any_number_of_allows(n_allows: int) -> None:
    policies: list[Any] = [ExplicitAllowRule()] * n_allows + [ExplicitDenyRule()]
    ep = make_ep(policies=policies)
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.outcome == DecisionOutcome.DENY


# ── Public policy_version accessor ────────────────────────────────────────────


def test_policy_version_property_returns_configured_value() -> None:
    """EnforcementPoint.policy_version exposes the value set at construction."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
        policy_version="v2.3.1",
    )
    assert ep.policy_version == "v2.3.1"


def test_policy_version_property_returns_none_when_not_set() -> None:
    """EnforcementPoint.policy_version is None when no version was provided."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
    )
    assert ep.policy_version is None


def test_policy_version_property_is_read_only() -> None:
    """EnforcementPoint.policy_version must not be assignable."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
        policy_version="v1",
    )
    with pytest.raises(AttributeError):
        ep.policy_version = "v2"  # type: ignore[misc]


def test_policy_version_propagates_to_response() -> None:
    """policy_version set on the EP appears verbatim in every DecisionResponse."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
        policy_version="release-42",
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.policy_version == "release-42"


def test_policy_version_none_propagates_to_response() -> None:
    """A None policy_version on the EP produces None in the DecisionResponse."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    response = ep.evaluate(make_request(), subject=subject)
    assert response.policy_version is None


def test_policy_version_propagates_to_audit_event() -> None:
    """policy_version set on the EP appears in the AuditEvent."""
    captured: list[AuditEvent] = []
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_capturing_writer(captured),
        policy_version="audit-v9",
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request(), subject=subject)
    assert len(captured) == 1
    assert captured[0].policy_version == "audit-v9"


def test_policy_version_none_propagates_to_audit_event() -> None:
    """A None policy_version on the EP produces None in the AuditEvent."""
    captured: list[AuditEvent] = []
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_capturing_writer(captured),
    )
    subject = Subject(id="u1", name="alice", roles=["operator"])
    ep.evaluate(make_request(), subject=subject)
    assert len(captured) == 1
    assert captured[0].policy_version is None


def test_policy_version_accessible_without_private_access() -> None:
    """Callers must be able to read policy_version without touching _policy_version."""
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)]),
        audit_writer=_null_writer(),
        policy_version="public-only",
    )
    # Access via the public property only — no underscore attribute.
    version = ep.policy_version
    assert version == "public-only"


# ── Private helpers for new tests ─────────────────────────────────────────────


def _null_writer() -> Any:
    class NullWriter:
        def write(self, event: AuditEvent) -> None:
            pass

    return NullWriter()


def _capturing_writer(target: list[AuditEvent]) -> Any:
    class CapturingWriter:
        def write(self, event: AuditEvent) -> None:
            target.append(event)

    return CapturingWriter()
