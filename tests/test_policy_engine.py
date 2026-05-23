"""
Tests for basis_core.policy.engine — PolicyEngine, Decision, and PolicyOutcome.

These tests verify the deny-overrides evaluation behavior without any I/O,
network, or infrastructure dependency. All inputs are constructed directly
as domain objects.
"""

from __future__ import annotations

from basis_core.domain.subject import Subject, SubjectType
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome
from basis_core.policy.rules import RolePolicyRule

# ── Fixtures ───────────────────────────────────────────────────────────────────


def make_subject(
    roles: list[str] | None = None,
    subject_type: SubjectType = SubjectType.HUMAN,
) -> Subject:
    return Subject(
        id="test-subject-id",
        name="test-subject",
        type=subject_type,
        roles=roles or [],
    )


ROLE_TABLE: dict[str, set[str]] = {
    "write:hvac:setpoint": {"operator", "admin"},
    "read:audit:log": {"admin"},
    "read:resources": {"viewer", "operator", "admin"},
}


# ── PolicyEngine deny-overrides behavior ───────────────────────────────────────


def test_engine_allows_when_subject_holds_permitted_role() -> None:
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    subject = make_subject(roles=["operator"])
    result = engine.evaluate(subject, "write:hvac:setpoint", resource_id="hvac:zone-a")
    assert result.allowed is True
    assert result.outcome == PolicyOutcome.ALLOW


def test_engine_denies_when_subject_lacks_required_role() -> None:
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    subject = make_subject(roles=["viewer"])
    result = engine.evaluate(subject, "write:hvac:setpoint", resource_id="hvac:zone-a")
    assert result.allowed is False
    assert result.outcome == PolicyOutcome.DENY


def test_engine_returns_not_applicable_for_unknown_action() -> None:
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    subject = make_subject(roles=["admin"])
    result = engine.evaluate(subject, "unknown:action:x")
    assert result.allowed is False
    assert result.outcome == PolicyOutcome.NOT_APPLICABLE
    assert "PolicyEngine" in result.evaluated_by


def test_engine_allows_admin_where_only_admin_permitted() -> None:
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    subject = make_subject(roles=["admin"])
    result = engine.evaluate(subject, "read:audit:log")
    assert result.allowed is True


def test_engine_denies_operator_on_admin_only_action() -> None:
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    subject = make_subject(roles=["operator"])
    result = engine.evaluate(subject, "read:audit:log")
    assert result.outcome == PolicyOutcome.DENY


def test_engine_second_rule_handles_uncovered_action() -> None:
    """A NOT_APPLICABLE result from the first rule does not block the second."""

    class AllowEverythingRule:
        def evaluate(
            self, subject, action, resource_id=None, identity_context=None, context=None
        ) -> Decision:
            return Decision(
                outcome=PolicyOutcome.ALLOW,
                reason="AllowEverythingRule: unconditional allow",
                evaluated_by="AllowEverythingRule",
            )

    engine = PolicyEngine(
        policies=[
            RolePolicyRule(ROLE_TABLE),  # NOT_APPLICABLE for "custom:action"
            AllowEverythingRule(),  # ALLOW for everything
        ]
    )
    subject = make_subject(roles=[])
    result = engine.evaluate(subject, "custom:action:x")
    assert result.allowed is True
    assert result.evaluated_by == "AllowEverythingRule"


def test_deny_overrides_allow() -> None:
    """A DENY from any rule overrides an ALLOW from another, regardless of order."""

    class AlwaysDenyRule:
        def evaluate(
            self, subject, action, resource_id=None, identity_context=None, context=None
        ) -> Decision:
            return Decision(
                outcome=PolicyOutcome.DENY,
                reason="AlwaysDenyRule: unconditional deny",
                evaluated_by="AlwaysDenyRule",
            )

    class AlwaysAllowRule:
        def evaluate(
            self, subject, action, resource_id=None, identity_context=None, context=None
        ) -> Decision:
            return Decision(
                outcome=PolicyOutcome.ALLOW,
                reason="AlwaysAllowRule: unconditional allow",
                evaluated_by="AlwaysAllowRule",
            )

    # DENY rule appears after ALLOW rule — DENY must still win.
    engine = PolicyEngine(policies=[AlwaysAllowRule(), AlwaysDenyRule()])
    subject = make_subject(roles=["admin"])
    result = engine.evaluate(subject, "write:hvac:setpoint")
    assert result.outcome == PolicyOutcome.DENY
    assert result.evaluated_by == "AlwaysDenyRule"


def test_engine_is_stateless() -> None:
    """Two successive calls with different subjects return independent results."""
    engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
    operator = make_subject(roles=["operator"])
    viewer = make_subject(roles=["viewer"])
    result_a = engine.evaluate(operator, "write:hvac:setpoint")
    result_b = engine.evaluate(viewer, "write:hvac:setpoint")
    assert result_a.outcome == PolicyOutcome.ALLOW
    assert result_b.outcome == PolicyOutcome.DENY


# ── Decision class ─────────────────────────────────────────────────────────────


def test_decision_repr_includes_verdict() -> None:
    allow = Decision(outcome=PolicyOutcome.ALLOW, reason="ok", evaluated_by="TestRule")
    deny = Decision(outcome=PolicyOutcome.DENY, reason="no", evaluated_by="TestRule")
    na = Decision(outcome=PolicyOutcome.NOT_APPLICABLE, reason="n/a", evaluated_by="TestRule")
    assert "ALLOW" in repr(allow)
    assert "DENY" in repr(deny)
    assert "NOT_APPLICABLE" in repr(na)


def test_decision_allowed_property() -> None:
    allow = Decision(outcome=PolicyOutcome.ALLOW, reason="ok", evaluated_by="T")
    deny = Decision(outcome=PolicyOutcome.DENY, reason="no", evaluated_by="T")
    na = Decision(outcome=PolicyOutcome.NOT_APPLICABLE, reason="n/a", evaluated_by="T")
    assert allow.allowed is True
    assert deny.allowed is False
    assert na.allowed is False
