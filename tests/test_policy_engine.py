"""
Tests for basis_core.policy.engine — PolicyEngine and Decision.

These tests verify the chain-of-responsibility evaluation behavior without
any I/O, network, or infrastructure dependency. All inputs are constructed
directly as domain objects.
"""

from __future__ import annotations

from typing import Optional

from basis_core.domain.subject import Subject, SubjectType
from basis_core.policy.engine import Decision, PolicyEngine
from basis_core.policy.rules import RolePolicy


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
    "read:audit:log":      {"admin"},
    "read:resources":      {"viewer", "operator", "admin"},
}


# ── PolicyEngine behavior ──────────────────────────────────────────────────────

def test_engine_allows_when_subject_holds_permitted_role() -> None:
    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    subject = make_subject(roles=["operator"])
    result = engine.evaluate(subject, "write:hvac:setpoint", "hvac:zone-a")
    assert result.allowed is True


def test_engine_denies_when_subject_lacks_required_role() -> None:
    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    subject = make_subject(roles=["viewer"])
    result = engine.evaluate(subject, "write:hvac:setpoint", "hvac:zone-a")
    assert result.allowed is False


def test_engine_fails_closed_for_unknown_action() -> None:
    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    subject = make_subject(roles=["admin"])
    result = engine.evaluate(subject, "unknown:action:not:in:table")
    assert result.allowed is False
    assert "PolicyEngine" in result.evaluated_by


def test_engine_allows_admin_where_only_admin_permitted() -> None:
    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    subject = make_subject(roles=["admin"])
    result = engine.evaluate(subject, "read:audit:log")
    assert result.allowed is True


def test_engine_denies_operator_on_admin_only_action() -> None:
    engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
    subject = make_subject(roles=["operator"])
    result = engine.evaluate(subject, "read:audit:log")
    assert result.allowed is False


def test_engine_chain_passes_through_to_second_policy() -> None:
    """A policy returning None for an unknown action passes to the next."""

    class AllowEverythingPolicy:
        def evaluate(self, subject, action, resource_id=None):
            return Decision(
                allowed=True,
                reason="AllowEverythingPolicy: unconditional allow",
                evaluated_by="AllowEverythingPolicy",
            )

    engine = PolicyEngine(policies=[
        RolePolicy(ROLE_TABLE),      # Does not cover "custom:action"
        AllowEverythingPolicy(),     # Covers everything
    ])
    subject = make_subject(roles=[])
    result = engine.evaluate(subject, "custom:action:not:in:role:table")
    assert result.allowed is True
    assert result.evaluated_by == "AllowEverythingPolicy"


def test_decision_repr_includes_verdict() -> None:
    allow = Decision(allowed=True, reason="ok", evaluated_by="TestPolicy")
    deny  = Decision(allowed=False, reason="no", evaluated_by="TestPolicy")
    assert "ALLOW" in repr(allow)
    assert "DENY"  in repr(deny)
