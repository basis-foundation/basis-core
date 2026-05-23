"""
Tests for Phase 1D: audit contract and decision traceability.

Covers:
  - All four decision paths produce correct AuditEvent records:
      allow, explicit deny, default deny (not_applicable), deny-overrides
  - Audit writer failure is caught, logged, and does not change the decision
  - AuditEvent rejects timezone-naive timestamps
  - AuditEvent serialization matches schema expectations
  - DecisionTrace and RuleEvaluation construction and properties
  - matched_rules populated correctly (allow/deny rules only, not not_applicable)
  - correlation_id passed through from evaluate() to AuditEvent
  - decision_id defaults to request_id
  - Import boundary: audit must not import api or adapters
"""

from __future__ import annotations

import ast
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from basis_core.api.enforcement import EnforcementPoint
from basis_core.audit.events import AUDIT_SCHEMA_VERSION, AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.audit.writer import LogAuditWriter, NullAuditWriter
from basis_core.decisions.models import DecisionOutcome, DecisionRequest
from basis_core.domain.subject import Subject, SubjectType
from basis_core.policy.engine import PolicyEngine, PolicyOutcome
from basis_core.policy.rules import ActionPolicyRule, RolePolicyRule

# ── Shared helpers ──────────────────────────────────────────────────────────────


def make_subject(roles: list[str] | None = None, name: str = "alice") -> Subject:
    return Subject(
        id=f"uid-{name}",
        name=name,
        type=SubjectType.HUMAN,
        roles=roles or [],
    )


def make_request(
    action: str = "write:hvac:setpoint",
    resource_id: str | None = "hvac:zone-a",
    subject_id: str = "uid-alice",
    roles: list[str] | None = None,
) -> DecisionRequest:
    return DecisionRequest(
        subject_id=subject_id,
        subject_roles=roles or ["operator"],
        resource_id=resource_id,
        action=action,
    )


ROLE_TABLE: dict[str, set[str]] = {
    "write:hvac:setpoint": {"operator", "admin"},
    "read:audit:log": {"admin"},
    "read:resources": {"viewer", "operator", "admin"},
}


class CapturingWriter:
    """AuditWriter that stores events for assertion."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    @property
    def last(self) -> AuditEvent:
        assert self.events, "No events were written"
        return self.events[-1]


def make_ep(
    writer: CapturingWriter | None = None, rules=None
) -> tuple[EnforcementPoint, CapturingWriter]:
    w = writer or CapturingWriter()
    engine = PolicyEngine(policies=rules or [RolePolicyRule(ROLE_TABLE)])
    ep = EnforcementPoint(engine=engine, audit_writer=w, policy_version="v1.1.0")
    return ep, w


# ── AuditEvent model validation ─────────────────────────────────────────────────


class TestAuditEventModel:
    def test_minimal_event_constructs(self) -> None:
        event = AuditEvent(action="read:resources")
        assert event.action == "read:resources"
        assert event.event_id
        assert event.timestamp.tzinfo is not None

    def test_schema_version_defaults_to_current(self) -> None:
        event = AuditEvent(action="read:resources")
        assert event.schema_version == AUDIT_SCHEMA_VERSION

    def test_empty_event_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="event_id"):
            AuditEvent(action="read:resources", event_id="")

    def test_empty_action_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="action"):
            AuditEvent(action="")

    def test_timezone_naive_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            AuditEvent(action="read:resources", timestamp=datetime(2026, 1, 1))

    def test_timezone_aware_timestamp_is_accepted(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        event = AuditEvent(action="read:resources", timestamp=ts)
        assert event.timestamp == ts

    def test_event_is_frozen(self) -> None:
        event = AuditEvent(action="read:resources")
        with pytest.raises(Exception):
            event.action = "write:hvac:setpoint"  # type: ignore[misc]

    def test_new_correlation_fields_default_to_none(self) -> None:
        event = AuditEvent(action="read:resources")
        assert event.decision_id is None
        assert event.correlation_id is None
        assert event.request_id is None

    def test_matched_rules_defaults_to_empty(self) -> None:
        event = AuditEvent(action="read:resources")
        assert event.matched_rules == []

    def test_trace_defaults_to_none(self) -> None:
        event = AuditEvent(action="read:resources")
        assert event.trace is None

    def test_full_event_serializes_to_json(self) -> None:
        trace = DecisionTrace(
            final_outcome="allow",
            evaluated_rules=[
                RuleEvaluation(rule_name="RolePolicyRule", outcome="allow", reason="ok")
            ],
            short_circuited=False,
        )
        event = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            action="write:hvac:setpoint",
            subject_id="uid-alice",
            subject_name="alice",
            subject_type="human",
            subject_roles=["operator"],
            resource_id="hvac:zone-a",
            outcome=AuditOutcome.ALLOWED,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.1.0",
            request_id="req-001",
            decision_id="req-001",
            matched_rules=["RolePolicyRule"],
            trace=trace,
        )
        data = event.model_dump(mode="json")
        serialized = json.dumps(data)
        parsed = json.loads(serialized)
        assert parsed["outcome"] == "allowed"
        assert parsed["matched_rules"] == ["RolePolicyRule"]
        assert parsed["trace"]["final_outcome"] == "allow"
        assert parsed["schema_version"] == AUDIT_SCHEMA_VERSION


# ── DecisionTrace and RuleEvaluation ───────────────────────────────────────────


class TestDecisionTrace:
    def test_rule_evaluation_constructs(self) -> None:
        re = RuleEvaluation(rule_name="MyRule", outcome="allow", reason="ok")
        assert re.rule_name == "MyRule"
        assert re.outcome == "allow"
        assert re.reason == "ok"

    def test_rule_evaluation_is_frozen(self) -> None:
        re = RuleEvaluation(rule_name="MyRule", outcome="allow", reason="ok")
        with pytest.raises(Exception):
            re.outcome = "deny"  # type: ignore[misc]

    def test_decision_trace_constructs(self) -> None:
        trace = DecisionTrace(
            final_outcome="deny",
            evaluated_rules=[
                RuleEvaluation(rule_name="RulA", outcome="allow", reason="ok"),
                RuleEvaluation(rule_name="RulB", outcome="deny", reason="no"),
            ],
            short_circuited=True,
        )
        assert trace.final_outcome == "deny"
        assert len(trace.evaluated_rules) == 2
        assert trace.short_circuited is True

    def test_matched_rule_names_excludes_not_applicable(self) -> None:
        trace = DecisionTrace(
            final_outcome="allow",
            evaluated_rules=[
                RuleEvaluation(rule_name="SkipRule", outcome="not_applicable", reason="n/a"),
                RuleEvaluation(rule_name="AllowRule", outcome="allow", reason="ok"),
            ],
        )
        assert trace.matched_rule_names == ["AllowRule"]

    def test_matched_rule_names_empty_when_all_not_applicable(self) -> None:
        trace = DecisionTrace(
            final_outcome="not_applicable",
            evaluated_rules=[
                RuleEvaluation(rule_name="RoleRule", outcome="not_applicable", reason="n/a"),
            ],
        )
        assert trace.matched_rule_names == []

    def test_matched_rule_names_includes_both_allow_and_deny(self) -> None:
        trace = DecisionTrace(
            final_outcome="deny",
            evaluated_rules=[
                RuleEvaluation(rule_name="AllowRule", outcome="allow", reason="ok"),
                RuleEvaluation(rule_name="DenyRule", outcome="deny", reason="no"),
            ],
        )
        assert "AllowRule" in trace.matched_rule_names
        assert "DenyRule" in trace.matched_rule_names


# ── EnforcementPoint audit output: all four decision paths ─────────────────────


class TestEnforcementPointAuditPaths:
    def test_allow_decision_produces_correct_audit_event(self) -> None:
        ep, writer = make_ep()
        subject = make_subject(["operator"])
        request = make_request("write:hvac:setpoint", roles=["operator"])
        response = ep.evaluate(request, subject=subject)
        assert response.outcome == DecisionOutcome.ALLOW
        assert len(writer.events) == 1
        event = writer.last
        assert event.outcome == AuditOutcome.ALLOWED
        assert event.event_type == AuditEventType.AUTHORIZATION_DECISION
        assert event.action == "write:hvac:setpoint"
        assert event.subject_id == subject.id
        assert event.subject_name == subject.name
        assert "RolePolicyRule" in event.matched_rules

    def test_explicit_deny_produces_correct_audit_event(self) -> None:
        ep, writer = make_ep()
        subject = make_subject(["viewer"])
        request = make_request("write:hvac:setpoint", roles=["viewer"])
        response = ep.evaluate(request, subject=subject)
        assert response.outcome == DecisionOutcome.DENY
        event = writer.last
        assert event.outcome == AuditOutcome.DENIED
        assert "RolePolicyRule" in event.matched_rules
        assert event.reason
        assert "viewer" in event.reason or "operator" in event.reason

    def test_default_deny_produces_correct_audit_event(self) -> None:
        ep, writer = make_ep()
        subject = make_subject(["admin"])
        request = make_request("invoke:unknown:action", resource_id=None, roles=["admin"])
        response = ep.evaluate(request, subject=subject)
        assert response.outcome == DecisionOutcome.NOT_APPLICABLE
        event = writer.last
        assert event.outcome == AuditOutcome.DENIED  # NOT_APPLICABLE → denied in audit
        assert event.evaluated_by == "PolicyEngine"
        assert event.matched_rules == []  # no rule matched
        assert event.trace is not None
        assert event.trace.final_outcome == "not_applicable"

    def test_deny_overrides_produces_correct_audit_event(self) -> None:
        """Allow from one rule is overridden by Deny from another; trace shows both."""
        allow_rule = ActionPolicyRule(
            {"write:hvac:setpoint": PolicyOutcome.ALLOW}, rule_name="AllowRule"
        )
        deny_rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}}, rule_name="RoleRule")
        ep, writer = make_ep(rules=[allow_rule, deny_rule])
        subject = make_subject(["viewer"])
        request = make_request("write:hvac:setpoint", roles=["viewer"])
        response = ep.evaluate(request, subject=subject)
        assert response.outcome == DecisionOutcome.DENY
        event = writer.last
        assert event.outcome == AuditOutcome.DENIED
        assert "AllowRule" in event.matched_rules
        assert "RoleRule" in event.matched_rules
        assert event.trace is not None
        # The trace should show AllowRule→allow and RoleRule→deny
        outcomes = {r.rule_name: r.outcome for r in event.trace.evaluated_rules}
        assert outcomes.get("AllowRule") == "allow"
        assert outcomes.get("RoleRule") == "deny"
        assert event.trace.final_outcome == "deny"

    def test_audit_event_contains_request_id(self) -> None:
        ep, writer = make_ep()
        request = make_request()
        ep.evaluate(request, subject=make_subject(["operator"]))
        assert writer.last.request_id == request.request_id

    def test_decision_id_defaults_to_request_id(self) -> None:
        ep, writer = make_ep()
        request = make_request()
        ep.evaluate(request, subject=make_subject(["operator"]))
        assert writer.last.decision_id == request.request_id

    def test_correlation_id_passed_through_to_audit_event(self) -> None:
        ep, writer = make_ep()
        request = make_request()
        ep.evaluate(request, subject=make_subject(["operator"]), correlation_id="trace-xyz")
        assert writer.last.correlation_id == "trace-xyz"

    def test_correlation_id_none_when_not_provided(self) -> None:
        ep, writer = make_ep()
        request = make_request()
        ep.evaluate(request, subject=make_subject(["operator"]))
        assert writer.last.correlation_id is None

    def test_audit_event_includes_policy_version(self) -> None:
        ep, writer = make_ep()
        ep.evaluate(make_request(), subject=make_subject(["operator"]))
        assert writer.last.policy_version == "v1.1.0"

    def test_trace_populated_for_allow(self) -> None:
        ep, writer = make_ep()
        ep.evaluate(make_request(), subject=make_subject(["operator"]))
        trace = writer.last.trace
        assert trace is not None
        assert trace.final_outcome == "allow"
        assert any(r.outcome == "allow" for r in trace.evaluated_rules)

    def test_trace_populated_for_deny(self) -> None:
        ep, writer = make_ep()
        ep.evaluate(make_request(), subject=make_subject(["viewer"]))
        trace = writer.last.trace
        assert trace is not None
        assert trace.final_outcome == "deny"
        assert any(r.outcome == "deny" for r in trace.evaluated_rules)

    def test_schema_version_present_in_audit_event(self) -> None:
        ep, writer = make_ep()
        ep.evaluate(make_request(), subject=make_subject(["operator"]))
        assert writer.last.schema_version == AUDIT_SCHEMA_VERSION


# ── Audit writer failure: decision must not change ──────────────────────────────


class TestAuditWriterFailure:
    class ExplodingWriter:
        def write(self, event: AuditEvent) -> None:
            raise RuntimeError("Storage unavailable")

    def test_audit_write_failure_does_not_change_allow_decision(self) -> None:
        engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
        ep = EnforcementPoint(
            engine=engine,
            audit_writer=self.ExplodingWriter(),
            policy_version="v1.1.0",
        )
        subject = make_subject(["operator"])
        response = ep.evaluate(make_request("write:hvac:setpoint"), subject=subject)
        # Decision stands even though audit write failed.
        assert response.outcome == DecisionOutcome.ALLOW

    def test_audit_write_failure_does_not_change_deny_decision(self) -> None:
        engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
        ep = EnforcementPoint(
            engine=engine,
            audit_writer=self.ExplodingWriter(),
            policy_version="v1.1.0",
        )
        subject = make_subject(["viewer"])
        response = ep.evaluate(make_request("write:hvac:setpoint"), subject=subject)
        assert response.outcome == DecisionOutcome.DENY

    def test_audit_write_failure_is_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
        ep = EnforcementPoint(
            engine=engine,
            audit_writer=self.ExplodingWriter(),
        )
        with caplog.at_level(logging.ERROR, logger="basis_core.api.enforcement"):
            ep.evaluate(make_request(), subject=make_subject(["operator"]))
        assert any("audit" in msg.lower() or "write" in msg.lower() for msg in caplog.messages)

    def test_null_writer_discards_silently(self) -> None:
        engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
        ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter())
        response = ep.evaluate(make_request(), subject=make_subject(["operator"]))
        assert response.outcome == DecisionOutcome.ALLOW


# ── LogAuditWriter ──────────────────────────────────────────────────────────────


class TestLogAuditWriter:
    def test_log_writer_emits_json(self, caplog: pytest.LogCaptureFixture) -> None:
        writer = LogAuditWriter()
        event = AuditEvent(
            action="read:resources",
            outcome=AuditOutcome.ALLOWED,
            reason="ok",
        )
        with caplog.at_level(logging.INFO, logger="basis_core.audit"):
            writer.write(event)
        assert caplog.records
        # The log message should be valid JSON.
        json.loads(caplog.records[-1].message)

    def test_log_writer_does_not_raise_on_malformed_event(self) -> None:
        """LogAuditWriter must swallow serialization errors, not propagate them."""
        writer = LogAuditWriter()

        class BadEvent:
            event_id = "x"

            def model_dump(self, **kwargs: Any) -> dict:
                raise ValueError("cannot serialize")

        # Should not raise.
        writer.write(BadEvent())  # type: ignore[arg-type]


# ── Audit import boundaries ─────────────────────────────────────────────────────


class TestAuditImportBoundaries:
    """
    Statically verify that the audit package does not import from api or adapters.
    Uses ast.parse() — no module execution required.
    """

    AUDIT_DIR = Path(__file__).parent.parent / "src" / "basis_core" / "audit"

    def _collect_imports(self, path: Path) -> list[str]:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        return imports

    def _all_audit_imports(self) -> list[str]:
        imports: list[str] = []
        for path in self.AUDIT_DIR.glob("*.py"):
            imports.extend(self._collect_imports(path))
        return imports

    def test_audit_does_not_import_from_api(self) -> None:
        imports = self._all_audit_imports()
        bad = [m for m in imports if "basis_core.api" in m]
        assert bad == [], f"audit imports from api: {bad}"

    def test_audit_does_not_import_from_adapters(self) -> None:
        imports = self._all_audit_imports()
        bad = [m for m in imports if "basis_core.adapters" in m]
        assert bad == [], f"audit imports from adapters: {bad}"

    def test_audit_does_not_import_from_policy(self) -> None:
        imports = self._all_audit_imports()
        bad = [m for m in imports if "basis_core.policy" in m]
        assert bad == [], f"audit imports from policy: {bad}"
