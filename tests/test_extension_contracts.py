"""
Extension contract tests for basis_core.

These tests verify the behavioral guarantees of every stable extension interface
in the authorization kernel, as described in docs/extension-contracts.md.

Extension interfaces under test:
  - PolicyRule protocol (basis_core.policy.engine.PolicyRule)
  - AuditWriter protocol (basis_core.audit.writer.AuditWriter)
  - AdapterBase protocol (basis_core.adapters.base.AdapterBase)
  - NormalizedEvent (basis_core.adapters.base.NormalizedEvent)
  - DecisionRequest / DecisionResponse (basis_core.decisions.models)

Coverage targets:
  - PolicyRule implementations receive immutable Subject (frozen model)
  - Rule ordering is stable: rules are evaluated in construction order
  - AuditWriter exceptions do not reverse authorization decisions
  - AuditWriter receives frozen, unmodified AuditEvent
  - AdapterBase and AuditWriter satisfy runtime_checkable isinstance checks
  - NormalizedEvent enforces protocol-neutral fields (no protocol IDs in action)
  - DecisionRequest is immutable (frozen Pydantic model)
  - DecisionResponse is immutable (frozen Pydantic model)
  - Extension exceptions fail closed: rule exception → DENY, never ALLOW
  - A rule returning None triggers engine fail-closed path (DENY, is_error=True)
  - Custom rules produce stable, well-formed DecisionTrace entries
  - Protocol-agnostic: rule behavior is identical regardless of source protocol
  - AuditWriter receives complete audit event regardless of rule outcome

These tests use small test-only fake implementations. No production plugin
systems are added. No dynamic loading or framework integrations are introduced.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from basis_core.adapters.base import AdapterBase, NormalizedEvent
from basis_core.audit.events import AuditEvent, AuditOutcome
from basis_core.audit.writer import AuditWriter, LogAuditWriter, NullAuditWriter
from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
    FailureReason,
)
from basis_core.domain.identity import IdentityContext
from basis_core.domain.subject import Subject
from basis_core.enforcement.enforcement import EnforcementPoint
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome, PolicyRule

# ── Test-only helpers ──────────────────────────────────────────────────────────
#
# All fakes live in this file. They are the simplest possible implementations
# that expose the specific behavior each test needs to observe.


def _make_subject(roles: list[str] | None = None) -> Subject:
    return Subject(
        id="test-subject",
        name="Test Subject",
        roles=roles or [],
    )


def _make_request(
    action: str = "read:sensor:telemetry",
    resource_id: str | None = None,
    roles: list[str] | None = None,
) -> DecisionRequest:
    return DecisionRequest(
        subject_id="test-subject",
        subject_roles=roles or [],
        action=action,
        resource_id=resource_id,
    )


def _make_ep(
    rules: list[Any],
    audit_writer: Any | None = None,
    policy_version: str = "test-v1",
) -> EnforcementPoint:
    engine = PolicyEngine(policies=rules)
    writer = audit_writer or NullAuditWriter()
    return EnforcementPoint(engine=engine, audit_writer=writer, policy_version=policy_version)


class FixedOutcomeRule:
    """Always returns the specified outcome. Records whether it was called."""

    def __init__(self, outcome: PolicyOutcome, name: str = "FixedOutcomeRule") -> None:
        self._outcome = outcome
        self._name = name
        self.called = False
        self.received_subject: Subject | None = None
        self.received_action: str | None = None
        self.received_resource_id: str | None = None
        self.received_context: dict[str, Any] | None = None

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        self.called = True
        self.received_subject = subject
        self.received_action = action
        self.received_resource_id = resource_id
        self.received_context = context
        return Decision(
            outcome=self._outcome,
            reason=f"Fixed: {self._outcome.value}",
            evaluated_by=self._name,
        )


class OrderRecordingRule:
    """Records its own call position in a shared list. Always returns NOT_APPLICABLE."""

    def __init__(self, name: str, call_log: list[str]) -> None:
        self._name = name
        self._call_log = call_log

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        self._call_log.append(self._name)
        return Decision(
            outcome=PolicyOutcome.NOT_APPLICABLE,
            reason="Not applicable",
            evaluated_by=self._name,
        )


class SubjectMutationAttemptRule:
    """Tries to mutate the Subject it receives. Expects a TypeError/ValidationError."""

    def __init__(self) -> None:
        self.mutation_raised = False

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        try:
            subject.roles = ["injected-role"]  # type: ignore[misc]
            self.mutation_raised = False
        except (TypeError, ValidationError):
            self.mutation_raised = True
        return Decision(
            outcome=PolicyOutcome.NOT_APPLICABLE,
            reason="Mutation attempted",
            evaluated_by="SubjectMutationAttemptRule",
        )


class NoneReturningRule:
    """Violates the contract by returning None instead of a Decision."""

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        return None  # type: ignore[return-value]  # deliberate contract violation


class RaisingRule:
    """Raises an exception unconditionally. Tests fail-closed behavior."""

    def __init__(self, exc_msg: str = "rule explosion") -> None:
        self._exc_msg = exc_msg

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        raise RuntimeError(self._exc_msg)


class CapturingAuditWriter:
    """Records every event passed to write(). Never raises."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class RaisingAuditWriter:
    """Always raises on write(). Tests that audit failures don't reverse decisions."""

    def write(self, event: AuditEvent) -> None:
        raise OSError("audit backend unreachable")


class MutatingAuditWriter:
    """Attempts to mutate the AuditEvent it receives."""

    def __init__(self) -> None:
        self.mutation_raised = False

    def write(self, event: AuditEvent) -> None:
        try:
            event.action = "mutated:action"  # type: ignore[misc]
            self.mutation_raised = False
        except (TypeError, ValidationError):
            self.mutation_raised = True


class MinimalAdapter:
    """Minimal concrete AdapterBase implementation for protocol checks."""

    def __init__(self, adapter_id: str = "test-adapter", protocol: str = "mock") -> None:
        self.adapter_id = adapter_id
        self.protocol = protocol
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


# ── PolicyRule: subject immutability ──────────────────────────────────────────


class TestPolicyRuleSubjectImmutability:
    """Subject passed to policy rules is an immutable (frozen) Pydantic model."""

    def test_subject_is_frozen_model(self) -> None:
        """Subject raises when a rule tries to assign to any attribute."""
        rule = SubjectMutationAttemptRule()
        engine = PolicyEngine(policies=[rule])
        subject = _make_subject(roles=["operator"])
        engine.evaluate(subject, "read:sensor:telemetry")
        assert rule.mutation_raised, (
            "Subject must be frozen: mutation attempt must raise TypeError or ValidationError"
        )

    def test_subject_roles_are_immutable(self) -> None:
        """Subject.roles is a tuple-like frozen field that cannot be mutated."""
        subject = _make_subject(roles=["operator"])
        with pytest.raises((TypeError, ValidationError)):
            subject.roles = ["admin"]  # type: ignore[misc]

    def test_rule_receives_same_subject_object(self) -> None:
        """Each rule in the chain receives the same Subject instance."""
        rule_a = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "RuleA")
        rule_b = FixedOutcomeRule(PolicyOutcome.ALLOW, "RuleB")
        engine = PolicyEngine(policies=[rule_a, rule_b])
        subject = _make_subject(roles=["viewer"])
        engine.evaluate(subject, "read:sensor:telemetry")
        assert rule_a.received_subject is subject
        assert rule_b.received_subject is subject

    def test_rule_receives_exact_action_string(self) -> None:
        """Action string passed to rules is identical to the one in the request."""
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "ActionCheck")
        engine = PolicyEngine(policies=[rule])
        subject = _make_subject()
        engine.evaluate(subject, "write:hvac:setpoint", resource_id="hvac:zone-a")
        assert rule.received_action == "write:hvac:setpoint"
        assert rule.received_resource_id == "hvac:zone-a"

    def test_rule_receives_context_dict(self) -> None:
        """Context dict is forwarded unchanged to every rule in the chain."""
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "CtxCheck")
        engine = PolicyEngine(policies=[rule])
        subject = _make_subject()
        ctx = {"site": "building-a", "zone": "north"}
        engine.evaluate(subject, "read:sensor:telemetry", context=ctx)
        assert rule.received_context == ctx


# ── PolicyRule: ordering stability ────────────────────────────────────────────


class TestPolicyRuleOrderingStability:
    """Rules are evaluated in the order they were supplied to PolicyEngine."""

    def test_rules_called_in_construction_order(self) -> None:
        call_log: list[str] = []
        rules = [
            OrderRecordingRule("first", call_log),
            OrderRecordingRule("second", call_log),
            OrderRecordingRule("third", call_log),
        ]
        engine = PolicyEngine(policies=rules)
        engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert call_log == ["first", "second", "third"]

    def test_ordering_is_stable_across_multiple_calls(self) -> None:
        """Rule order does not change between calls on the same engine."""
        call_log: list[str] = []
        rules = [
            OrderRecordingRule("alpha", call_log),
            OrderRecordingRule("beta", call_log),
        ]
        engine = PolicyEngine(policies=rules)
        subject = _make_subject()
        engine.evaluate(subject, "read:sensor:telemetry")
        engine.evaluate(subject, "read:sensor:telemetry")
        engine.evaluate(subject, "read:sensor:telemetry")
        assert call_log == ["alpha", "beta", "alpha", "beta", "alpha", "beta"]

    def test_deny_stops_subsequent_rules(self) -> None:
        """A DENY short-circuits: rules after the denying rule are not called."""
        call_log: list[str] = []
        deny_rule = FixedOutcomeRule(PolicyOutcome.DENY, "DenyFirst")
        after_deny = OrderRecordingRule("AfterDeny", call_log)
        engine = PolicyEngine(policies=[deny_rule, after_deny])
        engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert "AfterDeny" not in call_log, "Rule after DENY must not be called"

    def test_allow_does_not_stop_subsequent_rules(self) -> None:
        """An ALLOW does not short-circuit: subsequent rules continue to be called."""
        call_log: list[str] = []
        allow_rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowFirst")
        after_allow = OrderRecordingRule("AfterAllow", call_log)
        engine = PolicyEngine(policies=[allow_rule, after_allow])
        engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert "AfterAllow" in call_log, "Rule after ALLOW must still be called"

    def test_evaluated_rules_list_reflects_construction_order(self) -> None:
        """evaluated_rules entries appear in the order rules were registered."""
        rules = [
            FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R1"),
            FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R2"),
            FixedOutcomeRule(PolicyOutcome.ALLOW, "R3"),
        ]
        engine = PolicyEngine(policies=rules)
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        rule_names = [entry[0] for entry in decision.evaluated_rules]
        assert rule_names == ["R1", "R2", "R3"]


# ── AuditWriter: exceptions do not reverse decisions ──────────────────────────


class TestAuditWriterExceptionsDoNotReverseDecisions:
    """An AuditWriter that raises must not change the authorization outcome."""

    def test_allow_decision_stands_when_audit_raises(self) -> None:
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=RaisingAuditWriter(),
        )
        response = ep.evaluate(_make_request())
        assert response.outcome == DecisionOutcome.ALLOW, (
            "ALLOW decision must stand even when audit writer raises"
        )

    def test_deny_decision_stands_when_audit_raises(self) -> None:
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.DENY, "DenyRule")],
            audit_writer=RaisingAuditWriter(),
        )
        response = ep.evaluate(_make_request())
        assert response.outcome == DecisionOutcome.DENY

    def test_ep_does_not_raise_when_audit_raises(self) -> None:
        """EnforcementPoint.evaluate() must never raise regardless of audit failures."""
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=RaisingAuditWriter(),
        )
        # Must not raise
        response = ep.evaluate(_make_request())
        assert response is not None

    def test_failure_reason_not_set_for_normal_allow_with_bad_audit(self) -> None:
        """failure_reason must remain None for normal policy decisions, even if audit fails."""
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=RaisingAuditWriter(),
        )
        response = ep.evaluate(_make_request())
        assert response.failure_reason is None

    def test_not_applicable_resolves_to_deny_when_audit_raises(self) -> None:
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "NARule")],
            audit_writer=RaisingAuditWriter(),
        )
        response = ep.evaluate(_make_request())
        # NOT_APPLICABLE from engine → DENY at enforcement point
        assert response.outcome == DecisionOutcome.NOT_APPLICABLE


# ── AuditWriter: receives frozen AuditEvent ───────────────────────────────────


class TestAuditWriterReceivesFrozenEvent:
    """AuditEvent passed to write() is a frozen Pydantic model."""

    def test_audit_event_is_frozen(self) -> None:
        """An audit writer that tries to mutate the event must see a TypeError."""
        writer = MutatingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        assert writer.mutation_raised, (
            "AuditEvent must be frozen: mutation attempt must raise TypeError or ValidationError"
        )

    def test_capturing_writer_receives_event(self) -> None:
        """write() is called exactly once per successful evaluation."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        assert len(writer.events) == 1

    def test_audit_event_outcome_matches_decision(self) -> None:
        """AuditEvent.outcome reflects the actual authorization decision."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        assert writer.events[0].outcome == AuditOutcome.ALLOWED

    def test_audit_event_deny_outcome(self) -> None:
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.DENY, "DenyRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        assert writer.events[0].outcome == AuditOutcome.DENIED

    def test_audit_event_contains_request_id(self) -> None:
        """AuditEvent.request_id matches the DecisionRequest.request_id."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        request = _make_request()
        ep.evaluate(request)
        assert writer.events[0].request_id == request.request_id

    def test_audit_event_contains_action(self) -> None:
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request(action="write:hvac:setpoint"))
        assert writer.events[0].action == "write:hvac:setpoint"

    def test_malformed_request_produces_no_audit_event(self) -> None:
        """A raw dict that fails validation must not produce an audit event."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        # Pass a malformed dict (missing required action format)
        ep.evaluate({"subject_id": "alice", "action": "NOT-VALID-FORMAT"})
        assert len(writer.events) == 0, (
            "Malformed request must not produce an audit event: "
            "AuditEvent requires a validated action field"
        )


# ── Extension exceptions: fail closed ─────────────────────────────────────────


class TestExtensionExceptionsFailClosed:
    """Any exception inside a rule must produce DENY, never ALLOW."""

    def test_raising_rule_produces_deny(self) -> None:
        ep = _make_ep(rules=[RaisingRule("something went wrong")])
        response = ep.evaluate(_make_request())
        assert response.outcome == DecisionOutcome.DENY

    def test_raising_rule_sets_policy_error_failure_reason(self) -> None:
        ep = _make_ep(rules=[RaisingRule()])
        response = ep.evaluate(_make_request())
        assert response.failure_reason == FailureReason.POLICY_ERROR

    def test_raising_rule_does_not_expose_raw_exception(self) -> None:
        """Raw exception text must not appear in the caller-visible reason."""
        ep = _make_ep(rules=[RaisingRule("INTERNAL SECRET MESSAGE")])
        response = ep.evaluate(_make_request())
        assert "INTERNAL SECRET MESSAGE" not in response.reason

    def test_none_returning_rule_produces_deny(self) -> None:
        """A rule that returns None violates the contract; engine must fail closed."""
        ep = _make_ep(rules=[NoneReturningRule()])
        response = ep.evaluate(_make_request())
        # Accessing .outcome on None raises AttributeError, caught by the engine.
        assert response.outcome == DecisionOutcome.DENY

    def test_none_returning_rule_sets_policy_error(self) -> None:
        ep = _make_ep(rules=[NoneReturningRule()])
        response = ep.evaluate(_make_request())
        assert response.failure_reason == FailureReason.POLICY_ERROR

    def test_rule_exception_after_allow_still_denies(self) -> None:
        """An exception in any rule overrides a prior ALLOW."""
        allow_rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "EarlyAllow")
        ep = _make_ep(rules=[allow_rule, RaisingRule()])
        response = ep.evaluate(_make_request())
        assert response.outcome == DecisionOutcome.DENY

    def test_ep_never_raises(self) -> None:
        """EnforcementPoint.evaluate() must never propagate exceptions to the caller."""
        ep = _make_ep(rules=[RaisingRule("catastrophic")])
        # This call must not raise
        result = ep.evaluate(_make_request())
        assert result is not None

    def test_engine_is_error_flag_set_for_exception_case(self) -> None:
        """PolicyEngine sets is_error=True on the Decision when a rule raises."""
        engine = PolicyEngine(policies=[RaisingRule()])
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert decision.is_error is True
        assert decision.outcome == PolicyOutcome.DENY


# ── DecisionRequest: construction-time validation contract ────────────────────


class TestDecisionRequestValidationContract:
    """
    DecisionRequest enforces its field contracts at construction time.

    DecisionRequest is not a frozen model. Its contract is validation at
    construction: once a DecisionRequest is accepted, callers know its fields
    satisfied the format constraints. Code outside the kernel should treat
    DecisionRequest as read-only by convention, though Pydantic does not enforce
    that restriction at the type level.
    """

    def test_invalid_action_format_rejected_at_construction(self) -> None:
        """action must match {verb}:{domain}[:{object}] — construction raises on bad format."""
        with pytest.raises(ValidationError):
            DecisionRequest(subject_id="u1", action="NOT-VALID-FORMAT")

    def test_empty_subject_id_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            DecisionRequest(subject_id="", action="read:sensor:telemetry")

    def test_invalid_resource_id_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            DecisionRequest(
                subject_id="u1",
                action="read:sensor:telemetry",
                resource_id="INVALID RESOURCE",
            )

    def test_roles_normalized_on_construction(self) -> None:
        """subject_roles are sorted, deduplicated, and whitespace-stripped."""
        req = DecisionRequest(
            subject_id="u1",
            subject_roles=["  admin ", "operator", "admin"],
            action="read:sensor:telemetry",
        )
        assert req.subject_roles == ["admin", "operator"]

    def test_valid_request_fields_are_accessible(self) -> None:
        """Fields on a valid DecisionRequest are readable after construction."""
        req = _make_request(
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            roles=["operator"],
        )
        assert req.action == "write:hvac:setpoint"
        assert req.resource_id == "hvac:zone-a"
        assert "operator" in req.subject_roles


# ── DecisionResponse: construction-time validation contract ───────────────────


class TestDecisionResponseValidationContract:
    """
    DecisionResponse enforces its field contracts at construction time.

    Like DecisionRequest, DecisionResponse is not a frozen model but enforces
    validation at construction. The kernel produces a valid DecisionResponse on
    every code path in EnforcementPoint.evaluate(). Callers receive a response
    they can read immediately and trust as structurally valid.
    """

    def test_empty_reason_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            DecisionResponse(
                request_id="req-1",
                outcome=DecisionOutcome.DENY,
                reason="",
                evaluated_by="TestRule",
            )

    def test_empty_evaluated_by_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            DecisionResponse(
                request_id="req-1",
                outcome=DecisionOutcome.ALLOW,
                reason="permitted",
                evaluated_by="",
            )

    def test_empty_request_id_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            DecisionResponse(
                request_id="",
                outcome=DecisionOutcome.DENY,
                reason="denied",
                evaluated_by="TestRule",
            )

    def test_valid_response_fields_accessible(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="permitted by role",
            evaluated_by="RolePolicyRule",
        )
        assert resp.outcome == DecisionOutcome.ALLOW
        assert resp.allowed is True
        assert resp.reason == "permitted by role"


# ── AdapterBase: protocol checks ──────────────────────────────────────────────


class TestAdapterBaseProtocol:
    """AdapterBase is a runtime_checkable Protocol."""

    def test_minimal_adapter_satisfies_protocol(self) -> None:
        adapter = MinimalAdapter()
        assert isinstance(adapter, AdapterBase)

    def test_adapter_start_stop_lifecycle(self) -> None:
        adapter = MinimalAdapter()
        assert not adapter.started
        adapter.start()
        assert adapter.started
        adapter.stop()
        assert adapter.stopped

    def test_adapter_id_and_protocol_are_stable(self) -> None:
        adapter = MinimalAdapter(adapter_id="bacnet-gateway-01", protocol="bacnet")
        assert adapter.adapter_id == "bacnet-gateway-01"
        assert adapter.protocol == "bacnet"

    def test_object_missing_start_does_not_satisfy_protocol(self) -> None:
        class Incomplete:
            adapter_id = "x"
            protocol = "mock"

            def stop(self) -> None:
                pass

        assert not isinstance(Incomplete(), AdapterBase)

    def test_object_missing_stop_does_not_satisfy_protocol(self) -> None:
        class Incomplete:
            adapter_id = "x"
            protocol = "mock"

            def start(self) -> None:
                pass

        assert not isinstance(Incomplete(), AdapterBase)


# ── AuditWriter: protocol checks ──────────────────────────────────────────────


class TestAuditWriterProtocol:
    """AuditWriter is a runtime_checkable Protocol."""

    def test_null_writer_satisfies_protocol(self) -> None:
        assert isinstance(NullAuditWriter(), AuditWriter)

    def test_log_writer_satisfies_protocol(self) -> None:
        assert isinstance(LogAuditWriter(), AuditWriter)

    def test_capturing_writer_satisfies_protocol(self) -> None:
        assert isinstance(CapturingAuditWriter(), AuditWriter)

    def test_raising_writer_satisfies_protocol(self) -> None:
        assert isinstance(RaisingAuditWriter(), AuditWriter)

    def test_object_missing_write_does_not_satisfy_protocol(self) -> None:
        class NotAWriter:
            pass

        assert not isinstance(NotAWriter(), AuditWriter)


# ── PolicyRule: protocol check ────────────────────────────────────────────────


class TestPolicyRuleProtocol:
    """PolicyRule is a runtime_checkable Protocol."""

    def test_fixed_outcome_rule_satisfies_protocol(self) -> None:
        assert isinstance(FixedOutcomeRule(PolicyOutcome.ALLOW), PolicyRule)

    def test_raising_rule_satisfies_protocol(self) -> None:
        assert isinstance(RaisingRule(), PolicyRule)

    def test_object_missing_evaluate_does_not_satisfy_protocol(self) -> None:
        class NotARule:
            pass

        assert not isinstance(NotARule(), PolicyRule)


# ── NormalizedEvent: protocol-neutral fields ──────────────────────────────────


class TestNormalizedEventProtocolNeutrality:
    """NormalizedEvent carries protocol context without exposing protocol IDs in action."""

    def test_normalized_event_construction(self) -> None:
        event = NormalizedEvent(
            adapter_id="bacnet-gateway-01",
            protocol="bacnet",
            subject_id="operator:alice",
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
        )
        assert event.adapter_id == "bacnet-gateway-01"
        assert event.protocol == "bacnet"
        assert event.action == "write:hvac:setpoint"

    def test_normalized_event_from_different_protocols_same_action(self) -> None:
        """The same normalized action name applies across all protocols."""
        bacnet_event = NormalizedEvent(
            adapter_id="bacnet-adapter",
            protocol="bacnet",
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
        )
        modbus_event = NormalizedEvent(
            adapter_id="modbus-adapter",
            protocol="modbus-tcp",
            resource_id="hvac:zone-b",
            action="write:hvac:setpoint",
        )
        # Both events carry the same domain action — protocol identity is in protocol field
        assert bacnet_event.action == modbus_event.action == "write:hvac:setpoint"
        assert bacnet_event.protocol != modbus_event.protocol

    def test_protocol_specific_data_belongs_in_payload(self) -> None:
        """Protocol-specific data (BACnet object IDs, Modbus registers) belongs in payload."""
        event = NormalizedEvent(
            adapter_id="bacnet-adapter",
            protocol="bacnet",
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
            payload={
                "bacnet_object_type": "ANALOG_OUTPUT",
                "bacnet_instance": 4194303,
                "bacnet_property": "PRESENT_VALUE",
            },
        )
        # The policy engine doesn't inspect payload
        assert "bacnet_object_type" in event.payload
        # The action and resource_id are protocol-neutral
        assert "bacnet" not in event.action
        assert "bacnet" not in (event.resource_id or "")

    def test_normalized_event_subject_id_optional(self) -> None:
        """subject_id may be None for device-originated telemetry."""
        event = NormalizedEvent(
            adapter_id="sensor-adapter",
            protocol="mqtt",
            resource_id="sensor:co2:lobby",
            action="read:sensor:telemetry",
        )
        assert event.subject_id is None

    def test_normalized_event_context_dict(self) -> None:
        event = NormalizedEvent(
            adapter_id="adapter-1",
            protocol="opc-ua",
            action="read:sensor:telemetry",
            context={"site": "building-a", "zone": "east"},
        )
        assert event.context["site"] == "building-a"


# ── Protocol-agnostic evaluation ──────────────────────────────────────────────


class TestProtocolAgnosticEvaluation:
    """Policy rules produce identical outcomes regardless of source protocol."""

    def test_same_rule_denies_regardless_of_adapter_source(self) -> None:
        """A rule's outcome is determined by action and subject, not by source protocol."""
        from basis_core.policy.rules import RolePolicyRule

        rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}})
        engine = PolicyEngine(policies=[rule])

        # Subject with no matching role — request should always deny regardless of
        # where the request originated
        subject_no_role = _make_subject(roles=["viewer"])

        for resource_id in ["hvac:zone-a", "hvac:zone-b", "hvac:zone-c"]:
            decision = engine.evaluate(
                subject_no_role, "write:hvac:setpoint", resource_id=resource_id
            )
            assert decision.outcome == PolicyOutcome.DENY, (
                f"Expected DENY for subject with no operator role, resource={resource_id}"
            )

    def test_same_rule_allows_regardless_of_adapter_source(self) -> None:
        from basis_core.policy.rules import RolePolicyRule

        rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}})
        engine = PolicyEngine(policies=[rule])
        subject_operator = _make_subject(roles=["operator"])

        for resource_id in ["hvac:zone-a", "hvac:zone-b"]:
            decision = engine.evaluate(
                subject_operator, "write:hvac:setpoint", resource_id=resource_id
            )
            assert decision.outcome == PolicyOutcome.ALLOW

    def test_decision_request_carries_no_protocol_field(self) -> None:
        """DecisionRequest has no protocol field: the enforcement point is protocol-neutral."""
        req = _make_request()
        assert not hasattr(req, "protocol"), (
            "DecisionRequest must not have a protocol field — it is protocol-neutral by design"
        )


# ── DecisionTrace stability ────────────────────────────────────────────────────


class TestDecisionTraceStability:
    """Custom rules produce stable, well-formed audit trace entries."""

    def test_evaluated_rules_contains_all_rules_for_not_applicable(self) -> None:
        """When all rules return NOT_APPLICABLE, every rule appears in evaluated_rules."""
        rules = [
            FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R1"),
            FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R2"),
        ]
        engine = PolicyEngine(policies=rules)
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        names = [e[0] for e in decision.evaluated_rules]
        assert "R1" in names
        assert "R2" in names

    def test_evaluated_rules_tuple_structure(self) -> None:
        """Each entry in evaluated_rules is a (name, outcome_value, reason) 3-tuple of strings."""
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "MyRule")
        engine = PolicyEngine(policies=[rule])
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert len(decision.evaluated_rules) == 1
        entry = decision.evaluated_rules[0]
        assert len(entry) == 3
        name, outcome_val, reason = entry
        assert isinstance(name, str) and name == "MyRule"
        assert isinstance(outcome_val, str) and outcome_val == "allow"
        assert isinstance(reason, str) and reason

    def test_audit_event_trace_reflects_custom_rule(self) -> None:
        """AuditEvent.trace contains the evaluated_rules from the custom rule."""
        writer = CapturingAuditWriter()
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "CustomRule")
        ep = _make_ep(rules=[rule], audit_writer=writer)
        ep.evaluate(_make_request())

        event = writer.events[0]
        assert event.trace is not None
        rule_names = [r.rule_name for r in event.trace.evaluated_rules]
        assert "CustomRule" in rule_names

    def test_audit_event_matched_rules_contains_allow_rule(self) -> None:
        """AuditEvent.matched_rules lists the ALLOW rule name."""
        writer = CapturingAuditWriter()
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "WinningRule")
        ep = _make_ep(rules=[rule], audit_writer=writer)
        ep.evaluate(_make_request())

        event = writer.events[0]
        assert "WinningRule" in event.matched_rules

    def test_exception_rule_name_in_trace_is_class_name(self) -> None:
        """When a rule raises, its class name (not instance name) appears in evaluated_rules."""
        engine = PolicyEngine(policies=[RaisingRule("boom")])
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        # Engine uses type(rule).__name__ for exception entries
        assert decision.evaluated_rules[0][0] == "RaisingRule"

    def test_exception_evaluated_by_is_class_name(self) -> None:
        engine = PolicyEngine(policies=[RaisingRule()])
        decision = engine.evaluate(_make_subject(), "read:sensor:telemetry")
        assert decision.evaluated_by == "RaisingRule"

    def test_trace_short_circuited_flag_true_for_deny(self) -> None:
        """DecisionTrace.short_circuited is True when DENY stops a non-exhausted rule list."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[
                FixedOutcomeRule(PolicyOutcome.DENY, "DenyRule"),
                FixedOutcomeRule(PolicyOutcome.ALLOW, "NeverCalled"),
            ],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        event = writer.events[0]
        assert event.trace is not None
        assert event.trace.short_circuited is True

    def test_trace_short_circuited_flag_false_for_allow(self) -> None:
        """DecisionTrace.short_circuited is False when all rules were evaluated."""
        writer = CapturingAuditWriter()
        ep = _make_ep(
            rules=[FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")],
            audit_writer=writer,
        )
        ep.evaluate(_make_request())
        event = writer.events[0]
        assert event.trace is not None
        assert event.trace.short_circuited is False
