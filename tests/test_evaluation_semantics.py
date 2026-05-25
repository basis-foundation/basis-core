"""
Evaluation semantics contract tests for basis_core.policy.engine.

These tests verify the PolicyEngine's behavioral guarantees as described in
docs/evaluation-semantics.md. They are focused on the *contract*, not on
the correctness of individual rule types (covered in test_policy_rules.py) or
on the EnforcementPoint orchestration (covered in test_enforcement_point.py
and test_audit.py).

Coverage targets:
  - DENY short-circuits: subsequent rules are not called; evaluated_rules
    contains only rules up to and including the denying rule.
  - ALLOW does not short-circuit: all rules are evaluated even after ALLOW.
  - First ALLOW wins: evaluated_by and reason from the first ALLOW rule,
    regardless of later ALLOWs.
  - NOT_APPLICABLE passthrough: all rules are evaluated; evaluated_rules
    contains every rule.
  - Empty policy list: NOT_APPLICABLE outcome, evaluated_rules is empty.
  - Exception fail-closed: DENY with is_error=True; evaluated_rules contains
    only rules up to and including the failing rule.
  - Determinism: same inputs produce identical outcomes across calls.
  - Context forwarded: context dict is passed unchanged to every rule called.
  - short_circuited flag: True when DENY before full list; False otherwise.
  - Audit outcome mapping: NOT_APPLICABLE → AuditOutcome.DENIED at EP level.
"""

from __future__ import annotations

from typing import Any

import pytest

from basis_core.audit.events import AuditOutcome
from basis_core.decisions.models import DecisionOutcome, DecisionRequest
from basis_core.domain.subject import Subject, SubjectType
from basis_core.enforcement.enforcement import EnforcementPoint
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome

# ── Minimal test-only rule helpers ─────────────────────────────────────────────
#
# These rules are defined here rather than imported from production code so that
# the tests in this file remain focused on engine semantics rather than on the
# behaviour of any specific rule type. Each rule is as simple as possible.


class FixedOutcomeRule:
    """
    A rule that always returns the same outcome, and records whether it was called.

    Parameters
    ----------
    outcome:  The PolicyOutcome to return unconditionally.
    name:     The value that appears in Decision.evaluated_by.
    """

    def __init__(self, outcome: PolicyOutcome, name: str) -> None:
        self._outcome = outcome
        self._name = name
        self.call_count = 0

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: object = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        self.call_count += 1
        return Decision(
            outcome=self._outcome,
            reason=f"{self._name}: {self._outcome.value}",
            evaluated_by=self._name,
        )


class ExplodingRule:
    """A rule that always raises an unhandled exception."""

    def __init__(self, name: str = "ExplodingRule") -> None:
        self._name = name
        self.call_count = 0

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: object = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        self.call_count += 1
        raise RuntimeError(f"{self._name}: simulated rule failure")


class ContextCapturingRule:
    """A rule that captures the context dict it received and returns NOT_APPLICABLE."""

    def __init__(self) -> None:
        self.received_context: dict[str, Any] | None = None

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: object = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        self.received_context = context
        return Decision(
            outcome=PolicyOutcome.NOT_APPLICABLE,
            reason="no opinion",
            evaluated_by="ContextCapturingRule",
        )


def make_subject() -> Subject:
    return Subject(id="test-subject", name="test", type=SubjectType.HUMAN, roles=[])


def make_request(action: str = "read:test:resource") -> DecisionRequest:
    return DecisionRequest(subject_id="test-subject", action=action)


ACTION = "read:test:resource"

# ── DENY short-circuits ────────────────────────────────────────────────────────


class TestDenyShortCircuits:
    """
    A DENY from any rule must stop evaluation immediately. Rules registered
    after the denying rule must not be called. evaluated_rules must contain
    only rules up to and including the denying rule.
    """

    def test_deny_stops_subsequent_rule_from_being_called(self) -> None:
        deny_rule = FixedOutcomeRule(PolicyOutcome.DENY, "DenyRule")
        after_deny = FixedOutcomeRule(PolicyOutcome.ALLOW, "AfterDeny")
        engine = PolicyEngine(policies=[deny_rule, after_deny])

        engine.evaluate(make_subject(), ACTION)

        assert deny_rule.call_count == 1
        assert after_deny.call_count == 0, (
            "Rule registered after a DENY must not be called — DENY short-circuits"
        )

    def test_deny_in_middle_stops_all_remaining_rules(self) -> None:
        before = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Before")
        deny_rule = FixedOutcomeRule(PolicyOutcome.DENY, "DenyMiddle")
        after1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "After1")
        after2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "After2")
        engine = PolicyEngine(policies=[before, deny_rule, after1, after2])

        engine.evaluate(make_subject(), ACTION)

        assert before.call_count == 1
        assert deny_rule.call_count == 1
        assert after1.call_count == 0
        assert after2.call_count == 0

    def test_deny_evaluated_rules_contains_only_rules_up_to_deny(self) -> None:
        """evaluated_rules must not include entries for uncalled rules."""
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R1")
        r2 = FixedOutcomeRule(PolicyOutcome.DENY, "R2")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R3")
        engine = PolicyEngine(policies=[r1, r2, r3])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.DENY
        rule_names = [entry[0] for entry in decision.evaluated_rules]
        assert "R1" in rule_names
        assert "R2" in rule_names
        assert "R3" not in rule_names, (
            "R3 was registered after the denying rule and must not appear in evaluated_rules"
        )
        assert len(decision.evaluated_rules) == 2

    def test_first_rule_deny_evaluated_rules_has_one_entry(self) -> None:
        deny_rule = FixedOutcomeRule(PolicyOutcome.DENY, "ImmediateDeny")
        after = FixedOutcomeRule(PolicyOutcome.ALLOW, "NeverCalled")
        engine = PolicyEngine(policies=[deny_rule, after])

        decision = engine.evaluate(make_subject(), ACTION)

        assert len(decision.evaluated_rules) == 1
        assert decision.evaluated_rules[0][0] == "ImmediateDeny"

    def test_deny_evaluated_by_names_denying_rule(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipRule")
        r2 = FixedOutcomeRule(PolicyOutcome.DENY, "ActiveDeny")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.evaluated_by == "ActiveDeny"


# ── ALLOW does not short-circuit ───────────────────────────────────────────────


class TestAllowDoesNotShortCircuit:
    """
    An ALLOW from a rule must not stop evaluation. All remaining rules must
    still be called so that a subsequent DENY can override the ALLOW.
    evaluated_rules must contain entries for every registered rule.
    """

    def test_allow_does_not_prevent_subsequent_rule_from_being_called(self) -> None:
        allow_rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")
        after_allow = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "AfterAllow")
        engine = PolicyEngine(policies=[allow_rule, after_allow])

        engine.evaluate(make_subject(), ACTION)

        assert allow_rule.call_count == 1
        assert after_allow.call_count == 1, (
            "Rule registered after ALLOW must still be called — ALLOW does not short-circuit"
        )

    def test_allow_evaluated_rules_contains_all_registered_rules(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R1")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R2")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R3")
        engine = PolicyEngine(policies=[r1, r2, r3])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.ALLOW
        rule_names = [entry[0] for entry in decision.evaluated_rules]
        assert rule_names == ["R1", "R2", "R3"], (
            "All rules must appear in evaluated_rules when ALLOW does not short-circuit"
        )

    def test_allow_followed_by_deny_results_in_deny(self) -> None:
        """ALLOW does not short-circuit, so a subsequent DENY overrides it."""
        allow_first = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowFirst")
        deny_second = FixedOutcomeRule(PolicyOutcome.DENY, "DenySecond")
        engine = PolicyEngine(policies=[allow_first, deny_second])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.DENY
        assert allow_first.call_count == 1
        assert deny_second.call_count == 1

    def test_deny_after_allow_appears_in_evaluated_rules(self) -> None:
        allow_rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowFirst")
        deny_rule = FixedOutcomeRule(PolicyOutcome.DENY, "DenySecond")
        engine = PolicyEngine(policies=[allow_rule, deny_rule])

        decision = engine.evaluate(make_subject(), ACTION)

        rule_names = [entry[0] for entry in decision.evaluated_rules]
        assert "AllowFirst" in rule_names
        assert "DenySecond" in rule_names

    def test_three_rules_all_called_when_first_returns_allow(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R1")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R2")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "R3")
        engine = PolicyEngine(policies=[r1, r2, r3])

        engine.evaluate(make_subject(), ACTION)

        assert r1.call_count == 1
        assert r2.call_count == 1
        assert r3.call_count == 1


# ── First ALLOW wins ───────────────────────────────────────────────────────────


class TestFirstAllowWins:
    """
    When multiple rules return ALLOW, the first rule (in registration order)
    that returned ALLOW provides the evaluated_by and reason. All rules still
    appear in evaluated_rules.
    """

    def test_first_allow_provides_evaluated_by(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "FirstAllow")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "SecondAllow")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.ALLOW
        assert decision.evaluated_by == "FirstAllow"

    def test_not_applicable_followed_by_allow_gives_allow_evaluated_by(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipRule")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "ActiveAllow")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.evaluated_by == "ActiveAllow"

    def test_later_allow_does_not_override_first_allow_evaluated_by(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "FirstAllowRule")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipRule")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "ThirdAllowRule")
        engine = PolicyEngine(policies=[r1, r2, r3])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.evaluated_by == "FirstAllowRule"

    def test_multiple_allows_all_appear_in_evaluated_rules(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Allow1")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Allow2")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Allow3")
        engine = PolicyEngine(policies=[r1, r2, r3])

        decision = engine.evaluate(make_subject(), ACTION)

        rule_names = [entry[0] for entry in decision.evaluated_rules]
        assert rule_names == ["Allow1", "Allow2", "Allow3"]

    def test_first_allow_outcome_value_in_evaluated_rules(self) -> None:
        """evaluated_rules entries use plain strings, not PolicyOutcome enums."""
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipRule")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        # outcome_value in the tuple is a plain string.
        outcomes = {entry[0]: entry[1] for entry in decision.evaluated_rules}
        assert outcomes["AllowRule"] == "allow"
        assert outcomes["SkipRule"] == "not_applicable"


# ── NOT_APPLICABLE passthrough ─────────────────────────────────────────────────


class TestNotApplicablePassthrough:
    """
    NOT_APPLICABLE must not stop evaluation or block later rules.
    All rules are evaluated; evaluated_rules contains every entry.
    """

    def test_not_applicable_all_rules_evaluated(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R1")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R2")
        r3 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R3")
        engine = PolicyEngine(policies=[r1, r2, r3])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.NOT_APPLICABLE
        assert r1.call_count == 1
        assert r2.call_count == 1
        assert r3.call_count == 1

    def test_not_applicable_all_rules_in_evaluated_rules(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R1")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "R2")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert len(decision.evaluated_rules) == 2
        rule_names = [e[0] for e in decision.evaluated_rules]
        assert "R1" in rule_names
        assert "R2" in rule_names

    def test_not_applicable_evaluated_by_is_policy_engine(self) -> None:
        engine = PolicyEngine(policies=[FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip")])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.evaluated_by == "PolicyEngine"

    def test_not_applicable_allows_later_rule_to_allow(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Permit")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.ALLOW
        assert decision.evaluated_by == "Permit"

    def test_not_applicable_allows_later_rule_to_deny(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip")
        r2 = FixedOutcomeRule(PolicyOutcome.DENY, "Prohibit")
        engine = PolicyEngine(policies=[r1, r2])

        decision = engine.evaluate(make_subject(), ACTION)

        assert decision.outcome == PolicyOutcome.DENY
        assert decision.evaluated_by == "Prohibit"


# ── Empty policy list ──────────────────────────────────────────────────────────


class TestEmptyPolicyList:
    """An engine with no registered rules must return NOT_APPLICABLE."""

    def test_empty_engine_returns_not_applicable(self) -> None:
        engine = PolicyEngine(policies=[])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.outcome == PolicyOutcome.NOT_APPLICABLE

    def test_empty_engine_evaluated_rules_is_empty(self) -> None:
        engine = PolicyEngine(policies=[])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.evaluated_rules == []

    def test_empty_engine_evaluated_by_is_policy_engine(self) -> None:
        engine = PolicyEngine(policies=[])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.evaluated_by == "PolicyEngine"

    def test_empty_engine_allowed_is_false(self) -> None:
        engine = PolicyEngine(policies=[])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.allowed is False


# ── Exception fail-closed with partial trace ───────────────────────────────────


class TestExceptionFailClosed:
    """
    An unhandled exception inside a rule must produce DENY with is_error=True.
    Rules registered after the failing rule must not be called.
    evaluated_rules must include the failing rule but not later rules.
    """

    def test_exception_produces_deny(self) -> None:
        engine = PolicyEngine(policies=[ExplodingRule()])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.outcome == PolicyOutcome.DENY

    def test_exception_sets_is_error_flag(self) -> None:
        engine = PolicyEngine(policies=[ExplodingRule()])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.is_error is True

    def test_exception_does_not_set_is_error_on_normal_deny(self) -> None:
        engine = PolicyEngine(policies=[FixedOutcomeRule(PolicyOutcome.DENY, "NormalDeny")])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.is_error is False

    def test_exception_stops_subsequent_rules(self) -> None:
        exploding = ExplodingRule("ExplodingFirst")
        after = FixedOutcomeRule(PolicyOutcome.ALLOW, "NeverCalled")
        engine = PolicyEngine(policies=[exploding, after])

        engine.evaluate(make_subject(), ACTION)

        assert after.call_count == 0, (
            "Rules after an exception must not be called — exception short-circuits like DENY"
        )

    def test_exception_evaluated_rules_contains_failing_rule(self) -> None:
        # When a rule raises, the engine uses type(rule).__name__ as the rule name
        # in evaluated_rules — not any instance-level name attribute.
        before = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Before")
        exploding = ExplodingRule()  # class name is "ExplodingRule"
        after = FixedOutcomeRule(PolicyOutcome.ALLOW, "After")
        engine = PolicyEngine(policies=[before, exploding, after])

        decision = engine.evaluate(make_subject(), ACTION)

        rule_names = [e[0] for e in decision.evaluated_rules]
        assert "Before" in rule_names
        assert "ExplodingRule" in rule_names  # engine uses type(rule).__name__
        assert "After" not in rule_names

    def test_exception_evaluated_rules_has_deny_outcome_for_failing_rule(self) -> None:
        # The engine records the exception entry as ("ExplodingRule", "deny", str(exc)).
        engine = PolicyEngine(policies=[ExplodingRule()])
        decision = engine.evaluate(make_subject(), ACTION)
        outcomes = {e[0]: e[1] for e in decision.evaluated_rules}
        assert outcomes["ExplodingRule"] == "deny"

    def test_exception_evaluated_by_names_failing_rule(self) -> None:
        # evaluated_by is set to type(rule).__name__ for exception cases.
        engine = PolicyEngine(policies=[ExplodingRule()])
        decision = engine.evaluate(make_subject(), ACTION)
        assert decision.evaluated_by == "ExplodingRule"

    def test_exception_after_allow_still_produces_deny(self) -> None:
        allow_rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowFirst")
        exploding = ExplodingRule("ExplodingSecond")
        engine = PolicyEngine(policies=[allow_rule, exploding])

        decision = engine.evaluate(make_subject(), ACTION)

        # The ALLOW was recorded as first_allow, but the exception that follows
        # short-circuits with DENY.
        assert decision.outcome == PolicyOutcome.DENY
        assert decision.is_error is True


# ── evaluated_rules tuple structure ───────────────────────────────────────────


class TestEvaluatedRulesTupleStructure:
    """
    Each entry in evaluated_rules is a (rule_name, outcome_value, reason)
    tuple using plain strings for outcome_value — not PolicyOutcome enum values.
    """

    def test_evaluated_rules_entries_are_plain_string_tuples(self) -> None:
        engine = PolicyEngine(policies=[FixedOutcomeRule(PolicyOutcome.ALLOW, "TestRule")])
        decision = engine.evaluate(make_subject(), ACTION)
        entry = decision.evaluated_rules[0]
        assert isinstance(entry[0], str)  # rule_name
        assert isinstance(entry[1], str)  # outcome_value
        assert isinstance(entry[2], str)  # reason

    @pytest.mark.parametrize(
        "outcome, expected_str",
        [
            (PolicyOutcome.ALLOW, "allow"),
            (PolicyOutcome.DENY, "deny"),
            (PolicyOutcome.NOT_APPLICABLE, "not_applicable"),
        ],
    )
    def test_outcome_value_is_correct_plain_string(
        self, outcome: PolicyOutcome, expected_str: str
    ) -> None:
        engine = PolicyEngine(policies=[FixedOutcomeRule(outcome, "R")])
        decision = engine.evaluate(make_subject(), ACTION)
        # For DENY and NOT_APPLICABLE, the engine returns immediately with entries.
        # For ALLOW, all rules are iterated; entry is in the evaluated_rules list.
        assert decision.evaluated_rules[0][1] == expected_str


# ── Determinism ────────────────────────────────────────────────────────────────


class TestDeterminism:
    """
    Identical inputs must produce identical outcomes across repeated calls.
    The engine holds no mutable state that changes between evaluations.
    """

    def test_same_inputs_same_outcome_on_repeated_calls(self) -> None:
        engine = PolicyEngine(
            policies=[
                FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule"),
                FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipRule"),
            ]
        )
        subject = make_subject()
        outcomes = [engine.evaluate(subject, ACTION).outcome for _ in range(5)]
        assert len(set(outcomes)) == 1, "Repeated evaluations must produce the same outcome"

    def test_independent_calls_do_not_share_state(self) -> None:
        """Two calls with different outcomes must not interfere."""
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "AllowRule")
        r2 = FixedOutcomeRule(PolicyOutcome.DENY, "DenyRule")
        engine_a = PolicyEngine(policies=[r1])
        engine_b = PolicyEngine(policies=[r2])

        decision_a = engine_a.evaluate(make_subject(), ACTION)
        decision_b = engine_b.evaluate(make_subject(), ACTION)

        assert decision_a.outcome == PolicyOutcome.ALLOW
        assert decision_b.outcome == PolicyOutcome.DENY

    def test_engine_call_count_does_not_affect_outcome(self) -> None:
        rule = FixedOutcomeRule(PolicyOutcome.ALLOW, "Rule")
        engine = PolicyEngine(policies=[rule])
        subject = make_subject()

        # Call many times; outcome must always be ALLOW.
        for _ in range(10):
            decision = engine.evaluate(subject, ACTION)
            assert decision.outcome == PolicyOutcome.ALLOW


# ── Context forwarding ─────────────────────────────────────────────────────────


class TestContextForwarding:
    """
    The context dict passed to engine.evaluate() must be forwarded unchanged
    to every rule that is called during the evaluation.
    """

    def test_context_is_forwarded_to_rule(self) -> None:
        capturer = ContextCapturingRule()
        engine = PolicyEngine(policies=[capturer])
        ctx = {"site": "bldg-a", "window": "true"}

        engine.evaluate(make_subject(), ACTION, context=ctx)

        assert capturer.received_context == ctx

    def test_none_context_is_forwarded_as_none(self) -> None:
        capturer = ContextCapturingRule()
        engine = PolicyEngine(policies=[capturer])

        engine.evaluate(make_subject(), ACTION, context=None)

        assert capturer.received_context is None

    def test_context_forwarded_to_all_rules_in_chain(self) -> None:
        capturers = [ContextCapturingRule() for _ in range(3)]
        engine = PolicyEngine(policies=capturers)  # type: ignore[arg-type]
        ctx = {"key": "value"}

        engine.evaluate(make_subject(), ACTION, context=ctx)

        for capturer in capturers:
            assert capturer.received_context == ctx


# ── short_circuited flag in DecisionTrace ──────────────────────────────────────


class TestShortCircuitedFlag:
    """
    The DecisionTrace.short_circuited flag is set by the EnforcementPoint
    when a DENY is returned before all registered rules have been evaluated.

    short_circuited=True:  DENY outcome, fewer evaluated rules than total rules.
    short_circuited=False: ALLOW outcome (all rules evaluated).
    short_circuited=False: NOT_APPLICABLE outcome (all rules evaluated).
    short_circuited=False: DENY from the last rule (all rules evaluated).
    """

    def _make_ep(self, rules: list[Any]) -> tuple[EnforcementPoint, list]:
        from basis_core.audit.events import AuditEvent

        captured: list[AuditEvent] = []

        class CapturingWriter:
            def write(self, event: AuditEvent) -> None:
                captured.append(event)

        ep = EnforcementPoint(
            engine=PolicyEngine(policies=rules),
            audit_writer=CapturingWriter(),
            policy_version="test-v1",
        )
        return ep, captured

    def test_short_circuited_true_when_deny_before_last_rule(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.DENY, "EarlyDeny")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "NeverCalled")
        ep, captured = self._make_ep([r1, r2])

        ep.evaluate(make_request(), subject=make_subject())

        assert len(captured) == 1
        trace = captured[0].trace
        assert trace is not None
        assert trace.short_circuited is True

    def test_short_circuited_false_when_allow_outcome(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Allow")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip")
        ep, captured = self._make_ep([r1, r2])

        ep.evaluate(make_request(), subject=make_subject())

        trace = captured[0].trace
        assert trace is not None
        assert trace.short_circuited is False

    def test_short_circuited_false_when_deny_from_last_rule(self) -> None:
        """DENY from the last rule means all rules were evaluated — no short-circuit."""
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip")
        r2 = FixedOutcomeRule(PolicyOutcome.DENY, "FinalDeny")
        ep, captured = self._make_ep([r1, r2])

        ep.evaluate(make_request(), subject=make_subject())

        trace = captured[0].trace
        assert trace is not None
        assert trace.short_circuited is False

    def test_short_circuited_false_when_not_applicable_outcome(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip1")
        r2 = FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "Skip2")
        ep, captured = self._make_ep([r1, r2])

        ep.evaluate(make_request(), subject=make_subject())

        trace = captured[0].trace
        assert trace is not None
        assert trace.short_circuited is False

    def test_short_circuited_true_with_first_of_three_rules_denying(self) -> None:
        r1 = FixedOutcomeRule(PolicyOutcome.DENY, "DenyFirst")
        r2 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Skip2")
        r3 = FixedOutcomeRule(PolicyOutcome.ALLOW, "Skip3")
        ep, captured = self._make_ep([r1, r2, r3])

        ep.evaluate(make_request(), subject=make_subject())

        trace = captured[0].trace
        assert trace is not None
        assert trace.short_circuited is True
        # Only one rule evaluated.
        assert len(trace.evaluated_rules) == 1


# ── NOT_APPLICABLE → AuditOutcome.DENIED at enforcement point ─────────────────


class TestNotApplicableAuditMapping:
    """
    NOT_APPLICABLE from the engine must map to AuditOutcome.DENIED in the
    audit record. The DecisionResponse.outcome remains NOT_APPLICABLE so
    callers can distinguish the two cases.
    """

    def test_not_applicable_maps_to_denied_in_audit(self) -> None:
        from basis_core.audit.events import AuditEvent

        captured: list[AuditEvent] = []

        class CapturingWriter:
            def write(self, event: AuditEvent) -> None:
                captured.append(event)

        ep = EnforcementPoint(
            engine=PolicyEngine(
                policies=[FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipAll")]
            ),
            audit_writer=CapturingWriter(),
            policy_version="test-v1",
        )
        request = make_request()
        response = ep.evaluate(request, subject=make_subject())

        # Response preserves NOT_APPLICABLE.
        assert response.outcome == DecisionOutcome.NOT_APPLICABLE
        assert response.allowed is False

        # Audit records it as DENIED.
        assert len(captured) == 1
        assert captured[0].outcome == AuditOutcome.DENIED

    def test_not_applicable_trace_records_correct_final_outcome(self) -> None:
        from basis_core.audit.events import AuditEvent

        captured: list[AuditEvent] = []

        class CapturingWriter:
            def write(self, event: AuditEvent) -> None:
                captured.append(event)

        ep = EnforcementPoint(
            engine=PolicyEngine(
                policies=[FixedOutcomeRule(PolicyOutcome.NOT_APPLICABLE, "SkipAll")]
            ),
            audit_writer=CapturingWriter(),
            policy_version="test-v1",
        )
        ep.evaluate(make_request(), subject=make_subject())

        trace = captured[0].trace
        assert trace is not None
        # The trace records the engine's actual outcome, not the audit mapping.
        assert trace.final_outcome == "not_applicable"
