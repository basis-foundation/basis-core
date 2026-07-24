"""
tests/operation_aware/test_trace_assembly.py — tests for
`basis_core.evaluation.operation_aware.trace_assembly` (Milestone 8, PR 26
of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Trace
assembly function").

Covers `assemble_rule_evidence()` and `assemble_evaluation_trace()`: mapping
already-evaluated policy facts (`OperationAwarePolicyRule` +
`policy.operation_aware.condition_eval.RuleConditionEvaluation`) into the
audit-owned `TraceRuleEvidence`/`EvaluationTrace` contracts (PR 24/PR 25,
unmodified) through explicit vocabulary tables, rule-identity agreement,
ordered condition-evidence preservation, caller-supplied trace-level state,
determinism, purity, and boundedness.

Scope
─────
This file tests trace assembly only. It does not test, and must never test:
selector evaluation or condition operator dispatch (`test_selector.py`/
`test_operators.py`/`test_condition_eval.py` own that), bundle applicability
determination, candidate rule selection, effect aggregation, deny
precedence, default deny, or any final authorization outcome (later,
separately-scoped Milestone 9/PR 27 work) — none of that exists in this
module or this PR.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest
from pydantic import BaseModel

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import (
    RuleResult,
    TraceConditionResult,
    TraceRuleEffect,
    TraceRuleEvidence,
)
from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.domain.operation_aware_vocabulary import ReasonCode
from basis_core.evaluation.operation_aware.trace_assembly import (
    RuleIdentityMismatchError,
    _project_rule_rationale,
    assemble_evaluation_trace,
    assemble_rule_evidence,
)
from basis_core.policy.operation_aware.condition_eval import (
    RuleConditionEvaluation,
    RuleConditionResult,
    evaluate_rule_conditions,
)
from basis_core.policy.operation_aware.operators import ConditionEvaluation, ConditionResult
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule, RuleEffect

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers (mirrors test_condition_eval.py's conventions)
# ══════════════════════════════════════════════════════════════════════════

_SUBJECT_ID = "svc-trace-assembly-test"


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    kwargs: dict[str, object] = {
        "request_id": "req-trace-assembly-fixture-0001",
        "subject_id": _SUBJECT_ID,
        "action": "read:ahu",
    }
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


def _build_rule(
    *,
    match: dict[str, object] | None = None,
    conditions: list[dict[str, object]] | None = None,
    effect: str = "allow",
    rule_id: str = "rule-trace-assembly-fixture",
    reason_code: str | None = None,
    explanation: str | None = None,
) -> OperationAwarePolicyRule:
    kwargs: dict[str, object] = {"rule_id": rule_id, "effect": effect}
    if match is not None:
        kwargs["match"] = match
    if conditions is not None:
        kwargs["conditions"] = conditions
    if reason_code is not None:
        kwargs["reason_code"] = reason_code
    if explanation is not None:
        kwargs["explanation"] = explanation
    return OperationAwarePolicyRule.model_validate(kwargs)


def _match_cond(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to `ConditionResult.MATCH`."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": _SUBJECT_ID,
    }


def _no_match_cond(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to `ConditionResult.NO_MATCH`."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": "not-the-subject-id",
    }


def _error_cond(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to `ConditionResult.ERROR`: `future_operator`
    is structurally valid but not implemented by `operators.py`'s registry —
    the same convention `test_condition_eval.py`/`test_selector.py` use."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "future_operator",
        "expected_value": "irrelevant",
    }


def _collect_keys(value: object) -> set[str]:
    """Recursively collect every mapping key appearing anywhere in a
    (possibly nested) JSON-shaped structure. Used for boundedness
    assertions — checking exact key names rather than raw substrings avoids
    false positives from legitimate vocabulary *values* like `"matched"`/
    `"not_matched"` (which contain the substring "match" but are not the
    forbidden `match` key)."""
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, sub_value in value.items():
            keys.add(str(key))
            keys |= _collect_keys(sub_value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys |= _collect_keys(item)
    return keys


# ══════════════════════════════════════════════════════════════════════════
# 1. Match-only rule (selector matched, no conditions)
# ══════════════════════════════════════════════════════════════════════════


class TestMatchOnlyRuleNoConditions:
    def test_matched_rule_no_conditions_produces_honest_evidence(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-match-only",
            match={"actions": ["read:ahu"]},
            effect="allow",
            reason_code="rule_matched",
            explanation="Matches read-only AHU telemetry.",
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.MATCHED
        assert evaluation.condition_results == ()

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_id == "rule-match-only"
        assert evidence.effect is TraceRuleEffect.ALLOW
        assert evidence.rule_result is RuleResult.MATCHED
        assert evidence.condition_results is None
        assert evidence.reason_code == "rule_matched"
        assert evidence.explanation == "Matches read-only AHU telemetry."

        trace = assemble_evaluation_trace(
            [evidence],
            trace_id="trace-match-only",
            request_id=request.request_id,
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        assert isinstance(trace, EvaluationTrace)
        assert trace.rule_evidence == [evidence]


# ══════════════════════════════════════════════════════════════════════════
# 2. Selector mismatch
# ══════════════════════════════════════════════════════════════════════════


class TestSelectorMismatch:
    def test_selector_mismatch_conditions_absent_effect_preserved(self) -> None:
        request = _build_request(action="read:ahu")
        # match excludes the request's action; a condition that would ERROR
        # if ever reached proves it was never evaluated.
        rule = _build_rule(
            rule_id="rule-mismatch",
            match={"actions": ["write:ahu"]},
            conditions=[_error_cond("cond-would-error")],
            effect="deny",
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.NOT_MATCHED
        assert evaluation.condition_results == ()

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.NOT_MATCHED
        assert evidence.condition_results is None
        assert evidence.effect is TraceRuleEffect.DENY

        trace = assemble_evaluation_trace(
            [evidence],
            trace_id="trace-mismatch",
            request_id=request.request_id,
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.DENY,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        assert trace.rule_evidence[0].condition_results is None


# ══════════════════════════════════════════════════════════════════════════
# 3. Conditions all match
# ══════════════════════════════════════════════════════════════════════════


class TestConditionsAllMatch:
    def test_all_conditions_match_included_in_order(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-all-match",
            conditions=[_match_cond("cond-a"), _match_cond("cond-b"), _match_cond("cond-c")],
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.MATCHED
        assert [c.condition_id for c in evaluation.condition_results] == [
            "cond-a",
            "cond-b",
            "cond-c",
        ]

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.MATCHED
        assert evidence.condition_results is not None
        assert [c.condition_id for c in evidence.condition_results] == [
            "cond-a",
            "cond-b",
            "cond-c",
        ]
        assert all(c.result is TraceConditionResult.MATCHED for c in evidence.condition_results)


# ══════════════════════════════════════════════════════════════════════════
# 4. Condition no-match — no short-circuit
# ══════════════════════════════════════════════════════════════════════════


class TestConditionNoMatch:
    def test_no_match_condition_keeps_every_evaluated_condition(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-no-match",
            conditions=[
                _match_cond("cond-first"),
                _no_match_cond("cond-second"),
                _match_cond("cond-third"),
            ],
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.NOT_MATCHED
        # All three were evaluated -- no short-circuit after cond-second.
        assert [c.condition_id for c in evaluation.condition_results] == [
            "cond-first",
            "cond-second",
            "cond-third",
        ]

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.NOT_MATCHED
        assert evidence.condition_results is not None
        assert [c.condition_id for c in evidence.condition_results] == [
            "cond-first",
            "cond-second",
            "cond-third",
        ]
        results = {c.condition_id: c.result for c in evidence.condition_results}
        assert results["cond-first"] is TraceConditionResult.MATCHED
        assert results["cond-second"] is TraceConditionResult.NOT_MATCHED
        assert results["cond-third"] is TraceConditionResult.MATCHED


# ══════════════════════════════════════════════════════════════════════════
# 5. Condition error
# ══════════════════════════════════════════════════════════════════════════


class TestConditionError:
    def test_condition_error_forces_rule_error_and_is_not_omitted(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-error",
            conditions=[_match_cond("cond-ok"), _error_cond("cond-bad")],
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.ERROR

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.ERROR
        assert evidence.condition_results is not None
        results = {c.condition_id: c.result for c in evidence.condition_results}
        assert results["cond-ok"] is TraceConditionResult.MATCHED
        assert results["cond-bad"] is TraceConditionResult.ERROR
        # Error evidence is not converted to not_matched, and not omitted.
        assert len(evidence.condition_results) == 2

        # A trace containing a rule_result=error entry must be a failed
        # evaluation -- this is EvaluationTrace's own existing invariant
        # (PR 25), not something this module re-implements; assembling one
        # with evaluation_status=completed must fail construction-time
        # validation, proving trace assembly does not weaken it.
        with pytest.raises(Exception):
            assemble_evaluation_trace(
                [evidence],
                trace_id="trace-error-invalid",
                request_id=request.request_id,
                evaluation_status=EvaluationStatus.COMPLETED,
                outcome=TraceOutcome.DENY,
                bundle_applicability=TraceBundleApplicability.APPLICABLE,
            )

        trace = assemble_evaluation_trace(
            [evidence],
            trace_id="trace-error-valid",
            request_id=request.request_id,
            evaluation_status=EvaluationStatus.FAILED,
            outcome=None,
            bundle_applicability=None,
            failure_reason=TraceFailureReason.CONDITION_EVALUATION_ERROR,
        )
        assert trace.evaluation_status is EvaluationStatus.FAILED
        assert trace.rule_evidence[0].rule_result is RuleResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 6. Rule-ID mismatch
# ══════════════════════════════════════════════════════════════════════════


class TestRuleIdMismatch:
    def test_mismatched_rule_id_is_rejected(self) -> None:
        rule = _build_rule(rule_id="rule-authored", match={"actions": ["read:ahu"]})
        evaluation = RuleConditionEvaluation(
            rule_id="rule-different",
            result=RuleConditionResult.MATCHED,
            condition_results=(),
        )
        with pytest.raises(RuleIdentityMismatchError):
            assemble_rule_evidence(rule, evaluation)

    def test_matching_rule_id_succeeds(self) -> None:
        rule = _build_rule(rule_id="rule-same", match={"actions": ["read:ahu"]})
        evaluation = RuleConditionEvaluation(
            rule_id="rule-same",
            result=RuleConditionResult.MATCHED,
            condition_results=(),
        )
        evidence = assemble_rule_evidence(rule, evaluation)
        assert evidence.rule_id == "rule-same"


# ══════════════════════════════════════════════════════════════════════════
# 7. Explicit vocabulary mappings — exhaustive
# ══════════════════════════════════════════════════════════════════════════


class TestVocabularyMappings:
    @pytest.mark.parametrize(
        ("rule_effect", "expected"),
        [
            (RuleEffect.ALLOW, TraceRuleEffect.ALLOW),
            (RuleEffect.DENY, TraceRuleEffect.DENY),
        ],
    )
    def test_rule_effect_mapping(self, rule_effect: RuleEffect, expected: TraceRuleEffect) -> None:
        rule = _build_rule(
            rule_id="rule-effect", match={"actions": ["read:ahu"]}, effect=rule_effect.value
        )
        evaluation = RuleConditionEvaluation(
            rule_id="rule-effect", result=RuleConditionResult.MATCHED, condition_results=()
        )
        evidence = assemble_rule_evidence(rule, evaluation)
        assert evidence.effect is expected

    @pytest.mark.parametrize(
        ("source_result", "expected"),
        [
            (RuleConditionResult.MATCHED, RuleResult.MATCHED),
            (RuleConditionResult.NOT_MATCHED, RuleResult.NOT_MATCHED),
            (RuleConditionResult.ERROR, RuleResult.ERROR),
        ],
    )
    def test_rule_result_mapping(
        self, source_result: RuleConditionResult, expected: RuleResult
    ) -> None:
        rule = _build_rule(rule_id="rule-result", match={"actions": ["read:ahu"]})
        evaluation = RuleConditionEvaluation(
            rule_id="rule-result", result=source_result, condition_results=()
        )
        evidence = assemble_rule_evidence(rule, evaluation)
        assert evidence.rule_result is expected

    @pytest.mark.parametrize(
        ("source_result", "expected"),
        [
            (ConditionResult.MATCH, TraceConditionResult.MATCHED),
            (ConditionResult.NO_MATCH, TraceConditionResult.NOT_MATCHED),
            (ConditionResult.ERROR, TraceConditionResult.ERROR),
        ],
    )
    def test_condition_result_mapping(
        self, source_result: ConditionResult, expected: TraceConditionResult
    ) -> None:
        rule = _build_rule(rule_id="rule-cond-result", conditions=[_match_cond("cond-x")])
        # Aggregate rule result is irrelevant here -- only the per-condition
        # mapping is under test, so an ERROR-dominant aggregate is fine.
        aggregate = (
            RuleConditionResult.ERROR
            if source_result is ConditionResult.ERROR
            else (
                RuleConditionResult.MATCHED
                if source_result is ConditionResult.MATCH
                else RuleConditionResult.NOT_MATCHED
            )
        )
        evaluation = RuleConditionEvaluation(
            rule_id="rule-cond-result",
            result=aggregate,
            condition_results=(ConditionEvaluation(condition_id="cond-x", result=source_result),),
        )
        evidence = assemble_rule_evidence(rule, evaluation)
        assert evidence.condition_results is not None
        assert evidence.condition_results[0].result is expected


# ══════════════════════════════════════════════════════════════════════════
# 8. Rule ordering — nonlexical
# ══════════════════════════════════════════════════════════════════════════


class TestRuleOrdering:
    def _build_evidence_sequence(self) -> list[TraceRuleEvidence]:
        request = _build_request(action="read:ahu")
        evidence_list = []
        for rule_id in ("rule-z", "rule-a", "rule-m"):
            rule = _build_rule(rule_id=rule_id, match={"actions": ["read:ahu"]})
            evaluation = evaluate_rule_conditions(rule, request)
            evidence_list.append(assemble_rule_evidence(rule, evaluation))
        return evidence_list

    def test_nonlexical_rule_order_preserved_exactly(self) -> None:
        evidence_list = self._build_evidence_sequence()
        trace = assemble_evaluation_trace(
            evidence_list,
            trace_id="trace-rule-order",
            request_id="req-rule-order",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        assert [e.rule_id for e in trace.rule_evidence] == ["rule-z", "rule-a", "rule-m"]

    def test_repeated_assembly_is_equal(self) -> None:
        evidence_list = self._build_evidence_sequence()
        trace_a = assemble_evaluation_trace(
            evidence_list,
            trace_id="trace-repeat",
            request_id="req-repeat",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        trace_b = assemble_evaluation_trace(
            evidence_list,
            trace_id="trace-repeat",
            request_id="req-repeat",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        assert trace_a == trace_b

    def test_serialized_order_identical_and_round_trips(self) -> None:
        evidence_list = self._build_evidence_sequence()
        trace = assemble_evaluation_trace(
            evidence_list,
            trace_id="trace-serialize-order",
            request_id="req-serialize-order",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert [e["rule_id"] for e in dumped["rule_evidence"]] == ["rule-z", "rule-a", "rule-m"]
        restored = EvaluationTrace.model_validate(dumped)
        assert [e.rule_id for e in restored.rule_evidence] == ["rule-z", "rule-a", "rule-m"]
        assert restored == trace


# ══════════════════════════════════════════════════════════════════════════
# 9. Condition ordering — nonlexical
# ══════════════════════════════════════════════════════════════════════════


class TestConditionOrdering:
    def test_nonlexical_condition_order_preserved_exactly(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-condition-order",
            conditions=[
                _match_cond("condition-z"),
                _match_cond("condition-a"),
                _match_cond("condition-m"),
            ],
        )
        evaluation = evaluate_rule_conditions(rule, request)
        evidence = assemble_rule_evidence(rule, evaluation)
        assert evidence.condition_results is not None
        assert [c.condition_id for c in evidence.condition_results] == [
            "condition-z",
            "condition-a",
            "condition-m",
        ]


# ══════════════════════════════════════════════════════════════════════════
# 10. Trace identifiers
# ══════════════════════════════════════════════════════════════════════════


class TestTraceIdentifiers:
    def test_supplied_identifiers_preserved_exactly(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-supplied-id-0042",
            request_id="req-supplied-id-0042",
            correlation_id="corr-supplied-id-0042",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        )
        assert trace.trace_id == "trace-supplied-id-0042"
        assert trace.request_id == "req-supplied-id-0042"
        assert trace.correlation_id == "corr-supplied-id-0042"

    def test_no_identifier_is_generated_when_correlation_id_omitted(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-no-generation",
            request_id="req-no-generation",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        )
        # Omitted correlation_id stays exactly None -- nothing synthesizes a
        # value in its place.
        assert trace.correlation_id is None


# ══════════════════════════════════════════════════════════════════════════
# 11. Bundle metadata
# ══════════════════════════════════════════════════════════════════════════


class TestBundleMetadata:
    def test_bundle_id_and_version_preserved(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-bundle-meta",
            request_id="req-bundle-meta",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
            bundle_id="bundle-hvac-policy",
            bundle_version="1.2.3",
        )
        assert trace.bundle_id == "bundle-hvac-policy"
        assert trace.bundle_version == "1.2.3"

    def test_no_full_bundle_content_in_serialized_output(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-bundle-bounded",
            request_id="req-bundle-bounded",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
            bundle_id="bundle-hvac-policy",
            bundle_version="1.2.3",
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        keys = _collect_keys(dumped)
        assert keys == {
            "trace_id",
            "request_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "bundle_id",
            "bundle_version",
            "rule_evidence",
        }


# ══════════════════════════════════════════════════════════════════════════
# 12. Failed trace
# ══════════════════════════════════════════════════════════════════════════


class _ParentWrapper(BaseModel):
    """Test-only nested-model wrapper, used only to prove
    `EvaluationTrace`'s required-nullable serialization behavior (PR 25)
    survives unchanged when this module's output is embedded inside another
    Pydantic model -- one assembly integration regression, not a duplicate
    of PR 25's full serialization suite."""

    evaluation_trace: EvaluationTrace


class TestFailedTrace:
    def test_failed_trace_has_null_outcome_and_applicability(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-failed",
            request_id="req-failed",
            evaluation_status=EvaluationStatus.FAILED,
            outcome=None,
            bundle_applicability=None,
            failure_reason=TraceFailureReason.INVALID_REQUEST,
        )
        assert trace.evaluation_status is EvaluationStatus.FAILED
        assert trace.outcome is None
        assert trace.bundle_applicability is None
        assert trace.failure_reason is TraceFailureReason.INVALID_REQUEST
        assert trace.rule_evidence == []

    def test_failed_trace_direct_serialization_preserves_required_nullable_keys(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-failed-serialize",
            request_id="req-failed-serialize",
            evaluation_status=EvaluationStatus.FAILED,
            outcome=None,
            bundle_applicability=None,
            failure_reason=TraceFailureReason.INVALID_POLICY_BUNDLE,
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None
        assert "bundle_applicability" in dumped
        assert dumped["bundle_applicability"] is None

    def test_failed_trace_nested_serialization_preserves_required_nullable_keys(self) -> None:
        trace = assemble_evaluation_trace(
            [],
            trace_id="trace-failed-nested",
            request_id="req-failed-nested",
            evaluation_status=EvaluationStatus.FAILED,
            outcome=None,
            bundle_applicability=None,
            failure_reason=TraceFailureReason.POLICY_VALIDATION_FAILURE,
        )
        parent = _ParentWrapper(evaluation_trace=trace)
        dumped = parent.model_dump(mode="json", exclude_none=True)
        nested = dumped["evaluation_trace"]
        assert "outcome" in nested
        assert nested["outcome"] is None
        assert "bundle_applicability" in nested
        assert nested["bundle_applicability"] is None


# ══════════════════════════════════════════════════════════════════════════
# 13. Boundedness
# ══════════════════════════════════════════════════════════════════════════


class TestBoundedness:
    def test_serialized_output_excludes_prohibited_representative_keys(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-bounded",
            conditions=[_match_cond("cond-bounded"), _error_cond("cond-bounded-error")],
            reason_code="rule_bounded_reason",
            explanation="Bounded explanation text.",
        )
        evaluation = evaluate_rule_conditions(rule, request)
        evidence = assemble_rule_evidence(rule, evaluation)
        trace = assemble_evaluation_trace(
            [evidence],
            trace_id="trace-bounded",
            request_id=request.request_id,
            evaluation_status=EvaluationStatus.FAILED,
            outcome=None,
            bundle_applicability=None,
            failure_reason=TraceFailureReason.CONDITION_EVALUATION_ERROR,
            bundle_id="bundle-bounded",
            bundle_version="1.0.0",
            reason_code="trace_bounded_reason",
            explanation="Trace-level bounded explanation.",
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        keys = _collect_keys(dumped)
        prohibited = {
            "request",
            "policy_bundle",
            "match",
            "conditions",
            "field_path",
            "operator",
            "expected_value",
            "actual_value",
            "claims",
            "token",
            "raw_payload",
            "stack_trace",
            "metadata",
            "debug",
        }
        assert keys.isdisjoint(prohibited), f"Unexpected unbounded key(s): {keys & prohibited}"


# ══════════════════════════════════════════════════════════════════════════
# 14. No input mutation
# ══════════════════════════════════════════════════════════════════════════


class TestNoInputMutation:
    def test_assemble_rule_evidence_does_not_mutate_inputs(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(rule_id="rule-immutable", conditions=[_match_cond("cond-immutable")])
        evaluation = evaluate_rule_conditions(rule, request)

        rule_before = rule.model_copy(deep=True)
        evaluation_before = evaluation

        assemble_rule_evidence(rule, evaluation)

        assert rule == rule_before
        assert evaluation == evaluation_before

    def test_assemble_evaluation_trace_does_not_mutate_input_sequence(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(rule_id="rule-seq-immutable", match={"actions": ["read:ahu"]})
        evaluation = evaluate_rule_conditions(rule, request)
        evidence = assemble_rule_evidence(rule, evaluation)
        original_sequence: Sequence[TraceRuleEvidence] = [evidence]

        assemble_evaluation_trace(
            original_sequence,
            trace_id="trace-seq-immutable",
            request_id=request.request_id,
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.ALLOW,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
        )

        assert list(original_sequence) == [evidence]


# ══════════════════════════════════════════════════════════════════════════
# 15. v0.1 compatibility
# ══════════════════════════════════════════════════════════════════════════


class TestV01Compatibility:
    def test_decision_trace_import_still_resolves(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert DecisionTrace.__module__ == "basis_core.audit.trace"

    def test_decision_trace_fields_unchanged(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert set(DecisionTrace.model_fields) == {
            "final_outcome",
            "evaluated_rules",
            "short_circuited",
        }

    def test_rule_evaluation_fields_unchanged(self) -> None:
        from basis_core.audit.trace import RuleEvaluation

        assert set(RuleEvaluation.model_fields) == {"rule_name", "outcome", "reason"}


# ══════════════════════════════════════════════════════════════════════════
# 16. Rule-evidence rationale projection
#     (fix/operation-aware-rule-evidence-projection)
# ══════════════════════════════════════════════════════════════════════════
#
# `assemble_rule_evidence` previously copied `rule.reason_code`/
# `rule.explanation` into `TraceRuleEvidence` unconditionally, regardless of
# `rule_result`. Per `basis-architecture`'s merged evidence-provenance
# clarification (`docs/architecture/operation-aware-evidence-provenance-
# semantics.md` §3), a `matched` rule's authored rationale is preserved
# verbatim; a `not_matched`/`skipped`/`error` rule's is not. This section
# proves the corrected, `rule_result`-keyed projection performed by
# `_project_rule_rationale`.


class TestRationaleProjectionMatched:
    def test_matched_allow_preserves_authored_rationale_verbatim(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-matched-allow",
            match={"actions": ["read:ahu"]},
            effect="allow",
            reason_code="allow_rule_matched",
            explanation="Operators may read AHU telemetry.",
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.MATCHED

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.MATCHED
        assert evidence.effect is TraceRuleEffect.ALLOW
        assert evidence.reason_code == "allow_rule_matched"
        assert evidence.explanation == "Operators may read AHU telemetry."

    def test_matched_deny_preserves_authored_rationale_verbatim(self) -> None:
        request = _build_request(action="write:hvac:setpoint")
        rule = _build_rule(
            rule_id="rule-matched-deny",
            match={"actions": ["write:hvac:setpoint"]},
            effect="deny",
            reason_code="deny_rule_matched",
            explanation=("Deny precedence applied; an interlock-scoped deny rule matched."),
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.MATCHED

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.MATCHED
        assert evidence.effect is TraceRuleEffect.DENY
        assert evidence.reason_code == "deny_rule_matched"
        assert (
            evidence.explanation
            == "Deny precedence applied; an interlock-scoped deny rule matched."
        )


class TestRationaleProjectionNotMatched:
    def test_not_matched_allow_omits_authored_rationale(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-not-matched-allow",
            match={"actions": ["write:ahu"]},  # does not match the request's action
            effect="allow",
            reason_code="allow_rule_matched",
            explanation="Operators may read AHU telemetry.",
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.NOT_MATCHED

        evidence = assemble_rule_evidence(rule, evaluation)

        # Other bounded evidence remains intact -- only the rationale
        # projection changes.
        assert evidence.rule_id == "rule-not-matched-allow"
        assert evidence.effect is TraceRuleEffect.ALLOW
        assert evidence.rule_result is RuleResult.NOT_MATCHED
        assert evidence.condition_results is None
        assert evidence.reason_code is None
        assert evidence.explanation is None

    def test_not_matched_deny_omits_authored_rationale(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-not-matched-deny",
            match={"actions": ["write:ahu"]},
            effect="deny",
            reason_code="deny_rule_matched",
            explanation=("Deny precedence applied; an interlock-scoped deny rule matched."),
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.NOT_MATCHED

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_id == "rule-not-matched-deny"
        assert evidence.effect is TraceRuleEffect.DENY
        assert evidence.rule_result is RuleResult.NOT_MATCHED
        assert evidence.condition_results is None
        assert evidence.reason_code is None
        assert evidence.explanation is None


class TestRationaleProjectionSkipped:
    def test_skipped_rule_result_omits_rationale_via_projection_helper(self) -> None:
        """`assemble_rule_evidence` cannot actually produce `RuleResult.
        SKIPPED` through its only production call path today --
        `RuleConditionResult` (`policy.operation_aware.condition_eval`) has
        no member meaning "this rule was never evaluated", so
        `_RULE_CONDITION_RESULT_TO_RULE_RESULT` has no entry that could ever
        map to it (see `trace_assembly.py`'s own docstring, "Condition
        evidence -- no synthetic states"). This test exercises the real,
        existing typed `RuleResult.SKIPPED` value directly against
        `_project_rule_rationale` -- the narrow trace-assembly boundary --
        rather than inventing a second evaluator or a synthetic production
        path that does not exist."""
        reason_code, explanation = _project_rule_rationale(
            rule_result=RuleResult.SKIPPED,
            authored_reason_code=ReasonCode("would_have_matched"),
            authored_explanation="Authored rationale for a rule never reached.",
        )
        assert reason_code is None
        assert explanation is None


class TestRationaleProjectionError:
    def test_error_rule_never_uses_authored_success_or_deny_rationale(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(
            rule_id="rule-error-rationale",
            conditions=[_match_cond("cond-ok"), _error_cond("cond-bad")],
            effect="deny",
            reason_code="deny_rule_matched",
            explanation=("Deny precedence applied; an interlock-scoped deny rule matched."),
        )
        evaluation = evaluate_rule_conditions(rule, request)
        assert evaluation.result is RuleConditionResult.ERROR

        evidence = assemble_rule_evidence(rule, evaluation)

        assert evidence.rule_result is RuleResult.ERROR
        # No governed evaluation-error reason_code/explanation exists yet
        # anywhere in this pipeline (see `trace_assembly.py`'s docstring,
        # "Rule-evidence rationale projection") -- the rule's own authored
        # deny rationale must never stand in for it.
        assert evidence.reason_code is None
        assert evidence.explanation is None
        # Condition-level evidence is still fully preserved -- this fix
        # changes only rule-level rationale projection, not condition
        # evidence (already proven unconditionally by
        # `TestConditionError` above).
        assert evidence.condition_results is not None
        results = {c.condition_id: c.result for c in evidence.condition_results}
        assert results["cond-ok"] is TraceConditionResult.MATCHED
        assert results["cond-bad"] is TraceConditionResult.ERROR


class TestRationaleProjectionHelperExhaustiveAndDeterministic:
    """Direct tests of `_project_rule_rationale` -- the single, pure,
    total function this fix introduces. Exhaustive over every `RuleResult`
    member (including `SKIPPED`, unreachable through `assemble_rule_
    evidence`'s only production call path today) and proves determinism
    (equal inputs -> equal output), independent of `assemble_rule_
    evidence`'s own vocabulary mapping and condition-evidence handling."""

    @pytest.mark.parametrize(
        ("rule_result", "expected"),
        [
            (RuleResult.MATCHED, ("authored_reason", "authored_explanation")),
            (RuleResult.NOT_MATCHED, (None, None)),
            (RuleResult.SKIPPED, (None, None)),
            (RuleResult.ERROR, (None, None)),
        ],
    )
    def test_projection_by_rule_result(
        self, rule_result: RuleResult, expected: tuple[str | None, str | None]
    ) -> None:
        result = _project_rule_rationale(
            rule_result=rule_result,
            authored_reason_code=ReasonCode("authored_reason"),
            authored_explanation="authored_explanation",
        )
        assert result == expected

    def test_projection_is_deterministic(self) -> None:
        kwargs: dict[str, object] = {
            "rule_result": RuleResult.MATCHED,
            "authored_reason_code": ReasonCode("stable_reason"),
            "authored_explanation": "Stable explanation.",
        }
        assert _project_rule_rationale(**kwargs) == _project_rule_rationale(**kwargs)  # type: ignore[arg-type]

    def test_projection_handles_no_authored_rationale(self) -> None:
        """A matched rule that authored no `reason_code`/`explanation` at
        all (both `None`) projects `None`/`None` -- not an error, and not a
        synthesized value standing in for the missing rationale."""
        result = _project_rule_rationale(
            rule_result=RuleResult.MATCHED,
            authored_reason_code=None,
            authored_explanation=None,
        )
        assert result == (None, None)
