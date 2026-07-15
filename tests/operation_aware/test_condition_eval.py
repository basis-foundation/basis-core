"""
tests/operation_aware/test_condition_eval.py — tests for
`basis_core.policy.operation_aware.condition_eval` (Milestone 7, PR 23 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Condition
evaluation integration").

Covers `evaluate_rule_conditions()`, `RuleConditionResult`, and
`RuleConditionEvaluation`: selector-stage integration (structural mismatch,
match-with-no-conditions, match-with-conditions-pending), multi-condition
rule-level aggregation (all-match, no_match dominance, error dominance,
mixed no_match/error ordering), authored-order preservation, determinism,
the first-class condition-evaluation-error scenario, delegation to PR 22's
standalone `evaluate_condition` (no duplicated operator semantics), and
result-type immutability/boundedness.

Scope
─────
This file tests rule-level condition integration only. It does not test,
and must never test: condition operator dispatch or field-path resolution
(`test_operators.py` owns that), structural `match`-selector evaluation
(`test_selector.py` owns that), `TraceRuleEvidence`/`EvaluationTrace`, rule
effects, deny precedence, default deny, a final authorization outcome,
evaluation status, or failure-reason propagation — none of that exists in
this module or this PR (Milestone 8/9 onward, separately-scoped roadmap
work).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path
from unittest.mock import patch

import pytest

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware import operators as operators_module
from basis_core.policy.operation_aware.condition_eval import (
    RuleConditionEvaluation,
    RuleConditionResult,
    evaluate_rule_conditions,
)
from basis_core.policy.operation_aware.operators import ConditionEvaluation, ConditionResult
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule

MODULE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "basis_core"
    / "policy"
    / "operation_aware"
    / "condition_eval.py"
)

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════

_SUBJECT_ID = "svc-condition-eval-test"


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    """Build a minimal, otherwise-fixed `OperationAwareDecisionRequest`,
    merging `overrides` on top of the minimal required fields."""
    kwargs: dict[str, object] = {
        "request_id": "req-condition-eval-fixture-0001",
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
    rule_id: str = "rule-condition-eval-fixture",
) -> OperationAwarePolicyRule:
    """Build a minimal, otherwise-fixed `OperationAwarePolicyRule`. Exactly
    one of `match`/`conditions` must ultimately be non-`None`, matching
    `rule.py`'s own construction-time invariant."""
    kwargs: dict[str, object] = {"rule_id": rule_id, "effect": effect}
    if match is not None:
        kwargs["match"] = match
    if conditions is not None:
        kwargs["conditions"] = conditions
    return OperationAwarePolicyRule.model_validate(kwargs)


def _match_cond(condition_id: str) -> dict[str, object]:
    """A condition that deterministically evaluates to `ConditionResult.MATCH`
    against `_build_request()`'s default subject_id."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": _SUBJECT_ID,
    }


def _no_match_cond(condition_id: str) -> dict[str, object]:
    """A condition that deterministically evaluates to
    `ConditionResult.NO_MATCH` against `_build_request()`'s default
    subject_id."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": "not-the-subject-id",
    }


def _error_cond(condition_id: str) -> dict[str, object]:
    """A condition that deterministically evaluates to
    `ConditionResult.ERROR`: `future_operator` is structurally valid
    (accepted by `PolicyCondition`'s open, non-enum `operator` field) but
    not implemented by `operators.py`'s approved ten-operator registry —
    the same unsupported-but-structurally-valid-operator convention already
    established in `test_selector.py`."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "future_operator",
        "expected_value": "irrelevant",
    }


# ══════════════════════════════════════════════════════════════════════════
# 1. Selector integration
# ══════════════════════════════════════════════════════════════════════════


class TestSelectorIntegration:
    def test_selector_mismatch_rule_not_matched_conditions_not_evaluated(self) -> None:
        request = _build_request(action="read:ahu")
        # `match.actions` does not include the request's action -> structural
        # mismatch. The rule also carries a condition that would evaluate to
        # ERROR if it were ever evaluated -- proving it was not.
        rule = _build_rule(
            match={"actions": ["write:ahu"]},
            conditions=[_error_cond("cond-would-error")],
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.NOT_MATCHED
        assert result.condition_results == ()

    def test_selector_match_no_conditions_rule_matched(self) -> None:
        request = _build_request(action="read:ahu")
        rule = _build_rule(match={"actions": ["read:ahu"]})

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.MATCHED
        assert result.condition_results == ()

    def test_selector_match_one_matching_condition_rule_matched(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_match_cond("cond-1")])

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.MATCHED
        assert len(result.condition_results) == 1
        assert result.condition_results[0] == ConditionEvaluation(
            condition_id="cond-1", result=ConditionResult.MATCH
        )


# ══════════════════════════════════════════════════════════════════════════
# 2. Multiple-condition aggregation
# ══════════════════════════════════════════════════════════════════════════


class TestMultipleConditionAggregation:
    def test_all_conditions_match_rule_matched(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[_match_cond("cond-1"), _match_cond("cond-2"), _match_cond("cond-3")]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.MATCHED
        assert [c.result for c in result.condition_results] == [
            ConditionResult.MATCH,
            ConditionResult.MATCH,
            ConditionResult.MATCH,
        ]

    def test_first_condition_no_match_remaining_match_all_evaluated(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _no_match_cond("cond-1"),
                _match_cond("cond-2"),
                _match_cond("cond-3"),
            ]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.NOT_MATCHED
        assert len(result.condition_results) == 3
        assert [c.result for c in result.condition_results] == [
            ConditionResult.NO_MATCH,
            ConditionResult.MATCH,
            ConditionResult.MATCH,
        ]

    def test_middle_condition_no_match_authored_order_preserved(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _match_cond("cond-1"),
                _no_match_cond("cond-2"),
                _match_cond("cond-3"),
            ]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.NOT_MATCHED
        assert [c.condition_id for c in result.condition_results] == [
            "cond-1",
            "cond-2",
            "cond-3",
        ]
        assert [c.result for c in result.condition_results] == [
            ConditionResult.MATCH,
            ConditionResult.NO_MATCH,
            ConditionResult.MATCH,
        ]

    def test_multiple_no_match_results_rule_not_matched(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _no_match_cond("cond-1"),
                _match_cond("cond-2"),
                _no_match_cond("cond-3"),
            ]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.NOT_MATCHED
        assert len(result.condition_results) == 3

    def test_one_condition_errors_rule_error(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_error_cond("cond-1")])

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.ERROR
        assert len(result.condition_results) == 1
        assert result.condition_results[0].result is ConditionResult.ERROR

    def test_error_followed_by_matching_conditions_later_still_evaluated(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _error_cond("cond-1"),
                _match_cond("cond-2"),
                _match_cond("cond-3"),
            ]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.ERROR
        assert len(result.condition_results) == 3
        assert [c.result for c in result.condition_results] == [
            ConditionResult.ERROR,
            ConditionResult.MATCH,
            ConditionResult.MATCH,
        ]

    def test_no_match_followed_by_error_both_retained(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[_no_match_cond("cond-1"), _error_cond("cond-2")],
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.ERROR
        assert [c.result for c in result.condition_results] == [
            ConditionResult.NO_MATCH,
            ConditionResult.ERROR,
        ]

    def test_error_followed_by_no_match_both_retained(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[_error_cond("cond-1"), _no_match_cond("cond-2")],
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.ERROR
        assert [c.result for c in result.condition_results] == [
            ConditionResult.ERROR,
            ConditionResult.NO_MATCH,
        ]

    def test_multiple_errors_rule_error_every_result_retained(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _error_cond("cond-1"),
                _match_cond("cond-2"),
                _error_cond("cond-3"),
            ],
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.result is RuleConditionResult.ERROR
        assert len(result.condition_results) == 3
        assert [c.result for c in result.condition_results] == [
            ConditionResult.ERROR,
            ConditionResult.MATCH,
            ConditionResult.ERROR,
        ]


# ══════════════════════════════════════════════════════════════════════════
# 3. Authored order
# ══════════════════════════════════════════════════════════════════════════


class TestAuthoredOrder:
    def test_nonlexical_condition_ids_preserved_in_authored_order(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[
                _match_cond("condition-z"),
                _match_cond("condition-a"),
                _match_cond("condition-m"),
            ],
        )

        result = evaluate_rule_conditions(rule, request)

        assert [c.condition_id for c in result.condition_results] == [
            "condition-z",
            "condition-a",
            "condition-m",
        ]

    def test_repeated_evaluation_produces_equal_result(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[_match_cond("cond-1"), _no_match_cond("cond-2")],
        )

        first = evaluate_rule_conditions(rule, request)
        second = evaluate_rule_conditions(rule, request)

        assert first == second


# ══════════════════════════════════════════════════════════════════════════
# 4. First-class condition-evaluation-error scenario
# ══════════════════════════════════════════════════════════════════════════


class TestConditionEvaluationErrorScenario:
    """The deferred condition-evaluation-error scenario named but not
    covered by the five vendored canonical vectors (Section 10 of the
    roadmap plan) — a first-class, independent unit test, using a real
    PR 22 error behavior (a structurally valid but unsupported operator)."""

    def test_unsupported_operator_produces_condition_and_rule_level_error(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_error_cond("cond-unsupported-operator")])

        result = evaluate_rule_conditions(rule, request)

        assert len(result.condition_results) == 1
        assert result.condition_results[0].result is ConditionResult.ERROR
        assert result.result is RuleConditionResult.ERROR
        # The condition error must not silently become no_match or matched.
        assert result.result is not RuleConditionResult.NOT_MATCHED
        assert result.result is not RuleConditionResult.MATCHED

    def test_incompatible_type_comparison_produces_error(self) -> None:
        """An approved operator (`greater_than`) given an incompatible
        actual/expected type pair (`subject_id` is a string; `greater_than`
        only accepts the `number` family) is a second, independent real
        PR 22 error behavior."""
        request = _build_request()
        rule = _build_rule(
            conditions=[
                {
                    "condition_id": "cond-type-mismatch",
                    "field_path": "subject_id",
                    "operator": "greater_than",
                    "expected_value": 1,
                }
            ]
        )

        result = evaluate_rule_conditions(rule, request)

        assert result.condition_results[0].result is ConditionResult.ERROR
        assert result.result is RuleConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 5. PR 22 reuse / delegation
# ══════════════════════════════════════════════════════════════════════════


class TestPR22Delegation:
    def test_delegates_to_standalone_evaluate_condition_once_per_condition(self) -> None:
        request = _build_request()
        rule = _build_rule(
            conditions=[_match_cond("cond-1"), _no_match_cond("cond-2")],
        )

        with patch(
            "basis_core.policy.operation_aware.condition_eval.evaluate_condition",
            wraps=operators_module.evaluate_condition,
        ) as spy:
            result = evaluate_rule_conditions(rule, request)

        assert spy.call_count == 2
        called_condition_ids = [call.args[0].condition_id for call in spy.call_args_list]
        assert called_condition_ids == ["cond-1", "cond-2"]
        for call in spy.call_args_list:
            assert call.args[1] is request
        assert result.result is RuleConditionResult.NOT_MATCHED


# ══════════════════════════════════════════════════════════════════════════
# 6. Immutability and boundedness
# ══════════════════════════════════════════════════════════════════════════


class TestImmutabilityAndBoundedness:
    def test_rule_condition_evaluation_is_frozen(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_match_cond("cond-1")])
        result = evaluate_rule_conditions(rule, request)

        with pytest.raises(dataclasses.FrozenInstanceError):
            result.result = RuleConditionResult.ERROR  # type: ignore[misc]

    def test_condition_results_is_a_tuple_not_mutable_through_result(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_match_cond("cond-1"), _match_cond("cond-2")])
        result = evaluate_rule_conditions(rule, request)

        assert isinstance(result.condition_results, tuple)
        with pytest.raises(AttributeError):
            result.condition_results.append(  # type: ignore[attr-defined]
                ConditionEvaluation(condition_id="injected", result=ConditionResult.MATCH)
            )

    def test_result_type_carries_only_bounded_fields(self) -> None:
        """Proves no full request or full rule copy is carried -- only the
        rule's stable `rule_id`, the aggregate result, and the ordered
        per-condition results."""
        field_names = {f.name for f in dataclasses.fields(RuleConditionEvaluation)}
        assert field_names == {"rule_id", "result", "condition_results"}

    def test_rule_id_is_a_plain_string_identifier(self) -> None:
        request = _build_request()
        rule = _build_rule(conditions=[_match_cond("cond-1")], rule_id="rule-identifier-check")
        result = evaluate_rule_conditions(rule, request)

        assert result.rule_id == "rule-identifier-check"
        assert isinstance(result.rule_id, str)


# ══════════════════════════════════════════════════════════════════════════
# 7. Import boundary (static check, mirroring test_operators.py's convention)
# ══════════════════════════════════════════════════════════════════════════


class TestImportBoundary:
    def test_no_forbidden_imports(self) -> None:
        source = MODULE_PATH.read_text()
        tree = ast.parse(source)
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        forbidden_prefixes = (
            "basis_core.audit",
            "basis_core.enforcement",
            "basis_core.adapters",
            "basis_core.policy.engine",
            "basis_core.policy.rules",
        )
        for module_name in imported_modules:
            for forbidden in forbidden_prefixes:
                assert not module_name.startswith(forbidden), (
                    f"condition_eval.py imports {module_name!r}, which starts with the "
                    f"forbidden prefix {forbidden!r}."
                )
