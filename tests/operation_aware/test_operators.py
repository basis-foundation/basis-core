"""
tests/operation_aware/test_operators.py — tests for
`basis_core.policy.operation_aware.operators` (Milestone 7, PR 22 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Condition
operator registry implementation").

Covers the approved, finite ten-operator registry; the closed
`ConditionResult` vocabulary; field-path resolution (absent vs. unknown,
`subject_attrs` traversal, evidence-reference exclusion); every operator's
match/no-match/error behavior per the merged `basis-architecture`
clarification (`docs/architecture/condition-operator-semantics.md`); the
no-silent-coercion rule; unsupported-operator and unknown-path handling;
purity/determinism; and a static security-boundary check.

Scope
─────
This file tests standalone condition evaluation only: one `PolicyCondition`
against one `OperationAwareDecisionRequest`. It does not test, and must
never test: rule-level condition-array iteration or aggregation, selector
integration, `TraceRuleEvidence`/`EvaluationTrace`, rule effects, deny
precedence, or any final authorization outcome — none of that exists in
this module or this PR (PR 23 and later, separately-scoped roadmap work).

Does not duplicate `test_policy_condition.py`'s structural `PolicyCondition`
validation coverage (PR 12 owns condition *shape*; this file owns condition
*execution* semantics) — the one exception is a single confirmation that
list-indexing syntax remains structurally rejected by `PolicyCondition`
itself, included here only because it is directly relevant to this
module's field-path resolution boundary.
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path

import pytest
from pydantic import ValidationError

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.condition import PolicyCondition
from basis_core.policy.operation_aware.operators import (
    SUPPORTED_OPERATORS,
    ConditionEvaluation,
    ConditionResult,
    evaluate_condition,
)

MODULE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "basis_core"
    / "policy"
    / "operation_aware"
    / "operators.py"
)

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    """Build a minimal, otherwise-fixed `OperationAwareDecisionRequest`,
    merging `overrides` on top of the minimal required fields. Nested
    context objects may be supplied as plain dicts — pydantic validates
    them into their proper typed model."""
    kwargs: dict[str, object] = {
        "request_id": "req-operators-fixture-0001",
        "subject_id": "svc-operators-test",
        "action": "read:ahu",
    }
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


def _cond(
    *,
    condition_id: str = "cond-operators-fixture",
    field_path: str,
    operator: str,
    expected_value: object,
) -> PolicyCondition:
    return PolicyCondition(
        condition_id=condition_id,
        field_path=field_path,
        operator=operator,
        expected_value=expected_value,
    )


_APPROVED_OPERATORS = frozenset(
    {
        "equals",
        "not_equals",
        "in",
        "not_in",
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
        "exists",
        "not_exists",
    }
)


# ══════════════════════════════════════════════════════════════════════════
# 1. Registry contract
# ══════════════════════════════════════════════════════════════════════════


class TestRegistryContract:
    def test_supported_operators_matches_approved_set_exactly(self) -> None:
        assert SUPPORTED_OPERATORS == _APPROVED_OPERATORS
        extra = SUPPORTED_OPERATORS - _APPROVED_OPERATORS
        missing = _APPROVED_OPERATORS - SUPPORTED_OPERATORS
        assert extra == set(), f"Unapproved operators present: {extra}"
        assert missing == set(), f"Approved operators missing: {missing}"

    def test_approved_operator_count_is_ten(self) -> None:
        assert len(SUPPORTED_OPERATORS) == 10

    def test_supported_operators_is_immutable_frozenset(self) -> None:
        assert isinstance(SUPPORTED_OPERATORS, frozenset)
        with pytest.raises(AttributeError):
            SUPPORTED_OPERATORS.add("bogus")  # type: ignore[attr-defined]

    def test_no_alias_names_are_supported(self) -> None:
        aliases = {
            "eq",
            "ne",
            "gt",
            "gte",
            "lt",
            "lte",
            "contains",
            "matches",
            "regex",
            "starts_with",
            "ends_with",
            "any_of",
            "all_of",
            "between",
            "before",
            "after",
        }
        assert SUPPORTED_OPERATORS.isdisjoint(aliases)

    def test_deterministic_lookup_repeated_calls_agree(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="subject_id", operator="equals", expected_value="svc-operators-test"
        )
        first = evaluate_condition(condition, request)
        second = evaluate_condition(condition, request)
        assert first == second

    def test_unsupported_operator_evaluates_to_error_not_no_match_or_match(self) -> None:
        condition = _cond(
            field_path="risk_context.score",
            operator="future_architecture_operator",
            expected_value=0.5,
        )
        request = _build_request(risk_context={"score": 0.9})
        evaluation = evaluate_condition(condition, request)
        assert evaluation.result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 2. Result vocabulary
# ══════════════════════════════════════════════════════════════════════════


class TestResultVocabulary:
    def test_condition_result_is_closed_to_three_values(self) -> None:
        assert {member.value for member in ConditionResult} == {"match", "no_match", "error"}

    def test_invalid_result_value_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConditionResult("bogus")

    def test_condition_evaluation_is_immutable(self) -> None:
        evaluation = ConditionEvaluation(condition_id="cond-x", result=ConditionResult.MATCH)
        with pytest.raises(AttributeError):
            evaluation.result = ConditionResult.NO_MATCH  # type: ignore[misc]

    def test_condition_evaluation_carries_condition_id(self) -> None:
        condition = _cond(
            condition_id="cond-identity-check",
            field_path="subject_id",
            operator="exists",
            expected_value=True,
        )
        request = _build_request()
        evaluation = evaluate_condition(condition, request)
        assert evaluation.condition_id == "cond-identity-check"

    def test_two_evaluations_with_equal_fields_compare_equal(self) -> None:
        a = ConditionEvaluation(condition_id="cond-x", result=ConditionResult.MATCH)
        b = ConditionEvaluation(condition_id="cond-x", result=ConditionResult.MATCH)
        assert a == b


# ══════════════════════════════════════════════════════════════════════════
# 3. Field-path resolution
# ══════════════════════════════════════════════════════════════════════════


class TestFieldPathResolution:
    def test_valid_top_level_field(self) -> None:
        request = _build_request(subject_id="svc-alpha")
        condition = _cond(field_path="subject_id", operator="equals", expected_value="svc-alpha")
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_valid_nested_field(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(
            field_path="location.site_id", operator="equals", expected_value="west-campus"
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_optional_parent_absent(self) -> None:
        request = _build_request()  # location entirely absent
        condition = _cond(field_path="location.site_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_optional_leaf_absent_with_parent_present(self) -> None:
        request = _build_request(location={"building_id": "b1"})  # site_id not supplied
        condition = _cond(field_path="location.site_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_parent_absent_and_leaf_absent_collapse_to_same_result(self) -> None:
        no_parent = _build_request()
        leaf_absent = _build_request(location={"building_id": "b1"})
        condition = _cond(field_path="location.site_id", operator="not_exists", expected_value=True)
        assert (
            evaluate_condition(condition, no_parent).result
            == evaluate_condition(condition, leaf_absent).result
            == ConditionResult.MATCH
        )

    def test_unknown_top_level_path(self) -> None:
        request = _build_request()
        condition = _cond(field_path="future_context", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_unknown_nested_leaf(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(field_path="location.campus_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_unknown_nested_leaf_on_device(self) -> None:
        request = _build_request(device={"device_id": "ctrl-042"})
        condition = _cond(field_path="device.vendor_secret", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_subject_attrs_existing_key(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        condition = _cond(
            field_path="subject_attrs.department", operator="equals", expected_value="facilities"
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_subject_attrs_missing_key(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        condition = _cond(
            field_path="subject_attrs.clearance", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_subject_attrs_one_level_boundary(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        condition = _cond(field_path="subject_attrs", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_subject_attrs_deeper_traversal_rejected(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        condition = _cond(
            field_path="subject_attrs.department.region", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_identity_evidence_reference_path_excluded(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="identity_evidence_reference.identity_source",
            operator="exists",
            expected_value=True,
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_adapter_evidence_reference_path_excluded(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="adapter_evidence_reference.protocol",
            operator="not_exists",
            expected_value=True,
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_bare_identity_evidence_reference_also_excluded(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="identity_evidence_reference", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_list_index_syntax_structurally_rejected_by_policy_condition(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-bad-path",
                field_path="subject_roles[0]",
                operator="equals",
                expected_value="admin",
            )

    def test_extra_segment_past_scalar_leaf_is_unknown(self) -> None:
        request = _build_request()
        condition = _cond(field_path="subject_id.nickname", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 4/5. equals / not_equals
# ══════════════════════════════════════════════════════════════════════════


class TestEquals:
    def test_string_match(self) -> None:
        request = _build_request(action="read:ahu")
        condition = _cond(field_path="action", operator="equals", expected_value="read:ahu")
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_string_no_match(self) -> None:
        request = _build_request(action="read:ahu")
        condition = _cond(field_path="action", operator="equals", expected_value="write:ahu")
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_number_match_int_vs_int(self) -> None:
        request = _build_request(risk_context={"score": 5})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=5)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_number_match_int_vs_float_same_family(self) -> None:
        request = _build_request(risk_context={"score": 1})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=1.0)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_boolean_family_reserved_no_current_actual_field(self) -> None:
        # No scalar field on the request model populates the boolean family
        # directly; this documents that equals still requires a same-family
        # expected value for whichever fields exist (covered below via
        # string/number). No standalone boolean-actual test is possible
        # without bypassing typed models.
        assert True

    def test_missing_actual_is_no_match(self) -> None:
        request = _build_request()  # resource not supplied
        condition = _cond(field_path="resource", operator="equals", expected_value="hvac:zone-a")
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_expected_null_against_present_actual_is_error(self) -> None:
        request = _build_request(action="read:ahu")
        condition = _cond(field_path="action", operator="equals", expected_value=None)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_expected_null_against_missing_actual_is_no_match(self) -> None:
        request = _build_request()
        condition = _cond(field_path="resource", operator="equals", expected_value=None)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_incompatible_types_string_vs_number_is_error(self) -> None:
        request = _build_request(safety_context={"mode": "interlock-engaged"})
        condition = _cond(field_path="safety_context.mode", operator="equals", expected_value=1)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_boolean_never_equals_integer_one(self) -> None:
        # risk_context.score is the only numeric actual field; there is no
        # boolean-typed actual field to compare against `True`/`1` directly,
        # so this is proven at the expected-value classification layer: an
        # integer actual is never treated as matching a boolean expected.
        request = _build_request(risk_context={"score": 1})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_string_numeric_versus_number_not_coerced(self) -> None:
        request = _build_request(risk_context={"score": 3})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value="3")
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_array_actual_unsupported_is_error(self) -> None:
        request = _build_request(subject_roles=["operator", "admin"])
        condition = _cond(field_path="subject_roles", operator="equals", expected_value="operator")
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_array_expected_value_unsupported_is_error(self) -> None:
        request = _build_request(action="read:ahu")
        condition = _cond(field_path="action", operator="equals", expected_value=["read:ahu"])
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_structured_object_actual_is_error(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(field_path="location", operator="equals", expected_value="west-campus")
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_timestamp_actual_is_error(self) -> None:
        request = _build_request(evaluation_time="2026-07-14T10:00:00Z")
        condition = _cond(
            field_path="evaluation_time", operator="equals", expected_value="2026-07-14T10:00:00Z"
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


class TestNotEquals:
    def test_present_and_different_matches(self) -> None:
        request = _build_request(environment_context={"mode": "degraded-connectivity"})
        condition = _cond(
            field_path="environment_context.mode",
            operator="not_equals",
            expected_value="maintenance-mode",
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_present_and_equal_no_match(self) -> None:
        request = _build_request(environment_context={"mode": "maintenance-mode"})
        condition = _cond(
            field_path="environment_context.mode",
            operator="not_equals",
            expected_value="maintenance-mode",
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_absent_actual_is_no_match_not_match(self) -> None:
        """Absence must never be treated as satisfying 'not equal'."""
        request = _build_request()  # environment_context absent
        condition = _cond(
            field_path="environment_context.mode",
            operator="not_equals",
            expected_value="maintenance-mode",
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_expected_null_present_actual_is_error(self) -> None:
        request = _build_request(environment_context={"mode": "maintenance-mode"})
        condition = _cond(
            field_path="environment_context.mode", operator="not_equals", expected_value=None
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_expected_null_absent_actual_is_no_match(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="environment_context.mode", operator="not_equals", expected_value=None
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_incompatible_types_is_error(self) -> None:
        request = _build_request(environment_context={"mode": "maintenance-mode"})
        condition = _cond(
            field_path="environment_context.mode", operator="not_equals", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 6/7. in / not_in
# ══════════════════════════════════════════════════════════════════════════


class TestIn:
    def test_first_member_matches(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus", "north-annex"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_middle_member_matches(self) -> None:
        request = _build_request(location={"site_id": "east-campus"})
        condition = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus", "north-annex"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_final_member_matches(self) -> None:
        request = _build_request(location={"site_id": "north-annex"})
        condition = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus", "north-annex"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_no_member_matches(self) -> None:
        request = _build_request(location={"site_id": "south-depot"})
        condition = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_duplicate_expected_values_no_effect(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "west-campus", "east-campus"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_order_independence(self) -> None:
        request = _build_request(location={"site_id": "east-campus"})
        forward = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus"],
        )
        reverse = _cond(
            field_path="location.site_id",
            operator="in",
            expected_value=["east-campus", "west-campus"],
        )
        assert (
            evaluate_condition(forward, request).result
            == evaluate_condition(reverse, request).result
            == ConditionResult.MATCH
        )

    def test_empty_expected_array_never_matches(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(field_path="location.site_id", operator="in", expected_value=[])
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_incompatible_actual_type_is_error(self) -> None:
        request = _build_request(risk_context={"score": 42})
        condition = _cond(field_path="risk_context.score", operator="in", expected_value=["a", "b"])
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_missing_actual_is_no_match(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="location.site_id", operator="in", expected_value=["west-campus"]
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_scalar_expected_value_instead_of_array_is_error(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(
            field_path="location.site_id", operator="in", expected_value="west-campus"
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_no_coercion_number_array_vs_string_actual(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(field_path="device.device_class", operator="in", expected_value=[1, 2, 3])
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


class TestNotIn:
    def test_present_and_not_a_member_matches(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(
            field_path="device.device_class",
            operator="not_in",
            expected_value=["legacy-controller", "unmanaged-sensor"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_present_and_is_a_member_no_match(self) -> None:
        request = _build_request(device={"device_class": "legacy-controller"})
        condition = _cond(
            field_path="device.device_class",
            operator="not_in",
            expected_value=["legacy-controller", "unmanaged-sensor"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_missing_actual_is_no_match_not_match(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="device.device_class",
            operator="not_in",
            expected_value=["legacy-controller"],
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_empty_expected_array_always_matches(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(field_path="device.device_class", operator="not_in", expected_value=[])
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_incompatible_type_is_error_not_automatic_not_in(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(
            field_path="device.device_class", operator="not_in", expected_value=[1, 2, 3]
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 8. Numeric comparisons
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "op, actual, expected, want",
    [
        ("greater_than", 0.72, 0.5, ConditionResult.MATCH),
        ("greater_than", 0.3, 0.5, ConditionResult.NO_MATCH),
        ("greater_than", 0.5, 0.5, ConditionResult.NO_MATCH),
        ("greater_than_or_equal", 0.5, 0.5, ConditionResult.MATCH),
        ("greater_than_or_equal", 0.49, 0.5, ConditionResult.NO_MATCH),
        ("less_than", 0.1, 0.2, ConditionResult.MATCH),
        ("less_than", 0.5, 0.2, ConditionResult.NO_MATCH),
        ("less_than", 0.2, 0.2, ConditionResult.NO_MATCH),
        ("less_than_or_equal", 0.2, 0.2, ConditionResult.MATCH),
        ("less_than_or_equal", 0.9, 0.2, ConditionResult.NO_MATCH),
        ("greater_than", -1, -5, ConditionResult.MATCH),
        ("less_than", -5, -1, ConditionResult.MATCH),
        ("greater_than_or_equal", 0, 0, ConditionResult.MATCH),
        ("less_than_or_equal", 0, 0, ConditionResult.MATCH),
    ],
)
def test_numeric_comparison_match_and_boundary(
    op: str, actual: float, expected: float, want: ConditionResult
) -> None:
    request = _build_request(risk_context={"score": actual})
    condition = _cond(field_path="risk_context.score", operator=op, expected_value=expected)
    assert evaluate_condition(condition, request).result is want


@pytest.mark.parametrize(
    "op", ["greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"]
)
class TestNumericComparisonErrorsAndAbsence:
    def test_boolean_actual_rejected(self, op: str) -> None:
        # No numeric actual field can hold a bool (risk_context.score
        # rejects booleans at construction), so the boolean-rejection rule
        # is proven via a boolean *expected_value* against a numeric actual.
        request = _build_request(risk_context={"score": 1})
        condition = _cond(field_path="risk_context.score", operator=op, expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_string_actual_rejected(self, op: str) -> None:
        request = _build_request(risk_context={"classification": "elevated"})
        condition = _cond(field_path="risk_context.classification", operator=op, expected_value=0.5)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_array_expected_rejected(self, op: str) -> None:
        request = _build_request(risk_context={"score": 0.5})
        condition = _cond(field_path="risk_context.score", operator=op, expected_value=[0.1, 0.2])
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_missing_actual_is_no_match(self, op: str) -> None:
        request = _build_request()
        condition = _cond(field_path="risk_context.score", operator=op, expected_value=0.5)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_timestamp_actual_rejected(self, op: str) -> None:
        request = _build_request(evaluation_time="2026-07-14T10:00:00Z")
        condition = _cond(field_path="evaluation_time", operator=op, expected_value=0.5)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_no_string_ordering(self, op: str) -> None:
        request = _build_request(location={"site_id": "a-site"})
        condition = _cond(field_path="location.site_id", operator=op, expected_value="b-site")
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 9/10. exists / not_exists
# ══════════════════════════════════════════════════════════════════════════


class TestExists:
    def test_known_field_with_concrete_value_matches(self) -> None:
        request = _build_request(evaluation_time="2026-07-14T10:00:00Z")
        condition = _cond(field_path="evaluation_time", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_known_optional_field_observably_none_no_match(self) -> None:
        request = _build_request()
        condition = _cond(field_path="evaluation_time", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_absent_optional_parent_no_match(self) -> None:
        request = _build_request()
        condition = _cond(field_path="device.device_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_absent_optional_leaf_no_match(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(field_path="device.device_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_unknown_field_path_is_error(self) -> None:
        request = _build_request()
        condition = _cond(field_path="location.campus_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_known_subject_attrs_key_matches(self) -> None:
        request = _build_request(subject_attrs={"clearance": "level-3"})
        condition = _cond(
            field_path="subject_attrs.clearance", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_missing_subject_attrs_key_no_match(self) -> None:
        request = _build_request(subject_attrs={"clearance": "level-3"})
        condition = _cond(
            field_path="subject_attrs.department", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_expected_value_is_not_interpreted(self) -> None:
        """`expected_value` is required by the shared schema but must not
        change the result — proven by two otherwise-identical conditions
        differing only in `expected_value`."""
        request = _build_request(evaluation_time="2026-07-14T10:00:00Z")
        a = _cond(field_path="evaluation_time", operator="exists", expected_value=True)
        b = _cond(field_path="evaluation_time", operator="exists", expected_value="ignored-value")
        assert evaluate_condition(a, request).result == evaluate_condition(b, request).result

    def test_subject_roles_always_present_even_when_empty(self) -> None:
        """`subject_roles` defaults to `[]`, never `None` — always PRESENT,
        so `exists` always matches it (approved clarification §12.1)."""
        request = _build_request(subject_roles=[])
        condition = _cond(field_path="subject_roles", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH


class TestNotExists:
    def test_device_entirely_absent_matches(self) -> None:
        request = _build_request()
        condition = _cond(field_path="device.device_id", operator="not_exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_device_present_but_leaf_absent_matches(self) -> None:
        request = _build_request(device={"device_class": "gateway"})
        condition = _cond(field_path="device.device_id", operator="not_exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_device_id_present_no_match(self) -> None:
        request = _build_request(device={"device_id": "ctrl-042"})
        condition = _cond(field_path="device.device_id", operator="not_exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH

    def test_excluded_evidence_reference_path_is_error(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="adapter_evidence_reference.protocol",
            operator="not_exists",
            expected_value=True,
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_subject_roles_never_matches_even_when_empty(self) -> None:
        request = _build_request(subject_roles=[])
        condition = _cond(field_path="subject_roles", operator="not_exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.NO_MATCH


# ══════════════════════════════════════════════════════════════════════════
# 11/12. Unsupported operator / unknown paths
# ══════════════════════════════════════════════════════════════════════════


class TestUnsupportedOperatorCrossBoundary:
    def test_policy_condition_construction_succeeds_with_unimplemented_operator(self) -> None:
        """Proves the shared contract's `operator` field remains open even
        though this kernel version's registry is finite."""
        condition = PolicyCondition(
            condition_id="cond-future",
            field_path="risk_context.score",
            operator="future_architecture_operator",
            expected_value=0.5,
        )
        assert condition.operator == "future_architecture_operator"

    def test_evaluation_of_unimplemented_operator_is_error(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-future",
            field_path="risk_context.score",
            operator="future_architecture_operator",
            expected_value=0.5,
        )
        request = _build_request(risk_context={"score": 0.9})
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_unimplemented_operator_error_independent_of_field_path_validity(self) -> None:
        """An unsupported operator errors even when paired with a
        genuinely unknown field path — both are independently erroring
        conditions, never masking one another as a different outcome."""
        condition = PolicyCondition(
            condition_id="cond-future-bad-path",
            field_path="future_context.mode",
            operator="future_architecture_operator",
            expected_value="x",
        )
        request = _build_request()
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


class TestUnknownPaths:
    def test_unknown_root_field(self) -> None:
        request = _build_request()
        condition = _cond(field_path="future_context", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_unknown_nested_field(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(field_path="location.campus_id", operator="exists", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_excluded_evidence_reference_path(self) -> None:
        request = _build_request()
        condition = _cond(
            field_path="identity_evidence_reference.identity_source",
            operator="exists",
            expected_value=True,
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_unsupported_deep_mapping_path(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        condition = _cond(
            field_path="subject_attrs.department.region", operator="exists", expected_value=True
        )
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR


# ══════════════════════════════════════════════════════════════════════════
# 13. Type mismatch matrix
# ══════════════════════════════════════════════════════════════════════════


class TestTypeMismatchMatrix:
    """A systematic, but not exhaustively-Cartesian, table of governed
    actual/expected family transitions, cross-cutting several operators."""

    @pytest.mark.parametrize(
        "field_path, overrides, operator, expected_value",
        [
            ("action", {"action": "read:ahu"}, "equals", 1),  # string vs number
            ("action", {"action": "read:ahu"}, "equals", True),  # string vs boolean
            (
                "risk_context.score",
                {"risk_context": {"score": 1}},
                "equals",
                "1",
            ),  # number vs string
            (
                "risk_context.score",
                {"risk_context": {"score": 1}},
                "equals",
                True,
            ),  # number vs boolean
            ("subject_roles", {"subject_roles": ["a"]}, "equals", "a"),  # array actual vs string
            ("location", {"location": {"site_id": "s"}}, "equals", "s"),  # structured object actual
            (
                "evaluation_time",
                {"evaluation_time": "2026-07-14T10:00:00Z"},
                "equals",
                "2026-07-14T10:00:00Z",
            ),  # timestamp actual vs string
        ],
    )
    def test_incompatible_family_transitions_are_error(
        self, field_path: str, overrides: dict[str, object], operator: str, expected_value: object
    ) -> None:
        request = _build_request(**overrides)
        condition = _cond(field_path=field_path, operator=operator, expected_value=expected_value)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_mapping_actual_bare_subject_attrs_only_meaningful_for_existence(self) -> None:
        request = _build_request(subject_attrs={"department": "facilities"})
        comparison = _cond(
            field_path="subject_attrs", operator="equals", expected_value="facilities"
        )
        existence = _cond(field_path="subject_attrs", operator="exists", expected_value=True)
        assert evaluate_condition(comparison, request).result is ConditionResult.ERROR
        assert evaluate_condition(existence, request).result is ConditionResult.MATCH


# ══════════════════════════════════════════════════════════════════════════
# 14. No coercion regression matrix
# ══════════════════════════════════════════════════════════════════════════


class TestNoCoercion:
    @pytest.mark.parametrize(
        "field_path, overrides, expected_value",
        [
            ("risk_context.score", {"risk_context": {"score": 1}}, "1"),
            ("risk_context.score", {"risk_context": {"score": 1.0}}, "1.0"),
            ("risk_context.score", {"risk_context": {"score": 1}}, True),
            ("risk_context.score", {"risk_context": {"score": 0}}, False),
            ("action", {"action": "read:ahu"}, ["read:ahu"]),  # scalar vs one-element array
        ],
    )
    def test_no_silent_match_through_coercion(
        self, field_path: str, overrides: dict[str, object], expected_value: object
    ) -> None:
        request = _build_request(**overrides)
        condition = _cond(field_path=field_path, operator="equals", expected_value=expected_value)
        result = evaluate_condition(condition, request).result
        assert result is not ConditionResult.MATCH
        assert result is ConditionResult.ERROR

    def test_true_never_equals_one(self) -> None:
        request = _build_request(risk_context={"score": 1})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=True)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_false_never_equals_zero(self) -> None:
        request = _build_request(risk_context={"score": 0})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=False)
        assert evaluate_condition(condition, request).result is ConditionResult.ERROR

    def test_int_and_float_same_family_is_not_coercion(self) -> None:
        """1 == 1.0 is a same-family numeric comparison, not coercion."""
        request = _build_request(risk_context={"score": 1})
        condition = _cond(field_path="risk_context.score", operator="equals", expected_value=1.0)
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH

    def test_enum_backed_value_compares_as_its_serialized_string(self) -> None:
        """`operation_intent` resolves to its `.value` string — comparable
        directly to a plain string `expected_value`, not a coercion."""
        request = _build_request(operation_intent="read_only")
        condition = _cond(
            field_path="operation_intent", operator="equals", expected_value="read_only"
        )
        assert evaluate_condition(condition, request).result is ConditionResult.MATCH


# ══════════════════════════════════════════════════════════════════════════
# 15. Purity and determinism
# ══════════════════════════════════════════════════════════════════════════


class TestPurityAndDeterminism:
    def test_repeated_calls_are_equal(self) -> None:
        request = _build_request(
            location={"site_id": "west-campus"}, subject_attrs={"department": "ops"}
        )
        condition = _cond(
            field_path="location.site_id", operator="equals", expected_value="west-campus"
        )
        results = [evaluate_condition(condition, request) for _ in range(5)]
        assert all(r == results[0] for r in results)

    def test_condition_unchanged_after_evaluation(self) -> None:
        request = _build_request(location={"site_id": "west-campus"})
        condition = _cond(
            field_path="location.site_id", operator="equals", expected_value="west-campus"
        )
        before = condition.model_dump(mode="json")
        evaluate_condition(condition, request)
        after = condition.model_dump(mode="json")
        assert before == after

    def test_request_unchanged_after_evaluation(self) -> None:
        request = _build_request(
            location={"site_id": "west-campus"},
            subject_attrs={"department": "ops"},
            subject_roles=["operator"],
            safety_context={"mode": "normal", "constraint_ids": ["c-1", "c-2"]},
        )
        condition = _cond(
            field_path="safety_context.mode", operator="equals", expected_value="normal"
        )
        before = request.model_dump(mode="json")
        evaluate_condition(condition, request)
        after = request.model_dump(mode="json")
        assert before == after

    def test_nested_and_mapping_values_unchanged(self) -> None:
        request = _build_request(
            subject_attrs={"department": "ops"},
            location={"site_id": "west-campus"},
        )
        subject_attrs_before = copy.deepcopy(request.subject_attrs)
        location_before = request.location.model_dump(mode="json") if request.location else None
        condition = _cond(
            field_path="subject_attrs.department", operator="equals", expected_value="ops"
        )
        evaluate_condition(condition, request)
        assert request.subject_attrs == subject_attrs_before
        assert (
            request.location.model_dump(mode="json") if request.location else None
        ) == location_before

    def test_expected_value_array_unchanged(self) -> None:
        expected = ["west-campus", "east-campus"]
        condition = _cond(
            field_path="location.site_id", operator="in", expected_value=list(expected)
        )
        request = _build_request(location={"site_id": "west-campus"})
        evaluate_condition(condition, request)
        assert list(condition.expected_value) == expected  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# 16. Security boundary
# ══════════════════════════════════════════════════════════════════════════


class TestSecurityBoundary:
    _FORBIDDEN_IMPORT_PREFIXES = (
        "os",
        "sys",
        "subprocess",
        "socket",
        "requests",
        "httpx",
        "urllib",
        "boto3",
        "sqlite3",
        "importlib",
        "yaml",
    )
    _FORBIDDEN_CALL_NAMES = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "globals",
        "locals",
    }

    def _tree(self) -> ast.Module:
        source = MODULE_PATH.read_text(encoding="utf-8")
        return ast.parse(source, filename=str(MODULE_PATH))

    def test_module_exists(self) -> None:
        assert MODULE_PATH.is_file()

    def test_no_forbidden_imports(self) -> None:
        tree = self._tree()
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        violations = [
            m
            for m in imports
            if any(m == p or m.startswith(p + ".") for p in self._FORBIDDEN_IMPORT_PREFIXES)
        ]
        assert violations == []

    def test_imports_are_the_expected_narrow_set(self) -> None:
        tree = self._tree()
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        assert imports == {
            "__future__",
            "collections.abc",
            "dataclasses",
            "datetime",
            "enum",
            "types",
            "typing",
            "basis_core.decisions.operation_aware",
            "basis_core.policy.operation_aware.condition",
        }

    def test_no_forbidden_calls(self) -> None:
        tree = self._tree()
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in self._FORBIDDEN_CALL_NAMES:
                    violations.append(node.func.id)
        assert violations == []

    def test_no_forbidden_attribute_access(self) -> None:
        """No `os.system`, `os.environ`, `subprocess.*`, etc. — checked via
        AST attribute-access nodes rather than raw text, so prose mentions
        in the module docstring can never produce a false positive."""
        tree = self._tree()
        forbidden_roots = {"os", "subprocess", "socket"}
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in forbidden_roots:
                    violations.append(f"{node.value.id}.{node.attr}")
        assert violations == []

    def test_no_policy_engine_or_enforcement_or_audit_or_adapter_imports(self) -> None:
        tree = self._tree()
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        forbidden_prefixes = (
            "basis_core.audit",
            "basis_core.enforcement",
            "basis_core.adapters",
            "basis_core.policy.engine",
            "basis_core.policy.rules",
        )
        violations = [m for m in imports if any(m.startswith(p) for p in forbidden_prefixes)]
        assert violations == []
