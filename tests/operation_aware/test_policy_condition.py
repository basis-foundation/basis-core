"""
tests/operation_aware/test_policy_condition.py — tests for
`basis_core.policy.operation_aware.condition.PolicyCondition` (Milestone 4,
PR 12 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"PolicyCondition model").

Covers `PolicyCondition` construction, validation, immutability, equality,
and serialization round-trip — cross-checked against every vendored
`basis-schemas` v0.2.0 `policy-condition` contract example (five valid,
thirteen invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests condition *shape* only: construction, validation,
immutability, and schema alignment. It does not test, and must never test,
condition evaluation, match/no-match/error determination, operator
dispatch, or field-path resolution — none of that exists in this module or
this PR. `TestOperatorVocabularyRemainsOpen` in particular exists to prove
the *absence* of an operator whitelist, not to add one.

Does not test any later, not-yet-implemented operation-aware model
(`OperationAwarePolicyRule`, `PolicyBundle`, trace, audit, evaluator) — see
`tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import ast
import math

import pytest
from pydantic import ValidationError

from basis_core.policy.operation_aware.condition import PolicyCondition
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _condition_examples() -> tuple[list[object], list[object]]:
    document = load_contract("policy-condition")
    section = require_mapping_field(document, "policy_condition", context="policy-condition")
    examples = require_mapping_field(
        section, "examples", context="policy-condition.policy_condition"
    )
    valid = require_sequence_field(examples, "valid", context="policy-condition.examples")
    invalid = require_sequence_field(examples, "invalid", context="policy-condition.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _condition_examples()


def _invalid_example_value(entry: object) -> object:
    if isinstance(entry, dict) and "value" in entry and "reason" in entry:
        return entry["value"]
    return entry


def _invalid_example_reason(entry: object, index: int) -> str:
    if isinstance(entry, dict):
        reason = entry.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return f"example-{index}"


def _valid_example_id(example: object, index: int) -> str:
    if isinstance(example, dict):
        condition_id = example.get("condition_id")
        if isinstance(condition_id, str) and condition_id:
            return condition_id
    return f"example-{index}"


# A structurally valid condition reused across tests that need one but are
# not themselves testing condition_id/field_path/operator/expected_value
# validation.
_VALID_CONDITION_KWARGS: dict[str, object] = {
    "condition_id": "cond-clearance-equals-level-2",
    "field_path": "subject_attrs.clearance",
    "operator": "equals",
    "expected_value": "level-2",
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_five_valid_examples_are_vendored(self) -> None:
        # A supplementary count check — the parametrized tests below are
        # the primary completeness mechanism; this only guards against a
        # coincidental simultaneous add+remove in the vendored fixture.
        assert len(_VALID_EXAMPLES) == 5

    def test_thirteen_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 13

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        condition = PolicyCondition.model_validate(example)
        assert type(condition) is PolicyCondition

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            PolicyCondition.model_validate(value)


# ══════════════════════════════════════════════════════════════════════════
# Model configuration
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_model_is_frozen(self) -> None:
        assert PolicyCondition.model_config.get("frozen") is True

    def test_model_forbids_extra_fields(self) -> None:
        assert PolicyCondition.model_config.get("extra") == "forbid"

    def test_frozen_rejects_attribute_assignment(self) -> None:
        condition = PolicyCondition(**_VALID_CONDITION_KWARGS)
        with pytest.raises(ValidationError):
            condition.condition_id = "other"  # type: ignore[misc]

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(**_VALID_CONDITION_KWARGS, priority=1)  # type: ignore[call-arg]

    def test_missing_required_field_is_rejected(self) -> None:
        kwargs = dict(_VALID_CONDITION_KWARGS)
        del kwargs["operator"]
        with pytest.raises(ValidationError):
            PolicyCondition(**kwargs)  # type: ignore[arg-type]

    def test_equality_is_value_based(self) -> None:
        a = PolicyCondition(**_VALID_CONDITION_KWARGS)
        b = PolicyCondition(**_VALID_CONDITION_KWARGS)
        assert a == b
        assert a is not b

    def test_hashable(self) -> None:
        a = PolicyCondition(**_VALID_CONDITION_KWARGS)
        b = PolicyCondition(**_VALID_CONDITION_KWARGS)
        assert hash(a) == hash(b)
        assert len({a, b}) == 1

    def test_only_the_four_published_fields_exist(self) -> None:
        assert set(PolicyCondition.model_fields) == {
            "condition_id",
            "field_path",
            "operator",
            "expected_value",
        }

    def test_all_four_fields_are_required(self) -> None:
        for name, info in PolicyCondition.model_fields.items():
            assert info.is_required(), f"{name} must be required (no optional fields on PR 12)"


# ══════════════════════════════════════════════════════════════════════════
# condition_id
# ══════════════════════════════════════════════════════════════════════════


class TestConditionId:
    @pytest.mark.parametrize(
        "condition_id",
        ["cond-risk-score-high", "c", "condition_with_underscores", "CONDITION-1"],
    )
    def test_non_empty_condition_id_accepted(self, condition_id: str) -> None:
        condition = PolicyCondition(
            condition_id=condition_id,
            field_path="subject_attrs.clearance",
            operator="equals",
            expected_value="x",
        )
        assert condition.condition_id == condition_id

    def test_empty_condition_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="",
                field_path="subject_attrs.clearance",
                operator="equals",
                expected_value="x",
            )

    def test_whitespace_only_condition_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="   ",
                field_path="subject_attrs.clearance",
                operator="equals",
                expected_value="x",
            )

    def test_missing_condition_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                field_path="subject_attrs.clearance",  # type: ignore[call-arg]
                operator="equals",
                expected_value="x",
            )


# ══════════════════════════════════════════════════════════════════════════
# field_path
# ══════════════════════════════════════════════════════════════════════════


class TestFieldPath:
    @pytest.mark.parametrize(
        "field_path,description",
        [
            ("a", "smallest valid path (single lowercase letter)"),
            ("subject_id", "single segment"),
            ("subject_attrs.clearance", "two-segment dotted path"),
            ("location.site_id", "two-segment dotted path with underscore"),
            ("device.device_class", "two-segment dotted path"),
            ("protocol_context.protocol", "two-segment dotted path"),
            ("safety_context.safety_state", "two-segment dotted path"),
            ("risk_context.risk_level", "two-segment dotted path"),
            ("a.b.c.d", "multi-segment dotted path"),
            ("evaluation_time", "single segment with underscore"),
        ],
    )
    def test_valid_field_paths_accepted(self, field_path: str, description: str) -> None:
        condition = PolicyCondition(
            condition_id="cond-1",
            field_path=field_path,
            operator="equals",
            expected_value="x",
        )
        assert condition.field_path == field_path

    @pytest.mark.parametrize(
        "field_path,description",
        [
            ("", "empty string"),
            (".subject_id", "leading dot"),
            ("subject_id.", "trailing dot"),
            ("subject..id", "consecutive dots (empty segment)"),
            ("subject_roles[0]", "array-indexing syntax"),
            ("subject_attrs.get('clearance')", "method-call syntax"),
            ("Subject_Id", "uppercase characters"),
            ("subject id", "whitespace"),
            ("subject-id", "hyphen (not an underscore)"),
            ("1subject", "leading digit"),
            ("subject_id()", "function-call syntax"),
            ("subject_attrs.$where", "invalid punctuation"),
            ("{{subject_id}}", "template expression syntax"),
        ],
    )
    def test_malformed_field_paths_rejected(self, field_path: str, description: str) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path=field_path,
                operator="equals",
                expected_value="x",
            )

    def test_missing_field_path_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",  # type: ignore[call-arg]
                operator="equals",
                expected_value="x",
            )


# ══════════════════════════════════════════════════════════════════════════
# operator — open, structurally-validated identifier; no whitelist
# ══════════════════════════════════════════════════════════════════════════


class TestOperatorVocabularyRemainsOpen:
    """The most important boundary in PR 12: `operator` must accept any
    structurally well-formed identifier, including one that is not
    implemented anywhere and is not in the vendored contract's
    illustrative-only `illustrative_operators` list."""

    @pytest.mark.parametrize(
        "operator",
        ["equals", "not_equals", "in", "greater_than", "less_than", "exists"],
    )
    def test_illustrative_operators_are_accepted(self, operator: str) -> None:
        # These are the vendored contract's own `illustrative_operators` —
        # explicitly documented as non-final examples, not a closed set.
        condition = PolicyCondition(
            condition_id="cond-1",
            field_path="subject_attrs.clearance",
            operator=operator,
            expected_value="x",
        )
        assert condition.operator == operator

    def test_structurally_valid_but_semantically_unimplemented_operator_is_accepted(
        self,
    ) -> None:
        """Mandatory regression proof: `basis-core` implements no operator
        evaluation or dispatch anywhere yet, so *every* operator is
        currently "semantically unimplemented" in that sense — this test
        uses an invented identifier that additionally does not even appear
        in the vendored contract's illustrative list, to prove the
        acceptance is driven by structural validation alone, not by
        membership in any hardcoded list."""
        condition = PolicyCondition(
            condition_id="condition-future-operator",
            field_path="device.device_class",
            operator="future_architecture_operator",
            expected_value="controller",
        )
        assert condition.operator == "future_architecture_operator"

    def test_no_operator_enum_is_defined_in_the_module(self) -> None:
        """Behavior-level proof is `test_structurally_valid_...` above;
        this is a supplementary static check that the module defines no
        `Operator`-shaped enum class at all (source-level, not just
        "the field type isn't an enum")."""
        import inspect

        from basis_core.policy.operation_aware import condition as condition_module

        source = inspect.getsource(condition_module)
        tree = ast.parse(source)
        enum_like_class_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and "operator" in node.name.lower()
        }
        assert enum_like_class_names == set()

    @pytest.mark.parametrize(
        "operator,description",
        [
            ("", "empty string"),
            ("EQUALS", "uppercase"),
            ("equals:strict", "contains a colon"),
            ("equals-strict", "contains a hyphen"),
            ("_equals", "leading underscore"),
            ("equals_", "trailing underscore"),
            ("equals__strict", "doubled underscore"),
            ("1equals", "leading digit"),
            ("equals strict", "whitespace"),
        ],
    )
    def test_malformed_operators_rejected(self, operator: str, description: str) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="subject_attrs.clearance",
                operator=operator,
                expected_value="x",
            )

    def test_missing_operator_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",  # type: ignore[call-arg]
                field_path="subject_attrs.clearance",
                expected_value="x",
            )


# ══════════════════════════════════════════════════════════════════════════
# expected_value — scalar types
# ══════════════════════════════════════════════════════════════════════════


class TestExpectedValueScalarTypes:
    def test_string_scalar_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1",
            field_path="a.b",
            operator="equals",
            expected_value="level-2",
        )
        assert condition.expected_value == "level-2"
        assert isinstance(condition.expected_value, str)

    def test_integer_scalar_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=42
        )
        assert condition.expected_value == 42
        assert type(condition.expected_value) is int

    def test_float_scalar_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="greater_than", expected_value=0.5
        )
        assert condition.expected_value == 0.5
        assert type(condition.expected_value) is float

    @pytest.mark.parametrize("value", [True, False])
    def test_boolean_scalar_accepted(self, value: bool) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="exists", expected_value=value
        )
        assert condition.expected_value is value

    def test_explicit_null_scalar_accepted(self) -> None:
        # expected_value is REQUIRED but its value may legitimately be
        # null itself — see policy-condition.md §13.
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=None
        )
        assert condition.expected_value is None

    def test_missing_expected_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",  # type: ignore[call-arg]
                field_path="a.b",
                operator="equals",
            )

    def test_nan_scalar_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="equals",
                expected_value=math.nan,
            )

    def test_infinity_scalar_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="equals",
                expected_value=math.inf,
            )


# ══════════════════════════════════════════════════════════════════════════
# expected_value — homogeneous arrays
# ══════════════════════════════════════════════════════════════════════════


class TestExpectedValueHomogeneousArrays:
    def test_string_array_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1",
            field_path="location.site_id",
            operator="in",
            expected_value=["west-campus", "east-campus"],
        )
        assert condition.expected_value == ["west-campus", "east-campus"]

    def test_integer_array_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=[1, 2, 3]
        )
        assert condition.expected_value == [1, 2, 3]
        assert all(type(v) is int for v in condition.expected_value)  # type: ignore[union-attr]

    def test_float_array_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=[1.5, 2.5]
        )
        assert condition.expected_value == [1.5, 2.5]

    def test_boolean_array_accepted(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=[True, False]
        )
        assert condition.expected_value == [True, False]

    def test_mixed_integer_and_float_array_accepted_as_one_number_family(self) -> None:
        # The vendored contract publishes a single `number` scalar type
        # (not separate `integer`/`number` types — see
        # `expected_value_scalar_types` in policy-condition.yaml), so an
        # array mixing int and float items is homogeneous ("number") and
        # must be accepted, not rejected as heterogeneous.
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=[1, 2.5]
        )
        assert condition.expected_value == [1, 2.5]
        types = [type(v) for v in condition.expected_value]  # type: ignore[union-attr]
        assert types == [int, float]

    def test_empty_array_accepted(self) -> None:
        # The vendored contract documents no `minItems` constraint on
        # `expected_value`; an empty array is trivially homogeneous.
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=[]
        )
        assert condition.expected_value == []

    def test_array_order_is_preserved(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1",
            field_path="a.b",
            operator="in",
            expected_value=["c", "a", "b"],
        )
        assert condition.expected_value == ["c", "a", "b"]

    def test_duplicate_array_values_are_preserved_not_deduplicated(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="in", expected_value=["x", "x"]
        )
        assert condition.expected_value == ["x", "x"]


class TestExpectedValueMixedOrUnsupportedArrays:
    def test_string_and_number_mixed_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="location.site_id",
                operator="in",
                expected_value=["west-campus", 42],
            )

    def test_boolean_and_integer_mixed_array_rejected(self) -> None:
        # bool is a Python int subclass but must never be treated as the
        # same family as int/float here.
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1", field_path="a.b", operator="in", expected_value=[True, 1]
            )

    def test_boolean_and_false_zero_mixed_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1", field_path="a.b", operator="in", expected_value=[False, 0]
            )

    def test_null_inside_array_rejected(self) -> None:
        # expected_value_array_item_types excludes `null`, unlike the
        # top-level scalar form.
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="in",
                expected_value=["x", None],
            )

    def test_nested_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="in",
                expected_value=[[1, 2], [3, 4]],
            )

    def test_mapping_inside_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="in",
                expected_value=[{"a": 1}],
            )

    def test_nan_inside_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="a.b",
                operator="in",
                expected_value=[1.0, math.nan],
            )


class TestExpectedValueUnsupportedTopLevelShapes:
    def test_nested_object_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyCondition(
                condition_id="cond-1",
                field_path="subject_attrs.clearance",
                operator="equals",
                expected_value={"nested": "object-not-allowed"},
            )


# ══════════════════════════════════════════════════════════════════════════
# Strict primitive behavior — no silent coercion
# ══════════════════════════════════════════════════════════════════════════


class TestStrictPrimitiveBehavior:
    def test_string_one_is_not_confused_with_integer_one(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value="1"
        )
        assert condition.expected_value == "1"
        assert isinstance(condition.expected_value, str)
        assert condition.expected_value != 1

    def test_boolean_true_is_not_confused_with_integer_one(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=True
        )
        assert condition.expected_value is True
        assert type(condition.expected_value) is bool

    def test_boolean_false_is_not_confused_with_integer_zero(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=False
        )
        assert condition.expected_value is False
        assert type(condition.expected_value) is bool

    def test_integer_one_is_not_promoted_to_boolean_true(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=1
        )
        assert condition.expected_value == 1
        assert type(condition.expected_value) is int
        assert condition.expected_value is not True

    def test_integer_zero_is_not_promoted_to_boolean_false(self) -> None:
        condition = PolicyCondition(
            condition_id="cond-1", field_path="a.b", operator="equals", expected_value=0
        )
        assert condition.expected_value == 0
        assert type(condition.expected_value) is int
        assert condition.expected_value is not False


# ══════════════════════════════════════════════════════════════════════════
# Serialization round trip
# ══════════════════════════════════════════════════════════════════════════


class TestSerializationRoundTrip:
    @pytest.mark.parametrize(
        "kwargs",
        [
            _VALID_CONDITION_KWARGS,
            {
                "condition_id": "cond-risk-score-above-threshold",
                "field_path": "risk_context.score",
                "operator": "greater_than",
                "expected_value": 0.5,
            },
            {
                "condition_id": "cond-site-in-allowed-set",
                "field_path": "location.site_id",
                "operator": "in",
                "expected_value": ["west-campus", "east-campus"],
            },
            {
                "condition_id": "cond-null-value",
                "field_path": "a.b",
                "operator": "equals",
                "expected_value": None,
            },
        ],
    )
    def test_model_dump_json_round_trips(self, kwargs: dict[str, object]) -> None:
        condition = PolicyCondition(**kwargs)  # type: ignore[arg-type]
        dumped = condition.model_dump(mode="json")
        assert set(dumped) == {"condition_id", "field_path", "operator", "expected_value"}
        restored = PolicyCondition.model_validate(dumped)
        assert restored == condition


# ══════════════════════════════════════════════════════════════════════════
# No evaluation behavior
# ══════════════════════════════════════════════════════════════════════════


class TestNoEvaluationBehaviorExists:
    """This restriction is absolute — see this module's docstring. These
    are supplementary static checks; the primary proof is simply that no
    such methods are called anywhere in this file or in `condition.py`."""

    @pytest.mark.parametrize(
        "method_name",
        [
            "evaluate",
            "matches",
            "resolve_field_path",
            "get_actual_value",
            "compare",
        ],
    )
    def test_model_defines_no_evaluation_method(self, method_name: str) -> None:
        assert not hasattr(PolicyCondition, method_name)
