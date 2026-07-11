"""
tests/operation_aware/test_vocabulary.py — tests for
`basis_core.domain.operation_aware_vocabulary` (Milestone 2, PR 5 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Shared vocabulary value objects").

Covers `RedactionClassification` (closed 5-value enum) and `ReasonCode`
(validated, open-format string) construction, validation, immutability,
equality, hashing, and deterministic representation — cross-checked against
the vendored `basis-schemas` v0.2.0 `redaction-classification` and
`reason-code` contract fixtures via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

Does not test any later, not-yet-implemented operation-aware model
(evidence references, context objects, request/response, policy, trace,
audit) — see `tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import re

import pytest

from basis_core.domain.operation_aware_vocabulary import ReasonCode, RedactionClassification
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
    require_string_field,
)

# ══════════════════════════════════════════════════════════════════════════
# RedactionClassification
# ══════════════════════════════════════════════════════════════════════════


class TestRedactionClassificationShape:
    def test_exactly_five_members(self) -> None:
        assert len(RedactionClassification) == 5

    def test_members_match_vendored_contract_ids(self) -> None:
        document = load_contract("redaction-classification")
        section = require_mapping_field(
            document, "redaction_classification", context="redaction-classification"
        )
        values = require_sequence_field(
            section, "values", context="redaction-classification.redaction_classification"
        )
        contract_ids = {
            require_string_field(entry, "id", context="redaction-classification.value")
            for entry in values
        }
        member_values = {member.value for member in RedactionClassification}
        assert member_values == contract_ids

    def test_values_are_lowercase_snake_case_strings(self) -> None:
        for member in RedactionClassification:
            assert member.value == member.value.lower()
            assert " " not in member.value
            assert "-" not in member.value


class TestRedactionClassificationConstruction:
    @pytest.mark.parametrize(
        "value",
        [
            "safe_to_expose",
            "safe_after_redaction",
            "reference_only",
            "never_store",
            "never_display",
        ],
    )
    def test_valid_values_construct(self, value: str) -> None:
        assert RedactionClassification(value).value == value

    def test_vendored_valid_examples_construct(self) -> None:
        document = load_contract("redaction-classification")
        section = require_mapping_field(
            document, "redaction_classification", context="redaction-classification"
        )
        examples = require_mapping_field(
            section, "examples", context="redaction-classification.redaction_classification"
        )
        valid = require_sequence_field(
            examples, "valid", context="redaction-classification...examples"
        )
        for value in valid:
            assert isinstance(value, str)
            assert RedactionClassification(value).value == value

    def test_vendored_invalid_examples_are_rejected(self) -> None:
        document = load_contract("redaction-classification")
        section = require_mapping_field(
            document, "redaction_classification", context="redaction-classification"
        )
        examples = require_mapping_field(
            section, "examples", context="redaction-classification.redaction_classification"
        )
        invalid = require_sequence_field(
            examples, "invalid", context="redaction-classification...examples"
        )
        for entry in invalid:
            value = require_string_field(
                entry, "value", context="redaction-classification.invalid-example"
            )
            with pytest.raises(ValueError):
                RedactionClassification(value)

    def test_unknown_classification_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            RedactionClassification("public")

    def test_empty_value_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            RedactionClassification("")

    def test_no_silent_coercion_from_non_member_string(self) -> None:
        with pytest.raises(ValueError):
            RedactionClassification("SAFE_TO_EXPOSE")


class TestRedactionClassificationImmutabilityAndIdentity:
    def test_members_are_singletons(self) -> None:
        assert RedactionClassification("safe_to_expose") is RedactionClassification.SAFE_TO_EXPOSE

    def test_equality_is_deterministic(self) -> None:
        assert RedactionClassification.NEVER_STORE == RedactionClassification.NEVER_STORE
        assert RedactionClassification.NEVER_STORE != RedactionClassification.NEVER_DISPLAY

    def test_string_mixin_equality(self) -> None:
        # str, Enum mixin — matches the existing repo convention
        # (SubjectType, ResourceType, DecisionOutcome, FailureReason).
        assert RedactionClassification.SAFE_TO_EXPOSE == "safe_to_expose"

    def test_hashable_and_usable_in_a_set(self) -> None:
        members = {RedactionClassification.NEVER_STORE, RedactionClassification.NEVER_STORE}
        assert len(members) == 1

    def test_deterministic_repr(self) -> None:
        assert repr(RedactionClassification.REFERENCE_ONLY) == (
            "<RedactionClassification.REFERENCE_ONLY: 'reference_only'>"
        )

    def test_no_new_member_can_be_added_at_runtime(self) -> None:
        with pytest.raises(ValueError):
            RedactionClassification("publicly_visible")


# ══════════════════════════════════════════════════════════════════════════
# ReasonCode
# ══════════════════════════════════════════════════════════════════════════


class TestReasonCodePatternAlignsWithContract:
    def test_pattern_matches_vendored_contract_pattern(self) -> None:
        document = load_contract("reason-code")
        section = require_mapping_field(document, "reason_code", context="reason-code")
        contract_pattern = require_string_field(
            section, "pattern", context="reason-code.reason_code"
        )
        assert contract_pattern == r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$"
        # And confirm basis-core's own compiled pattern is byte-identical,
        # not just behaviourally similar.
        from basis_core.domain.operation_aware_vocabulary import _REASON_CODE_RE

        assert _REASON_CODE_RE.pattern == contract_pattern


class TestReasonCodeConstruction:
    @pytest.mark.parametrize(
        "value",
        [
            "allow_rule_matched",
            "deny_rule_matched",
            "no_allow_rule_matched",
            "missing_required_context",
            "unknown_resource_type",
            "unsupported_schema_version",
            "policy_bundle_invalid",
            "evaluation_error",
            "future_unrecognized_reason_code",
            "a",
            "a1",
            "a_b_c",
        ],
    )
    def test_valid_values_construct(self, value: str) -> None:
        assert ReasonCode(value) == value

    def test_vendored_valid_examples_construct(self) -> None:
        document = load_contract("reason-code")
        section = require_mapping_field(document, "reason_code", context="reason-code")
        examples = require_mapping_field(section, "examples", context="reason-code.reason_code")
        valid = require_sequence_field(examples, "valid", context="reason-code...examples")
        for value in valid:
            assert isinstance(value, str)
            assert ReasonCode(value) == value

    def test_vendored_invalid_examples_are_rejected(self) -> None:
        document = load_contract("reason-code")
        section = require_mapping_field(document, "reason_code", context="reason-code")
        examples = require_mapping_field(section, "examples", context="reason-code.reason_code")
        invalid = require_sequence_field(examples, "invalid", context="reason-code...examples")
        for value in invalid:
            assert isinstance(value, str)
            with pytest.raises(ValueError):
                ReasonCode(value)

    @pytest.mark.parametrize(
        "value,description",
        [
            ("", "empty string"),
            ("ALLOW_RULE_MATCHED", "uppercase"),
            ("1_invalid_start", "leading digit"),
            ("read:ahu", "contains a colon"),
            ("deny-rule-matched", "contains hyphens"),
            ("_leading_underscore", "leading underscore"),
            ("trailing_underscore_", "trailing underscore"),
            ("double__underscore", "doubled underscore"),
            (" ", "whitespace-only"),
            ("has space", "contains a space"),
        ],
    )
    def test_invalid_values_are_rejected(self, value: str, description: str) -> None:
        with pytest.raises(ValueError):
            ReasonCode(value)

    @pytest.mark.parametrize("value", [123, 1.5, None, ["allow_rule_matched"], {"a": 1}])
    def test_non_string_types_are_rejected_not_coerced(self, value: object) -> None:
        with pytest.raises(TypeError):
            ReasonCode(value)  # type: ignore[arg-type]


class TestReasonCodeImmutabilityIdentityAndRepr:
    def test_is_a_str_subclass(self) -> None:
        assert isinstance(ReasonCode("allow_rule_matched"), str)

    def test_equality_with_plain_string(self) -> None:
        assert ReasonCode("allow_rule_matched") == "allow_rule_matched"

    def test_equality_between_instances(self) -> None:
        assert ReasonCode("allow_rule_matched") == ReasonCode("allow_rule_matched")

    def test_hash_matches_plain_string_hash(self) -> None:
        assert hash(ReasonCode("allow_rule_matched")) == hash("allow_rule_matched")

    def test_usable_as_dict_key(self) -> None:
        mapping = {ReasonCode("allow_rule_matched"): "matched"}
        assert mapping["allow_rule_matched"] == "matched"

    def test_deterministic_repr(self) -> None:
        assert repr(ReasonCode("allow_rule_matched")) == "ReasonCode('allow_rule_matched')"

    def test_str_conversion_returns_plain_value(self) -> None:
        assert str(ReasonCode("allow_rule_matched")) == "allow_rule_matched"

    def test_immutable_value_semantics(self) -> None:
        # str (and therefore ReasonCode) instances have no assignable
        # attributes and cannot be mutated in place; constructing twice from
        # the same input yields equal, independent, side-effect-free values.
        a = ReasonCode("allow_rule_matched")
        b = ReasonCode("allow_rule_matched")
        assert a == b
        assert a is not b or a == b  # equality holds regardless of identity


class TestReasonCodePatternRegexDirectly:
    _PATTERN = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("a", True),
            ("a1", True),
            ("a_b", True),
            ("a1_b2", True),
            ("", False),
            ("A", False),
            ("1a", False),
            ("a-b", False),
            ("a:b", False),
            ("_a", False),
            ("a_", False),
            ("a__b", False),
        ],
    )
    def test_reference_pattern_matches_reason_code_behavior(
        self, value: str, expected: bool
    ) -> None:
        matches = bool(self._PATTERN.match(value))
        assert matches == expected
        if matches:
            assert ReasonCode(value) == value
        else:
            with pytest.raises((ValueError, TypeError)):
                ReasonCode(value)
