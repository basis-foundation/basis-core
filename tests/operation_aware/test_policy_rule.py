"""
tests/operation_aware/test_policy_rule.py — tests for
`basis_core.policy.operation_aware.rule.OperationAwarePolicyRule` (Milestone
4, PR 13 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"OperationAwarePolicyRule model").

Covers `OperationAwarePolicyRule`/`OperationAwarePolicyMatch`/`RuleEffect`
construction, validation, immutability, equality, and serialization
round-trip — cross-checked against every vendored `basis-schemas` v0.2.0
`policy-rule` contract example (four valid, sixteen invalid) via the
existing test-only loader (`tests/helpers/operation_aware_contracts.py`).

This file tests rule *shape* only: construction, validation, immutability,
and schema alignment. It does not test, and must never test, rule matching,
condition evaluation, deny precedence, ordering, or bundle-level behavior —
none of that exists in this module or this PR.
`TestNamingCollisionRegression` is the mandatory, mechanically-checked proof
that `from basis_core.policy import PolicyRule` continues to resolve to the
existing v0.1.0 `Protocol`, unaffected by anything added here.

Does not test any later, not-yet-implemented operation-aware model
(`PolicyBundle`, trace, audit, evaluator) — see
`tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basis_core.policy.operation_aware.condition import PolicyCondition
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
    RuleEffect,
)
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _rule_examples() -> tuple[list[object], list[object]]:
    document = load_contract("policy-rule")
    section = require_mapping_field(document, "policy_rule", context="policy-rule")
    examples = require_mapping_field(section, "examples", context="policy-rule.policy_rule")
    valid = require_sequence_field(examples, "valid", context="policy-rule.examples")
    invalid = require_sequence_field(examples, "invalid", context="policy-rule.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _rule_examples()


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
        rule_id = example.get("rule_id")
        if isinstance(rule_id, str) and rule_id:
            return rule_id
    return f"example-{index}"


# A structurally valid rule reused across tests that need one but are not
# themselves testing rule_id/effect/match/conditions validation.
_VALID_RULE_KWARGS: dict[str, object] = {
    "rule_id": "rule-operator-read-ahu",
    "effect": "allow",
    "match": {"subject_roles": ["operator"], "actions": ["read:ahu"]},
}

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
    def test_four_valid_examples_are_vendored(self) -> None:
        # A supplementary count check — the parametrized tests below are
        # the primary completeness mechanism; this only guards against a
        # coincidental simultaneous add+remove in the vendored fixture.
        assert len(_VALID_EXAMPLES) == 4

    def test_sixteen_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 16

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        rule = OperationAwarePolicyRule.model_validate(example)
        assert type(rule) is OperationAwarePolicyRule
        if "conditions" in example:
            assert all(type(condition) is PolicyCondition for condition in rule.conditions)
        if "match" in example:
            assert type(rule.match) is OperationAwarePolicyMatch

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule.model_validate(value)


# ══════════════════════════════════════════════════════════════════════════
# Model configuration
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_rule_model_is_frozen(self) -> None:
        assert OperationAwarePolicyRule.model_config.get("frozen") is True

    def test_rule_model_forbids_extra_fields(self) -> None:
        assert OperationAwarePolicyRule.model_config.get("extra") == "forbid"

    def test_match_model_is_frozen(self) -> None:
        assert OperationAwarePolicyMatch.model_config.get("frozen") is True

    def test_match_model_forbids_extra_fields(self) -> None:
        assert OperationAwarePolicyMatch.model_config.get("extra") == "forbid"

    def test_frozen_rejects_attribute_assignment(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        with pytest.raises(ValidationError):
            rule.rule_id = "other"  # type: ignore[misc]

    def test_unknown_top_level_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**_VALID_RULE_KWARGS, priority=1)  # type: ignore[call-arg]

    def test_missing_rule_id_is_rejected(self) -> None:
        kwargs = dict(_VALID_RULE_KWARGS)
        del kwargs["rule_id"]
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**kwargs)  # type: ignore[arg-type]

    def test_missing_effect_is_rejected(self) -> None:
        kwargs = dict(_VALID_RULE_KWARGS)
        del kwargs["effect"]
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**kwargs)  # type: ignore[arg-type]

    def test_equality_is_value_based(self) -> None:
        a = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        b = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        assert a == b
        assert a is not b

    def test_only_the_six_published_fields_exist(self) -> None:
        assert set(OperationAwarePolicyRule.model_fields) == {
            "rule_id",
            "effect",
            "match",
            "conditions",
            "reason_code",
            "explanation",
        }

    def test_rule_id_and_effect_are_required(self) -> None:
        assert OperationAwarePolicyRule.model_fields["rule_id"].is_required()
        assert OperationAwarePolicyRule.model_fields["effect"].is_required()

    def test_match_conditions_reason_code_explanation_are_optional(self) -> None:
        for name in ("match", "conditions", "reason_code", "explanation"):
            assert not OperationAwarePolicyRule.model_fields[name].is_required(), name

    def test_match_defaults_to_none(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="r1", effect="deny", conditions=[_VALID_CONDITION_KWARGS]
        )
        assert rule.match is None

    def test_conditions_defaults_to_none(self) -> None:
        # The vendored contract types `conditions` as `[array, "null"]`;
        # `None` (not `[]`) is the stored representation for "no
        # conditions" — see rule.py's "Contract basis for `None`".
        rule = OperationAwarePolicyRule(
            rule_id="r1", effect="allow", match={"actions": ["read:ahu"]}
        )
        assert rule.conditions is None

    def test_reason_code_defaults_to_none(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        assert rule.reason_code is None

    def test_explanation_defaults_to_none(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        assert rule.explanation is None

    def test_only_the_twenty_published_selector_fields_exist_on_match(self) -> None:
        assert set(OperationAwarePolicyMatch.model_fields) == {
            "subject_ids",
            "subject_roles",
            "identity_sources",
            "authority_modes",
            "actions",
            "resources",
            "resource_types",
            "site_ids",
            "building_ids",
            "zone_ids",
            "area_ids",
            "device_ids",
            "device_classes",
            "protocols",
            "protocol_operations",
            "operation_intents",
            "safety_modes",
            "safety_classifications",
            "environment_modes",
            "risk_classifications",
        }

    def test_all_selector_fields_are_optional(self) -> None:
        for name, info in OperationAwarePolicyMatch.model_fields.items():
            assert not info.is_required(), f"{name} must be optional"


# ══════════════════════════════════════════════════════════════════════════
# RuleEffect
# ══════════════════════════════════════════════════════════════════════════


class TestRuleEffect:
    @pytest.mark.parametrize("effect", ["allow", "deny"])
    def test_valid_effects_accepted(self, effect: str) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect=effect, match={"actions": ["read:ahu"]}
        )
        assert rule.effect == RuleEffect(effect)

    @pytest.mark.parametrize(
        "effect",
        ["not_applicable", "ALLOW", "DENY", "default_deny", "implicit_deny", "unknown", ""],
    )
    def test_invalid_effects_rejected(self, effect: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect=effect, match={"actions": ["read:ahu"]}
            )

    def test_not_applicable_specifically_rejected_as_bundle_applicability_outcome(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-not-applicable-effect",
                effect="not_applicable",
                match={"actions": ["read:ahu"]},
            )

    def test_missing_effect_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1",  # type: ignore[call-arg]
                match={"actions": ["read:ahu"]},
            )

    def test_effect_serializes_to_plain_string(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        dumped = rule.model_dump(mode="json")
        assert dumped["effect"] == "allow"
        assert isinstance(dumped["effect"], str)


# ══════════════════════════════════════════════════════════════════════════
# rule_id
# ══════════════════════════════════════════════════════════════════════════


class TestRuleId:
    @pytest.mark.parametrize(
        "rule_id", ["rule-operator-read-ahu-telemetry", "r", "rule_with_underscores", "RULE-1"]
    )
    def test_non_empty_rule_id_accepted(self, rule_id: str) -> None:
        rule = OperationAwarePolicyRule(
            rule_id=rule_id, effect="allow", match={"actions": ["read:ahu"]}
        )
        assert rule.rule_id == rule_id

    def test_empty_rule_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="", effect="allow", match={"actions": ["read:ahu"]})

    def test_whitespace_only_rule_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="   ", effect="allow", match={"actions": ["read:ahu"]})

    def test_missing_rule_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                effect="allow",  # type: ignore[call-arg]
                match={"actions": ["read:ahu"]},
            )


# ══════════════════════════════════════════════════════════════════════════
# Match typing and selector validation
# ══════════════════════════════════════════════════════════════════════════


class TestMatchTyping:
    def test_dict_reconstructs_as_typed_match_model(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"actions": ["read:ahu"]}
        )
        assert type(rule.match) is OperationAwarePolicyMatch

    def test_unknown_selector_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1",
                effect="allow",
                match={"actions": ["read:ahu"], "priority_selector": ["high"]},
            )

    def test_wrong_selector_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"actions": "read:ahu"}
            )

    def test_malformed_action_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow", match={"actions": ["read"]})

    def test_malformed_resource_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"resources": ["rooftop-1"]}
            )

    def test_valid_resource_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"resources": ["hvac:zone-a"]}
        )
        assert rule.match is not None
        assert rule.match.resources == ["hvac:zone-a"]

    def test_malformed_resource_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"resource_types": ["HVAC"]}
            )

    def test_malformed_authority_mode_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"authority_modes": ["Federated Mode"]}
            )

    def test_malformed_device_class_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"device_classes": ["Controller"]}
            )

    def test_malformed_protocol_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"protocols": ["BACnet"]}
            )

    def test_malformed_safety_mode_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"safety_modes": ["Interlock Engaged"]}
            )

    @pytest.mark.parametrize(
        "operation_intent", ["read_only", "state_changing", "control_affecting"]
    )
    def test_valid_operation_intents_accepted(self, operation_intent: str) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1",
            effect="allow",
            match={"operation_intents": [operation_intent]},
        )
        assert rule.match is not None
        assert rule.match.operation_intents == [operation_intent]

    def test_invalid_operation_intent_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"operation_intents": ["destructive"]}
            )

    @pytest.mark.parametrize(
        "field_name",
        [
            "subject_ids",
            "subject_roles",
            "identity_sources",
            "authority_modes",
            "actions",
            "resources",
            "resource_types",
            "site_ids",
            "building_ids",
            "zone_ids",
            "area_ids",
            "device_ids",
            "device_classes",
            "protocols",
            "protocol_operations",
            "operation_intents",
            "safety_modes",
            "safety_classifications",
            "environment_modes",
            "risk_classifications",
        ],
    )
    def test_empty_selector_array_rejected_for_every_field(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow", match={field_name: []})

    def test_omitted_selector_imposes_no_restriction(self) -> None:
        # Omitted selectors default to None (never []) without triggering
        # the empty-array rejection that an *explicit* [] input would.
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"actions": ["read:ahu"]}
        )
        assert rule.match is not None
        assert rule.match.subject_ids is None
        assert rule.match.resources is None

    def test_explicit_null_selector_rejected(self) -> None:
        # The vendored contract types every match_shape selector field as
        # `array` only — no `"null"` variant is published (unlike
        # `match`/`conditions` themselves). An explicit null must
        # therefore be rejected, not silently treated as omission — see
        # rule.py's `_reject_explicit_null_selectors`.
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1",
                effect="allow",
                match={"actions": ["read:ahu"], "subject_ids": None},
            )

    def test_explicit_null_selector_rejected_even_when_only_selector_present(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow", match={"actions": None})

    def test_omitted_key_is_distinguished_from_explicit_null_value(self) -> None:
        # The core distinction this correction depends on: a key entirely
        # absent from the input mapping is accepted (falls through to the
        # field's own None default); the same key present with value None
        # is rejected. This is only possible via the raw-mapping
        # `model_validator(mode="before")` inspection in rule.py, since an
        # ordinary field validator cannot tell the two apart.
        omitted = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"actions": ["read:ahu"]}
        )
        assert omitted.match is not None
        assert omitted.match.subject_ids is None
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-2",
                effect="allow",
                match={"actions": ["read:ahu"], "subject_ids": None},
            )

    def test_non_empty_selector_array_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"subject_ids": ["operator-1", "operator-2"]}
        )
        assert rule.match is not None
        assert rule.match.subject_ids == ["operator-1", "operator-2"]

    def test_whitespace_only_free_form_selector_item_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"subject_ids": ["   "]}
            )

    def test_mutable_input_list_cannot_mutate_constructed_rule(self) -> None:
        actions = ["read:ahu"]
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"actions": actions}
        )
        actions.append("write:ahu")
        assert rule.match is not None
        assert rule.match.actions == ["read:ahu"]


# ══════════════════════════════════════════════════════════════════════════
# Conditions typing
# ══════════════════════════════════════════════════════════════════════════


class TestConditionsTyping:
    def test_dicts_reconstruct_as_policy_condition(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1",
            effect="deny",
            conditions=[_VALID_CONDITION_KWARGS],
        )
        assert len(rule.conditions) == 1
        assert type(rule.conditions[0]) is PolicyCondition

    def test_malformed_nested_condition_rejected(self) -> None:
        malformed = dict(_VALID_CONDITION_KWARGS)
        del malformed["operator"]
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="deny", conditions=[malformed])

    def test_conditions_preserve_order(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        cond_b = dict(_VALID_CONDITION_KWARGS, condition_id="cond-b")
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b]
        )
        assert [c.condition_id for c in rule.conditions] == ["cond-a", "cond-b"]

    def test_original_input_list_mutation_cannot_alter_constructed_rule(self) -> None:
        conditions_input = [dict(_VALID_CONDITION_KWARGS)]
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=conditions_input
        )
        conditions_input.append(dict(_VALID_CONDITION_KWARGS, condition_id="cond-extra"))
        assert len(rule.conditions) == 1

    def test_explicit_empty_conditions_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="allow", match={"actions": ["read:ahu"]}, conditions=[]
            )

    def test_explicit_null_conditions_treated_as_omitted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1",
            effect="allow",
            match={"actions": ["read:ahu"]},
            conditions=None,
        )
        assert rule.conditions is None


# ══════════════════════════════════════════════════════════════════════════
# At-least-one-of(match, conditions) invariant
# ══════════════════════════════════════════════════════════════════════════


class TestAtLeastOneOfMatchOrConditions:
    def test_match_absent_and_conditions_absent_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow")

    def test_match_none_and_conditions_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow", match=None, conditions=[])

    def test_empty_match_object_and_empty_conditions_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="allow", match={}, conditions=[])

    def test_non_empty_match_with_no_conditions_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="allow", match={"actions": ["read:ahu"]}
        )
        assert rule.match is not None
        assert rule.conditions is None

    def test_no_match_with_non_empty_conditions_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[_VALID_CONDITION_KWARGS]
        )
        assert rule.match is None
        assert len(rule.conditions) == 1

    def test_non_empty_match_with_non_empty_conditions_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1",
            effect="deny",
            match={"operation_intents": ["control_affecting"]},
            conditions=[_VALID_CONDITION_KWARGS],
        )
        assert rule.match is not None
        assert len(rule.conditions) == 1

    def test_empty_match_object_alone_rejected_even_though_it_is_a_match_emptiness_case(
        self,
    ) -> None:
        # An entirely empty match object ({}) is invalid at
        # OperationAwarePolicyMatch's own construction boundary,
        # independent of whether conditions is populated.
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="deny", match={}, conditions=[_VALID_CONDITION_KWARGS]
            )


# ══════════════════════════════════════════════════════════════════════════
# condition_id uniqueness
# ══════════════════════════════════════════════════════════════════════════


class TestConditionIdUniqueness:
    def test_two_duplicate_ids_rejected(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-duplicate")
        cond_b = dict(
            _VALID_CONDITION_KWARGS,
            condition_id="cond-duplicate",
            field_path="risk_context.classification",
            operator="equals",
            expected_value="elevated",
        )
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b])

    def test_three_entries_with_one_duplicate_rejected(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        cond_b = dict(_VALID_CONDITION_KWARGS, condition_id="cond-b")
        cond_a_dup = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(
                rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b, cond_a_dup]
            )

    def test_same_condition_shape_with_different_ids_accepted(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        cond_b = dict(_VALID_CONDITION_KWARGS, condition_id="cond-b")
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b]
        )
        assert len(rule.conditions) == 2

    def test_different_conditions_with_unique_ids_accepted(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        cond_b = dict(
            _VALID_CONDITION_KWARGS,
            condition_id="cond-b",
            field_path="risk_context.score",
            operator="greater_than",
            expected_value=0.5,
        )
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b]
        )
        assert [c.condition_id for c in rule.conditions] == ["cond-a", "cond-b"]

    def test_no_silent_deduplication_ordering_preserved(self) -> None:
        cond_a = dict(_VALID_CONDITION_KWARGS, condition_id="cond-a")
        cond_b = dict(
            _VALID_CONDITION_KWARGS,
            condition_id="cond-b",
            field_path="risk_context.score",
            operator="greater_than",
            expected_value=0.9,
        )
        cond_c = dict(
            _VALID_CONDITION_KWARGS,
            condition_id="cond-c",
            field_path="risk_context.classification",
            operator="equals",
            expected_value="elevated",
        )
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[cond_a, cond_b, cond_c]
        )
        assert [c.condition_id for c in rule.conditions] == ["cond-a", "cond-b", "cond-c"]
        assert len(rule.conditions) == 3


# ══════════════════════════════════════════════════════════════════════════
# reason_code
# ══════════════════════════════════════════════════════════════════════════


class TestReasonCode:
    def test_valid_open_reason_code_accepted(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS, reason_code="allow_rule_matched")
        assert rule.reason_code == "allow_rule_matched"

    def test_structurally_valid_but_not_illustrative_reason_code_accepted(self) -> None:
        # No closed whitelist: any structurally well-formed reason code is
        # accepted, not just the vendored contract's illustrative examples.
        rule = OperationAwarePolicyRule(
            **_VALID_RULE_KWARGS, reason_code="future_architecture_reason"
        )
        assert rule.reason_code == "future_architecture_reason"

    def test_malformed_reason_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**_VALID_RULE_KWARGS, reason_code="ALLOW_RULE_MATCHED")

    def test_missing_reason_code_defaults_to_none(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        assert rule.reason_code is None


# ══════════════════════════════════════════════════════════════════════════
# explanation
# ══════════════════════════════════════════════════════════════════════════


class TestExplanation:
    def test_valid_static_explanation_accepted(self) -> None:
        rule = OperationAwarePolicyRule(
            **_VALID_RULE_KWARGS, explanation="Operators may read AHU telemetry."
        )
        assert rule.explanation == "Operators may read AHU telemetry."

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**_VALID_RULE_KWARGS, explanation=12345)  # type: ignore[arg-type]

    def test_empty_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**_VALID_RULE_KWARGS, explanation="")

    def test_whitespace_only_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwarePolicyRule(**_VALID_RULE_KWARGS, explanation="   ")

    def test_missing_explanation_defaults_to_none(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        assert rule.explanation is None

    def test_explanation_is_not_template_interpreted(self) -> None:
        # No interpolation mechanism exists; a template-looking string is
        # stored verbatim as opaque text, not executed or substituted.
        text = "Denied because {{subject_id}} lacks clearance."
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS, explanation=text)
        assert rule.explanation == text


# ══════════════════════════════════════════════════════════════════════════
# Serialization round trip
# ══════════════════════════════════════════════════════════════════════════


class TestSerializationRoundTrip:
    """The governed round-trip convention for this model is
    `model_dump(mode="json", exclude_none=True)` (never a plain
    `model_dump(mode="json")` with no arguments) — see rule.py's
    docstring, "Governed serialization convention". `exclude_none=True`
    is an ordinary `model_dump` call-time option, not a custom serializer
    or custom encoder."""

    _ROUND_TRIP_KWARGS: list[dict[str, object]] = [
        _VALID_RULE_KWARGS,
        {
            "rule_id": "rule-deny-elevated-risk",
            "effect": "deny",
            "conditions": [_VALID_CONDITION_KWARGS],
            "reason_code": "deny_rule_matched",
            "explanation": "Denies operations when risk is elevated.",
        },
        {
            "rule_id": "rule-scoped-with-condition",
            "effect": "deny",
            "match": {"operation_intents": ["control_affecting"]},
            "conditions": [_VALID_CONDITION_KWARGS],
        },
        # A rule with no conditions at all and only one populated
        # selector — every one of the other 19 selectors, plus
        # `conditions`, is left at its "unset" value.
        {"rule_id": "rule-minimal", "effect": "allow", "match": {"actions": ["read:ahu"]}},
    ]

    @pytest.mark.parametrize("kwargs", _ROUND_TRIP_KWARGS)
    def test_model_dump_json_produces_all_published_field_names(
        self, kwargs: dict[str, object]
    ) -> None:
        # A plain (non-exclude_none) dump still names every published
        # top-level field — this is unaffected by the governed
        # round-trip convention, which only changes what gets *omitted*.
        rule = OperationAwarePolicyRule(**kwargs)  # type: ignore[arg-type]
        dumped = rule.model_dump(mode="json")
        assert set(dumped) == {
            "rule_id",
            "effect",
            "match",
            "conditions",
            "reason_code",
            "explanation",
        }
        assert isinstance(dumped["effect"], str)
        if dumped["reason_code"] is not None:
            assert isinstance(dumped["reason_code"], str)

    @pytest.mark.parametrize("kwargs", _ROUND_TRIP_KWARGS)
    def test_governed_serialization_convention_round_trips(self, kwargs: dict[str, object]) -> None:
        # Requirement 7: serialized output reconstructs into an equal
        # rule, via the governed exclude_none=True convention.
        rule = OperationAwarePolicyRule(**kwargs)  # type: ignore[arg-type]
        dumped = rule.model_dump(mode="json", exclude_none=True)
        restored = OperationAwarePolicyRule.model_validate(dumped)
        assert restored == rule

    def test_exclude_none_omits_unused_selectors_and_unset_top_level_fields(self) -> None:
        # Requirement 5: model_dump(mode="json", exclude_none=True) omits
        # unused selectors (and unset top-level fields) entirely, rather
        # than emitting them as null.
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        dumped = rule.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "rule_id": "rule-operator-read-ahu",
            "effect": "allow",
            "match": {"subject_roles": ["operator"], "actions": ["read:ahu"]},
        }
        assert "conditions" not in dumped
        assert "reason_code" not in dumped
        assert "explanation" not in dumped
        assert "subject_ids" not in dumped["match"]
        assert "resources" not in dumped["match"]

    def test_governed_serialized_output_contains_no_empty_arrays_or_nulls(self) -> None:
        # Requirement 6: the governed serialized output contains neither
        # empty selector arrays nor null selector values.
        rule = OperationAwarePolicyRule(
            rule_id="rule-1",
            effect="deny",
            match={
                "operation_intents": ["control_affecting"],
                "safety_modes": ["interlock-engaged"],
            },
            conditions=[_VALID_CONDITION_KWARGS],
        )
        dumped = rule.model_dump(mode="json", exclude_none=True)
        assert all(v is not None for v in dumped.values())
        for selector_value in dumped["match"].values():
            assert selector_value is not None
            assert selector_value != []

    def test_plain_model_dump_json_would_emit_null_selectors_by_contrast(self) -> None:
        # Documents why exclude_none=True is required: a plain dump (no
        # arguments) emits an explicit null for every unset field —
        # structurally valid JSON, but not the governed contract shape.
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        plain_dumped = rule.model_dump(mode="json")
        assert plain_dumped["conditions"] is None
        assert plain_dumped["match"]["subject_ids"] is None
        assert plain_dumped["match"]["resources"] is None

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip_through_governed_convention(
        self, example: object
    ) -> None:
        # Requirement 8: all four vendored valid examples round-trip
        # through the governed serialization convention.
        assert isinstance(example, dict)
        rule = OperationAwarePolicyRule.model_validate(example)
        dumped = rule.model_dump(mode="json", exclude_none=True)
        restored = OperationAwarePolicyRule.model_validate(dumped)
        assert restored == rule

    def test_match_dumps_as_json_compatible_mapping(self) -> None:
        rule = OperationAwarePolicyRule(**_VALID_RULE_KWARGS)
        dumped = rule.model_dump(mode="json", exclude_none=True)
        assert isinstance(dumped["match"], dict)
        assert dumped["match"]["actions"] == ["read:ahu"]

    def test_conditions_dump_as_json_compatible_list_of_mappings(self) -> None:
        rule = OperationAwarePolicyRule(
            rule_id="rule-1", effect="deny", conditions=[_VALID_CONDITION_KWARGS]
        )
        dumped = rule.model_dump(mode="json", exclude_none=True)
        assert isinstance(dumped["conditions"], list)
        assert dumped["conditions"][0]["condition_id"] == _VALID_CONDITION_KWARGS["condition_id"]


# ══════════════════════════════════════════════════════════════════════════
# No evaluation behavior
# ══════════════════════════════════════════════════════════════════════════


class TestNoEvaluationBehaviorExists:
    """This restriction is absolute — see this module's docstring and
    `rule.py`'s docstring. These are supplementary static checks; the
    primary proof is simply that no such methods are called anywhere in
    this file or in `rule.py`."""

    @pytest.mark.parametrize(
        "method_name",
        ["evaluate", "matches", "matches_request", "resolve", "apply"],
    )
    def test_rule_model_defines_no_evaluation_method(self, method_name: str) -> None:
        assert not hasattr(OperationAwarePolicyRule, method_name)

    @pytest.mark.parametrize(
        "method_name",
        ["evaluate", "matches", "matches_request", "resolve", "apply"],
    )
    def test_match_model_defines_no_evaluation_method(self, method_name: str) -> None:
        assert not hasattr(OperationAwarePolicyMatch, method_name)


# ══════════════════════════════════════════════════════════════════════════
# Naming-collision regression — load-bearing compatibility test for PR 13
# ══════════════════════════════════════════════════════════════════════════


class TestNamingCollisionRegression:
    """Mandatory regression: `from basis_core.policy import PolicyRule`
    must continue to resolve to the existing v0.1.0 `Protocol`, unaffected
    by anything added in this PR. `OperationAwarePolicyRule` is a distinct
    symbol, never aliased to `PolicyRule`, and never exported from
    `basis_core.policy`."""

    def test_policy_rule_import_still_resolves_to_v01_protocol(self) -> None:
        from basis_core.policy import PolicyRule
        from basis_core.policy.engine import PolicyRule as V01PolicyRule

        assert PolicyRule is V01PolicyRule

    def test_operation_aware_policy_rule_is_not_policy_rule(self) -> None:
        from basis_core.policy import PolicyRule

        assert OperationAwarePolicyRule is not PolicyRule

    def test_operation_aware_policy_rule_exported_under_its_own_distinct_name(self) -> None:
        """As of PR 35 (Milestone 11), `OperationAwarePolicyRule` is
        stabilized as part of `basis_core.policy`'s package-level public
        API — but only under its own distinct name, never as `PolicyRule`.
        `PolicyRule` above (this class's other tests) continues to resolve
        to the unrelated v0.1.0 Protocol, unchanged."""
        import basis_core.policy as policy_package
        from basis_core.policy.operation_aware.rule import (
            OperationAwarePolicyRule as concrete,
        )

        assert "OperationAwarePolicyRule" in policy_package.__all__
        assert policy_package.OperationAwarePolicyRule is concrete
        assert "PolicyRule" in policy_package.__all__
        assert policy_package.PolicyRule is not policy_package.OperationAwarePolicyRule

    def test_v01_policy_rule_is_a_protocol_not_a_pydantic_model(self) -> None:
        import typing

        from pydantic import BaseModel

        from basis_core.policy import PolicyRule

        # The v0.1.0 PolicyRule is a typing.Protocol (a code interface),
        # structurally distinct from OperationAwarePolicyRule's Pydantic
        # BaseModel (a data shape) — this is the "code interface vs. data
        # shape" distinction the roadmap plan's Section 11 documents.
        assert issubclass(PolicyRule, typing.Protocol)  # type: ignore[arg-type]
        assert not issubclass(PolicyRule, BaseModel)
        assert issubclass(OperationAwarePolicyRule, BaseModel)
