"""
tests/operation_aware/test_policy_validation.py — tests for
`basis_core.policy.operation_aware.validation` (Milestone 4, PR 15 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Policy
bundle structural + semantic validation pipeline").

Covers the `PolicyBundleValidationError` hierarchy, the
`validate_policy_bundle()` structural/semantic pipeline, duplicate-`rule_id`
rejection (including the vendored `invalid-policy-bundle` canonical-vector
fixture, loaded directly via the existing test-only loader), duplicate-
`condition_id` handling, purity (no mutation, no stored validation state),
and the absence of any evaluation/applicability behavior on this module or
the bundle it returns.

This file tests the validation *pipeline* only: it does not test, and must
never test, scope-to-request applicability (PR 17), rule/condition
evaluation, or canonical-vector conformance beyond the one
`invalid-policy-bundle` fixture PR 15's own roadmap entry requires (broad
canonical-vector coverage across all five scenarios is PR 16's separate
scope — see `tests/operation_aware/README.md`'s scope boundaries).

The PR 13 / PR 15 duplicate-`condition_id` overlap
────────────────────────────────────────────────────────────────────────
`rule.py`'s `OperationAwarePolicyRule` already rejects duplicate
`condition_id` values within one rule's `conditions`, structurally, via its
own `model_validator(mode="after")` (`_check_condition_id_uniqueness`,
PR 13) — see `validation.py`'s docstring, "Duplicate `condition_id`", for
the full explanation this test file assumes as background. Two consequences
this file demonstrates explicitly, rather than hiding:

  - `TestDuplicateConditionIds.test_duplicate_within_one_rule_via_mapping_
    is_structural_not_semantic` proves that mapping input carrying a
    duplicate `condition_id` is rejected by this module's *structural*
    stage (`StructuralPolicyValidationError`, with PR 13's own
    `pydantic.ValidationError` preserved as `__cause__`) — never reaching
    `SemanticPolicyValidationError` — because `PolicyBundle.model_validate`
    itself already fails first.
  - `TestDuplicateConditionIds.test_pipeline_detects_duplicate_condition_id_
    when_reachable` proves `validation.py`'s own
    `_validate_unique_condition_ids` genuinely executes and raises
    `DuplicateConditionIdError` when given a typed `PolicyBundle` that
    exhibits the violation — built via `OperationAwarePolicyRule.
    model_construct(...)`/`PolicyBundle.model_construct(...)`, pydantic's
    own public "already-validated data" construction path that
    intentionally skips field/model validators. This is the only way to
    construct the violating case at all, precisely because `rule.py`'s
    ordinary constructor path (exercised in the previous test) refuses to
    build it. Nothing about `rule.py`'s own validator is weakened, removed,
    or bypassed for any ordinary caller — see `validation.py`'s docstring
    for the full rationale.
"""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from basis_core.policy.operation_aware.bundle import PolicyBundle
from basis_core.policy.operation_aware.condition import PolicyCondition
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule, RuleEffect
from basis_core.policy.operation_aware.validation import (
    DuplicateConditionIdError,
    DuplicateRuleIdError,
    PolicyBundleValidationError,
    SemanticPolicyValidationError,
    StructuralPolicyValidationError,
    validate_policy_bundle,
)
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ══════════════════════════════════════════════════════════════════════════
# Shared builders — fresh dicts/instances per call, never shared mutable
# module-level state
# ══════════════════════════════════════════════════════════════════════════


def _condition_kwargs(condition_id: str) -> dict[str, object]:
    return {
        "condition_id": condition_id,
        "field_path": "subject_attrs.clearance",
        "operator": "equals",
        "expected_value": "high",
    }


def _rule_dict(
    rule_id: str, *, action: str = "read:ahu", effect: str = "allow"
) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "effect": effect,
        "match": {"actions": [action]},
    }


def _rule_dict_with_conditions(rule_id: str, condition_ids: list[str]) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "effect": "allow",
        "conditions": [_condition_kwargs(cid) for cid in condition_ids],
    }


def _bundle_dict(
    *, rules: list[dict[str, object]] | None = None, **overrides: object
) -> dict[str, object]:
    base: dict[str, object] = {
        "bundle_id": "bundle-test",
        "bundle_version": "1.0.0",
        "schema_version": "0.2.0",
        "policy_owner": "test-owner",
        "rules": rules if rules is not None else [_rule_dict("rule-1")],
    }
    base.update(overrides)
    return base


def _bundle_with_duplicate_condition_ids_via_model_construct() -> PolicyBundle:
    """Build a real, correctly-typed `PolicyBundle` whose one rule carries
    two `PolicyCondition` instances sharing a `condition_id` — a shape
    `OperationAwarePolicyRule`'s own ordinary constructor
    (`_check_condition_id_uniqueness`, PR 13) refuses to produce. Uses
    pydantic's own public `model_construct` ("already-validated data")
    escape hatch, which intentionally skips field/model validators, so
    this module's `_validate_unique_condition_ids` can be proven to
    execute and raise for real. See this file's module docstring and
    `validation.py`'s docstring for the full rationale. Does not weaken,
    remove, or bypass `rule.py`'s validator for any ordinary caller —
    `test_duplicate_condition_ids_rejected_by_ordinary_rule_construction`
    below proves the ordinary path still refuses this exact shape.
    """
    cond_a = PolicyCondition(**_condition_kwargs("cond-duplicate"))
    cond_b = PolicyCondition(
        condition_id="cond-duplicate",
        field_path="subject_attrs.clearance",
        operator="equals",
        expected_value="low",
    )
    rule = OperationAwarePolicyRule.model_construct(
        rule_id="rule-bypassed",
        effect=RuleEffect.ALLOW,
        match=None,
        conditions=[cond_a, cond_b],
        reason_code=None,
        explanation=None,
    )
    return PolicyBundle.model_construct(
        bundle_id="bundle-condition-dup-probe",
        bundle_version="1.0.0",
        schema_version="0.2.0",
        policy_owner="test-owner",
        scope=None,
        rules=[rule],
        description=None,
        source_ref=None,
        approval_ref=None,
        created_at=None,
        updated_at=None,
        compatibility_target=None,
        deprecated=False,
        replaced_by=None,
    )


# ══════════════════════════════════════════════════════════════════════════
# Error hierarchy
# ══════════════════════════════════════════════════════════════════════════


class TestErrorHierarchy:
    def test_structural_error_is_policy_bundle_validation_error(self) -> None:
        assert issubclass(StructuralPolicyValidationError, PolicyBundleValidationError)

    def test_semantic_error_is_policy_bundle_validation_error(self) -> None:
        assert issubclass(SemanticPolicyValidationError, PolicyBundleValidationError)

    def test_duplicate_rule_id_error_is_semantic(self) -> None:
        assert issubclass(DuplicateRuleIdError, SemanticPolicyValidationError)

    def test_duplicate_condition_id_error_is_semantic(self) -> None:
        assert issubclass(DuplicateConditionIdError, SemanticPolicyValidationError)

    def test_structural_and_semantic_are_distinct(self) -> None:
        assert not issubclass(StructuralPolicyValidationError, SemanticPolicyValidationError)
        assert not issubclass(SemanticPolicyValidationError, StructuralPolicyValidationError)

    def test_root_error_is_not_a_pydantic_error(self) -> None:
        assert not issubclass(PolicyBundleValidationError, ValidationError)
        assert PolicyBundleValidationError is not ValidationError

    def test_root_error_is_a_plain_exception(self) -> None:
        assert issubclass(PolicyBundleValidationError, Exception)

    def test_original_pydantic_error_preserved_as_cause(self) -> None:
        with pytest.raises(StructuralPolicyValidationError) as exc_info:
            validate_policy_bundle(_bundle_dict(bundle_id=""))
        assert isinstance(exc_info.value.__cause__, ValidationError)


# ══════════════════════════════════════════════════════════════════════════
# Structural input
# ══════════════════════════════════════════════════════════════════════════


class TestStructuralValidation:
    def test_valid_mapping_returns_policy_bundle(self) -> None:
        result = validate_policy_bundle(_bundle_dict())
        assert type(result) is PolicyBundle

    def test_existing_policy_bundle_instance_returns_successfully(self) -> None:
        bundle = PolicyBundle.model_validate(_bundle_dict())
        result = validate_policy_bundle(bundle)
        assert type(result) is PolicyBundle
        assert result == bundle

    def test_typed_input_skips_re_validation_and_returns_same_instance(self) -> None:
        bundle = PolicyBundle.model_validate(_bundle_dict())
        result = validate_policy_bundle(bundle)
        assert result is bundle

    def test_missing_required_field_raises_structural_error(self) -> None:
        malformed = _bundle_dict()
        del malformed["bundle_id"]
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(malformed)

    def test_empty_bundle_id_raises_structural_error(self) -> None:
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(_bundle_dict(bundle_id="  "))

    def test_malformed_nested_rule_raises_structural_error(self) -> None:
        malformed = _bundle_dict(rules=[{"rule_id": "rule-1", "effect": "not_a_real_effect"}])
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(malformed)

    def test_malformed_scope_raises_structural_error(self) -> None:
        malformed = _bundle_dict(scope={})
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(malformed)

    def test_unknown_field_raises_structural_error(self) -> None:
        malformed = _bundle_dict(unexpected_field="not part of the contract")
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(malformed)

    def test_empty_rules_raises_structural_error(self) -> None:
        malformed = _bundle_dict(rules=[])
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle(malformed)

    def test_non_mapping_non_bundle_input_raises_structural_error(self) -> None:
        with pytest.raises(StructuralPolicyValidationError):
            validate_policy_bundle("not a mapping or a PolicyBundle")  # type: ignore[arg-type]

    def test_raw_mapping_input_is_not_mutated(self) -> None:
        raw = _bundle_dict()
        before = copy.deepcopy(raw)
        validate_policy_bundle(raw)
        assert raw == before

    def test_raw_mapping_input_is_not_mutated_on_failure(self) -> None:
        raw = _bundle_dict(rules=[_rule_dict("dup"), _rule_dict("dup")])
        before = copy.deepcopy(raw)
        with pytest.raises(PolicyBundleValidationError):
            validate_policy_bundle(raw)
        assert raw == before


# ══════════════════════════════════════════════════════════════════════════
# Duplicate rule_id
# ══════════════════════════════════════════════════════════════════════════


class TestDuplicateRuleIds:
    def test_two_duplicates_rejected(self) -> None:
        bundle = _bundle_dict(
            rules=[_rule_dict("rule-a"), _rule_dict("rule-a", action="write:ahu")]
        )
        with pytest.raises(DuplicateRuleIdError):
            validate_policy_bundle(bundle)

    def test_duplicate_among_three_rules_rejected(self) -> None:
        bundle = _bundle_dict(
            rules=[
                _rule_dict("rule-a"),
                _rule_dict("rule-b", action="write:ahu"),
                _rule_dict("rule-a", action="browse:ahu"),
            ]
        )
        with pytest.raises(DuplicateRuleIdError):
            validate_policy_bundle(bundle)

    def test_all_unique_accepted(self) -> None:
        bundle = _bundle_dict(
            rules=[
                _rule_dict("rule-a"),
                _rule_dict("rule-b", action="write:ahu"),
                _rule_dict("rule-c", action="browse:ahu"),
            ]
        )
        result = validate_policy_bundle(bundle)
        assert type(result) is PolicyBundle
        assert len(result.rules) == 3

    def test_same_rule_shape_different_ids_accepted(self) -> None:
        bundle = _bundle_dict(
            rules=[
                _rule_dict("rule-a"),
                _rule_dict("rule-b"),
            ]
        )
        result = validate_policy_bundle(bundle)
        assert result.rules[0].match == result.rules[1].match

    def test_exact_rule_id_appears_in_error(self) -> None:
        bundle = _bundle_dict(
            rules=[_rule_dict("rule-duplicate-marker"), _rule_dict("rule-duplicate-marker")]
        )
        with pytest.raises(DuplicateRuleIdError, match="rule-duplicate-marker"):
            validate_policy_bundle(bundle)

    def test_bundle_id_appears_in_error(self) -> None:
        bundle = _bundle_dict(
            bundle_id="bundle-id-marker",
            rules=[_rule_dict("rule-a"), _rule_dict("rule-a")],
        )
        with pytest.raises(DuplicateRuleIdError, match="bundle-id-marker"):
            validate_policy_bundle(bundle)

    def test_deterministic_repeated_error_message(self) -> None:
        def _message() -> str:
            bundle = _bundle_dict(rules=[_rule_dict("rule-a"), _rule_dict("rule-a")])
            with pytest.raises(DuplicateRuleIdError) as exc_info:
                validate_policy_bundle(bundle)
            return str(exc_info.value)

        assert _message() == _message()

    def test_comparison_is_exact_string_not_normalized(self) -> None:
        # "Rule-A" and "rule-a" must NOT be treated as duplicates — no
        # lowercasing, trimming, or other normalization.
        bundle = _bundle_dict(
            rules=[_rule_dict("Rule-A"), _rule_dict("rule-a", action="write:ahu")]
        )
        result = validate_policy_bundle(bundle)
        assert {rule.rule_id for rule in result.rules} == {"Rule-A", "rule-a"}

    def test_first_of_three_rules_is_preserved_not_dropped(self) -> None:
        # Authored order is preserved on the failure path too — this test
        # only proves the pipeline doesn't silently keep-first/keep-last
        # by inspecting the raised error's identified rule_id.
        bundle = _bundle_dict(
            rules=[
                _rule_dict("rule-x"),
                _rule_dict("rule-y", action="write:ahu"),
                _rule_dict("rule-x", action="browse:ahu"),
            ]
        )
        with pytest.raises(DuplicateRuleIdError, match="rule-x"):
            validate_policy_bundle(bundle)


# ══════════════════════════════════════════════════════════════════════════
# Duplicate condition_id
# ══════════════════════════════════════════════════════════════════════════


class TestDuplicateConditionIds:
    def test_duplicate_within_one_rule_via_mapping_is_structural_not_semantic(self) -> None:
        # See this file's module docstring, "The PR 13 / PR 15 duplicate-
        # condition_id overlap": PR 13's own rule-level validator rejects
        # this before this module's semantic stage ever runs.
        bundle = _bundle_dict(rules=[_rule_dict_with_conditions("rule-1", ["cond-a", "cond-a"])])
        with pytest.raises(StructuralPolicyValidationError) as exc_info:
            validate_policy_bundle(bundle)
        assert not isinstance(exc_info.value, SemanticPolicyValidationError)
        assert isinstance(exc_info.value.__cause__, ValidationError)
        assert "condition_id" in str(exc_info.value.__cause__)

    def test_duplicate_condition_ids_rejected_by_ordinary_rule_construction(self) -> None:
        # Direct proof that PR 13's own validator is what fires first —
        # exercised against `OperationAwarePolicyRule` directly, not
        # through this module.
        with pytest.raises(ValidationError, match="condition_id"):
            OperationAwarePolicyRule(
                rule_id="rule-1",
                effect="allow",
                conditions=[_condition_kwargs("cond-a"), _condition_kwargs("cond-a")],
            )

    def test_same_condition_id_across_different_rules_accepted(self) -> None:
        bundle = _bundle_dict(
            rules=[
                _rule_dict_with_conditions("rule-a", ["cond-shared"]),
                _rule_dict_with_conditions("rule-b", ["cond-shared"]),
            ]
        )
        result = validate_policy_bundle(bundle)
        assert type(result) is PolicyBundle

    def test_unique_condition_ids_within_rule_accepted(self) -> None:
        bundle = _bundle_dict(rules=[_rule_dict_with_conditions("rule-a", ["cond-1", "cond-2"])])
        result = validate_policy_bundle(bundle)
        assert len(result.rules[0].conditions or []) == 2

    def test_pipeline_detects_duplicate_condition_id_when_reachable(self) -> None:
        # See this file's module docstring and `validation.py`'s docstring
        # for why `model_construct` is required to reach this branch, and
        # why that does not weaken rule.py's own check for ordinary
        # callers (see the previous `model_construct`-free test above).
        bundle = _bundle_with_duplicate_condition_ids_via_model_construct()
        with pytest.raises(DuplicateConditionIdError, match="rule-bypassed") as exc_info:
            validate_policy_bundle(bundle)
        assert "cond-duplicate" in str(exc_info.value)
        assert isinstance(exc_info.value, SemanticPolicyValidationError)

    def test_pipeline_condition_id_check_is_deterministic(self) -> None:
        def _message() -> str:
            bundle = _bundle_with_duplicate_condition_ids_via_model_construct()
            with pytest.raises(DuplicateConditionIdError) as exc_info:
                validate_policy_bundle(bundle)
            return str(exc_info.value)

        assert _message() == _message()


# ══════════════════════════════════════════════════════════════════════════
# Canonical invalid-policy-bundle fixture
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalInvalidFixture:
    """Uses the vendored `invalid-policy-bundle` canonical-vector fixture
    directly (`tests/fixtures/basis-schemas/v0.2.0/compatibility/
    invalid-policy-bundle/invalid-policy-bundle.yaml`), loaded via the
    existing test-only loader (`tests/helpers/operation_aware_contracts.
    load_scenario_artifact`) — never copied into this file, never
    imitated, and never mutated on disk."""

    def _load_raw(self) -> dict[str, object]:
        raw = load_scenario_artifact("invalid-policy-bundle", "policy_bundle")
        assert isinstance(raw, dict)
        return raw

    def test_raw_fixture_is_structurally_valid(self) -> None:
        # The fixture's only intended defect is semantic (duplicate
        # rule_id) — plain PolicyBundle construction must succeed.
        bundle = PolicyBundle.model_validate(self._load_raw())
        assert type(bundle) is PolicyBundle
        assert len(bundle.rules) == 2

    def test_pipeline_rejects_fixture_semantically(self) -> None:
        with pytest.raises(SemanticPolicyValidationError) as exc_info:
            validate_policy_bundle(self._load_raw())
        assert not isinstance(exc_info.value, StructuralPolicyValidationError)

    def test_error_type_is_duplicate_rule_id_error(self) -> None:
        with pytest.raises(DuplicateRuleIdError):
            validate_policy_bundle(self._load_raw())

    def test_error_mentions_duplicate_rule_id(self) -> None:
        with pytest.raises(DuplicateRuleIdError, match="allow-duplicate-rule"):
            validate_policy_bundle(self._load_raw())

    def test_error_mentions_bundle_id(self) -> None:
        with pytest.raises(DuplicateRuleIdError, match="bundle-compat-invalid-policy"):
            validate_policy_bundle(self._load_raw())

    def test_correcting_only_duplicate_rule_id_succeeds(self) -> None:
        fixed = copy.deepcopy(self._load_raw())
        assert isinstance(fixed, dict)
        rules = fixed["rules"]
        assert isinstance(rules, list)
        assert len(rules) == 2
        second_rule = rules[1]
        assert isinstance(second_rule, dict)
        second_rule["rule_id"] = "allow-duplicate-rule-corrected"

        result = validate_policy_bundle(fixed)

        assert type(result) is PolicyBundle
        assert {rule.rule_id for rule in result.rules} == {
            "allow-duplicate-rule",
            "allow-duplicate-rule-corrected",
        }

    def test_no_fixture_mutation_on_disk(self) -> None:
        first_load = self._load_raw()
        with pytest.raises(PolicyBundleValidationError):
            validate_policy_bundle(first_load)
        second_load = self._load_raw()
        assert first_load == second_load


# ══════════════════════════════════════════════════════════════════════════
# Purity
# ══════════════════════════════════════════════════════════════════════════


class TestPurity:
    def test_input_mapping_not_mutated_on_success(self) -> None:
        raw = _bundle_dict()
        before = copy.deepcopy(raw)
        validate_policy_bundle(raw)
        assert raw == before

    def test_typed_bundle_input_not_mutated(self) -> None:
        bundle = PolicyBundle.model_validate(_bundle_dict())
        before = bundle.model_dump(mode="json")
        validate_policy_bundle(bundle)
        after = bundle.model_dump(mode="json")
        assert before == after

    def test_no_validation_state_field_exists_on_policy_bundle(self) -> None:
        forbidden = {
            "validation_status",
            "is_valid",
            "validated",
            "validation_errors",
            "validated_at",
        }
        assert forbidden.isdisjoint(PolicyBundle.model_fields.keys())

    def test_same_bundle_instance_may_be_returned_for_valid_typed_input(self) -> None:
        bundle = PolicyBundle.model_validate(_bundle_dict())
        result = validate_policy_bundle(bundle)
        assert result is bundle

    def test_no_evaluation_result_type_exists(self) -> None:
        import basis_core.policy.operation_aware.validation as validation_module

        assert not hasattr(validation_module, "DecisionResult")
        assert not hasattr(validation_module, "EvaluationResult")


# ══════════════════════════════════════════════════════════════════════════
# No behavior leakage
# ══════════════════════════════════════════════════════════════════════════


class TestNoBehaviorLeakage:
    _FORBIDDEN_NAMES = (
        "evaluate",
        "determine_applicability",
        "matches_request",
        "select_policy",
        "load_policy",
    )

    def test_validation_module_defines_no_evaluation_symbols(self) -> None:
        import basis_core.policy.operation_aware.validation as validation_module

        for name in self._FORBIDDEN_NAMES:
            assert not hasattr(validation_module, name), f"validation.py must not define {name!r}"

    def test_returned_bundle_has_no_evaluation_methods(self) -> None:
        result = validate_policy_bundle(_bundle_dict())
        for name in self._FORBIDDEN_NAMES:
            assert not hasattr(result, name), f"PolicyBundle must not gain {name!r}"

    def test_validate_policy_bundle_does_not_return_none(self) -> None:
        result = validate_policy_bundle(_bundle_dict())
        assert result is not None

    def test_validate_policy_bundle_does_not_return_bool(self) -> None:
        result = validate_policy_bundle(_bundle_dict())
        assert not isinstance(result, bool)
