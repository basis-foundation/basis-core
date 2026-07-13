"""
tests/operation_aware/test_policy_bundle.py — tests for
`basis_core.policy.operation_aware.bundle.PolicyBundle` (Milestone 4, PR 14
of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"PolicyBundle model").

Covers `PolicyBundle`/`PolicyBundleScope` construction, validation,
immutability, equality, and serialization round-trip — cross-checked
against every vendored `basis-schemas` v0.2.0 `policy-bundle` contract
example (four valid, thirteen invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests bundle *shape* only: construction, validation,
immutability, and schema alignment. It does not test, and must never
test, scope-to-request applicability, bundle selection, bundle loading, or
rule/condition evaluation — none of that exists in this module or this PR.

Vendored invalid example — "duplicate rule IDs within one bundle" — and
the PR 14 / PR 15 boundary
────────────────────────────────────────────────────────────────────────
The vendored contract's own `examples.invalid` block includes one example
("duplicate rule IDs within one bundle") that depends on BUNDLE-level
`rule_id`-uniqueness validation — a check the roadmap plan and
`policy-bundle.yaml`'s own `constraints` explicitly assign to PR 15's
separate structural/semantic validation pipeline
(`basis_core.policy.operation_aware.validation.validate_policy_bundle`),
not to this PR's `PolicyBundle` model. `_DEFERRED_INVALID_REASONS` names
this example explicitly; `TestFixtureConformance` both proves the
exclusion is scoped to exactly that one example
(`test_only_duplicate_rule_id_example_is_deferred`) and proves that this
module's own `PolicyBundle.model_validate` — the *structural* boundary
only — still accepts it today
(`test_deferred_example_is_accepted_by_pr14_pending_pr15`), which remains
correct and unchanged: `PolicyBundle` itself was never meant to reject it.
PR 15's `validate_policy_bundle` now rejects this same example at the
semantic layer — see `tests/operation_aware/test_policy_validation.py`
and `tests/operation_aware/test_contract_conformance.py`'s
`TestPolicyBundleAllInvalidExamplesEnforced`, which is where global
enforcement of this example now lives. Naming this test module's local
exclusion "deferred" continues to describe this module's own scope
accurately (`PolicyBundle` construction alone); it does not imply the
example remains unvalidated anywhere in the codebase. See `bundle.py`'s
docstring, "Deferred to PR 15", for the full rationale.

Does not test any later, not-yet-implemented operation-aware model
(canonical compatibility vectors, applicability, trace, audit, evaluator)
— see `tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from basis_core.policy.operation_aware.bundle import PolicyBundle, PolicyBundleScope
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _bundle_examples() -> tuple[list[object], list[object]]:
    document = load_contract("policy-bundle")
    section = require_mapping_field(document, "policy_bundle", context="policy-bundle")
    examples = require_mapping_field(section, "examples", context="policy-bundle.policy_bundle")
    valid = require_sequence_field(examples, "valid", context="policy-bundle.examples")
    invalid = require_sequence_field(examples, "invalid", context="policy-bundle.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _bundle_examples()

# See this module's docstring, "Deferred vendored invalid example". Matched
# against each invalid example's own `reason` field, not by position — a
# reordering of the vendored fixture does not silently break this filter.
_DEFERRED_INVALID_REASONS: frozenset[str] = frozenset({"duplicate rule IDs within one bundle"})


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
        bundle_id = example.get("bundle_id")
        if isinstance(bundle_id, str) and bundle_id:
            return bundle_id
    return f"example-{index}"


#: Every invalid example except the one explicitly deferred to PR 15.
_ENFORCED_INVALID_EXAMPLES: list[object] = [
    entry
    for entry in _INVALID_EXAMPLES
    if not (isinstance(entry, dict) and entry.get("reason") in _DEFERRED_INVALID_REASONS)
]

_DEFERRED_INVALID_EXAMPLES: list[object] = [
    entry
    for entry in _INVALID_EXAMPLES
    if isinstance(entry, dict) and entry.get("reason") in _DEFERRED_INVALID_REASONS
]


# A structurally valid rule/bundle reused across tests that need one but are
# not themselves testing bundle_id/version/owner/rules validation.
_VALID_RULE_KWARGS: dict[str, object] = {
    "rule_id": "rule-operator-read-ahu",
    "effect": "allow",
    "match": {"subject_roles": ["operator"], "actions": ["read:ahu"]},
}

_VALID_BUNDLE_KWARGS: dict[str, object] = {
    "bundle_id": "baseline-read-only-telemetry",
    "bundle_version": "1.0.0",
    "schema_version": "0.1.0",
    "policy_owner": "platform-security-team",
    "rules": [_VALID_RULE_KWARGS],
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_four_valid_examples_are_vendored(self) -> None:
        assert len(_VALID_EXAMPLES) == 4

    def test_thirteen_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 13

    def test_only_duplicate_rule_id_example_is_deferred(self) -> None:
        assert len(_DEFERRED_INVALID_EXAMPLES) == 1
        assert len(_ENFORCED_INVALID_EXAMPLES) == 12

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        bundle = PolicyBundle.model_validate(example)
        assert type(bundle) is PolicyBundle
        assert all(type(rule) is OperationAwarePolicyRule for rule in bundle.rules)
        if "scope" in example and example["scope"] is not None:
            assert type(bundle.scope) is PolicyBundleScope

    @pytest.mark.parametrize(
        "entry",
        _ENFORCED_INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_ENFORCED_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            PolicyBundle.model_validate(value)

    def test_deferred_example_is_accepted_by_pr14_pending_pr15(self) -> None:
        # Documents, rather than hides, the PR 14/PR 15 boundary: this
        # module (PolicyBundle's own structural construction) does not
        # implement duplicate-rule_id rejection, so the one vendored
        # invalid example that depends on it constructs successfully via
        # plain PolicyBundle.model_validate, exactly as it always has. PR
        # 15 has now landed and rejects this same example at the semantic
        # layer via validate_policy_bundle — see
        # tests/operation_aware/test_policy_validation.py — but that is a
        # separate entry point this test does not (and must not) exercise;
        # this test's job is only to prove PolicyBundle's own structural
        # boundary was, and remains, correctly scoped.
        assert len(_DEFERRED_INVALID_EXAMPLES) == 1
        value = _invalid_example_value(_DEFERRED_INVALID_EXAMPLES[0])
        bundle = PolicyBundle.model_validate(value)
        assert type(bundle) is PolicyBundle
        assert len(bundle.rules) == 2
        assert bundle.rules[0].rule_id == bundle.rules[1].rule_id == "rule-duplicate"


# ══════════════════════════════════════════════════════════════════════════
# Model configuration
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_bundle_model_is_frozen(self) -> None:
        assert PolicyBundle.model_config.get("frozen") is True

    def test_bundle_model_forbids_extra_fields(self) -> None:
        assert PolicyBundle.model_config.get("extra") == "forbid"

    def test_scope_model_is_frozen(self) -> None:
        assert PolicyBundleScope.model_config.get("frozen") is True

    def test_scope_model_forbids_extra_fields(self) -> None:
        assert PolicyBundleScope.model_config.get("extra") == "forbid"

    def test_frozen_rejects_top_level_attribute_assignment(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        with pytest.raises(ValidationError):
            bundle.bundle_id = "other"  # type: ignore[misc]

    def test_frozen_rejects_nested_scope_attribute_assignment(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS, scope={"site_ids": ["west-campus"]})
        assert bundle.scope is not None
        with pytest.raises(ValidationError):
            bundle.scope.site_ids = ["other"]  # type: ignore[misc]

    def test_frozen_rejects_nested_rule_attribute_assignment(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        with pytest.raises(ValidationError):
            bundle.rules[0].rule_id = "other"  # type: ignore[misc]

    def test_unknown_top_level_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**_VALID_BUNDLE_KWARGS, priority=1)  # type: ignore[call-arg]

    def test_equality_is_value_based(self) -> None:
        a = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        b = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert a == b
        assert a is not b

    def test_only_the_fourteen_published_fields_exist(self) -> None:
        assert set(PolicyBundle.model_fields) == {
            "bundle_id",
            "bundle_version",
            "schema_version",
            "policy_owner",
            "scope",
            "rules",
            "description",
            "source_ref",
            "approval_ref",
            "created_at",
            "updated_at",
            "compatibility_target",
            "deprecated",
            "replaced_by",
        }

    def test_required_fields_match_contract(self) -> None:
        for name in ("bundle_id", "bundle_version", "schema_version", "policy_owner", "rules"):
            assert PolicyBundle.model_fields[name].is_required(), name

    def test_optional_fields_match_contract(self) -> None:
        for name in (
            "scope",
            "description",
            "source_ref",
            "approval_ref",
            "created_at",
            "updated_at",
            "compatibility_target",
            "deprecated",
            "replaced_by",
        ):
            assert not PolicyBundle.model_fields[name].is_required(), name

    def test_optional_field_defaults(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.scope is None
        assert bundle.description is None
        assert bundle.source_ref is None
        assert bundle.approval_ref is None
        assert bundle.created_at is None
        assert bundle.updated_at is None
        assert bundle.compatibility_target is None
        assert bundle.deprecated is False
        assert bundle.replaced_by is None

    def test_only_the_ten_published_selector_fields_exist_on_scope(self) -> None:
        assert set(PolicyBundleScope.model_fields) == {
            "actions",
            "resource_types",
            "site_ids",
            "building_ids",
            "zone_ids",
            "area_ids",
            "device_classes",
            "environment_modes",
            "authority_modes",
            "protocols",
        }

    def test_all_scope_selector_fields_are_optional(self) -> None:
        for name, info in PolicyBundleScope.model_fields.items():
            assert not info.is_required(), f"{name} must be optional"


# ══════════════════════════════════════════════════════════════════════════
# bundle_id
# ══════════════════════════════════════════════════════════════════════════


class TestBundleId:
    @pytest.mark.parametrize(
        "bundle_id", ["building-automation-baseline", "b", "bundle_with_underscores", "BUNDLE-1"]
    )
    def test_non_empty_bundle_id_accepted(self, bundle_id: str) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS, bundle_id=bundle_id)
        bundle = PolicyBundle(**kwargs)  # type: ignore[arg-type]
        assert bundle.bundle_id == bundle_id

    def test_empty_bundle_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, bundle_id=""))

    def test_whitespace_only_bundle_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, bundle_id="   "))

    def test_missing_bundle_id_rejected(self) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS)
        del kwargs["bundle_id"]
        with pytest.raises(ValidationError):
            PolicyBundle(**kwargs)  # type: ignore[arg-type]

    def test_bundle_id_not_inferred_from_rule_id_grammar(self) -> None:
        # bundle_id has no character-set pattern beyond non-empty — unlike
        # rule_id/condition_id, it is never validated against any
        # colon-delimited or identifier-specific grammar.
        kwargs = dict(_VALID_BUNDLE_KWARGS, bundle_id="Not A Rule Id! 123")
        bundle = PolicyBundle(**kwargs)  # type: ignore[arg-type]
        assert bundle.bundle_id == "Not A Rule Id! 123"


# ══════════════════════════════════════════════════════════════════════════
# bundle_version / schema_version
# ══════════════════════════════════════════════════════════════════════════


class TestVersionFields:
    @pytest.mark.parametrize("version", ["1.0.0", "0.1.0", "10.20.30", "0.0.1"])
    def test_valid_bundle_version_accepted(self, version: str) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, bundle_version=version))
        assert bundle.bundle_version == version

    @pytest.mark.parametrize("version", ["1.0.0", "0.1.0", "10.20.30"])
    def test_valid_schema_version_accepted(self, version: str) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, schema_version=version))
        assert bundle.schema_version == version

    @pytest.mark.parametrize("version", ["v1", "1.0", "1", "current", "", "1.0.0-beta", "1.0.0.0"])
    def test_malformed_bundle_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, bundle_version=version))

    @pytest.mark.parametrize("version", ["v1", "1.0", "1", "current", ""])
    def test_malformed_schema_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, schema_version=version))

    def test_missing_bundle_version_rejected(self) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS)
        del kwargs["bundle_version"]
        with pytest.raises(ValidationError):
            PolicyBundle(**kwargs)  # type: ignore[arg-type]

    def test_missing_schema_version_rejected(self) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS)
        del kwargs["schema_version"]
        with pytest.raises(ValidationError):
            PolicyBundle(**kwargs)  # type: ignore[arg-type]

    def test_bundle_version_and_schema_version_are_distinct_and_independent(self) -> None:
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, bundle_version="2.3.1", schema_version="0.1.0")
        )
        assert bundle.bundle_version == "2.3.1"
        assert bundle.schema_version == "0.1.0"
        assert bundle.bundle_version != bundle.schema_version

    def test_no_version_comparison_or_ordering_behavior_exists(self) -> None:
        # Every Python object trivially has `__lt__`/`__gt__` (the default
        # `object` slot wrappers, which raise/return NotImplemented) — that
        # is not a meaningful signal, so this checks only for an
        # application-specific comparison/negotiation method instead.
        assert not hasattr(PolicyBundle, "compare_versions")
        assert not hasattr(PolicyBundle, "is_newer_than")
        assert not hasattr(PolicyBundle, "negotiate_version")


# ══════════════════════════════════════════════════════════════════════════
# policy_owner
# ══════════════════════════════════════════════════════════════════════════


class TestPolicyOwner:
    def test_valid_owner_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, policy_owner="west-campus-ot-team"))
        assert bundle.policy_owner == "west-campus-ot-team"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, policy_owner=12345))  # type: ignore[arg-type]

    def test_empty_owner_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, policy_owner=""))

    def test_whitespace_only_owner_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, policy_owner="   "))

    def test_missing_owner_rejected(self) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS)
        del kwargs["policy_owner"]
        with pytest.raises(ValidationError):
            PolicyBundle(**kwargs)  # type: ignore[arg-type]

    def test_policy_owner_has_no_identity_or_authorization_behavior(self) -> None:
        # Provenance metadata only: no authorization/identity-resolution
        # method exists anywhere on this model.
        assert not hasattr(PolicyBundle, "authorize")
        assert not hasattr(PolicyBundle, "resolve_owner")
        assert not hasattr(PolicyBundle, "verify_owner")


# ══════════════════════════════════════════════════════════════════════════
# scope
# ══════════════════════════════════════════════════════════════════════════


class TestScope:
    def test_omitted_scope_accepted_and_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.scope is None

    def test_explicit_null_scope_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope=None))
        assert bundle.scope is None

    def test_empty_scope_object_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={}))

    def test_one_populated_scope_dimension_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": ["west-campus"]}))
        assert bundle.scope is not None
        assert bundle.scope.site_ids == ["west-campus"]
        assert bundle.scope.building_ids is None

    def test_multiple_populated_scope_dimensions_accepted(self) -> None:
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                scope={"site_ids": ["west-campus"], "resource_types": ["hvac"]},
            )
        )
        assert bundle.scope is not None
        assert bundle.scope.site_ids == ["west-campus"]
        assert bundle.scope.resource_types == ["hvac"]

    def test_unknown_scope_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(_VALID_BUNDLE_KWARGS, scope={"country": "not-a-published-selector"})
            )

    def test_wrong_selector_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": "west-campus"}))

    @pytest.mark.parametrize(
        "field_name",
        [
            "actions",
            "resource_types",
            "site_ids",
            "building_ids",
            "zone_ids",
            "area_ids",
            "device_classes",
            "environment_modes",
            "authority_modes",
            "protocols",
        ],
    )
    def test_empty_selector_array_rejected_for_every_field(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={field_name: []}))

    def test_explicit_null_nested_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(
                    _VALID_BUNDLE_KWARGS,
                    scope={"site_ids": ["west-campus"], "building_ids": None},
                )
            )

    def test_omitted_nested_selector_is_distinguished_from_explicit_null(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": ["west-campus"]}))
        assert bundle.scope is not None
        assert bundle.scope.building_ids is None
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(
                    _VALID_BUNDLE_KWARGS,
                    scope={"site_ids": ["west-campus"], "building_ids": None},
                )
            )

    def test_malformed_action_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"actions": ["read"]}))

    def test_valid_action_selector_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"actions": ["read:ahu"]}))
        assert bundle.scope is not None
        assert bundle.scope.actions == ["read:ahu"]

    def test_malformed_resource_type_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"resource_types": ["HVAC"]}))

    def test_malformed_device_class_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"device_classes": ["Controller"]}))

    def test_malformed_environment_mode_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(_VALID_BUNDLE_KWARGS, scope={"environment_modes": ["Training Mode"]})
            )

    def test_malformed_authority_mode_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(_VALID_BUNDLE_KWARGS, scope={"authority_modes": ["Federated Mode"]})
            )

    def test_malformed_protocol_selector_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"protocols": ["BACnet"]}))

    def test_free_form_selector_item_no_pattern_but_non_empty_required(self) -> None:
        # site_ids/building_ids/zone_ids/area_ids have no published
        # character-set pattern, only a non-empty-string requirement.
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": ["West Campus! 123"]})
        )
        assert bundle.scope is not None
        assert bundle.scope.site_ids == ["West Campus! 123"]

    def test_whitespace_only_free_form_selector_item_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": ["   "]}))

    def test_dict_reconstructs_as_typed_scope_model(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": ["west-campus"]}))
        assert type(bundle.scope) is PolicyBundleScope

    def test_scope_input_mapping_mutation_cannot_alter_constructed_bundle(self) -> None:
        scope_input = {"site_ids": ["west-campus"]}
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope=scope_input))
        scope_input["site_ids"].append("east-campus")
        scope_input["building_ids"] = ["building-1"]
        assert bundle.scope is not None
        assert bundle.scope.site_ids == ["west-campus"]
        assert bundle.scope.building_ids is None

    def test_scope_selector_input_list_mutation_cannot_alter_constructed_bundle(self) -> None:
        site_ids = ["west-campus"]
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, scope={"site_ids": site_ids}))
        site_ids.append("east-campus")
        assert bundle.scope is not None
        assert bundle.scope.site_ids == ["west-campus"]

    def test_no_applicability_method_exists_on_bundle(self) -> None:
        for method_name in (
            "determine_applicability",
            "is_applicable",
            "matches_request",
            "matches",
        ):
            assert not hasattr(PolicyBundle, method_name), method_name

    def test_no_applicability_method_exists_on_scope(self) -> None:
        for method_name in (
            "determine_applicability",
            "is_applicable",
            "matches_request",
            "matches",
        ):
            assert not hasattr(PolicyBundleScope, method_name), method_name


# ══════════════════════════════════════════════════════════════════════════
# rules
# ══════════════════════════════════════════════════════════════════════════


class TestRules:
    def test_one_valid_nested_rule_accepted(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert len(bundle.rules) == 1

    def test_several_valid_nested_rules_accepted(self) -> None:
        rule_b = dict(_VALID_RULE_KWARGS, rule_id="rule-2")
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[_VALID_RULE_KWARGS, rule_b]))
        assert len(bundle.rules) == 2

    def test_nested_dict_reconstructs_as_operation_aware_policy_rule(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert type(bundle.rules[0]) is OperationAwarePolicyRule

    def test_missing_rules_rejected(self) -> None:
        kwargs = dict(_VALID_BUNDLE_KWARGS)
        del kwargs["rules"]
        with pytest.raises(ValidationError):
            PolicyBundle(**kwargs)  # type: ignore[arg-type]

    def test_null_rules_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=None))  # type: ignore[arg-type]

    def test_empty_rules_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[]))

    def test_malformed_nested_rule_rejected(self) -> None:
        malformed = dict(_VALID_RULE_KWARGS)
        del malformed["effect"]
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[malformed]))

    def test_rules_containing_non_rule_primitive_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=["not-a-rule"]))

    def test_rule_order_preserved(self) -> None:
        rule_a = dict(_VALID_RULE_KWARGS, rule_id="rule-a")
        rule_b = dict(_VALID_RULE_KWARGS, rule_id="rule-b")
        rule_c = dict(_VALID_RULE_KWARGS, rule_id="rule-c")
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[rule_a, rule_b, rule_c]))
        assert [r.rule_id for r in bundle.rules] == ["rule-a", "rule-b", "rule-c"]

    def test_rules_not_sorted(self) -> None:
        rule_z = dict(_VALID_RULE_KWARGS, rule_id="rule-z")
        rule_a = dict(_VALID_RULE_KWARGS, rule_id="rule-a")
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[rule_z, rule_a]))
        assert [r.rule_id for r in bundle.rules] == ["rule-z", "rule-a"]

    def test_rules_not_deduplicated(self) -> None:
        # Duplicate rule_id rejection is explicitly deferred to PR 15 (see
        # this module's docstring) — until then, duplicates are preserved
        # verbatim, never silently collapsed.
        rule_a = dict(_VALID_RULE_KWARGS, rule_id="rule-duplicate")
        rule_b = dict(_VALID_RULE_KWARGS, rule_id="rule-duplicate")
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[rule_a, rule_b]))
        assert len(bundle.rules) == 2

    def test_input_list_mutation_cannot_alter_constructed_bundle(self) -> None:
        rules_input = [dict(_VALID_RULE_KWARGS)]
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=rules_input))
        rules_input.append(dict(_VALID_RULE_KWARGS, rule_id="rule-extra"))
        assert len(bundle.rules) == 1

    def test_no_evaluation_or_ordering_behavior_exists(self) -> None:
        for method_name in ("evaluate", "select_rule", "apply_precedence"):
            assert not hasattr(PolicyBundle, method_name)


# ══════════════════════════════════════════════════════════════════════════
# Metadata / provenance fields
# ══════════════════════════════════════════════════════════════════════════


class TestDescription:
    def test_valid_description_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, description="HVAC operation rules."))
        assert bundle.description == "HVAC operation rules."

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, description=12345))  # type: ignore[arg-type]

    def test_empty_description_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, description=""))

    def test_missing_description_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.description is None

    def test_description_is_not_template_interpreted(self) -> None:
        text = "Governs {{site_id}} HVAC operations."
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, description=text))
        assert bundle.description == text


class TestSourceRef:
    def test_valid_source_ref_accepted(self) -> None:
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, source_ref="policy-authoring/west-campus")
        )
        assert bundle.source_ref == "policy-authoring/west-campus"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, source_ref=12345))  # type: ignore[arg-type]

    def test_empty_source_ref_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, source_ref=""))

    def test_missing_source_ref_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.source_ref is None

    def test_source_ref_is_never_fetched(self) -> None:
        assert not hasattr(PolicyBundle, "fetch_source")
        assert not hasattr(PolicyBundle, "resolve_source_ref")


class TestApprovalRef:
    def test_valid_approval_ref_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, approval_ref="change-4821"))
        assert bundle.approval_ref == "change-4821"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, approval_ref=12345))  # type: ignore[arg-type]

    def test_empty_approval_ref_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, approval_ref=""))

    def test_missing_approval_ref_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.approval_ref is None

    def test_approval_ref_presence_does_not_imply_approval(self) -> None:
        assert not hasattr(PolicyBundle, "is_approved")
        assert not hasattr(PolicyBundle, "verify_approval")


class TestTimestamps:
    def test_valid_tz_aware_created_at_accepted(self) -> None:
        ts = datetime(2026, 5, 1, tzinfo=timezone.utc)
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, created_at=ts))
        assert bundle.created_at == ts

    def test_valid_tz_aware_updated_at_accepted(self) -> None:
        ts = datetime(2026, 6, 15, 9, 30, tzinfo=timezone.utc)
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, updated_at=ts))
        assert bundle.updated_at == ts

    def test_iso8601_z_suffix_string_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, created_at="2026-05-01T00:00:00Z"))
        assert bundle.created_at is not None
        assert bundle.created_at.tzinfo is not None

    def test_naive_created_at_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, created_at=datetime(2026, 5, 1)))

    def test_naive_updated_at_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, updated_at=datetime(2026, 5, 1)))

    def test_naive_iso8601_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, created_at="2026-05-01T00:00:00"))

    def test_missing_timestamps_default_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.created_at is None
        assert bundle.updated_at is None

    def test_no_runtime_clock_default_is_applied(self) -> None:
        # created_at/updated_at have no default_factory=datetime.now (or
        # equivalent) — omitting them yields None, never "now".
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.created_at is None
        assert bundle.updated_at is None

    def test_no_chronology_comparison_is_enforced(self) -> None:
        # updated_at may legitimately precede created_at; this module
        # implements no cross-field ordering check between them.
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                created_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
                updated_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )
        )
        assert bundle.updated_at is not None
        assert bundle.created_at is not None
        assert bundle.updated_at < bundle.created_at


class TestCompatibilityTarget:
    def test_valid_compatibility_target_accepted(self) -> None:
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, compatibility_target="basis-core>=0.2.0,<0.3.0")
        )
        assert bundle.compatibility_target == "basis-core>=0.2.0,<0.3.0"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(
                **dict(_VALID_BUNDLE_KWARGS, compatibility_target=12345)  # type: ignore[arg-type]
            )

    def test_empty_compatibility_target_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, compatibility_target=""))

    def test_missing_compatibility_target_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.compatibility_target is None

    def test_no_compatibility_resolution_behavior_exists(self) -> None:
        assert not hasattr(PolicyBundle, "resolve_compatibility")
        assert not hasattr(PolicyBundle, "is_compatible")


class TestDeprecated:
    def test_default_is_false(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.deprecated is False

    def test_explicit_true_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, deprecated=True))
        assert bundle.deprecated is True

    def test_explicit_false_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, deprecated=False))
        assert bundle.deprecated is False

    @pytest.mark.parametrize("value", [1, 0, "true", "false", "yes", "no", 1.0])
    def test_non_boolean_coercion_rejected(self, value: object) -> None:
        # Strict boolean behavior: no int/str/float is silently coerced.
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, deprecated=value))  # type: ignore[arg-type]

    def test_deprecated_does_not_disable_construction(self) -> None:
        # Lifecycle metadata only: a deprecated bundle still constructs
        # successfully, and this module has no evaluation to "disable".
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, deprecated=True))
        assert type(bundle) is PolicyBundle


class TestReplacedBy:
    def test_valid_replaced_by_accepted(self) -> None:
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, deprecated=True, replaced_by="west-campus-hvac-operations")
        )
        assert bundle.replaced_by == "west-campus-hvac-operations"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, replaced_by=12345))  # type: ignore[arg-type]

    def test_empty_replaced_by_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, replaced_by=""))

    def test_missing_replaced_by_defaults_to_none(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        assert bundle.replaced_by is None

    def test_replaced_by_present_without_deprecated_true_is_accepted(self) -> None:
        # The vendored contract explicitly does not enforce this cross-
        # field relationship ("that alignment is not implemented here") —
        # this module therefore implements no such invariant.
        bundle = PolicyBundle(
            **dict(_VALID_BUNDLE_KWARGS, deprecated=False, replaced_by="some-other-bundle")
        )
        assert bundle.replaced_by == "some-other-bundle"
        assert bundle.deprecated is False

    def test_deprecated_true_without_replaced_by_is_accepted(self) -> None:
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, deprecated=True))
        assert bundle.deprecated is True
        assert bundle.replaced_by is None

    def test_replaced_by_existence_is_never_checked(self) -> None:
        # No lookup, resolution, or existence-check method exists.
        assert not hasattr(PolicyBundle, "resolve_replacement")
        assert not hasattr(PolicyBundle, "verify_replacement_exists")


# ══════════════════════════════════════════════════════════════════════════
# validation_status prohibition
# ══════════════════════════════════════════════════════════════════════════


class TestValidationStatusProhibition:
    def test_validation_status_kwarg_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**_VALID_BUNDLE_KWARGS, validation_status="valid")  # type: ignore[call-arg]

    def test_validation_status_is_not_a_declared_field(self) -> None:
        assert "validation_status" not in PolicyBundle.model_fields

    @pytest.mark.parametrize(
        "value", ["valid", "invalid", "approved", "pending", "draft", "checked"]
    )
    def test_no_self_attested_validity_field_of_any_spelling_is_accepted(self, value: str) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle(**_VALID_BUNDLE_KWARGS, validation_status=value)  # type: ignore[call-arg]


# ══════════════════════════════════════════════════════════════════════════
# Serialization round trip
# ══════════════════════════════════════════════════════════════════════════


class TestSerializationRoundTrip:
    """The governed round-trip convention for this model is
    `model_dump(mode="json", exclude_none=True)` (never a plain
    `model_dump(mode="json")` with no arguments) — see bundle.py's
    docstring, "Governed serialization convention"."""

    _ROUND_TRIP_KWARGS: list[dict[str, object]] = [
        _VALID_BUNDLE_KWARGS,
        {
            **_VALID_BUNDLE_KWARGS,
            "scope": {"site_ids": ["west-campus"], "resource_types": ["hvac"]},
            "description": "HVAC operation rules scoped to the west campus site.",
        },
        {
            **_VALID_BUNDLE_KWARGS,
            "source_ref": "policy-authoring/vendor-remote-access-baseline",
            "approval_ref": "change-4821",
            "created_at": "2026-05-01T00:00:00Z",
            "updated_at": "2026-06-15T09:30:00Z",
            "compatibility_target": "basis-core>=0.2.0,<0.3.0",
        },
        {
            **_VALID_BUNDLE_KWARGS,
            "deprecated": True,
            "replaced_by": "west-campus-hvac-operations",
        },
    ]

    @pytest.mark.parametrize("kwargs", _ROUND_TRIP_KWARGS)
    def test_model_dump_json_produces_all_published_field_names(
        self, kwargs: dict[str, object]
    ) -> None:
        bundle = PolicyBundle(**kwargs)  # type: ignore[arg-type]
        dumped = bundle.model_dump(mode="json")
        assert set(dumped) == {
            "bundle_id",
            "bundle_version",
            "schema_version",
            "policy_owner",
            "scope",
            "rules",
            "description",
            "source_ref",
            "approval_ref",
            "created_at",
            "updated_at",
            "compatibility_target",
            "deprecated",
            "replaced_by",
        }
        assert isinstance(dumped["deprecated"], bool)

    @pytest.mark.parametrize("kwargs", _ROUND_TRIP_KWARGS)
    def test_governed_serialization_convention_round_trips(self, kwargs: dict[str, object]) -> None:
        bundle = PolicyBundle(**kwargs)  # type: ignore[arg-type]
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        restored = PolicyBundle.model_validate(dumped)
        assert restored == bundle

    def test_exclude_none_omits_unused_optional_fields(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        assert "scope" not in dumped
        assert "description" not in dumped
        assert "source_ref" not in dumped
        assert "approval_ref" not in dumped
        assert "created_at" not in dumped
        assert "updated_at" not in dumped
        assert "compatibility_target" not in dumped
        assert "replaced_by" not in dumped
        # `deprecated` defaults to `False`, not `None` — it is always
        # present in the governed dump, exactly as the vendored contract
        # publishes a `false` default rather than a null-omittable field.
        assert dumped["deprecated"] is False

    def test_governed_serialized_scope_contains_no_invalid_nulls_or_empty_arrays(self) -> None:
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                scope={"site_ids": ["west-campus"], "resource_types": ["hvac"]},
            )
        )
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        assert "building_ids" not in dumped["scope"]
        for selector_value in dumped["scope"].values():
            assert selector_value is not None
            assert selector_value != []

    def test_nested_rule_effect_and_reason_code_serialize_as_strings(self) -> None:
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                rules=[dict(_VALID_RULE_KWARGS, reason_code="allow_rule_matched")],
            )
        )
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        assert isinstance(dumped["rules"][0]["effect"], str)
        assert isinstance(dumped["rules"][0]["reason_code"], str)

    def test_timestamps_serialize_as_strings(self) -> None:
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                created_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
                updated_at=datetime(2026, 6, 15, 9, 30, tzinfo=timezone.utc),
            )
        )
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        assert isinstance(dumped["created_at"], str)
        assert isinstance(dumped["updated_at"], str)

    def test_nested_rules_reconstruct_strongly_typed_after_round_trip(self) -> None:
        bundle = PolicyBundle(**_VALID_BUNDLE_KWARGS)
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        restored = PolicyBundle.model_validate(dumped)
        assert all(type(rule) is OperationAwarePolicyRule for rule in restored.rules)

    def test_rule_order_preserved_through_round_trip(self) -> None:
        rule_a = dict(_VALID_RULE_KWARGS, rule_id="rule-a")
        rule_b = dict(_VALID_RULE_KWARGS, rule_id="rule-b")
        bundle = PolicyBundle(**dict(_VALID_BUNDLE_KWARGS, rules=[rule_a, rule_b]))
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        restored = PolicyBundle.model_validate(dumped)
        assert [r.rule_id for r in restored.rules] == ["rule-a", "rule-b"]

    def test_scope_selector_order_preserved_through_round_trip(self) -> None:
        bundle = PolicyBundle(
            **dict(
                _VALID_BUNDLE_KWARGS,
                scope={"site_ids": ["west-campus", "east-campus"]},
            )
        )
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        restored = PolicyBundle.model_validate(dumped)
        assert restored.scope is not None
        assert restored.scope.site_ids == ["west-campus", "east-campus"]

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip_through_governed_convention(
        self, example: object
    ) -> None:
        assert isinstance(example, dict)
        bundle = PolicyBundle.model_validate(example)
        dumped = bundle.model_dump(mode="json", exclude_none=True)
        restored = PolicyBundle.model_validate(dumped)
        assert restored == bundle

    def test_no_custom_serializer_or_encoder_exists(self) -> None:
        # `exclude_none=True` is an ordinary `model_dump` call-time option,
        # not a custom serializer/encoder method defined on this class.
        assert not hasattr(PolicyBundle, "to_json")
        assert not hasattr(PolicyBundle, "serialize")
        assert not hasattr(PolicyBundle, "__json_encoder__")


# ══════════════════════════════════════════════════════════════════════════
# No behavior
# ══════════════════════════════════════════════════════════════════════════


class TestNoEvaluationOrLifecycleBehaviorExists:
    """This restriction is absolute — see this module's and `bundle.py`'s
    docstrings. These are supplementary static checks; the primary proof is
    simply that no such methods are called anywhere in this file or in
    `bundle.py`."""

    @pytest.mark.parametrize(
        "method_name",
        [
            "evaluate",
            "determine_applicability",
            "is_applicable",
            "select",
            "load",
            "approve",
            "verify",
            "resolve_replacement",
            "matches",
            "matches_request",
        ],
    )
    def test_bundle_model_defines_no_such_method(self, method_name: str) -> None:
        assert not hasattr(PolicyBundle, method_name)

    @pytest.mark.parametrize(
        "method_name",
        ["evaluate", "determine_applicability", "is_applicable", "matches", "matches_request"],
    )
    def test_scope_model_defines_no_such_method(self, method_name: str) -> None:
        assert not hasattr(PolicyBundleScope, method_name)
