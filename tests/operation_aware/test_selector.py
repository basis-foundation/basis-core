"""
tests/operation_aware/test_selector.py — tests for
`basis_core.policy.operation_aware.selector` (Milestone 6, PR 19 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Rule
match-criteria evaluator").

Covers `evaluate_rule_selectors()`, `SelectorMatchResult`, and
`SelectorEvaluation`: the result representation's closedness and
immutability, every one of the twenty current `OperationAwarePolicyMatch`
selector categories (absent/matching/mismatching/missing-request-
counterpart, including both structural forms of "no value" for nested
categories), `subject_roles`'s any-exact-intersection semantics, combined
multi-category evaluation, the four-case condition gate (match-only,
match-plus-conditions, mismatch-plus-conditions, conditions-only), rule
effect/metadata independence, purity, determinism, and the three vendored
canonical compatibility vectors this PR is authorized to consume
(`allow-basic`, `deny-precedence`, `default-deny`).

Scope
─────
This file tests structural selector matching only. It does not test, and
must never test: `PolicyCondition` operator dispatch or field-path
resolution, `rule.effect` application, deny precedence, default deny, a
final authorization outcome, evaluation traces, decision responses, audit
evidence, or bundle applicability (`applicability.py`'s own test file owns
that) — none of that exists in this module or this PR.

PR 20 addition — deterministic candidate-rule ordering
────────────────────────────────────────────────────────────────────────
This file also covers `select_candidate_rules()` and
`CandidateRuleEvaluation` (Milestone 6, PR 20 — "Selector
determinism/ordering tests"): proof that candidate-rule output is sorted
by exact ascending lexical `rule_id` and is independent of input list
order, dict insertion order, set-derived iteration order, `rule.effect`,
`SelectorEvaluation.result`, and `SelectorEvaluation.conditions_pending`.
It still does not test rule-effect application, deny precedence, default
deny, a final authorization outcome, evaluation traces, or audit evidence
— `select_candidate_rules` produces an ordered list of per-rule selector
evaluations only; nothing here chooses a winning rule or asserts a final
decision.
"""

from __future__ import annotations

import dataclasses
import itertools
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.bundle import PolicyBundle
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyRule,
)
from basis_core.policy.operation_aware.selector import (
    CandidateRuleEvaluation,
    SelectorEvaluation,
    SelectorMatchResult,
    evaluate_rule_selectors,
    select_candidate_rules,
)
from basis_core.policy.operation_aware.validation import validate_policy_bundle
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════


def _build_rule(
    *,
    match: dict[str, object] | None = None,
    conditions: list[dict[str, object]] | None = None,
    effect: str = "allow",
    rule_id: str = "rule-selector-fixture",
    reason_code: str | None = None,
    explanation: str | None = None,
) -> OperationAwarePolicyRule:
    """Build a minimal, otherwise-fixed `OperationAwarePolicyRule`. Exactly
    one of `match`/`conditions` must ultimately be non-`None` for the
    result to validate — the same invariant `rule.py` itself enforces;
    this helper does not work around it."""
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


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    """Build a minimal, otherwise-fixed `OperationAwareDecisionRequest`,
    merging `overrides` on top of the minimal required fields."""
    kwargs: dict[str, object] = {
        "request_id": "req-selector-fixture-0001",
        "subject_id": "svc-selector-test",
        "action": "read:ahu",
    }
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


# A structurally valid condition, reused wherever a match-plus-conditions
# rule needs a non-empty `conditions` array. This file never inspects a
# condition's `operator`/`field_path`/`expected_value` from the assertion
# side — only that its mere presence flips `conditions_pending`.
_SAMPLE_CONDITION: dict[str, object] = {
    "condition_id": "cond-risk-score-high",
    "field_path": "risk_context.score",
    "operator": "greater_than",
    "expected_value": 0.8,
}

# A structurally valid but semantically unimplemented operator — proves no
# operator dispatch occurs: this rule's condition-pending result must not
# depend on whether `future_operator` is "supported".
_UNIMPLEMENTED_OPERATOR_CONDITION: dict[str, object] = {
    "condition_id": "cond-future",
    "field_path": "risk_context.score",
    "operator": "future_operator",
    "expected_value": 0.8,
}


# ══════════════════════════════════════════════════════════════════════════
# Result representation
# ══════════════════════════════════════════════════════════════════════════


class TestResultRepresentation:
    def test_result_is_closed_to_matched_and_not_matched(self) -> None:
        assert {member.value for member in SelectorMatchResult} == {
            "matched",
            "not_matched",
        }

    def test_invalid_result_value_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            SelectorMatchResult("bogus")

    def test_selector_evaluation_is_immutable(self) -> None:
        evaluation = SelectorEvaluation(
            result=SelectorMatchResult.MATCHED, conditions_pending=False
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            evaluation.result = SelectorMatchResult.NOT_MATCHED  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            evaluation.conditions_pending = True  # type: ignore[misc]

    def test_selector_evaluation_equality(self) -> None:
        a = SelectorEvaluation(SelectorMatchResult.MATCHED, False)
        b = SelectorEvaluation(SelectorMatchResult.MATCHED, False)
        c = SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, False)
        d = SelectorEvaluation(SelectorMatchResult.MATCHED, True)
        assert a == b
        assert a != c
        assert a != d

    def test_deterministic_repeated_construction(self) -> None:
        a = SelectorEvaluation(SelectorMatchResult.MATCHED, False)
        b = SelectorEvaluation(SelectorMatchResult.MATCHED, False)
        assert a == b

    def test_result_enum_has_plain_string_values(self) -> None:
        assert SelectorMatchResult.MATCHED.value == "matched"
        assert SelectorMatchResult.NOT_MATCHED.value == "not_matched"


# ══════════════════════════════════════════════════════════════════════════
# Per-category selector specs — the twenty `OperationAwarePolicyMatch`
# selector categories
# ══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class _SelectorSpec:
    id: str
    match_field: str
    allowed_values: tuple[str, str]
    mismatch_value: str
    matching_extra: Callable[[str], dict[str, object]]
    # `None` only for `subject_ids`/`actions` -- `subject_id`/`action` are
    # required request fields, so no "request has no value for this
    # category" state can be constructed for them without bypassing
    # request validation.
    absent_extra: dict[str, object] | None
    # Populated only for categories nested inside an optional context
    # object (`location`, `device`, `protocol_context`, `safety_context`,
    # `environment_context`, `risk_context`); `None` for flat-field
    # categories, which have no parent object and therefore no second
    # absence form.
    parent_present_child_absent_extra: dict[str, object] | None = None

    def match(self, values: list[str]) -> dict[str, object]:
        return {self.match_field: values}


_SELECTOR_SPECS: tuple[_SelectorSpec, ...] = (
    _SelectorSpec(
        id="subject_ids",
        match_field="subject_ids",
        allowed_values=("svc-selector-alpha", "svc-selector-beta"),
        mismatch_value="svc-selector-gamma",
        matching_extra=lambda v: {"subject_id": v},
        absent_extra=None,
    ),
    _SelectorSpec(
        id="subject_roles",
        match_field="subject_roles",
        allowed_values=("operator", "administrator"),
        mismatch_value="vendor",
        matching_extra=lambda v: {"subject_roles": [v]},
        # "roles omitted" and "roles empty" collapse to the same
        # observable state on this model (`subject_roles` defaults to
        # `[]`, never `None`) -- see `TestSubjectRoles` for both readings.
        absent_extra={"subject_roles": []},
    ),
    _SelectorSpec(
        id="identity_sources",
        match_field="identity_sources",
        allowed_values=("idp-alpha", "idp-beta"),
        mismatch_value="idp-gamma",
        matching_extra=lambda v: {"identity_source": v},
        absent_extra={},
    ),
    _SelectorSpec(
        id="authority_modes",
        match_field="authority_modes",
        allowed_values=("federated", "synchronized"),
        mismatch_value="standalone",
        matching_extra=lambda v: {"authority_mode": v},
        absent_extra={},
    ),
    _SelectorSpec(
        id="actions",
        match_field="actions",
        allowed_values=("read:ahu", "write:hvac:setpoint"),
        mismatch_value="browse:chiller",
        matching_extra=lambda v: {"action": v},
        absent_extra=None,
    ),
    _SelectorSpec(
        id="resources",
        match_field="resources",
        allowed_values=("ahu:rooftop-1", "hvac:zone-a"),
        mismatch_value="chiller:unit-1",
        matching_extra=lambda v: {"resource": v},
        absent_extra={},
    ),
    _SelectorSpec(
        id="resource_types",
        match_field="resource_types",
        allowed_values=("ahu", "hvac"),
        mismatch_value="chiller",
        matching_extra=lambda v: {"resource_type": v},
        absent_extra={},
    ),
    _SelectorSpec(
        id="site_ids",
        match_field="site_ids",
        allowed_values=("site-a", "site-b"),
        mismatch_value="site-c",
        matching_extra=lambda v: {"location": {"site_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _SelectorSpec(
        id="building_ids",
        match_field="building_ids",
        allowed_values=("bldg-a", "bldg-b"),
        mismatch_value="bldg-c",
        matching_extra=lambda v: {"location": {"building_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _SelectorSpec(
        id="zone_ids",
        match_field="zone_ids",
        allowed_values=("zone-a", "zone-b"),
        mismatch_value="zone-c",
        matching_extra=lambda v: {"location": {"zone_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _SelectorSpec(
        id="area_ids",
        match_field="area_ids",
        allowed_values=("area-a", "area-b"),
        mismatch_value="area-c",
        matching_extra=lambda v: {"location": {"area_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _SelectorSpec(
        id="device_ids",
        match_field="device_ids",
        allowed_values=("device-a", "device-b"),
        mismatch_value="device-c",
        matching_extra=lambda v: {"device": {"device_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"device": {}},
    ),
    _SelectorSpec(
        id="device_classes",
        match_field="device_classes",
        allowed_values=("sensor", "actuator"),
        mismatch_value="controller",
        matching_extra=lambda v: {"device": {"device_class": v}},
        absent_extra={},
        parent_present_child_absent_extra={"device": {}},
    ),
    _SelectorSpec(
        id="protocols",
        match_field="protocols",
        allowed_values=("bacnet", "modbus"),
        mismatch_value="mqtt",
        matching_extra=lambda v: {"protocol_context": {"protocol": v}},
        absent_extra={},
        parent_present_child_absent_extra={"protocol_context": {}},
    ),
    _SelectorSpec(
        id="protocol_operations",
        match_field="protocol_operations",
        allowed_values=("ReadProperty", "WriteProperty"),
        mismatch_value="SubscribeCOV",
        matching_extra=lambda v: {"protocol_context": {"operation": v}},
        absent_extra={},
        parent_present_child_absent_extra={"protocol_context": {}},
    ),
    _SelectorSpec(
        id="operation_intents",
        match_field="operation_intents",
        allowed_values=("read_only", "state_changing"),
        mismatch_value="control_affecting",
        matching_extra=lambda v: {"operation_intent": v},
        absent_extra={},
    ),
    _SelectorSpec(
        id="safety_modes",
        match_field="safety_modes",
        allowed_values=("interlock-engaged", "maintenance-mode"),
        mismatch_value="normal-operation",
        matching_extra=lambda v: {"safety_context": {"mode": v}},
        absent_extra={},
        parent_present_child_absent_extra={"safety_context": {}},
    ),
    _SelectorSpec(
        id="safety_classifications",
        match_field="safety_classifications",
        allowed_values=("elevated", "critical"),
        mismatch_value="nominal",
        matching_extra=lambda v: {"safety_context": {"classification": v}},
        absent_extra={},
        parent_present_child_absent_extra={"safety_context": {}},
    ),
    _SelectorSpec(
        id="environment_modes",
        match_field="environment_modes",
        allowed_values=("production", "staging"),
        mismatch_value="development",
        matching_extra=lambda v: {"environment_context": {"mode": v}},
        absent_extra={},
        parent_present_child_absent_extra={"environment_context": {}},
    ),
    _SelectorSpec(
        id="risk_classifications",
        match_field="risk_classifications",
        allowed_values=("moderate", "high"),
        mismatch_value="low",
        matching_extra=lambda v: {"risk_context": {"classification": v}},
        absent_extra={},
        parent_present_child_absent_extra={"risk_context": {}},
    ),
)

_SPECS_BY_ID: dict[str, _SelectorSpec] = {spec.id: spec for spec in _SELECTOR_SPECS}
_OPTIONAL_SPECS: tuple[_SelectorSpec, ...] = tuple(
    spec for spec in _SELECTOR_SPECS if spec.absent_extra is not None
)
_NESTED_SPECS: tuple[_SelectorSpec, ...] = tuple(
    spec for spec in _SELECTOR_SPECS if spec.parent_present_child_absent_extra is not None
)

_ALL_IDS = [spec.id for spec in _SELECTOR_SPECS]
_OPTIONAL_IDS = [spec.id for spec in _OPTIONAL_SPECS]
_NESTED_IDS = [spec.id for spec in _NESTED_SPECS]


def _merge_extra(extra: dict[str, object], spec: _SelectorSpec, value: str) -> dict[str, object]:
    """A new request-extra mapping equal to `extra` except that `spec`'s
    category is overridden to `value`. For nested categories, the shared
    parent sub-mapping is merged, not replaced, so this can be chained
    across multiple categories sharing one parent (e.g. `site_ids` then
    `building_ids`) without one call blanking a sibling. Never mutates
    `extra`."""
    result: dict[str, object] = dict(extra)
    piece = spec.matching_extra(value)
    (key, val) = next(iter(piece.items()))
    if isinstance(val, dict):
        existing = result.get(key)
        merged_parent: dict[str, object] = dict(existing) if isinstance(existing, dict) else {}
        merged_parent.update(val)
        result[key] = merged_parent
    else:
        result[key] = val
    return result


def _all_matching_match() -> dict[str, object]:
    return {spec.match_field: [spec.allowed_values[0]] for spec in _SELECTOR_SPECS}


def _all_matching_request_extra() -> dict[str, object]:
    extra: dict[str, object] = {}
    for spec in _SELECTOR_SPECS:
        extra = _merge_extra(extra, spec, spec.allowed_values[0])
    return extra


_ALL_MATCHING_MATCH: dict[str, object] = _all_matching_match()
_ALL_MATCHING_REQUEST_EXTRA: dict[str, object] = _all_matching_request_extra()


def _anchor_match(exclude_id: str) -> dict[str, object]:
    """A one-category match object guaranteed to structurally match the
    default `_build_request()` output, used whenever a test needs a valid,
    non-empty `match` object that deliberately excludes `exclude_id`'s own
    category. `actions: ["read:ahu"]` matches the default request's
    `action` for every spec except `actions` itself, for which
    `subject_ids` (matching the default request's `subject_id`) is used
    instead."""
    if exclude_id != "actions":
        return {"actions": ["read:ahu"]}
    return {"subject_ids": ["svc-selector-test"]}


# ══════════════════════════════════════════════════════════════════════════
# Selector-field inventory
# ══════════════════════════════════════════════════════════════════════════


class TestEverySelectorCategoryIsCovered:
    """`OperationAwarePolicyMatch` currently publishes twenty independently-
    optional selector fields (`rule.py`'s `_ALL_SELECTOR_FIELDS`); this
    class proves `_SELECTOR_SPECS` covers all twenty. If a future PR adds a
    twenty-first selector field without a corresponding spec here, this
    test fails loudly rather than silently under-covering the new
    category."""

    def test_every_selector_field_is_covered(self) -> None:
        from basis_core.policy.operation_aware.rule import _ALL_SELECTOR_FIELDS

        covered = {spec.match_field for spec in _SELECTOR_SPECS}
        assert covered == set(_ALL_SELECTOR_FIELDS)


# ══════════════════════════════════════════════════════════════════════════
# Per-category: selector absent -> no restriction
# ══════════════════════════════════════════════════════════════════════════


class TestPerCategorySelectorAbsent:
    @pytest.mark.parametrize("spec", _SELECTOR_SPECS, ids=_ALL_IDS)
    def test_selector_absent_request_counterpart_present_is_matched(
        self, spec: _SelectorSpec
    ) -> None:
        rule = _build_rule(match=_anchor_match(spec.id))
        request = _build_request(**spec.matching_extra(spec.allowed_values[0]))
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.MATCHED

    @pytest.mark.parametrize("spec", _NESTED_SPECS, ids=_NESTED_IDS)
    def test_selector_absent_parent_present_child_absent_is_matched(
        self, spec: _SelectorSpec
    ) -> None:
        rule = _build_rule(match=_anchor_match(spec.id))
        assert spec.parent_present_child_absent_extra is not None
        request = _build_request(**spec.parent_present_child_absent_extra)
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.MATCHED


# ══════════════════════════════════════════════════════════════════════════
# Per-category: selector present, request counterpart missing
# ══════════════════════════════════════════════════════════════════════════


class TestPerCategorySelectorPresentCounterpartMissing:
    @pytest.mark.parametrize("spec", _OPTIONAL_SPECS, ids=_OPTIONAL_IDS)
    def test_selector_present_request_counterpart_entirely_absent_is_not_matched(
        self, spec: _SelectorSpec
    ) -> None:
        assert spec.absent_extra is not None
        rule = _build_rule(match=spec.match(list(spec.allowed_values)))
        request = _build_request(**spec.absent_extra)
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is False

    @pytest.mark.parametrize("spec", _NESTED_SPECS, ids=_NESTED_IDS)
    def test_selector_present_parent_present_child_absent_is_not_matched(
        self, spec: _SelectorSpec
    ) -> None:
        assert spec.parent_present_child_absent_extra is not None
        rule = _build_rule(match=spec.match(list(spec.allowed_values)))
        request = _build_request(**spec.parent_present_child_absent_extra)
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is False


# ══════════════════════════════════════════════════════════════════════════
# Per-category: exact membership (first member, later member, non-member)
# ══════════════════════════════════════════════════════════════════════════


class TestPerCategoryExactMembership:
    @pytest.mark.parametrize("spec", _SELECTOR_SPECS, ids=_ALL_IDS)
    def test_first_member_match_is_matched(self, spec: _SelectorSpec) -> None:
        rule = _build_rule(match=spec.match(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.allowed_values[0]))
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.MATCHED

    @pytest.mark.parametrize("spec", _SELECTOR_SPECS, ids=_ALL_IDS)
    def test_non_first_member_match_is_matched(self, spec: _SelectorSpec) -> None:
        rule = _build_rule(match=spec.match(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.allowed_values[1]))
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.MATCHED

    @pytest.mark.parametrize("spec", _SELECTOR_SPECS, ids=_ALL_IDS)
    def test_non_member_value_is_not_matched(self, spec: _SelectorSpec) -> None:
        rule = _build_rule(match=spec.match(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.mismatch_value))
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is False


# ══════════════════════════════════════════════════════════════════════════
# `subject_roles` — any-exact-intersection semantics
# ══════════════════════════════════════════════════════════════════════════


class TestSubjectRoles:
    def test_one_exact_overlap_matches(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator", "administrator"]})
        request = _build_request(subject_roles=["viewer", "operator"])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.MATCHED

    def test_multiple_overlaps_match(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator", "administrator"]})
        request = _build_request(subject_roles=["operator", "administrator", "viewer"])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.MATCHED

    def test_no_overlap_is_not_matched(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator", "administrator"]})
        request = _build_request(subject_roles=["vendor"])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.NOT_MATCHED

    def test_request_roles_omitted_is_not_matched(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator"]})
        request = _build_request()  # subject_roles defaults to []
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.NOT_MATCHED

    def test_request_roles_empty_is_not_matched(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator"]})
        request = _build_request(subject_roles=[])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.NOT_MATCHED

    def test_selector_multiple_alternatives_any_overlap_sufficient(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator", "administrator", "vendor"]})
        request = _build_request(subject_roles=["vendor"])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.MATCHED

    def test_full_list_equality_is_not_required(self) -> None:
        # Selector has three roles, request has only one of them -- not
        # "all selector roles present on the request".
        rule = _build_rule(match={"subject_roles": ["operator", "administrator", "vendor"]})
        request = _build_request(subject_roles=["operator"])
        assert evaluate_rule_selectors(rule, request).result is SelectorMatchResult.MATCHED
        # Request has roles the selector does not name at all -- not "all
        # request roles present in the selector".
        request_extra_roles = _build_request(subject_roles=["operator", "guest", "auditor"])
        assert (
            evaluate_rule_selectors(rule, request_extra_roles).result is SelectorMatchResult.MATCHED
        )

    def test_different_ordering_produces_same_result(self) -> None:
        rule_forward = _build_rule(
            rule_id="rule-roles-forward", match={"subject_roles": ["operator", "administrator"]}
        )
        rule_reversed = _build_rule(
            rule_id="rule-roles-reversed", match={"subject_roles": ["administrator", "operator"]}
        )
        request = _build_request(subject_roles=["operator"])
        forward_result = evaluate_rule_selectors(rule_forward, request)
        reversed_result = evaluate_rule_selectors(rule_reversed, request)
        assert forward_result.result is reversed_result.result is SelectorMatchResult.MATCHED


# ══════════════════════════════════════════════════════════════════════════
# Multiple categories combined
# ══════════════════════════════════════════════════════════════════════════


class TestMultipleCategoriesCombined:
    def test_all_twenty_categories_matching_is_matched(self) -> None:
        rule = _build_rule(match=_ALL_MATCHING_MATCH)
        request = _build_request(**_ALL_MATCHING_REQUEST_EXTRA)
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.MATCHED
        assert result.conditions_pending is False

    @pytest.mark.parametrize("spec", _SELECTOR_SPECS, ids=_ALL_IDS)
    def test_one_mismatch_among_all_populated_categories_is_not_matched(
        self, spec: _SelectorSpec
    ) -> None:
        extra = _merge_extra(_ALL_MATCHING_REQUEST_EXTRA, spec, spec.mismatch_value)
        rule = _build_rule(match=_ALL_MATCHING_MATCH)
        request = _build_request(**extra)
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is False


# ══════════════════════════════════════════════════════════════════════════
# Match-only rules (no conditions)
# ══════════════════════════════════════════════════════════════════════════


class TestMatchOnlyRules:
    def test_selectors_match_conditions_absent_is_matched(self) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]})
        request = _build_request(action="read:ahu")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.MATCHED, False)

    def test_selectors_fail_conditions_absent_is_not_matched(self) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]})
        request = _build_request(action="write:hvac:setpoint")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, False)


# ══════════════════════════════════════════════════════════════════════════
# Match plus conditions — the condition gate
# ══════════════════════════════════════════════════════════════════════════


class TestMatchPlusConditions:
    def test_selectors_match_conditions_present_is_not_matched_pending(self) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]}, conditions=[_SAMPLE_CONDITION])
        request = _build_request(action="read:ahu")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, True)

    def test_selectors_fail_conditions_present_is_not_matched_not_pending(self) -> None:
        # Structural mismatch short-circuits -- conditions never needed
        # evaluating regardless of their presence.
        rule = _build_rule(match={"actions": ["read:ahu"]}, conditions=[_SAMPLE_CONDITION])
        request = _build_request(action="write:hvac:setpoint")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, False)

    def test_unimplemented_operator_condition_still_reports_pending(self) -> None:
        # Proves no operator dispatch occurs: an invented, unimplemented
        # operator name does not raise and does not change the result --
        # this module never inspects `operator` at all.
        rule = _build_rule(
            match={"actions": ["read:ahu"]}, conditions=[_UNIMPLEMENTED_OPERATOR_CONDITION]
        )
        request = _build_request(action="read:ahu")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, True)


# ══════════════════════════════════════════════════════════════════════════
# Conditions-only rules (`match is None`)
# ══════════════════════════════════════════════════════════════════════════


class TestConditionsOnlyRules:
    def test_conditions_only_rule_is_not_matched_pending(self) -> None:
        rule = _build_rule(match=None, conditions=[_SAMPLE_CONDITION])
        request = _build_request()
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, True)

    def test_conditions_only_rule_with_unimplemented_operator_is_still_pending(self) -> None:
        rule = _build_rule(match=None, conditions=[_UNIMPLEMENTED_OPERATOR_CONDITION])
        request = _build_request()
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, True)

    def test_conditions_only_rule_is_never_matched_regardless_of_request(self) -> None:
        # `match is None` imposes no structural restriction at all -- an
        # "exotic" request must still never produce `MATCHED`, because
        # conditions have not been evaluated.
        rule = _build_rule(match=None, conditions=[_SAMPLE_CONDITION])
        request = _build_request(
            subject_id="svc-anything",
            action="write:chiller:setpoint",
            subject_roles=["operator", "vendor"],
        )
        result = evaluate_rule_selectors(rule, request)
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is True


# ══════════════════════════════════════════════════════════════════════════
# Rule effect independence
# ══════════════════════════════════════════════════════════════════════════


class TestRuleEffectDoesNotAffectSelectors:
    @pytest.mark.parametrize("effect", ["allow", "deny"])
    def test_matching_rule_same_result_regardless_of_effect(self, effect: str) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]}, effect=effect)
        request = _build_request(action="read:ahu")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.MATCHED, False)

    @pytest.mark.parametrize("effect", ["allow", "deny"])
    def test_mismatching_rule_same_result_regardless_of_effect(self, effect: str) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]}, effect=effect)
        request = _build_request(action="write:hvac:setpoint")
        result = evaluate_rule_selectors(rule, request)
        assert result == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, False)


# ══════════════════════════════════════════════════════════════════════════
# Rule metadata independence
# ══════════════════════════════════════════════════════════════════════════


class TestRuleMetadataDoesNotAffectSelectors:
    def test_varying_rule_id_reason_code_explanation_same_result(self) -> None:
        rule_a = _build_rule(
            rule_id="rule-metadata-a",
            match={"actions": ["read:ahu"]},
            reason_code="allow_rule_matched",
            explanation="Rule A explanation.",
        )
        rule_b = _build_rule(
            rule_id="rule-metadata-b",
            match={"actions": ["read:ahu"]},
            reason_code="deny_rule_matched",
            explanation="A completely different explanation for rule B.",
        )
        request = _build_request(action="read:ahu")
        assert evaluate_rule_selectors(rule_a, request) == evaluate_rule_selectors(rule_b, request)


# ══════════════════════════════════════════════════════════════════════════
# Purity
# ══════════════════════════════════════════════════════════════════════════


class TestPurity:
    def test_does_not_mutate_rule_or_request(self) -> None:
        rule = _build_rule(match=_ALL_MATCHING_MATCH)
        request = _build_request(**_ALL_MATCHING_REQUEST_EXTRA)

        rule_dump_before = rule.model_dump(mode="json", exclude_none=True)
        request_dump_before = request.model_dump(mode="json", exclude_none=True)

        evaluate_rule_selectors(rule, request)

        assert rule.model_dump(mode="json", exclude_none=True) == rule_dump_before
        assert request.model_dump(mode="json", exclude_none=True) == request_dump_before

    def test_does_not_mutate_request_subject_roles_list(self) -> None:
        rule = _build_rule(match={"subject_roles": ["operator", "administrator"]})
        roles_before = ["viewer", "operator"]
        request = _build_request(subject_roles=list(roles_before))

        evaluate_rule_selectors(rule, request)

        assert list(request.subject_roles) == roles_before


# ══════════════════════════════════════════════════════════════════════════
# Determinism
# ══════════════════════════════════════════════════════════════════════════


class TestDeterminism:
    def test_repeated_evaluation_of_matching_rule_returns_equal_results(self) -> None:
        rule = _build_rule(match={"actions": ["read:ahu"]})
        request = _build_request(action="read:ahu")
        first = evaluate_rule_selectors(rule, request)
        second = evaluate_rule_selectors(rule, request)
        assert first == second == SelectorEvaluation(SelectorMatchResult.MATCHED, False)

    def test_repeated_evaluation_of_conditions_only_rule_returns_equal_results(self) -> None:
        rule = _build_rule(match=None, conditions=[_SAMPLE_CONDITION])
        request = _build_request()
        first = evaluate_rule_selectors(rule, request)
        second = evaluate_rule_selectors(rule, request)
        assert first == second == SelectorEvaluation(SelectorMatchResult.NOT_MATCHED, True)


# ══════════════════════════════════════════════════════════════════════════
# Canonical compatibility scenarios — `allow-basic`, `deny-precedence`,
# `default-deny` only (`not-applicable`/`invalid-policy-bundle` are
# explicitly out of scope for this PR; see this module's boundary docs)
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalAllowBasic:
    def test_allow_rule_selectors_are_matched(self) -> None:
        bundle_raw = load_scenario_artifact("allow-basic", "policy_bundle")
        request_raw = load_scenario_artifact("allow-basic", "request")

        bundle = validate_policy_bundle(bundle_raw)  # type: ignore[arg-type]
        request = OperationAwareDecisionRequest.model_validate(request_raw)

        assert len(bundle.rules) == 1
        result = evaluate_rule_selectors(bundle.rules[0], request)

        assert result.result is SelectorMatchResult.MATCHED
        assert result.conditions_pending is False


class TestCanonicalDenyPrecedence:
    def test_allow_and_deny_rule_selectors_are_both_matched(self) -> None:
        bundle_raw = load_scenario_artifact("deny-precedence", "policy_bundle")
        request_raw = load_scenario_artifact("deny-precedence", "request")

        bundle = validate_policy_bundle(bundle_raw)  # type: ignore[arg-type]
        request = OperationAwareDecisionRequest.model_validate(request_raw)

        rules_by_id = {rule.rule_id: rule for rule in bundle.rules}
        assert set(rules_by_id) == {
            "allow-operator-write-hvac-setpoint",
            "deny-control-during-interlock",
        }

        allow_result = evaluate_rule_selectors(
            rules_by_id["allow-operator-write-hvac-setpoint"], request
        )
        deny_result = evaluate_rule_selectors(rules_by_id["deny-control-during-interlock"], request)

        # This test deliberately does not choose a winning rule or assert
        # a final DENY -- deny precedence is a later, separately-scoped
        # rule-aggregation stage this module does not implement.
        assert allow_result.result is SelectorMatchResult.MATCHED
        assert allow_result.conditions_pending is False
        assert deny_result.result is SelectorMatchResult.MATCHED
        assert deny_result.conditions_pending is False


class TestCanonicalDefaultDeny:
    def test_rule_selectors_are_not_matched(self) -> None:
        bundle_raw = load_scenario_artifact("default-deny", "policy_bundle")
        request_raw = load_scenario_artifact("default-deny", "request")

        bundle = validate_policy_bundle(bundle_raw)  # type: ignore[arg-type]
        request = OperationAwareDecisionRequest.model_validate(request_raw)

        assert len(bundle.rules) == 1
        result = evaluate_rule_selectors(bundle.rules[0], request)

        # The rule requires subject_roles: [operator]; the request's
        # subject_roles is [vendor] -- a structural mismatch. This test
        # does not implement or assert default deny (a later,
        # separately-scoped rule-aggregation concern) -- only that this
        # one rule's selectors do not match.
        assert result.result is SelectorMatchResult.NOT_MATCHED
        assert result.conditions_pending is False


# ══════════════════════════════════════════════════════════════════════════
# PR 20 — deterministic candidate-rule ordering
# ══════════════════════════════════════════════════════════════════════════
#
# `select_candidate_rules()` / `CandidateRuleEvaluation` coverage: proof
# that candidate output is sorted by exact ascending lexical `rule_id` and
# is independent of input list order, dict insertion order, set-derived
# iteration order, `rule.effect`, `SelectorEvaluation.result`, and
# `SelectorEvaluation.conditions_pending`. `rule_id` ordering here is a
# determinism guarantee only -- it is never treated as authorization
# precedence in any assertion below.


def _bundle(rule_id: str, **rule_kwargs: object) -> OperationAwarePolicyRule:
    """Thin rename of `_build_rule` for this section's rule-ordering
    fixtures -- `rule_id` is always the first, explicit argument here
    because every test in this section distinguishes rules by id."""
    return _build_rule(rule_id=rule_id, **rule_kwargs)


# Three rules whose `rule_id` values are deliberately out of lexical order
# as authored below (zulu, alpha, mike), matched against one fixed request
# via `resource_type` so that each rule's selector result is distinct and
# independently verifiable:
#   rule-alpha  matches (resource_types: ["ahu"], no conditions)
#   rule-mike   does not match (resource_types: ["hvac"])
#   rule-zulu   selectors match but carries a condition -> not_matched,
#               conditions_pending=True
# Canonical ascending-lexical-order output: rule-alpha, rule-mike, rule-zulu.
_ORDERING_REQUEST = _build_request(resource_type="ahu")

_RULE_ZULU = _bundle("rule-zulu", match={"resource_types": ["ahu"]}, conditions=[_SAMPLE_CONDITION])
_RULE_ALPHA = _bundle("rule-alpha", match={"resource_types": ["ahu"]})
_RULE_MIKE = _bundle("rule-mike", match={"resource_types": ["hvac"]})

_CANONICAL_ORDER = ("rule-alpha", "rule-mike", "rule-zulu")


def _assert_canonical_order(
    result: tuple[CandidateRuleEvaluation, ...],
) -> None:
    assert tuple(candidate.rule.rule_id for candidate in result) == _CANONICAL_ORDER
    by_id = {candidate.rule.rule_id: candidate for candidate in result}
    assert by_id["rule-alpha"].selector_evaluation == SelectorEvaluation(
        SelectorMatchResult.MATCHED, False
    )
    assert by_id["rule-mike"].selector_evaluation == SelectorEvaluation(
        SelectorMatchResult.NOT_MATCHED, False
    )
    assert by_id["rule-zulu"].selector_evaluation == SelectorEvaluation(
        SelectorMatchResult.NOT_MATCHED, True
    )


class TestCandidateResultShape:
    def test_result_is_immutable_tuple(self) -> None:
        result = select_candidate_rules([_RULE_ALPHA], _ORDERING_REQUEST)
        assert isinstance(result, tuple)
        with pytest.raises(AttributeError):
            result.append(result[0])  # type: ignore[attr-defined]

    def test_candidate_rule_evaluation_is_immutable(self) -> None:
        result = select_candidate_rules([_RULE_ALPHA], _ORDERING_REQUEST)
        candidate = result[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            candidate.rule = _RULE_MIKE  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            candidate.selector_evaluation = SelectorEvaluation(
                SelectorMatchResult.NOT_MATCHED, False
            )  # type: ignore[misc]

    def test_candidate_preserves_the_same_rule_object(self) -> None:
        result = select_candidate_rules([_RULE_ALPHA], _ORDERING_REQUEST)
        assert result[0].rule is _RULE_ALPHA

    def test_candidate_selector_evaluation_matches_direct_call(self) -> None:
        result = select_candidate_rules([_RULE_ZULU], _ORDERING_REQUEST)
        assert result[0].selector_evaluation == evaluate_rule_selectors(
            _RULE_ZULU, _ORDERING_REQUEST
        )


class TestOriginalAndReversedOrder:
    def test_original_list_order_produces_canonical_order(self) -> None:
        result = select_candidate_rules([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE], _ORDERING_REQUEST)
        _assert_canonical_order(result)

    def test_reversed_list_order_produces_identical_canonical_order(self) -> None:
        forward = [_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE]
        reversed_input = list(reversed(forward))
        result = select_candidate_rules(reversed_input, _ORDERING_REQUEST)
        _assert_canonical_order(result)


class TestArbitraryPermutations:
    @pytest.mark.parametrize(
        "permutation",
        list(itertools.permutations([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE])),
        ids=lambda perm: "-".join(r.rule_id for r in perm),
    )
    def test_every_permutation_produces_identical_canonical_order(
        self, permutation: tuple[OperationAwarePolicyRule, ...]
    ) -> None:
        result = select_candidate_rules(list(permutation), _ORDERING_REQUEST)
        _assert_canonical_order(result)


class TestDictionaryInsertionOrder:
    def test_two_different_dict_insertion_orders_produce_identical_output(self) -> None:
        dict_a = {"zulu": _RULE_ZULU, "alpha": _RULE_ALPHA, "mike": _RULE_MIKE}
        dict_b = {"mike": _RULE_MIKE, "alpha": _RULE_ALPHA, "zulu": _RULE_ZULU}

        assert list(dict_a.keys()) != list(dict_b.keys())  # genuinely different insertion order

        result_a = select_candidate_rules(dict_a.values(), _ORDERING_REQUEST)
        result_b = select_candidate_rules(dict_b.values(), _ORDERING_REQUEST)

        _assert_canonical_order(result_a)
        _assert_canonical_order(result_b)
        assert result_a == result_b


class TestSetDerivedOrder:
    """`OperationAwarePolicyRule` is not safely hashable: its own frozen
    Pydantic `model_config` makes the *model* immutable, but several of its
    fields (`match`'s selector arrays, `conditions`) are plain `list`
    values, and Python lists are themselves unhashable -- attempting
    `hash(rule)` raises `TypeError: unhashable type: 'list'` for any rule
    with a populated selector or condition array (verified directly against
    this repository's current model, not assumed). Forcing the rule model
    to become hashable merely to exercise a set here would alter production
    model semantics for a test's convenience, which this PR's brief
    explicitly forbids.

    Instead, this class builds sets of the rules' own stable `rule_id`
    strings (themselves plain, safely hashable `str` values) in two
    different insertion orders, resolves each id back to the *same* typed
    rule object via a `rule_id -> rule` mapping, and feeds the resulting
    iterable -- built from a set, but containing the original typed rules,
    never copies or reconstructions -- into `select_candidate_rules`. This
    exercises "does output depend on set-derived iteration order" honestly,
    without changing what a candidate rule iterable is typed as anywhere in
    production code, and without using unseeded/hash-randomized behavior as
    the thing under test -- the assertion is always against the fixed
    canonical order, never against whatever order the set happens to
    produce.
    """

    def test_rule_object_is_not_hashable(self) -> None:
        with pytest.raises(TypeError):
            hash(_RULE_ALPHA)

    def test_set_derived_id_order_produces_canonical_output(self) -> None:
        rules_by_id = {"rule-zulu": _RULE_ZULU, "rule-alpha": _RULE_ALPHA, "rule-mike": _RULE_MIKE}

        ids_forward = {"rule-zulu", "rule-alpha", "rule-mike"}
        ids_reversed_insertion = {"rule-mike", "rule-alpha", "rule-zulu"}

        rules_from_forward = [rules_by_id[rule_id] for rule_id in ids_forward]
        rules_from_reversed = [rules_by_id[rule_id] for rule_id in ids_reversed_insertion]

        result_forward = select_candidate_rules(rules_from_forward, _ORDERING_REQUEST)
        result_reversed = select_candidate_rules(rules_from_reversed, _ORDERING_REQUEST)

        _assert_canonical_order(result_forward)
        _assert_canonical_order(result_reversed)
        assert result_forward == result_reversed


class TestStatePreservationAcrossOrderings:
    def test_matched_not_matched_and_pending_states_all_survive_reordering(self) -> None:
        forward = select_candidate_rules([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE], _ORDERING_REQUEST)
        reversed_ = select_candidate_rules([_RULE_MIKE, _RULE_ALPHA, _RULE_ZULU], _ORDERING_REQUEST)
        assert forward == reversed_
        _assert_canonical_order(forward)


class TestEffectDoesNotAffectOrdering:
    def test_lexical_order_wins_even_when_it_agrees_with_deny_first(self) -> None:
        # IDs chosen so lexical order happens to put a DENY rule first --
        # this must be because of the id, never because it is DENY.
        deny_rule = _bundle("rule-a-first", match={"actions": ["read:ahu"]}, effect="deny")
        allow_rule = _bundle("rule-b-second", match={"actions": ["read:ahu"]}, effect="allow")
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([allow_rule, deny_rule], request)
        assert tuple(c.rule.rule_id for c in result) == ("rule-a-first", "rule-b-second")

    def test_lexical_order_wins_even_when_it_disagrees_with_deny_first(self) -> None:
        # IDs chosen so lexical order puts the ALLOW rule first and the
        # DENY rule second -- proving deny is never hoisted to the front.
        allow_rule = _bundle("rule-a-allow-first", match={"actions": ["read:ahu"]}, effect="allow")
        deny_rule = _bundle("rule-b-deny-second", match={"actions": ["read:ahu"]}, effect="deny")
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([deny_rule, allow_rule], request)
        assert tuple(c.rule.rule_id for c in result) == (
            "rule-a-allow-first",
            "rule-b-deny-second",
        )


class TestSelectorResultDoesNotAffectOrdering:
    def test_not_matched_rule_sorts_before_matched_rule_by_id(self) -> None:
        not_matched = _bundle("rule-a-not-matched", match={"actions": ["write:hvac:setpoint"]})
        matched = _bundle("rule-b-matched", match={"actions": ["read:ahu"]})
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([matched, not_matched], request)
        assert tuple(c.rule.rule_id for c in result) == (
            "rule-a-not-matched",
            "rule-b-matched",
        )
        by_id = {c.rule.rule_id: c for c in result}
        not_matched_result = by_id["rule-a-not-matched"].selector_evaluation.result
        matched_result = by_id["rule-b-matched"].selector_evaluation.result
        assert not_matched_result is SelectorMatchResult.NOT_MATCHED
        assert matched_result is SelectorMatchResult.MATCHED

    def test_matched_rule_sorts_before_not_matched_rule_by_id(self) -> None:
        matched = _bundle("rule-a-matched", match={"actions": ["read:ahu"]})
        not_matched = _bundle("rule-b-not-matched", match={"actions": ["write:hvac:setpoint"]})
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([not_matched, matched], request)
        assert tuple(c.rule.rule_id for c in result) == (
            "rule-a-matched",
            "rule-b-not-matched",
        )
        by_id = {c.rule.rule_id: c for c in result}
        matched_result = by_id["rule-a-matched"].selector_evaluation.result
        not_matched_result = by_id["rule-b-not-matched"].selector_evaluation.result
        assert matched_result is SelectorMatchResult.MATCHED
        assert not_matched_result is SelectorMatchResult.NOT_MATCHED


class TestConditionsPendingDoesNotAffectOrdering:
    def test_pending_rule_sorts_before_matched_rule_by_id(self) -> None:
        pending = _bundle(
            "rule-a-pending",
            match={"actions": ["read:ahu"]},
            conditions=[_SAMPLE_CONDITION],
        )
        matched = _bundle("rule-b-matched", match={"actions": ["read:ahu"]})
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([matched, pending], request)
        assert tuple(c.rule.rule_id for c in result) == ("rule-a-pending", "rule-b-matched")
        by_id = {c.rule.rule_id: c for c in result}
        assert by_id["rule-a-pending"].selector_evaluation.conditions_pending is True
        assert by_id["rule-b-matched"].selector_evaluation.conditions_pending is False

    def test_pending_rule_sorts_after_matched_rule_by_id(self) -> None:
        matched = _bundle("rule-a-matched", match={"actions": ["read:ahu"]})
        pending = _bundle(
            "rule-b-pending",
            match={"actions": ["read:ahu"]},
            conditions=[_SAMPLE_CONDITION],
        )
        request = _build_request(action="read:ahu")

        result = select_candidate_rules([pending, matched], request)
        assert tuple(c.rule.rule_id for c in result) == ("rule-a-matched", "rule-b-pending")
        by_id = {c.rule.rule_id: c for c in result}
        assert by_id["rule-a-matched"].selector_evaluation.conditions_pending is False
        assert by_id["rule-b-pending"].selector_evaluation.conditions_pending is True


class TestInputImmutability:
    def test_does_not_mutate_input_list_order(self) -> None:
        original_order = [_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE]
        input_list = list(original_order)

        select_candidate_rules(input_list, _ORDERING_REQUEST)

        assert input_list == original_order

    def test_does_not_mutate_rule_or_request(self) -> None:
        rule_dump_before = _RULE_ALPHA.model_dump(mode="json", exclude_none=True)
        request_dump_before = _ORDERING_REQUEST.model_dump(mode="json", exclude_none=True)

        select_candidate_rules([_RULE_ALPHA], _ORDERING_REQUEST)

        assert _RULE_ALPHA.model_dump(mode="json", exclude_none=True) == rule_dump_before
        assert _ORDERING_REQUEST.model_dump(mode="json", exclude_none=True) == request_dump_before

    def test_returns_new_tuple_not_a_view_over_input(self) -> None:
        input_list = [_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE]
        result = select_candidate_rules(input_list, _ORDERING_REQUEST)
        input_list.clear()
        # Clearing the caller's list after the call must not affect the
        # already-returned result -- proves the tuple is independently
        # constructed, not a lazy view.
        _assert_canonical_order(result)


class TestRepeatability:
    def test_repeated_calls_with_identical_input_return_equal_output(self) -> None:
        first = select_candidate_rules([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE], _ORDERING_REQUEST)
        second = select_candidate_rules([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE], _ORDERING_REQUEST)
        assert first == second


class TestEmptyAndSingleRuleCandidates:
    def test_empty_iterable_produces_empty_tuple(self) -> None:
        result = select_candidate_rules([], _ORDERING_REQUEST)
        assert result == ()

    def test_single_rule_produces_single_candidate(self) -> None:
        result = select_candidate_rules([_RULE_ALPHA], _ORDERING_REQUEST)
        assert len(result) == 1
        assert result[0].rule.rule_id == "rule-alpha"
        assert result[0].selector_evaluation == SelectorEvaluation(
            SelectorMatchResult.MATCHED, False
        )


class TestCanonicalDenyPrecedenceFixtureOrdering:
    """Uses the real canonical `deny-precedence` policy bundle and request
    (the same fixture `TestCanonicalDenyPrecedence` already consumes above).
    Proves ordering only: no DENY precedence is applied, no winning rule is
    selected, and no final decision, response, trace, or audit evidence of
    any kind is loaded or asserted here.
    """

    def test_reversed_in_memory_rule_sequence_produces_identical_candidate_order(
        self,
    ) -> None:
        bundle_raw = load_scenario_artifact("deny-precedence", "policy_bundle")
        request_raw = load_scenario_artifact("deny-precedence", "request")

        bundle = validate_policy_bundle(bundle_raw)  # type: ignore[arg-type]
        request = OperationAwareDecisionRequest.model_validate(request_raw)

        # The fixture's own on-disk order is allow-then-deny; this test
        # does not assume that is the canonical evaluator order -- it
        # builds a second, deliberately reversed in-memory sequence from
        # the same typed rules and requires identical candidate output.
        fixture_order = tuple(bundle.rules)
        reversed_order = tuple(reversed(fixture_order))
        assert fixture_order != reversed_order  # the fixture must not already be a palindrome

        result_fixture_order = select_candidate_rules(fixture_order, request)
        result_reversed_order = select_candidate_rules(reversed_order, request)

        assert result_fixture_order == result_reversed_order

        expected_ids = tuple(sorted(rule.rule_id for rule in fixture_order))
        assert tuple(c.rule.rule_id for c in result_fixture_order) == expected_ids
        assert expected_ids == (
            "allow-operator-write-hvac-setpoint",
            "deny-control-during-interlock",
        )

        # Selector results are preserved -- both rules structurally match
        # this request (see `TestCanonicalDenyPrecedence` above); this test
        # does not choose a winning rule, apply deny precedence, or
        # evaluate a final DENY.
        for candidate in result_fixture_order:
            assert candidate.selector_evaluation.result is SelectorMatchResult.MATCHED
            assert candidate.selector_evaluation.conditions_pending is False


class TestSameBundleReconstructedInDifferentOrders:
    """The roadmap's exact required PR 20 test: the same bundle,
    constructed via two different, deliberately reordered in-memory rule
    lists, must produce identical candidate-selection output. `PolicyBundle`
    is frozen, so this builds two separate, independently valid
    `PolicyBundle` instances with identical metadata and identical logical
    rules but a different `rules` array order, rather than mutating one
    bundle in place.
    """

    @staticmethod
    def _make_bundle(rules: list[OperationAwarePolicyRule]) -> PolicyBundle:
        return PolicyBundle.model_validate(
            {
                "bundle_id": "bundle-pr20-ordering-fixture",
                "bundle_version": "1.0.0",
                "schema_version": "0.1.0",
                "policy_owner": "pr20-ordering-test",
                "rules": rules,
            }
        )

    def test_two_bundles_with_reordered_rules_produce_identical_candidate_output(
        self,
    ) -> None:
        bundle_a = self._make_bundle([_RULE_ZULU, _RULE_ALPHA, _RULE_MIKE])
        bundle_b = self._make_bundle([_RULE_MIKE, _RULE_ZULU, _RULE_ALPHA])

        assert bundle_a.rules != bundle_b.rules  # genuinely different on-bundle order

        result_a = select_candidate_rules(bundle_a.rules, _ORDERING_REQUEST)
        result_b = select_candidate_rules(bundle_b.rules, _ORDERING_REQUEST)

        assert result_a == result_b
        _assert_canonical_order(result_a)
