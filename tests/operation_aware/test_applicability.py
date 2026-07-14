"""
tests/operation_aware/test_applicability.py — tests for
`basis_core.policy.operation_aware.applicability` (Milestone 5, PR 17 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Bundle
scope model + applicability determination").

Covers `determine_applicability()` and `ApplicabilityResult`: global-scope
applicability, every individual `PolicyBundleScope` dimension's
match/mismatch/missing-request-counterpart behavior, a focused
multi-dimension check, the vendored `not-applicable` canonical
compatibility vector, and purity (no mutation of either input).

Scope — PR 17 vs PR 18
────────────────────────────────────────────────────────────────────────
PR 17's tests (`TestGlobalScope` through `TestPurity`, above the PR 18
section marker below) prove the implementation and give representative,
single-value coverage of every scope dimension, per PR 17's own
completion criteria — they deliberately do NOT implement the full
Cartesian product of every dimension's present/absent combination, nor
exhaustive combined-dimension coverage.

PR 18 ("Applicability unit tests (exhaustive)") extends this same file
with that missing coverage, below `TestPurity`: the full per-dimension
presence matrix (selector absent/present × request counterpart
absent/present, including both structural forms of "the request has no
value for this dimension" for dimensions nested inside an optional
context object — the parent object itself absent, and the parent object
present but this one field absent), exact first-member and non-first-
member membership, selector-order invariance, duplicate-selector
tolerance, and combined-dimension coverage (all ten dimensions matching;
one mismatch, one missing request counterpart, or one omitted bundle
selector at a time; multiple simultaneous mismatches). See the roadmap
plan's PR 17/PR 18 entries and `applicability.py`'s own docstring, "Not
implemented by this module".

This file tests applicability classification only. It does not test, and
must never test: rule matching, condition evaluation, rule effects, deny
precedence, default-deny, a final authorization outcome, evaluation
traces, decision responses, audit evidence, or gateway/enforcement
behavior — none of that exists in this module or this PR.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.applicability import (
    ApplicabilityResult,
    determine_applicability,
)
from basis_core.policy.operation_aware.bundle import PolicyBundle
from basis_core.policy.operation_aware.validation import validate_policy_bundle
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════

# A structurally valid rule, reused across every bundle built in this
# module — this file does not test rule content, match criteria, or
# effects, so one fixed, minimal, valid rule is sufficient everywhere a
# bundle needs a non-empty `rules` array. Matches the same convention
# `test_policy_bundle.py`'s `_VALID_RULE_KWARGS` already establishes.
_VALID_RULE_KWARGS: dict[str, object] = {
    "rule_id": "rule-applicability-fixture",
    "effect": "allow",
    "match": {"subject_roles": ["operator"], "actions": ["read:hvac"]},
}


def _build_bundle(scope: dict[str, object] | None) -> PolicyBundle:
    """Build a minimal, otherwise-fixed `PolicyBundle` with the given
    `scope` (or no `scope` field at all when `scope is None`)."""
    kwargs: dict[str, object] = {
        "bundle_id": "bundle-applicability-fixture",
        "bundle_version": "1.0.0",
        "schema_version": "0.1.0",
        "policy_owner": "applicability-test-suite",
        "rules": [_VALID_RULE_KWARGS],
    }
    if scope is not None:
        kwargs["scope"] = scope
    return PolicyBundle.model_validate(kwargs)


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    """Build a minimal, otherwise-fixed `OperationAwareDecisionRequest`,
    merging `overrides` on top of the minimal required fields."""
    kwargs: dict[str, object] = {
        "request_id": "req-applicability-fixture-0001",
        "subject_id": "svc-applicability-test",
        "action": "read:hvac",
    }
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


# ══════════════════════════════════════════════════════════════════════════
# Global scope: scope omitted -> applicable, unconditionally
# ══════════════════════════════════════════════════════════════════════════


class TestGlobalScope:
    def test_scope_omitted_is_applicable(self) -> None:
        bundle = _build_bundle(scope=None)
        request = _build_request()
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    def test_scope_omitted_is_applicable_regardless_of_request_content(self) -> None:
        # No scope means no dimension is inspected at all -- an otherwise
        # "exotic" request (mismatched-looking values for every context
        # category) must still be applicable, because there is nothing to
        # mismatch against.
        bundle = _build_bundle(scope=None)
        request = _build_request(
            action="write:chiller:setpoint",
            resource_type="chiller",
            authority_mode="standalone",
            location={"site_id": "site-z", "building_id": "bldg-z"},
            device={"device_class": "actuator"},
            environment_context={"mode": "staging"},
            protocol_context={"protocol": "modbus"},
        )
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Per-dimension coverage
# ══════════════════════════════════════════════════════════════════════════
#
# One case per `PolicyBundleScope` selector field. Each case scopes the
# bundle on exactly one dimension, leaving every other dimension
# unconstrained, so a failure names precisely which dimension broke.

_ALL_DIMENSION_CASES: list[dict[str, object]] = [
    {
        "id": "actions",
        "scope": {"actions": ["read:hvac", "write:hvac:setpoint"]},
        "matching_extra": {"action": "write:hvac:setpoint"},
        "mismatched_extra": {"action": "browse:chiller"},
        # `action` is a required field on OperationAwareDecisionRequest --
        # there is no "missing request counterpart" state to construct.
        "missing_extra": None,
    },
    {
        "id": "resource_types",
        "scope": {"resource_types": ["hvac"]},
        "matching_extra": {"resource_type": "hvac"},
        "mismatched_extra": {"resource_type": "chiller"},
        "missing_extra": {},
    },
    {
        "id": "site_ids",
        "scope": {"site_ids": ["site-a"]},
        "matching_extra": {"location": {"site_id": "site-a"}},
        "mismatched_extra": {"location": {"site_id": "site-b"}},
        "missing_extra": {},
    },
    {
        "id": "building_ids",
        "scope": {"building_ids": ["bldg-a"]},
        "matching_extra": {"location": {"building_id": "bldg-a"}},
        "mismatched_extra": {"location": {"building_id": "bldg-b"}},
        "missing_extra": {},
    },
    {
        "id": "zone_ids",
        "scope": {"zone_ids": ["zone-a"]},
        "matching_extra": {"location": {"zone_id": "zone-a"}},
        "mismatched_extra": {"location": {"zone_id": "zone-b"}},
        "missing_extra": {},
    },
    {
        "id": "area_ids",
        "scope": {"area_ids": ["area-a"]},
        "matching_extra": {"location": {"area_id": "area-a"}},
        "mismatched_extra": {"location": {"area_id": "area-b"}},
        "missing_extra": {},
    },
    {
        "id": "device_classes",
        "scope": {"device_classes": ["sensor"]},
        "matching_extra": {"device": {"device_class": "sensor"}},
        "mismatched_extra": {"device": {"device_class": "actuator"}},
        "missing_extra": {},
    },
    {
        "id": "environment_modes",
        "scope": {"environment_modes": ["production"]},
        "matching_extra": {"environment_context": {"mode": "production"}},
        "mismatched_extra": {"environment_context": {"mode": "staging"}},
        "missing_extra": {},
    },
    {
        "id": "authority_modes",
        "scope": {"authority_modes": ["federated"]},
        "matching_extra": {"authority_mode": "federated"},
        "mismatched_extra": {"authority_mode": "standalone"},
        "missing_extra": {},
    },
    {
        "id": "protocols",
        "scope": {"protocols": ["bacnet"]},
        "matching_extra": {"protocol_context": {"protocol": "bacnet"}},
        "mismatched_extra": {"protocol_context": {"protocol": "modbus"}},
        "missing_extra": {},
    },
]

# `actions` has no "missing request counterpart" case -- `action` is
# required. Every other dimension has one.
_MISSING_COUNTERPART_CASES: list[dict[str, object]] = [
    case for case in _ALL_DIMENSION_CASES if case["missing_extra"] is not None
]


class TestEachScopeDimension:
    """`PolicyBundleScope` currently publishes ten independently-optional
    selector fields (`bundle.py`'s `_ALL_SCOPE_SELECTOR_FIELDS`); this
    class covers all ten. If a future PR adds an eleventh selector field
    without adding a corresponding case here, `test_every_scope_selector_
    field_is_covered` fails loudly rather than silently under-covering the
    new dimension."""

    def test_every_scope_selector_field_is_covered(self) -> None:
        from basis_core.policy.operation_aware.bundle import _ALL_SCOPE_SELECTOR_FIELDS

        covered = {case["scope_field"] for case in _dimension_field_names()}
        assert covered == set(_ALL_SCOPE_SELECTOR_FIELDS)

    @pytest.mark.parametrize(
        "case", _ALL_DIMENSION_CASES, ids=[str(c["id"]) for c in _ALL_DIMENSION_CASES]
    )
    def test_matching_value_is_applicable(self, case: dict[str, object]) -> None:
        bundle = _build_bundle(scope=case["scope"])  # type: ignore[arg-type]
        request = _build_request(**case["matching_extra"])  # type: ignore[arg-type]
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize(
        "case", _ALL_DIMENSION_CASES, ids=[str(c["id"]) for c in _ALL_DIMENSION_CASES]
    )
    def test_mismatched_value_is_not_applicable(self, case: dict[str, object]) -> None:
        bundle = _build_bundle(scope=case["scope"])  # type: ignore[arg-type]
        request = _build_request(**case["mismatched_extra"])  # type: ignore[arg-type]
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    @pytest.mark.parametrize(
        "case",
        _MISSING_COUNTERPART_CASES,
        ids=[str(c["id"]) for c in _MISSING_COUNTERPART_CASES],
    )
    def test_missing_request_counterpart_is_not_applicable(self, case: dict[str, object]) -> None:
        bundle = _build_bundle(scope=case["scope"])  # type: ignore[arg-type]
        request = _build_request(**case["missing_extra"])  # type: ignore[arg-type]
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE


def _dimension_field_names() -> list[dict[str, str]]:
    """Map each case's `id` to the actual `PolicyBundleScope` field name
    it scopes on (identical today -- kept as an explicit indirection so a
    future rename of a case `id` cannot silently desynchronize from the
    real field name without this helper needing an update too)."""
    return [{"scope_field": next(iter(case["scope"]))} for case in _ALL_DIMENSION_CASES]  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Focused multi-dimension coverage (PR 18 owns exhaustive combinations)
# ══════════════════════════════════════════════════════════════════════════


class TestMultipleDimensions:
    _SCOPE: dict[str, object] = {
        "actions": ["write:hvac:setpoint"],
        "resource_types": ["hvac"],
        "site_ids": ["site-a"],
    }

    def test_all_populated_dimensions_match_is_applicable(self) -> None:
        bundle = _build_bundle(scope=self._SCOPE)
        request = _build_request(
            action="write:hvac:setpoint",
            resource_type="hvac",
            location={"site_id": "site-a"},
        )
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    def test_one_mismatch_among_multiple_populated_dimensions_is_not_applicable(self) -> None:
        bundle = _build_bundle(scope=self._SCOPE)
        request = _build_request(
            action="write:hvac:setpoint",
            resource_type="hvac",
            # site_id mismatches; actions and resource_types both match.
            location={"site_id": "site-b"},
        )
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Canonical `not-applicable` compatibility vector
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalNotApplicableScenario:
    """The vendored `not-applicable` canonical compatibility vector
    (`tests/fixtures/basis-schemas/v0.2.0/compatibility/not-applicable/`):
    a bundle scoped to `resource_types: [hvac]` paired with a request
    whose `resource_type` is `chiller`. Only `policy_bundle` and `request`
    artifacts are consumed here -- this test does not load or assert
    against the scenario's expected trace, response, or audit-evidence
    artifacts (later conformance milestones own those)."""

    def test_bundle_and_request_load_with_the_documented_mismatch(self) -> None:
        # Proves the fixture pairing is what this test believes it is,
        # before asserting anything about determine_applicability's
        # behavior against it.
        bundle_raw = load_scenario_artifact("not-applicable", "policy_bundle")
        request_raw = load_scenario_artifact("not-applicable", "request")
        assert isinstance(bundle_raw, dict)
        assert isinstance(request_raw, dict)
        assert bundle_raw["scope"] == {"resource_types": ["hvac"]}
        assert request_raw["resource_type"] == "chiller"

    def test_canonical_bundle_is_not_applicable_to_its_paired_request(self) -> None:
        bundle_raw = load_scenario_artifact("not-applicable", "policy_bundle")
        request_raw = load_scenario_artifact("not-applicable", "request")

        bundle = validate_policy_bundle(bundle_raw)  # type: ignore[arg-type]
        request = OperationAwareDecisionRequest.model_validate(request_raw)

        result = determine_applicability(bundle, request)

        assert result is ApplicabilityResult.NOT_APPLICABLE
        # Not merely "some string" -- the actual closed-enum member.
        assert result.value == "not_applicable"


# ══════════════════════════════════════════════════════════════════════════
# Purity
# ══════════════════════════════════════════════════════════════════════════


class TestPurity:
    def test_determine_applicability_does_not_mutate_bundle_or_request(self) -> None:
        bundle = _build_bundle(scope={"resource_types": ["hvac"]})
        request = _build_request(resource_type="chiller")

        bundle_dump_before = bundle.model_dump(mode="json", exclude_none=True)
        request_dump_before = request.model_dump(mode="json", exclude_none=True)

        determine_applicability(bundle, request)

        assert bundle.model_dump(mode="json", exclude_none=True) == bundle_dump_before
        assert request.model_dump(mode="json", exclude_none=True) == request_dump_before

    def test_determine_applicability_is_deterministic(self) -> None:
        bundle = _build_bundle(scope={"resource_types": ["hvac"]})
        request = _build_request(resource_type="chiller")

        first = determine_applicability(bundle, request)
        second = determine_applicability(bundle, request)

        assert first is second is ApplicabilityResult.NOT_APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# PR 18 — Applicability unit tests (exhaustive)
# ══════════════════════════════════════════════════════════════════════════
#
# Everything below closes Milestone 5 (roadmap plan, PR 18): the full
# per-dimension presence matrix, exact-membership coverage, selector-order
# invariance, duplicate-selector tolerance, and exhaustive combined-
# dimension coverage. PR 17's tests above already prove the implementation
# works and give representative single-value coverage of every dimension —
# nothing above is duplicated below merely to inflate the test count.
#
# Deliberately out of scope here, same as everywhere else in this file:
# `OperationAwarePolicyMatch`, rule selector evaluation, subject/resource/
# location/device/protocol-operation/safety/environment/risk matching at
# the *rule* level, conditions, effects, or any matched/not_matched or
# final-authorization result (PR 19's boundary, per the roadmap plan).


# ── `_DimensionSpec` — one small test-local data table, not a matcher ──────
#
# Captures, for each of the ten `PolicyBundleScope` selector dimensions,
# only the test *data* needed to build the exhaustive matrix below: how to
# build a scope selector for it, how to build a request whose value for
# just that one dimension is a given value, and — for dimensions nested
# inside an optional context object — both structural forms of "the
# request carries no value for this dimension" (the parent context object
# entirely absent, and the parent object present but this one field
# absent). This performs no applicability comparison of its own; all of
# that still lives only in `applicability.py`'s `_selector_matches` and its
# ten per-dimension helpers.


@dataclass(frozen=True)
class _DimensionSpec:
    id: str
    scope_field: str
    allowed_values: tuple[str, str]
    mismatch_value: str
    matching_extra: Callable[[str], dict[str, object]]
    # `None` only for `actions` — `request.action` is required, so no
    # "request has no value for this dimension" state can be constructed
    # for it without bypassing request validation (see this file's PR 18
    # section docstring and `applicability.py`'s own required-field note).
    absent_extra: dict[str, object] | None
    # Populated only for dimensions nested inside an optional context
    # object (`location`, `device`, `environment_context`,
    # `protocol_context`); `None` for the three flat-field dimensions
    # (`actions`, `resource_types`, `authority_modes`), which have no
    # parent object and therefore no second absence form.
    parent_present_child_absent_extra: dict[str, object] | None = None

    def scope(self, values: list[str]) -> dict[str, object]:
        return {self.scope_field: values}


_DIMENSION_SPECS: tuple[_DimensionSpec, ...] = (
    _DimensionSpec(
        id="actions",
        scope_field="actions",
        allowed_values=("read:hvac", "write:hvac:setpoint"),
        mismatch_value="browse:chiller",
        matching_extra=lambda v: {"action": v},
        absent_extra=None,
    ),
    _DimensionSpec(
        id="resource_types",
        scope_field="resource_types",
        allowed_values=("hvac", "chiller"),
        mismatch_value="lighting",
        matching_extra=lambda v: {"resource_type": v},
        absent_extra={},
    ),
    _DimensionSpec(
        id="site_ids",
        scope_field="site_ids",
        allowed_values=("site-a", "site-b"),
        mismatch_value="site-c",
        matching_extra=lambda v: {"location": {"site_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _DimensionSpec(
        id="building_ids",
        scope_field="building_ids",
        allowed_values=("bldg-a", "bldg-b"),
        mismatch_value="bldg-c",
        matching_extra=lambda v: {"location": {"building_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _DimensionSpec(
        id="zone_ids",
        scope_field="zone_ids",
        allowed_values=("zone-a", "zone-b"),
        mismatch_value="zone-c",
        matching_extra=lambda v: {"location": {"zone_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _DimensionSpec(
        id="area_ids",
        scope_field="area_ids",
        allowed_values=("area-a", "area-b"),
        mismatch_value="area-c",
        matching_extra=lambda v: {"location": {"area_id": v}},
        absent_extra={},
        parent_present_child_absent_extra={"location": {}},
    ),
    _DimensionSpec(
        id="device_classes",
        scope_field="device_classes",
        allowed_values=("sensor", "actuator"),
        mismatch_value="controller",
        matching_extra=lambda v: {"device": {"device_class": v}},
        absent_extra={},
        parent_present_child_absent_extra={"device": {}},
    ),
    _DimensionSpec(
        id="environment_modes",
        scope_field="environment_modes",
        allowed_values=("production", "staging"),
        mismatch_value="development",
        matching_extra=lambda v: {"environment_context": {"mode": v}},
        absent_extra={},
        parent_present_child_absent_extra={"environment_context": {}},
    ),
    _DimensionSpec(
        id="authority_modes",
        scope_field="authority_modes",
        allowed_values=("federated", "synchronized"),
        mismatch_value="standalone",
        matching_extra=lambda v: {"authority_mode": v},
        absent_extra={},
    ),
    _DimensionSpec(
        id="protocols",
        scope_field="protocols",
        allowed_values=("bacnet", "modbus"),
        mismatch_value="mqtt",
        matching_extra=lambda v: {"protocol_context": {"protocol": v}},
        absent_extra={},
        parent_present_child_absent_extra={"protocol_context": {}},
    ),
)

_DIMENSION_SPECS_BY_ID: dict[str, _DimensionSpec] = {spec.id: spec for spec in _DIMENSION_SPECS}
_OPTIONAL_DIMENSION_SPECS: tuple[_DimensionSpec, ...] = tuple(
    spec for spec in _DIMENSION_SPECS if spec.absent_extra is not None
)
_NESTED_DIMENSION_SPECS: tuple[_DimensionSpec, ...] = tuple(
    spec for spec in _DIMENSION_SPECS if spec.parent_present_child_absent_extra is not None
)

_ALL_IDS = [spec.id for spec in _DIMENSION_SPECS]
_OPTIONAL_IDS = [spec.id for spec in _OPTIONAL_DIMENSION_SPECS]
_NESTED_IDS = [spec.id for spec in _NESTED_DIMENSION_SPECS]


def _with_dimension_value(
    extra: dict[str, object], spec: _DimensionSpec, value: str
) -> dict[str, object]:
    """A new request-extra mapping equal to `extra` except that `spec`'s
    dimension is overridden to `value`. For the four `location`-nested
    dimensions, the shared `location` sub-mapping is merged, not replaced,
    so this can be chained across multiple location dimensions (e.g.
    `site_ids` then `building_ids`) without one call blanking a value the
    previous call already applied. Never mutates `extra`."""
    result = dict(extra)
    piece = spec.matching_extra(value)
    if "location" in piece:
        merged_location: dict[str, object] = dict(result.get("location", {}))  # type: ignore[arg-type]
        merged_location.update(piece["location"])  # type: ignore[arg-type]
        result["location"] = merged_location
    else:
        result.update(piece)
    return result


# ══════════════════════════════════════════════════════════════════════════
# Per-dimension presence matrix — selector absent
# ══════════════════════════════════════════════════════════════════════════
#
# `TestGlobalScope` (PR 17, above) already proves "selector absent,
# request counterpart absent (or at its ordinary default)" -> applicable,
# for every dimension simultaneously (an entirely-default request against
# a scope-less bundle) and is not repeated here. What PR 17 does not cover
# is the case where the selector is absent but the request *does* carry a
# value for that dimension -- still unconstrained, but only meaningful to
# prove per-dimension since each case supplies a different field.


class TestPerDimensionScopeAbsent:
    """Selector absent -> that dimension never constrains applicability,
    including when the request carries an (irrelevant) value for it."""

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_scope_absent_request_counterpart_present_is_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        bundle = _build_bundle(scope=None)
        request = _build_request(**spec.matching_extra(spec.allowed_values[0]))
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize("spec", _NESTED_DIMENSION_SPECS, ids=_NESTED_IDS)
    def test_scope_absent_parent_present_child_absent_is_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        bundle = _build_bundle(scope=None)
        assert spec.parent_present_child_absent_extra is not None
        request = _build_request(**spec.parent_present_child_absent_extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Per-dimension presence matrix — selector present, request counterpart
# missing (both structural absence forms for nested dimensions)
# ══════════════════════════════════════════════════════════════════════════


class TestPerDimensionScopePresentCounterpartMissing:
    """Selector present + request has no value for that dimension at all
    -> `not_applicable`, in both structural forms a nested dimension's
    "no value" can take. `actions` is excluded: `request.action` is
    required, so this state cannot be constructed for it (see
    `_DimensionSpec.absent_extra`'s docstring)."""

    @pytest.mark.parametrize("spec", _OPTIONAL_DIMENSION_SPECS, ids=_OPTIONAL_IDS)
    def test_scope_present_request_counterpart_entirely_absent_is_not_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        assert spec.absent_extra is not None
        bundle = _build_bundle(scope=spec.scope(list(spec.allowed_values)))
        request = _build_request(**spec.absent_extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    @pytest.mark.parametrize("spec", _NESTED_DIMENSION_SPECS, ids=_NESTED_IDS)
    def test_scope_present_parent_present_child_absent_is_not_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        assert spec.parent_present_child_absent_extra is not None
        bundle = _build_bundle(scope=spec.scope(list(spec.allowed_values)))
        request = _build_request(**spec.parent_present_child_absent_extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Per-dimension exact membership
# ══════════════════════════════════════════════════════════════════════════


class TestPerDimensionExactMembership:
    """Selector present + request counterpart present: exact membership
    within the selector, not first-value-only comparison, and not
    ordering-significant (see `TestSelectorOrderInvariance` below for the
    ordering half of that claim)."""

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_first_member_match_is_applicable(self, spec: _DimensionSpec) -> None:
        bundle = _build_bundle(scope=spec.scope(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.allowed_values[0]))
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_non_first_member_match_is_applicable(self, spec: _DimensionSpec) -> None:
        bundle = _build_bundle(scope=spec.scope(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.allowed_values[1]))
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_non_member_value_is_not_applicable(self, spec: _DimensionSpec) -> None:
        bundle = _build_bundle(scope=spec.scope(list(spec.allowed_values)))
        request = _build_request(**spec.matching_extra(spec.mismatch_value))
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Selector order invariance
# ══════════════════════════════════════════════════════════════════════════


class TestSelectorOrderInvariance:
    """Selector order must not affect applicability. This is a regression
    test, not a new semantic feature: `applicability.py`'s
    `_selector_matches` already implements membership as plain `value in
    selector`, which is inherently order-independent — the implementation
    is not modified here, only proven to stay that way."""

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_matching_value_is_applicable_regardless_of_selector_order(
        self, spec: _DimensionSpec
    ) -> None:
        first, second = spec.allowed_values
        request = _build_request(**spec.matching_extra(second))
        forward = _build_bundle(scope=spec.scope([first, second]))
        reversed_order = _build_bundle(scope=spec.scope([second, first]))
        assert determine_applicability(forward, request) is ApplicabilityResult.APPLICABLE
        assert determine_applicability(reversed_order, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_non_member_value_is_not_applicable_regardless_of_selector_order(
        self, spec: _DimensionSpec
    ) -> None:
        first, second = spec.allowed_values
        request = _build_request(**spec.matching_extra(spec.mismatch_value))
        forward = _build_bundle(scope=spec.scope([first, second]))
        reversed_order = _build_bundle(scope=spec.scope([second, first]))
        assert determine_applicability(forward, request) is ApplicabilityResult.NOT_APPLICABLE
        assert (
            determine_applicability(reversed_order, request) is ApplicabilityResult.NOT_APPLICABLE
        )


# ══════════════════════════════════════════════════════════════════════════
# Duplicate selector values
# ══════════════════════════════════════════════════════════════════════════


class TestDuplicateSelectorValues:
    """`PolicyBundleScope` places no uniqueness constraint on a selector's
    items — confirmed by reading `bundle.py`'s field validators directly:
    only non-emptiness (`_reject_explicit_empty_array`), item non-
    emptiness/pattern (`_check_non_empty_items`, `_check_pattern_items`),
    and "at least one populated selector" (`_check_at_least_one_populated_
    selector`) are enforced; no dedup or item-uniqueness check exists
    anywhere in that model. Duplicates are therefore structurally valid
    input, not a state PR 18 needs to bypass validation to construct.

    `_selector_matches` itself is a plain `value in selector` membership
    test — duplicate tolerance is a property of that one shared primitive
    every dimension helper delegates to, not a per-dimension concern, so
    one representative dimension is exercised here rather than all ten
    (this file's "do not duplicate existing tests merely to increase test
    count" instruction applies to needless per-dimension repetition just
    as much as it applies to re-testing PR 17's own cases)."""

    _SPEC = _DIMENSION_SPECS_BY_ID["site_ids"]

    def test_duplicate_matching_selector_values_is_applicable(self) -> None:
        matching, _ = self._SPEC.allowed_values
        bundle = _build_bundle(scope=self._SPEC.scope([matching, matching]))
        request = _build_request(**self._SPEC.matching_extra(matching))
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    def test_duplicate_non_matching_selector_values_is_not_applicable(self) -> None:
        _, other = self._SPEC.allowed_values
        bundle = _build_bundle(scope=self._SPEC.scope([other, other]))
        request = _build_request(**self._SPEC.matching_extra(self._SPEC.mismatch_value))
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE


# ══════════════════════════════════════════════════════════════════════════
# Combined-dimension coverage
# ══════════════════════════════════════════════════════════════════════════
#
# One bundle scope populated on all ten dimensions ("all-matching scope"),
# paired with one request whose value for every one of those ten
# dimensions matches ("all-matching request"). Every test below starts
# from this same fixed pair and applies exactly one focused mutation, so a
# failure names precisely which dimension broke the combination.
#
# Deliberately not a full `2**10 x 2**10` cartesian product across all ten
# dimensions simultaneously: `determine_applicability` combines its ten
# per-dimension boolean checks with a single, pure `all(...)` over a fixed
# tuple (`applicability.py`, "Public entry point") — there is no shared
# mutable state and no interaction between any two dimension checks, so
# one-mismatch-at-a-time (below) already exercises every input to that
# `all(...)` that can flip its result from `True` to `False`, and one-
# omitted-selector-at-a-time already exercises every input that can flip
# a dimension from "checked" to "unconstrained". A larger combinatorial
# product would add no further semantic confidence over what those two
# matrices already prove, only combinatorial noise — the same caution
# this file's own non-goals and the roadmap's PR 18 entry both flag
# ("cartesian coverage ... not combinatorially wasteful"). Pairwise
# coverage across every distinct pair of dimensions was considered and
# not added for the same reason: with no cross-dimension interaction in
# the implementation, a pairwise matrix could only reproduce what the
# one-at-a-time matrices below already establish.


def _all_matching_request_extra() -> dict[str, object]:
    extra: dict[str, object] = {}
    for spec in _DIMENSION_SPECS:
        extra = _with_dimension_value(extra, spec, spec.allowed_values[0])
    return extra


def _all_matching_scope() -> dict[str, object]:
    return {spec.scope_field: [spec.allowed_values[0]] for spec in _DIMENSION_SPECS}


_ALL_MATCHING_REQUEST_EXTRA: dict[str, object] = _all_matching_request_extra()
_ALL_MATCHING_SCOPE: dict[str, object] = _all_matching_scope()

_CHILD_FIELD_BY_LOCATION_SCOPE_FIELD: dict[str, str] = {
    "site_ids": "site_id",
    "building_ids": "building_id",
    "zone_ids": "zone_id",
    "area_ids": "area_id",
}
_PARENT_FIELD_BY_SINGLE_CHILD_SCOPE_FIELD: dict[str, str] = {
    "device_classes": "device",
    "environment_modes": "environment_context",
    "protocols": "protocol_context",
}
_FLAT_REQUEST_FIELD_BY_SCOPE_FIELD: dict[str, str] = {
    "resource_types": "resource_type",
    "authority_modes": "authority_mode",
}


def _remove_one_counterpart_from_all_matching_extra(spec: _DimensionSpec) -> dict[str, object]:
    """The all-matching request extra, with exactly `spec`'s request
    counterpart removed — every other dimension's populated value is left
    untouched. For the four `location`-nested dimensions this drops only
    that one field from the shared `location` mapping (never the whole
    object, which would silently also blank its three siblings); for the
    three single-field-parent nested dimensions (`device`,
    `environment_context`, `protocol_context`), dropping the entire parent
    is equivalent to blanking just that one field, since it is the only
    field either parent carries in this baseline."""
    extra = dict(_ALL_MATCHING_REQUEST_EXTRA)
    if spec.scope_field in _CHILD_FIELD_BY_LOCATION_SCOPE_FIELD:
        child_field = _CHILD_FIELD_BY_LOCATION_SCOPE_FIELD[spec.scope_field]
        location = dict(extra["location"])  # type: ignore[arg-type]
        del location[child_field]
        extra["location"] = location
        return extra
    if spec.scope_field in _PARENT_FIELD_BY_SINGLE_CHILD_SCOPE_FIELD:
        del extra[_PARENT_FIELD_BY_SINGLE_CHILD_SCOPE_FIELD[spec.scope_field]]
        return extra
    del extra[_FLAT_REQUEST_FIELD_BY_SCOPE_FIELD[spec.scope_field]]
    return extra


class TestAllDimensionsCombined:
    def test_all_dimensions_populated_and_matching_is_applicable(self) -> None:
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**_ALL_MATCHING_REQUEST_EXTRA)
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_one_mismatch_among_all_populated_dimensions_is_not_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        extra = _with_dimension_value(_ALL_MATCHING_REQUEST_EXTRA, spec, spec.mismatch_value)
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    @pytest.mark.parametrize("spec", _OPTIONAL_DIMENSION_SPECS, ids=_OPTIONAL_IDS)
    def test_one_missing_request_counterpart_among_all_populated_dimensions_is_not_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        extra = _remove_one_counterpart_from_all_matching_extra(spec)
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    @pytest.mark.parametrize("spec", _DIMENSION_SPECS, ids=_ALL_IDS)
    def test_one_omitted_scope_selector_among_all_populated_dimensions_is_applicable(
        self, spec: _DimensionSpec
    ) -> None:
        scope = {
            field: values
            for field, values in _ALL_MATCHING_SCOPE.items()
            if field != spec.scope_field
        }
        bundle = _build_bundle(scope=scope)
        request = _build_request(**_ALL_MATCHING_REQUEST_EXTRA)
        assert determine_applicability(bundle, request) is ApplicabilityResult.APPLICABLE


class TestMultipleMismatches:
    """Focused cases proving multiple simultaneous mismatches remain
    `not_applicable` — not asserting which mismatch is evaluated first;
    `determine_applicability`'s only public observation is the final
    two-value result (this file's PR 18 section docstring)."""

    def test_two_mismatches_is_not_applicable(self) -> None:
        extra = _ALL_MATCHING_REQUEST_EXTRA
        for dim_id in ("site_ids", "protocols"):
            spec = _DIMENSION_SPECS_BY_ID[dim_id]
            extra = _with_dimension_value(extra, spec, spec.mismatch_value)
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    def test_several_mismatches_is_not_applicable(self) -> None:
        extra = _ALL_MATCHING_REQUEST_EXTRA
        for dim_id in ("actions", "resource_types", "device_classes", "authority_modes"):
            spec = _DIMENSION_SPECS_BY_ID[dim_id]
            extra = _with_dimension_value(extra, spec, spec.mismatch_value)
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE

    def test_every_populated_dimension_mismatching_is_not_applicable(self) -> None:
        extra = _ALL_MATCHING_REQUEST_EXTRA
        for spec in _DIMENSION_SPECS:
            extra = _with_dimension_value(extra, spec, spec.mismatch_value)
        bundle = _build_bundle(scope=_ALL_MATCHING_SCOPE)
        request = _build_request(**extra)
        assert determine_applicability(bundle, request) is ApplicabilityResult.NOT_APPLICABLE
