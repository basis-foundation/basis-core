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
This module proves the implementation and gives representative coverage
of every scope dimension, per PR 17's own completion criteria. It does
NOT implement the full Cartesian product of every dimension's
present/absent combination, nor exhaustive combined-dimension coverage —
that is PR 18's dedicated scope, which extends this same file. See the
roadmap plan's PR 17/PR 18 entries and `applicability.py`'s own
docstring, "Not implemented by this module".

This file tests applicability classification only. It does not test, and
must never test: rule matching, condition evaluation, rule effects, deny
precedence, default-deny, a final authorization outcome, evaluation
traces, decision responses, audit evidence, or gateway/enforcement
behavior — none of that exists in this module or this PR.
"""

from __future__ import annotations

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
