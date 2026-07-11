"""
tests/operation_aware/test_compatibility_fixture_loading.py —
compatibility-scenario fixture-loading tests (Milestone 1, PR 4 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

These tests prove that every artifact of every one of the 5 pinned
compatibility scenarios is parseable and has the expected broad shape, using
only the generic loader in `tests/helpers/operation_aware_contracts.py` and
the existing scenario/artifact inventory in
`tests/helpers/basis_schemas_snapshot.py`. They intentionally do not assert
decision outcomes, compare expected traces or responses, or otherwise
interpret scenario semantics — that is later, separate roadmap work (see
`tests/fixtures/basis-schemas/v0.2.0/README.md`).
"""

from __future__ import annotations

import pytest

from tests.helpers.basis_schemas_snapshot import (
    ALL_SCENARIO_ARTIFACTS,
    COMPATIBILITY_SCENARIOS,
    GATEWAY_ONLY_SCENARIO_ARTIFACTS,
    KERNEL_SCENARIO_ARTIFACTS,
    list_scenario_artifacts,
)
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ── Every expected artifact of every scenario loads ──────────────────────


@pytest.mark.parametrize("scenario", COMPATIBILITY_SCENARIOS)
@pytest.mark.parametrize("artifact", ALL_SCENARIO_ARTIFACTS)
def test_every_expected_artifact_loads_successfully(scenario: str, artifact: str) -> None:
    document = load_scenario_artifact(scenario, artifact)
    assert document is not None


@pytest.mark.parametrize("scenario", COMPATIBILITY_SCENARIOS)
@pytest.mark.parametrize("artifact", ALL_SCENARIO_ARTIFACTS)
def test_every_expected_artifact_has_a_mapping_root(scenario: str, artifact: str) -> None:
    document = load_scenario_artifact(scenario, artifact)
    assert isinstance(document, dict), (
        f"{scenario}/{artifact} expected a mapping root, got {type(document).__name__}."
    )


# ── Artifact discovery uses the existing helper inventory ───────────────


@pytest.mark.parametrize("scenario", COMPATIBILITY_SCENARIOS)
def test_artifact_discovery_uses_the_existing_helper_inventory(scenario: str) -> None:
    assert set(list_scenario_artifacts(scenario)) == set(ALL_SCENARIO_ARTIFACTS)


def test_kernel_and_gateway_only_artifact_sets_are_disjoint_and_complete() -> None:
    assert set(KERNEL_SCENARIO_ARTIFACTS).isdisjoint(GATEWAY_ONLY_SCENARIO_ARTIFACTS)
    assert set(KERNEL_SCENARIO_ARTIFACTS) | set(GATEWAY_ONLY_SCENARIO_ARTIFACTS) == set(
        ALL_SCENARIO_ARTIFACTS
    )


# ── Gateway-only artifacts remain reference-only ─────────────────────────


@pytest.mark.parametrize("scenario", COMPATIBILITY_SCENARIOS)
def test_gateway_only_artifact_still_loads_as_reference_data(scenario: str) -> None:
    """basis-core does not produce, consume, or own `GatewayAuditEvent` (see
    `tests/fixtures/basis-schemas/v0.2.0/README.md`, "Kernel-owned vs.
    gateway-only artifacts"). This confirms the artifact still parses as
    part of the vendored snapshot, without ever treating it as a
    kernel-expected output."""
    assert "expected_gateway_audit_event" in GATEWAY_ONLY_SCENARIO_ARTIFACTS
    assert "expected_gateway_audit_event" not in KERNEL_SCENARIO_ARTIFACTS

    document = load_scenario_artifact(scenario, "expected_gateway_audit_event")
    assert isinstance(document, dict)


# ── The intentionally-invalid scenario still parses ──────────────────────


def test_invalid_policy_bundle_scenario_still_parses_as_yaml() -> None:
    """`invalid-policy-bundle` is intentionally invalid per the
    `policy-bundle` contract's own field policy (duplicate `rule_id`
    values) — but it is still well-formed YAML. This test proves only that
    it parses and has a mapping root; it does not assert or reproduce the
    duplicate-rule_id business rule that makes it semantically invalid."""
    document = load_scenario_artifact("invalid-policy-bundle", "policy_bundle")
    assert isinstance(document, dict)
    assert document.get("bundle_id") == "bundle-compat-invalid-policy"
