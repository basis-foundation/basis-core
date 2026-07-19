"""
tests/test_basis_schemas_snapshot.py — inventory tests for the vendored
`basis-schemas` operation-aware snapshot (currently `v0.2.1`, per
`tests/helpers/basis_schemas_snapshot.py`'s `SNAPSHOT_RELEASE`).

These tests protect the *shape* of the vendored snapshot: exactly which
contracts and scenarios are present, and which artifacts each scenario
carries. They do not test operation-aware evaluation semantics (there is no
evaluator yet) and they do not parse or validate YAML contract content.

Cross-references
─────────────────
tests/fixtures/basis-schemas/v0.2.1/README.md — ownership and boundary docs.
tests/helpers/basis_schemas_snapshot.py       — discovery helpers under test.
tests/test_basis_schemas_snapshot_integrity.py — manifest/hash integrity.
tests/test_basis_schemas_snapshot_provenance.py — source provenance values.
"""

from __future__ import annotations

from tests.helpers.basis_schemas_snapshot import (
    ALL_SCENARIO_ARTIFACTS,
    COMPATIBILITY_ROOT,
    GATEWAY_ONLY_SCENARIO_ARTIFACTS,
    KERNEL_SCENARIO_ARTIFACTS,
    SCHEMAS_ROOT,
    SnapshotPathError,
    get_scenario_artifact,
    get_schema_path,
    list_compatibility_scenarios,
    list_operation_aware_contracts,
)

# ---------------------------------------------------------------------------
# Independent expected inventories.
#
# These are hardcoded here, deliberately NOT imported from
# tests/helpers/basis_schemas_snapshot.py's own constants, so that an
# accidental edit to that module's inventory also fails these tests rather
# than trivially agreeing with itself.
# ---------------------------------------------------------------------------

EXPECTED_OPERATION_AWARE_CONTRACTS = frozenset(
    {
        "contract-metadata",
        "redaction-classification",
        "reason-code",
        "identity-evidence-reference",
        "adapter-evidence-reference",
        "operation-aware-decision-request",
        "policy-condition",
        "policy-rule",
        "policy-bundle",
        "trace-rule-evidence",
        "evaluation-trace",
        "operation-aware-decision-response",
        "audit-evidence",
        "gateway-audit-event",
    }
)

EXPECTED_COMPATIBILITY_SCENARIOS = frozenset(
    {
        "allow-basic",
        "deny-precedence",
        "default-deny",
        "not-applicable",
        "invalid-policy-bundle",
    }
)

EXPECTED_SCENARIO_FILES = {
    "allow-basic": {
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    },
    "deny-precedence": {
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    },
    "default-deny": {
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    },
    "not-applicable": {
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    },
    "invalid-policy-bundle": {
        "operation-aware-decision-request.yaml",
        "invalid-policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    },
}


# ── Contract inventory ──────────────────────────────────────────────────


class TestOperationAwareContractInventory:
    def test_exactly_fourteen_contracts_present(self) -> None:
        found = set(list_operation_aware_contracts())
        assert len(found) == 14, (
            f"Expected exactly 14 contracts, found {len(found)}: {sorted(found)}"
        )

    def test_contract_inventory_matches_expected_set_exactly(self) -> None:
        found = set(list_operation_aware_contracts())
        missing = EXPECTED_OPERATION_AWARE_CONTRACTS - found
        unexpected = found - EXPECTED_OPERATION_AWARE_CONTRACTS
        assert not missing, f"Missing expected contract(s): {sorted(missing)}"
        assert not unexpected, f"Unexpected contract directory/directories: {sorted(unexpected)}"

    def test_first_wave_contracts_are_not_vendored(self) -> None:
        """The six first-wave contracts that mirror v0.1.0 unchanged must not
        appear in this operation-aware snapshot — they are out of scope."""
        first_wave = {
            "vocabulary",
            "action-string",
            "resource-identifier",
            "decision-request",
            "decision-response",
            "audit-event",
        }
        found = set(list_operation_aware_contracts())
        assert not (found & first_wave), (
            f"First-wave contract(s) incorrectly vendored into the operation-aware "
            f"snapshot: {sorted(found & first_wave)}"
        )

    def test_every_contract_has_exactly_one_yaml_file(self) -> None:
        for contract in sorted(EXPECTED_OPERATION_AWARE_CONTRACTS):
            contract_dir = SCHEMAS_ROOT / contract
            assert contract_dir.is_dir(), f"Missing contract directory: {contract_dir}"
            files = sorted(p.name for p in contract_dir.iterdir() if p.is_file())
            assert files == [f"{contract}.yaml"], (
                f"Contract directory {contract_dir} does not contain exactly "
                f"['{contract}.yaml']; found {files}"
            )

    def test_get_schema_path_resolves_every_expected_contract(self) -> None:
        for contract in sorted(EXPECTED_OPERATION_AWARE_CONTRACTS):
            path = get_schema_path(contract)
            assert path.is_file()
            assert path.name == f"{contract}.yaml"

    def test_get_schema_path_rejects_unknown_contract(self) -> None:
        import pytest

        with pytest.raises(SnapshotPathError):
            get_schema_path("not-a-real-contract")


# ── Compatibility scenario inventory ────────────────────────────────────


class TestCompatibilityScenarioInventory:
    def test_exactly_five_scenarios_present(self) -> None:
        found = set(list_compatibility_scenarios())
        assert len(found) == 5, f"Expected exactly 5 scenarios, found {len(found)}: {sorted(found)}"

    def test_scenario_inventory_matches_expected_set_exactly(self) -> None:
        found = set(list_compatibility_scenarios())
        missing = EXPECTED_COMPATIBILITY_SCENARIOS - found
        unexpected = found - EXPECTED_COMPATIBILITY_SCENARIOS
        assert not missing, f"Missing expected scenario(s): {sorted(missing)}"
        assert not unexpected, f"Unexpected scenario directory/directories: {sorted(unexpected)}"

    def test_each_scenario_contains_exactly_its_expected_artifact_set(self) -> None:
        for scenario, expected_files in EXPECTED_SCENARIO_FILES.items():
            scenario_dir = COMPATIBILITY_ROOT / scenario
            assert scenario_dir.is_dir(), f"Missing scenario directory: {scenario_dir}"
            actual_files = {p.name for p in scenario_dir.iterdir() if p.is_file()}
            assert actual_files == expected_files, (
                f"Scenario {scenario!r} artifact set mismatch.\n"
                f"  missing: {sorted(expected_files - actual_files)}\n"
                f"  unexpected: {sorted(actual_files - expected_files)}"
            )

    def test_invalid_policy_bundle_scenario_never_carries_a_valid_policy_bundle_file(
        self,
    ) -> None:
        """invalid-policy-bundle/ must use invalid-policy-bundle.yaml, never
        policy-bundle.yaml — the naming makes the fixture's intent
        unmistakable, per basis-schemas' own compatibility README."""
        scenario_dir = COMPATIBILITY_ROOT / "invalid-policy-bundle"
        assert (scenario_dir / "invalid-policy-bundle.yaml").is_file()
        assert not (scenario_dir / "policy-bundle.yaml").exists()

    def test_get_scenario_artifact_resolves_every_kernel_artifact(self) -> None:
        for scenario in sorted(EXPECTED_COMPATIBILITY_SCENARIOS):
            for artifact in KERNEL_SCENARIO_ARTIFACTS:
                path = get_scenario_artifact(scenario, artifact)
                assert path.is_file(), f"{scenario}/{artifact} -> {path} missing"

    def test_get_scenario_artifact_resolves_gateway_only_artifact(self) -> None:
        for scenario in sorted(EXPECTED_COMPATIBILITY_SCENARIOS):
            path = get_scenario_artifact(scenario, "expected_gateway_audit_event")
            assert path.is_file()

    def test_get_scenario_artifact_rejects_unknown_scenario(self) -> None:
        import pytest

        with pytest.raises(SnapshotPathError):
            get_scenario_artifact("not-a-real-scenario", "request")

    def test_get_scenario_artifact_rejects_unknown_artifact(self) -> None:
        import pytest

        with pytest.raises(SnapshotPathError):
            get_scenario_artifact("allow-basic", "not_a_real_artifact")


# ── Kernel vs. gateway artifact boundary ────────────────────────────────


class TestKernelVsGatewayArtifactBoundary:
    def test_gateway_only_artifacts_are_disjoint_from_kernel_artifacts(self) -> None:
        assert set(KERNEL_SCENARIO_ARTIFACTS).isdisjoint(GATEWAY_ONLY_SCENARIO_ARTIFACTS)

    def test_all_scenario_artifacts_is_union_of_both(self) -> None:
        assert set(ALL_SCENARIO_ARTIFACTS) == set(KERNEL_SCENARIO_ARTIFACTS) | set(
            GATEWAY_ONLY_SCENARIO_ARTIFACTS
        )

    def test_gateway_audit_event_is_the_only_gateway_only_artifact(self) -> None:
        """basis-core does not produce, consume, or own GatewayAuditEvent
        records. This is the one artifact per scenario that is retained
        purely as cross-boundary reference data."""
        assert set(GATEWAY_ONLY_SCENARIO_ARTIFACTS) == {"expected_gateway_audit_event"}

    def test_kernel_artifacts_cover_request_bundle_trace_response_audit(self) -> None:
        assert set(KERNEL_SCENARIO_ARTIFACTS) == {
            "request",
            "policy_bundle",
            "expected_evaluation_trace",
            "expected_response",
            "expected_audit_evidence",
        }
