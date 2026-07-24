"""
tests/test_basis_schemas_snapshot_v0_2_2_correction.py — exactness tests for
the `basis-schemas` `v0.2.2` re-vendoring (chore/vendor-basis-schemas-v0.2.2).

This module proves the specific, narrow claims this vendoring PR makes,
which the generic inventory/integrity/provenance tests
(`tests/test_basis_schemas_snapshot.py`,
`tests/test_basis_schemas_snapshot_integrity.py`,
`tests/test_basis_schemas_snapshot_provenance.py`) do not by themselves
cover, because those tests only ever look at the single *active* snapshot
resolved through `tests/helpers/basis_schemas_snapshot.py`'s
`SNAPSHOT_RELEASE` (now `v0.2.2`):

  1. The historical `v0.2.1` snapshot is untouched — byte-identical to what
     it recorded before this PR, including the evidence-provenance
     disagreements `v0.2.2` corrects.
  2. Every input artifact (`operation-aware-decision-request.yaml`,
     `policy-bundle.yaml`/`invalid-policy-bundle.yaml`) and all 14 schema
     contracts are byte-identical between `v0.2.1` and `v0.2.2` — only the
     20 `expected-*.yaml` result artifacts (4 per scenario × 5 scenarios)
     changed.
  3. Top-level `explanation` is `null` on every result artifact across all
     five scenarios — no aggregate prose is synthesized.
  4. Per-rule evidence follows `rule_result`: `matched` preserves authored
     `reason_code`/`explanation` verbatim (including a matched-but-
     non-decisive rule under deny precedence); `not_matched`/`skipped` omit
     both; the corrected `deny-precedence` wording uses the plural
     "operations".
  5. Bundle identity (`bundle_id`/`bundle_version`) is present on
     `not-applicable` and `invalid-policy-bundle`, which `v0.2.1` omitted it
     from.
  6. Cross-artifact agreement holds for the fields each artifact type
     actually owns, respecting the kernel/gateway boundary.
  7. Bounded negative (mutation) coverage: deliberately-corrupted in-memory
     copies of the loaded fixtures fail the same assertions that pass
     against the real, corrected fixtures — proof that these tests would
     actually catch drift, not merely agree with whatever is on disk.
  8. Every vendored YAML file in the `v0.2.2` snapshot parses.

This module does not assert anything about `basis-core` evaluator/engine
behavior (that remains PR 37's scope, not this PR's) and does not treat
`expected-gateway-audit-event.yaml` as a kernel-owned artifact (see
`tests/fixtures/basis-schemas/v0.2.0/README.md`'s "Kernel-owned vs.
gateway-only artifacts" section, which still applies unchanged). No file on
disk is mutated by this module — negative coverage operates on in-memory
`copy.deepcopy`d structures only.

Cross-references
─────────────────
tests/fixtures/basis-schemas/v0.2.2/README.md — what changed and why.
tests/test_basis_schemas_snapshot_v0_2_1_correction.py — the analogous
    module for the prior `v0.2.1` re-vendoring; this module follows the same
    structure and conventions.
docs/implementation/basis-core-v0.2-operation-aware-plan.md — Milestone 12's
    PR 37 status note, updated by this PR to record v0.2.2 as vendored and
    active, and all reconciliation prerequisites for PR 37 as complete.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml

_FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "basis-schemas"
_V0_2_1 = _FIXTURES_ROOT / "v0.2.1"
_V0_2_2 = _FIXTURES_ROOT / "v0.2.2"

_SCENARIOS = (
    "allow-basic",
    "deny-precedence",
    "default-deny",
    "not-applicable",
    "invalid-policy-bundle",
)

_RESULT_ARTIFACTS = (
    "expected-evaluation-trace.yaml",
    "expected-operation-aware-decision-response.yaml",
    "expected-audit-evidence.yaml",
    "expected-gateway-audit-event.yaml",
)

_INPUT_ARTIFACT_FILENAMES = {
    "allow-basic": ("operation-aware-decision-request.yaml", "policy-bundle.yaml"),
    "deny-precedence": ("operation-aware-decision-request.yaml", "policy-bundle.yaml"),
    "default-deny": ("operation-aware-decision-request.yaml", "policy-bundle.yaml"),
    "not-applicable": ("operation-aware-decision-request.yaml", "policy-bundle.yaml"),
    "invalid-policy-bundle": (
        "operation-aware-decision-request.yaml",
        "invalid-policy-bundle.yaml",
    ),
}

# The v0.2.1 SHA-256 digests recorded for the 20 result artifacts this PR
# corrects (4 per scenario x 5 scenarios), captured at the time this
# vendoring PR began. Hardcoded independently of v0.2.1/manifest.json so an
# accidental edit to *both* the file and the historical manifest entry would
# still be caught here — the same tamper-evidence pattern
# test_basis_schemas_snapshot_v0_2_1_correction.py used for v0.2.0's
# corrected scenario.
_V0_2_1_RESULT_ARTIFACT_DIGESTS: dict[str, str] = {
    "allow-basic/expected-audit-evidence.yaml": (
        "f930cd0dc6cd19408ab42a443a42edb658fe2918f32db3c804a7df08d8c53f68"
    ),
    "allow-basic/expected-evaluation-trace.yaml": (
        "95a2b5032b571566ea8ce90ee41f5b506782249cce07cec59d439bbb476eede7"
    ),
    "allow-basic/expected-gateway-audit-event.yaml": (
        "f4f7cf2342002b97fc11bf7bfae4b2a45e70809422e745eecbff0eda137db2d6"
    ),
    "allow-basic/expected-operation-aware-decision-response.yaml": (
        "4082519e620bcf5aa8f654d688832172252e036d73b77e8539c8336d911b09c9"
    ),
    "default-deny/expected-audit-evidence.yaml": (
        "fb4b3919e63b7078a08e740f65531041897f6132fc267ceb21bb945082c5816b"
    ),
    "default-deny/expected-evaluation-trace.yaml": (
        "8082137bfae5b0ee4cd092f3e11dc2925b1e71b8b1e230bc5c40d349c6d62b4a"
    ),
    "default-deny/expected-gateway-audit-event.yaml": (
        "49465203fe5b4d498b7c047ea77c08a6451753e080b154674b8e5dc9f273e88d"
    ),
    "default-deny/expected-operation-aware-decision-response.yaml": (
        "af82174996a97fbee7839e29c294e3800c617c11518bd3b09ad8ffcb65986178"
    ),
    "deny-precedence/expected-audit-evidence.yaml": (
        "ddad37760dca10d06f93b2ad741f434a52a25ce56ee1fdd1a5be03435b5995d5"
    ),
    "deny-precedence/expected-evaluation-trace.yaml": (
        "e044cf2514ec1ce4c86d45c01c738d04043f7f7c15540ed541b2c25ac1dcf3f2"
    ),
    "deny-precedence/expected-gateway-audit-event.yaml": (
        "4dc3efe23aaf6c55895d43862a812e82e857c5f3dfc9ce378220c7f714aef068"
    ),
    "deny-precedence/expected-operation-aware-decision-response.yaml": (
        "2eb11d25310a1dac708d2c44728961b6627e7e42c8c478a294a3508f899e4502"
    ),
    "invalid-policy-bundle/expected-audit-evidence.yaml": (
        "1c4215b22d0d2f620d6ffb3f8ea96aa32bb8afc997aacec8dea008110fedc9b4"
    ),
    "invalid-policy-bundle/expected-evaluation-trace.yaml": (
        "651ad5916e3dcdb3404edd4f496ee26f01771b088fe99ff90d0ecd9cc199842a"
    ),
    "invalid-policy-bundle/expected-gateway-audit-event.yaml": (
        "2cdaed669a8e3fe211ee4b2579f01bd1a46f51ccd644206057b52721db94e914"
    ),
    "invalid-policy-bundle/expected-operation-aware-decision-response.yaml": (
        "d922df3ba9f78a5024c1bb5b82d4c61a153ee04f24d03b81e5e3ab0f22225cef"
    ),
    "not-applicable/expected-audit-evidence.yaml": (
        "8fdc98c20de845fe59b945991d2165efeaa5429f4176884a57db944d0562b716"
    ),
    "not-applicable/expected-evaluation-trace.yaml": (
        "2e79103117c3565fdb17b98dab479797c1add69189e0c16ab27229c4124c68c0"
    ),
    "not-applicable/expected-gateway-audit-event.yaml": (
        "65bceeb3d6614004c8625c98656f294b312b63eca8745cb71275b15274626b39"
    ),
    "not-applicable/expected-operation-aware-decision-response.yaml": (
        "884960c69731d3de44d6a84c390a42446af38e02c79522c996855c36f451488c"
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_scenario(release_root: Path, scenario: str) -> dict[str, Any]:
    scenario_dir = release_root / "compatibility" / scenario
    policy_filename = (
        "invalid-policy-bundle.yaml"
        if scenario == "invalid-policy-bundle"
        else "policy-bundle.yaml"
    )
    return {
        "request": _load_yaml(scenario_dir / "operation-aware-decision-request.yaml"),
        "bundle": _load_yaml(scenario_dir / policy_filename),
        "trace": _load_yaml(scenario_dir / "expected-evaluation-trace.yaml"),
        "response": _load_yaml(scenario_dir / "expected-operation-aware-decision-response.yaml"),
        "audit": _load_yaml(scenario_dir / "expected-audit-evidence.yaml"),
        "gateway": _load_yaml(scenario_dir / "expected-gateway-audit-event.yaml"),
    }


def _load_v0_2_2_scenario(scenario: str) -> dict[str, Any]:
    return _load_scenario(_V0_2_2, scenario)


# ── Reusable governed-semantics assertions ──────────────────────────────
#
# Factored out so the negative-mutation tests below can run the *same*
# assertion against a deliberately corrupted in-memory copy and prove it
# fails, rather than merely asserting fixed values twice.


def _assert_no_synthesized_top_level_explanation(artifact: dict[str, Any]) -> None:
    explanation = artifact.get("explanation")
    assert explanation is None, (
        f"Expected null explanation, no synthesized prose; got {explanation!r}"
    )


def _assert_bundle_identity(
    artifact: dict[str, Any], *, bundle_id: str, bundle_version: str
) -> None:
    assert artifact.get("bundle_id") == bundle_id, (
        f"Expected bundle_id={bundle_id!r}; got {artifact.get('bundle_id')!r}"
    )
    assert artifact.get("bundle_version") == bundle_version, (
        f"Expected bundle_version={bundle_version!r}; got {artifact.get('bundle_version')!r}"
    )


def _assert_matched_rule_evidence(
    rule_evidence: list[dict[str, Any]],
    rule_id: str,
    *,
    reason_code: str,
    explanation: str,
) -> None:
    matches = [r for r in rule_evidence if r.get("rule_id") == rule_id]
    assert matches, f"Expected a rule_evidence entry for rule_id={rule_id!r}; found none"
    entry = matches[0]
    assert entry.get("rule_result") == "matched", (
        f"{rule_id}: rule_result={entry.get('rule_result')!r}"
    )
    assert entry.get("reason_code") == reason_code, (
        f"{rule_id}: reason_code={entry.get('reason_code')!r}, expected {reason_code!r}"
    )
    assert entry.get("explanation") == explanation, (
        f"{rule_id}: explanation={entry.get('explanation')!r}, expected {explanation!r}"
    )


def _assert_non_matched_rule_omits_rationale(entry: dict[str, Any]) -> None:
    assert entry.get("rule_result") in ("not_matched", "skipped"), (
        f"Expected rule_result in ('not_matched', 'skipped'); got {entry.get('rule_result')!r}"
    )
    assert "reason_code" not in entry, (
        f"not_matched/skipped rule unexpectedly carries reason_code: {entry}"
    )
    assert "explanation" not in entry, (
        f"not_matched/skipped rule unexpectedly carries explanation: {entry}"
    )


# ── 1. Historical v0.2.1 snapshot is untouched ──────────────────────────


class TestHistoricalV0_2_1SnapshotUnchanged:
    def test_v0_2_1_directory_still_exists(self) -> None:
        assert _V0_2_1.is_dir(), f"Historical snapshot removed: {_V0_2_1}"

    def test_v0_2_1_manifest_still_declares_v0_2_1_provenance(self) -> None:
        import json

        manifest = json.loads((_V0_2_1 / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["source_release"] == "v0.2.1"
        assert manifest["source_commit"] == "945acd107016bcbcb114f440474df204ead3f8f3"

    def test_v0_2_1_result_artifacts_are_byte_identical_to_before_this_pr(self) -> None:
        mismatches = []
        for rel_path, expected_digest in _V0_2_1_RESULT_ARTIFACT_DIGESTS.items():
            actual_digest = _sha256(_V0_2_1 / "compatibility" / rel_path)
            if actual_digest != expected_digest:
                mismatches.append((rel_path, expected_digest, actual_digest))
        assert not mismatches, (
            f"v0.2.1 result artifact(s) changed since before this PR (v0.2.1 must remain "
            f"immutable): {mismatches}"
        )

    def test_v0_2_1_still_carries_the_superseded_semantics(self) -> None:
        """v0.2.1's own not-applicable trace must still omit bundle identity —
        proving this PR corrected only the new v0.2.2 sibling, not the
        historical snapshot."""
        trace = _load_yaml(
            _V0_2_1 / "compatibility" / "not-applicable" / "expected-evaluation-trace.yaml"
        )
        assert "bundle_id" not in trace or trace.get("bundle_id") is None, (
            "Expected v0.2.1's not-applicable trace to still lack corrected bundle identity; "
            f"found bundle_id={trace.get('bundle_id')!r}"
        )


# ── 2. Inputs and schemas unchanged; only result artifacts differ ──────


class TestOnlyResultArtifactsChangedFromV0_2_1:
    def test_every_input_artifact_matches_byte_for_byte(self) -> None:
        mismatches = []
        for scenario, filenames in _INPUT_ARTIFACT_FILENAMES.items():
            for filename in filenames:
                v1_path = _V0_2_1 / "compatibility" / scenario / filename
                v2_path = _V0_2_2 / "compatibility" / scenario / filename
                if _sha256(v1_path) != _sha256(v2_path):
                    mismatches.append(f"{scenario}/{filename}")
        assert not mismatches, f"Unexpected drift in input artifact(s): {mismatches}"

    def test_all_fourteen_schema_contracts_match_byte_for_byte(self) -> None:
        mismatches = []
        v1_root = _V0_2_1 / "schemas"
        v2_root = _V0_2_2 / "schemas"
        for contract_dir in sorted(p for p in v1_root.iterdir() if p.is_dir()):
            filename = f"{contract_dir.name}.yaml"
            if _sha256(contract_dir / filename) != _sha256(v2_root / contract_dir.name / filename):
                mismatches.append(contract_dir.name)
        assert not mismatches, f"Unexpected schema contract drift: {mismatches}"

    def test_every_result_artifact_actually_changed(self) -> None:
        """Sanity check on this PR's own claim: all 20 result artifacts (the
        ones v0.2.2 corrects) must differ from their v0.2.1 predecessor —
        an unchanged one here would mean the correction did not take
        effect for that file."""
        unchanged = []
        for scenario in _SCENARIOS:
            for filename in _RESULT_ARTIFACTS:
                v1_path = _V0_2_1 / "compatibility" / scenario / filename
                v2_path = _V0_2_2 / "compatibility" / scenario / filename
                if _sha256(v1_path) == _sha256(v2_path):
                    unchanged.append(f"{scenario}/{filename}")
        assert not unchanged, f"Expected these result artifacts to change in v0.2.2: {unchanged}"


# ── 3-5. Per-scenario corrected-semantics assertions ────────────────────


class TestAllowBasicCorrections:
    def test_top_level_explanations_are_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("allow-basic")
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    def test_matched_rule_preserves_authored_explanation_and_reason_code(self) -> None:
        artifacts = _load_v0_2_2_scenario("allow-basic")
        _assert_matched_rule_evidence(
            artifacts["trace"]["rule_evidence"],
            "allow-operator-read-ahu",
            reason_code="allow_rule_matched",
            explanation="Operators may read AHU telemetry.",
        )

    def test_outcome_remains_allow(self) -> None:
        artifacts = _load_v0_2_2_scenario("allow-basic")
        for name in ("trace", "response", "gateway"):
            assert artifacts[name]["outcome"] == "allow", (
                f"{name}: outcome={artifacts[name]['outcome']!r}"
            )


class TestDenyPrecedenceCorrections:
    def test_top_level_explanations_are_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    def test_matched_allow_rule_remains_represented_and_non_decisive(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        _assert_matched_rule_evidence(
            artifacts["trace"]["rule_evidence"],
            "allow-operator-write-hvac-setpoint",
            reason_code="allow_rule_matched",
            explanation="Operators may write HVAC setpoints.",
        )

    def test_matched_deny_rule_preserves_corrected_plural_wording(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        _assert_matched_rule_evidence(
            artifacts["trace"]["rule_evidence"],
            "deny-control-during-interlock",
            reason_code="deny_rule_matched",
            explanation="Control-affecting operations are denied while an interlock is engaged.",
        )

    def test_corrected_wording_uses_plural_operations_not_singular(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        deny_entry = next(
            r
            for r in artifacts["trace"]["rule_evidence"]
            if r["rule_id"] == "deny-control-during-interlock"
        )
        assert "operations are denied" in deny_entry["explanation"]
        assert "operation is denied" not in deny_entry["explanation"]

    def test_both_matched_rule_ids_present_and_ordered(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        rule_ids = [r["rule_id"] for r in artifacts["trace"]["rule_evidence"]]
        assert rule_ids == ["allow-operator-write-hvac-setpoint", "deny-control-during-interlock"]
        assert artifacts["audit"]["matched_rule_ids"] == rule_ids

    def test_aggregate_outcome_remains_deny(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["outcome"] == "deny", (
                f"{name}: outcome={artifacts[name]['outcome']!r}"
            )


class TestDefaultDenyCorrections:
    def test_top_level_explanations_are_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("default-deny")
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    def test_non_matching_rule_omits_authored_rationale(self) -> None:
        artifacts = _load_v0_2_2_scenario("default-deny")
        rule_evidence = artifacts["trace"]["rule_evidence"]
        assert len(rule_evidence) == 1
        _assert_non_matched_rule_omits_rationale(rule_evidence[0])

    def test_matched_rule_ids_is_empty(self) -> None:
        artifacts = _load_v0_2_2_scenario("default-deny")
        assert artifacts["audit"]["matched_rule_ids"] == []

    def test_aggregate_outcome_remains_deny(self) -> None:
        artifacts = _load_v0_2_2_scenario("default-deny")
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["outcome"] == "deny", (
                f"{name}: outcome={artifacts[name]['outcome']!r}"
            )


class TestNotApplicableCorrections:
    def test_top_level_explanations_are_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    def test_evaluation_remains_not_applicable(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        for name in ("trace", "response", "gateway"):
            assert artifacts[name]["outcome"] == "not_applicable"

    def test_no_matched_rules_introduced(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        assert artifacts["trace"]["rule_evidence"] == []
        assert artifacts["audit"]["matched_rule_ids"] == []

    def test_bundle_identity_present_and_correct(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        for name in ("trace", "response", "audit"):
            _assert_bundle_identity(
                artifacts[name],
                bundle_id="bundle-compat-hvac-scope",
                bundle_version="1.0.0",
            )


class TestInvalidPolicyBundleCorrections:
    def test_top_level_explanations_are_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    def test_evaluation_status_remains_failed(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["evaluation_status"] == "failed"

    def test_outcome_remains_null(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("trace", "response", "gateway"):
            assert artifacts[name]["outcome"] is None

    def test_failure_reason_remains_policy_validation_failure(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["failure_reason"] == "policy_validation_failure"

    def test_bundle_identity_present_and_correct(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("trace", "response", "audit"):
            _assert_bundle_identity(
                artifacts[name],
                bundle_id="bundle-compat-invalid-policy",
                bundle_version="1.0.0",
            )

    def test_no_replacement_reason_code_is_invented(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        for name in ("trace", "response", "audit"):
            reason_code = artifacts[name].get("reason_code")
            assert reason_code is None, f"{name}: unexpectedly carries reason_code {reason_code!r}"

    def test_no_matched_rules_introduced(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        assert artifacts["trace"]["rule_evidence"] == []

    def test_duplicate_rule_id_defect_still_present(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        rule_ids = [rule["rule_id"] for rule in artifacts["bundle"]["rules"]]
        assert rule_ids.count("allow-duplicate-rule") >= 2, (
            f"Expected 'allow-duplicate-rule' to repeat; got: {rule_ids}"
        )


# ── 6. Cross-artifact agreement, respecting ownership boundaries ────────


class TestCrossArtifactAgreement:
    """Shared evidence-provenance fields agree across
    OperationAwareDecisionResponse / EvaluationTrace / AuditEvidence /
    GatewayAuditEvent wherever a field is actually shared. Per
    tests/fixtures/basis-schemas/v0.2.0/README.md's "Kernel-owned vs.
    gateway-only artifacts" section, GatewayAuditEvent is never required to
    carry kernel-only fields (rule_evidence, matched_rule_ids), and its own
    reason_code is not required to equal the kernel's (it explains the
    gateway's own enforcement choice, a separate layer)."""

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_top_level_explanation_null_across_all_owning_artifacts(self, scenario: str) -> None:
        artifacts = _load_v0_2_2_scenario(scenario)
        for name in ("response", "trace", "audit", "gateway"):
            _assert_no_synthesized_top_level_explanation(artifacts[name])

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_evaluation_status_agrees_across_trace_response_audit_gateway(
        self, scenario: str
    ) -> None:
        artifacts = _load_v0_2_2_scenario(scenario)
        values = {
            name: artifacts[name]["evaluation_status"]
            for name in ("trace", "response", "audit", "gateway")
        }
        assert len(set(values.values())) == 1, (
            f"{scenario}: evaluation_status disagreement: {values}"
        )

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_outcome_agrees_across_trace_response_gateway(self, scenario: str) -> None:
        artifacts = _load_v0_2_2_scenario(scenario)
        values = {name: artifacts[name]["outcome"] for name in ("trace", "response", "gateway")}
        assert len(set(values.values())) == 1, f"{scenario}: outcome disagreement: {values}"

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_failure_reason_agrees_across_trace_response_audit_gateway(self, scenario: str) -> None:
        artifacts = _load_v0_2_2_scenario(scenario)
        values = {
            name: artifacts[name].get("failure_reason")
            for name in ("trace", "response", "audit", "gateway")
        }
        assert len(set(values.values())) == 1, f"{scenario}: failure_reason disagreement: {values}"

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_bundle_identity_agrees_across_trace_response_audit_when_present(
        self, scenario: str
    ) -> None:
        artifacts = _load_v0_2_2_scenario(scenario)
        values = {
            name: (artifacts[name].get("bundle_id"), artifacts[name].get("bundle_version"))
            for name in ("trace", "response", "audit")
        }
        assert len(set(values.values())) == 1, f"{scenario}: bundle identity disagreement: {values}"

    def test_matched_rule_ids_agree_between_trace_and_audit_evidence(self) -> None:
        """`invalid-policy-bundle` is exempt: rule evaluation never began
        (bundle validation failed first), so its AuditEvidence carries no
        `matched_rule_ids` field at all — absence there is itself the
        governed shape, not a disagreement with the trace's empty
        `rule_evidence`."""
        for scenario in _SCENARIOS:
            artifacts = _load_v0_2_2_scenario(scenario)
            trace_matched = [
                r["rule_id"]
                for r in artifacts["trace"]["rule_evidence"]
                if r["rule_result"] == "matched"
            ]
            if scenario == "invalid-policy-bundle":
                assert "matched_rule_ids" not in artifacts["audit"], (
                    "Expected invalid-policy-bundle's audit evidence to omit matched_rule_ids "
                    "entirely (rule evaluation never began)"
                )
                continue
            assert artifacts["audit"]["matched_rule_ids"] == trace_matched, (
                f"{scenario}: matched_rule_ids disagreement between trace and audit evidence"
            )

    def test_gateway_never_asserted_to_carry_kernel_only_rule_evidence(self) -> None:
        """Mechanical proof of the ownership boundary this test class
        documents: GatewayAuditEvent fixtures never carry rule_evidence or
        matched_rule_ids — asserting their absence, not merely omitting the
        assertion, keeps the boundary visible if it were ever violated."""
        for scenario in _SCENARIOS:
            gateway = _load_v0_2_2_scenario(scenario)["gateway"]
            assert "rule_evidence" not in gateway
            assert "matched_rule_ids" not in gateway


# ── 7. Bounded negative mutation coverage (in-memory only) ──────────────


class TestNegativeMutationCoverage:
    """Each test proves the corresponding positive assertion above would
    actually fail against corrupted data. No file on disk is written to —
    every mutation operates on a `copy.deepcopy`d in-memory structure."""

    def test_synthesizing_a_null_top_level_explanation_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        mutated = copy.deepcopy(artifacts["response"])
        mutated["explanation"] = "No applicable policy bundle covers this request."
        with pytest.raises(AssertionError):
            _assert_no_synthesized_top_level_explanation(mutated)

    def test_removing_bundle_identity_from_not_applicable_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("not-applicable")
        mutated = copy.deepcopy(artifacts["trace"])
        del mutated["bundle_id"]
        del mutated["bundle_version"]
        with pytest.raises(AssertionError):
            _assert_bundle_identity(
                mutated, bundle_id="bundle-compat-hvac-scope", bundle_version="1.0.0"
            )

    def test_removing_bundle_identity_from_invalid_policy_bundle_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("invalid-policy-bundle")
        mutated = copy.deepcopy(artifacts["response"])
        mutated["bundle_id"] = None
        mutated["bundle_version"] = None
        with pytest.raises(AssertionError):
            _assert_bundle_identity(
                mutated, bundle_id="bundle-compat-invalid-policy", bundle_version="1.0.0"
            )

    def test_copying_authored_rationale_onto_a_not_matched_rule_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("default-deny")
        mutated = copy.deepcopy(artifacts["trace"]["rule_evidence"][0])
        mutated["reason_code"] = "allow_rule_matched"
        mutated["explanation"] = "Operators may read AHU telemetry."
        with pytest.raises(AssertionError):
            _assert_non_matched_rule_omits_rationale(mutated)

    def test_removing_matched_allow_evidence_from_deny_precedence_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        mutated_rule_evidence = [
            r
            for r in copy.deepcopy(artifacts["trace"]["rule_evidence"])
            if r["rule_id"] != "allow-operator-write-hvac-setpoint"
        ]
        with pytest.raises(AssertionError):
            _assert_matched_rule_evidence(
                mutated_rule_evidence,
                "allow-operator-write-hvac-setpoint",
                reason_code="allow_rule_matched",
                explanation="Operators may write HVAC setpoints.",
            )

    def test_changing_exact_authored_wording_fails(self) -> None:
        artifacts = _load_v0_2_2_scenario("deny-precedence")
        mutated_rule_evidence = copy.deepcopy(artifacts["trace"]["rule_evidence"])
        for entry in mutated_rule_evidence:
            if entry["rule_id"] == "deny-control-during-interlock":
                entry["explanation"] = (
                    "Control-affecting operation is denied while an interlock is engaged."
                )
        with pytest.raises(AssertionError):
            _assert_matched_rule_evidence(
                mutated_rule_evidence,
                "deny-control-during-interlock",
                reason_code="deny_rule_matched",
                explanation=(
                    "Control-affecting operations are denied while an interlock is engaged."
                ),
            )

    def test_evaluation_status_disagreement_is_detected(self) -> None:
        artifacts = _load_v0_2_2_scenario("allow-basic")
        mutated_audit = copy.deepcopy(artifacts["audit"])
        mutated_audit["evaluation_status"] = "failed"
        values = {
            "response": artifacts["response"]["evaluation_status"],
            "trace": artifacts["trace"]["evaluation_status"],
            "audit": mutated_audit["evaluation_status"],
            "gateway": artifacts["gateway"]["evaluation_status"],
        }
        assert len(set(values.values())) != 1, "Expected the mutated evaluation_status to disagree"


# ── 8. Every vendored YAML file in v0.2.2 parses ─────────────────────────


class TestAllVendoredYamlParsesInV0_2_2:
    def test_every_schema_yaml_parses(self) -> None:
        failures = []
        for path in sorted((_V0_2_2 / "schemas").rglob("*.yaml")):
            try:
                parsed = _load_yaml(path)
            except yaml.YAMLError as exc:
                failures.append((str(path), str(exc)))
                continue
            if not isinstance(parsed, dict):
                failures.append((str(path), f"parsed as {type(parsed).__name__}, expected dict"))
        assert not failures, f"Schema YAML parse failure(s): {failures}"

    def test_every_compatibility_yaml_parses(self) -> None:
        failures = []
        for path in sorted((_V0_2_2 / "compatibility").rglob("*.yaml")):
            try:
                parsed = _load_yaml(path)
            except yaml.YAMLError as exc:
                failures.append((str(path), str(exc)))
                continue
            if not isinstance(parsed, dict):
                failures.append((str(path), f"parsed as {type(parsed).__name__}, expected dict"))
        assert not failures, f"Compatibility YAML parse failure(s): {failures}"
