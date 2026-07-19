"""
tests/test_basis_schemas_snapshot_v0_2_1_correction.py — exactness tests for
the `basis-schemas` `v0.2.1` re-vendoring (chore/vendor-basis-schemas-v0.2.1).

This module proves the specific, narrow claims this vendoring PR makes,
which the generic inventory/integrity/provenance tests
(`tests/test_basis_schemas_snapshot.py`,
`tests/test_basis_schemas_snapshot_integrity.py`,
`tests/test_basis_schemas_snapshot_provenance.py`) do not by themselves
cover, because those tests only ever look at the single *active* snapshot
resolved through `tests/helpers/basis_schemas_snapshot.py`'s
`SNAPSHOT_RELEASE` (now `v0.2.1`):

  1. The historical `v0.2.0` snapshot is untouched — byte-identical to what
     it recorded before this PR, including its own now-superseded
     `invalid_policy_bundle` / `policy_bundle_invalid` values.
  2. The four corrected `v0.2.1` result artifacts use
     `failure_reason: policy_validation_failure` and no longer use
     `invalid_policy_bundle` anywhere, and the removed `reason_code:
     policy_bundle_invalid` is not replaced by any other reason code.
  3. Cross-artifact agreement within the corrected scenario: status,
     outcome, failure reason, and request/trace identity agree across the
     trace, response, audit-evidence, and gateway-audit-event artifacts.
  4. Gateway enforcement remains `deny`; kernel `outcome` remains `null`.
  5. The duplicate `rule_id` defect (`allow-duplicate-rule`) is still
     present in `invalid-policy-bundle.yaml` — the scenario's defect is
     unchanged, only its documented failure classification is corrected.
  6. The other four scenarios (`allow-basic`, `deny-precedence`,
     `default-deny`, `not-applicable`) are byte-identical between `v0.2.0`
     and `v0.2.1`.
  7. Every vendored YAML file in the `v0.2.1` snapshot parses.

This module does not assert anything about `basis-core` evaluator/engine
behavior (that remains PR 28's scope, not this PR's) and does not treat
`expected-gateway-audit-event.yaml` as a kernel-owned artifact (see
`tests/fixtures/basis-schemas/v0.2.0/README.md`'s "Kernel-owned vs.
gateway-only artifacts" section, which still applies unchanged).

Cross-references
─────────────────
tests/fixtures/basis-schemas/v0.2.1/README.md — what changed and why.
docs/implementation/basis-core-v0.2-operation-aware-plan.md — PR 27B's
    "Known upstream conflict" note, updated by this PR to record the
    reconciliation as complete in `v0.2.1`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

_FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "basis-schemas"
_V0_2_0 = _FIXTURES_ROOT / "v0.2.0"
_V0_2_1 = _FIXTURES_ROOT / "v0.2.1"

_UNCHANGED_SCENARIOS = ("allow-basic", "deny-precedence", "default-deny", "not-applicable")

_CORRECTED_SCENARIO = "invalid-policy-bundle"
_CORRECTED_RESULT_ARTIFACTS = (
    "expected-evaluation-trace.yaml",
    "expected-operation-aware-decision-response.yaml",
    "expected-audit-evidence.yaml",
    "expected-gateway-audit-event.yaml",
)

# The v0.2.0 SHA-256 digests recorded in tests/fixtures/basis-schemas/v0.2.0/
# manifest.json for the five files v0.2.1 corrects, captured at the time
# this vendoring PR began. Hardcoded independently of that manifest so an
# accidental edit to *both* the file and the historical manifest entry would
# still be caught here.
_V0_2_0_CORRECTED_SCENARIO_DIGESTS = {
    "expected-audit-evidence.yaml": (
        "f89a8725bacb9161d2f69c218e9ff7d304e2ad36df72fd5613783f9cb8fd87f3"
    ),
    "expected-evaluation-trace.yaml": (
        "aac753d87034dfb495238028c59ba52bbb9bb66c6e2fae8eac649f5c23850aab"
    ),
    "expected-gateway-audit-event.yaml": (
        "2a681aa94f50ba85b753076cab904050c8e3d8e8489ee3f234943bb585d29073"
    ),
    "expected-operation-aware-decision-response.yaml": (
        "2dbe4950df33087782489401cbe1a21947fe02830dfa990ec9388ace2685d2a8"
    ),
    "invalid-policy-bundle.yaml": (
        "39f5368cfe057b019ed46866591b8a585816aff7967f848801fa63d3d05bf250"
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ── 1. Historical v0.2.0 snapshot is untouched ──────────────────────────


class TestHistoricalV0_2_0SnapshotUnchanged:
    def test_v0_2_0_directory_still_exists(self) -> None:
        assert _V0_2_0.is_dir(), f"Historical snapshot removed: {_V0_2_0}"

    def test_v0_2_0_manifest_still_declares_v0_2_0_provenance(self) -> None:
        import json

        manifest = json.loads((_V0_2_0 / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["source_release"] == "v0.2.0"
        assert manifest["source_commit"] == "1d3af3cfd38686173980cfb47f8fa44659a4e1c4"

    def test_v0_2_0_corrected_scenario_files_are_byte_identical_to_before_this_pr(self) -> None:
        scenario_dir = _V0_2_0 / "compatibility" / _CORRECTED_SCENARIO
        mismatches = []
        for filename, expected_digest in _V0_2_0_CORRECTED_SCENARIO_DIGESTS.items():
            actual_digest = _sha256(scenario_dir / filename)
            if actual_digest != expected_digest:
                mismatches.append((filename, expected_digest, actual_digest))
        assert not mismatches, (
            f"v0.2.0/compatibility/{_CORRECTED_SCENARIO}/ file(s) changed since before this "
            f"PR (v0.2.0 must remain immutable): {mismatches}"
        )

    def test_v0_2_0_still_carries_the_superseded_classification(self) -> None:
        """v0.2.0's own copy must still say what it always said — proving
        this PR corrected only the new v0.2.1 sibling, not the historical
        snapshot."""
        trace_text = (
            _V0_2_0 / "compatibility" / _CORRECTED_SCENARIO / "expected-evaluation-trace.yaml"
        ).read_text(encoding="utf-8")
        assert "invalid_policy_bundle" in trace_text
        assert "policy_bundle_invalid" in trace_text


# ── 2 & 3 & 4. Corrected v0.2.1 artifacts: value, cross-artifact agreement ─


class TestCorrectedArtifactsUseNewFailureReason:
    def test_all_four_result_artifacts_use_policy_validation_failure(self) -> None:
        scenario_dir = _V0_2_1 / "compatibility" / _CORRECTED_SCENARIO
        for filename in _CORRECTED_RESULT_ARTIFACTS:
            parsed = _load_yaml(scenario_dir / filename)
            assert parsed["failure_reason"] == "policy_validation_failure", (
                f"{filename}: failure_reason={parsed.get('failure_reason')!r}, "
                "expected 'policy_validation_failure'"
            )

    def test_no_corrected_artifact_field_value_is_invalid_policy_bundle(self) -> None:
        """Checks parsed field *values*, not prose. The upstream v0.2.1
        rewrite of expected-evaluation-trace.yaml's explanatory comment
        legitimately mentions `invalid_policy_bundle` in prose (contrasting
        it with the corrected `policy_validation_failure` classification) —
        that is expected commentary, not a residual field value, and is not
        what this PR (or upstream's correction) needed to remove. See
        test_policy_bundle_invalid_string_not_present_in_any_corrected_artifact
        below for the reason_code case, which upstream did fully remove."""
        scenario_dir = _V0_2_1 / "compatibility" / _CORRECTED_SCENARIO
        offenders = []
        for filename in _CORRECTED_RESULT_ARTIFACTS:
            parsed = _load_yaml(scenario_dir / filename)
            if parsed.get("failure_reason") == "invalid_policy_bundle":
                offenders.append(filename)
        assert not offenders, (
            f"v0.2.1 corrected artifact(s) still set failure_reason: invalid_policy_bundle: "
            f"{offenders}"
        )

    def test_removed_reason_code_is_not_replaced_by_any_other_reason_code(self) -> None:
        """v0.2.1 removes reason_code: policy_bundle_invalid outright — no
        replacement reason code is invented, upstream or here."""
        scenario_dir = _V0_2_1 / "compatibility" / _CORRECTED_SCENARIO
        offenders = []
        for filename in _CORRECTED_RESULT_ARTIFACTS:
            parsed = _load_yaml(scenario_dir / filename)
            if "reason_code" in parsed:
                offenders.append((filename, parsed["reason_code"]))
        assert not offenders, (
            f"v0.2.1 corrected artifact(s) unexpectedly carry a reason_code: {offenders}"
        )

    def test_policy_bundle_invalid_string_not_present_in_any_corrected_artifact(self) -> None:
        scenario_dir = _V0_2_1 / "compatibility" / _CORRECTED_SCENARIO
        offenders = []
        for filename in _CORRECTED_RESULT_ARTIFACTS:
            text = (scenario_dir / filename).read_text(encoding="utf-8")
            if "policy_bundle_invalid" in text:
                offenders.append(filename)
        assert not offenders, (
            f"v0.2.1 corrected artifact(s) still reference policy_bundle_invalid: {offenders}"
        )


class TestCrossArtifactAgreementInCorrectedScenario:
    def _load_all(self) -> dict[str, Any]:
        scenario_dir = _V0_2_1 / "compatibility" / _CORRECTED_SCENARIO
        return {
            "request": _load_yaml(scenario_dir / "operation-aware-decision-request.yaml"),
            "bundle": _load_yaml(scenario_dir / "invalid-policy-bundle.yaml"),
            "trace": _load_yaml(scenario_dir / "expected-evaluation-trace.yaml"),
            "response": _load_yaml(
                scenario_dir / "expected-operation-aware-decision-response.yaml"
            ),
            "audit": _load_yaml(scenario_dir / "expected-audit-evidence.yaml"),
            "gateway": _load_yaml(scenario_dir / "expected-gateway-audit-event.yaml"),
        }

    def test_evaluation_status_failed_across_trace_response_audit_gateway(self) -> None:
        artifacts = self._load_all()
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["evaluation_status"] == "failed", (
                f"{name}: evaluation_status={artifacts[name].get('evaluation_status')!r}"
            )

    def test_outcome_null_across_trace_response_gateway(self) -> None:
        artifacts = self._load_all()
        for name in ("trace", "response", "gateway"):
            assert artifacts[name]["outcome"] is None, (
                f"{name}: outcome={artifacts[name].get('outcome')!r}, expected null"
            )

    def test_failure_reason_agrees_across_trace_response_audit_gateway(self) -> None:
        artifacts = self._load_all()
        names = ("trace", "response", "audit", "gateway")
        values = {name: artifacts[name]["failure_reason"] for name in names}
        assert len(set(values.values())) == 1, f"failure_reason disagreement: {values}"
        assert next(iter(values.values())) == "policy_validation_failure"

    def test_request_id_agrees_across_all_artifacts(self) -> None:
        artifacts = self._load_all()
        request_id = artifacts["request"]["request_id"]
        for name in ("trace", "response", "audit", "gateway"):
            assert artifacts[name]["request_id"] == request_id, (
                f"{name}: request_id={artifacts[name].get('request_id')!r}, expected {request_id!r}"
            )

    def test_trace_id_agrees_across_trace_audit_gateway(self) -> None:
        artifacts = self._load_all()
        trace_id = artifacts["trace"]["trace_id"]
        for name in ("audit", "gateway"):
            key = "trace_id"
            assert artifacts[name][key] == trace_id, (
                f"{name}: trace_id={artifacts[name].get(key)!r}, expected {trace_id!r}"
            )
        assert artifacts["response"]["trace_id"] == trace_id

    def test_gateway_enforcement_action_is_deny(self) -> None:
        artifacts = self._load_all()
        assert artifacts["gateway"]["enforcement_action"] == "deny"

    def test_bundle_still_declares_duplicate_rule_id_defect(self) -> None:
        artifacts = self._load_all()
        rule_ids = [rule["rule_id"] for rule in artifacts["bundle"]["rules"]]
        assert len(rule_ids) == len(artifacts["bundle"]["rules"])
        assert len(rule_ids) != len(set(rule_ids)), (
            f"Expected a duplicate rule_id defect; got unique ids: {rule_ids}"
        )
        assert rule_ids.count("allow-duplicate-rule") >= 2, (
            f"Expected 'allow-duplicate-rule' to repeat; got: {rule_ids}"
        )


# ── 5. The other four scenarios are unchanged between v0.2.0 and v0.2.1 ───


class TestUnchangedScenariosAreByteIdenticalAcrossVersions:
    def test_every_unchanged_scenario_artifact_matches_byte_for_byte(self) -> None:
        mismatches = []
        for scenario in _UNCHANGED_SCENARIOS:
            v0_dir = _V0_2_0 / "compatibility" / scenario
            v1_dir = _V0_2_1 / "compatibility" / scenario
            filenames = sorted(p.name for p in v0_dir.iterdir() if p.is_file())
            for filename in filenames:
                if _sha256(v0_dir / filename) != _sha256(v1_dir / filename):
                    mismatches.append(f"{scenario}/{filename}")
        assert not mismatches, f"Unexpected drift in unchanged scenario(s): {mismatches}"

    def test_all_fourteen_schema_contracts_match_byte_for_byte(self) -> None:
        mismatches = []
        v0_root = _V0_2_0 / "schemas"
        v1_root = _V0_2_1 / "schemas"
        for contract_dir in sorted(p for p in v0_root.iterdir() if p.is_dir()):
            filename = f"{contract_dir.name}.yaml"
            if _sha256(contract_dir / filename) != _sha256(v1_root / contract_dir.name / filename):
                mismatches.append(contract_dir.name)
        assert not mismatches, f"Unexpected schema contract drift: {mismatches}"


# ── 6. Every vendored YAML file in v0.2.1 parses ───────────────────────────


class TestAllVendoredYamlParsesInV0_2_1:
    def test_every_schema_yaml_parses(self) -> None:
        failures = []
        for path in sorted((_V0_2_1 / "schemas").rglob("*.yaml")):
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
        for path in sorted((_V0_2_1 / "compatibility").rglob("*.yaml")):
            try:
                parsed = _load_yaml(path)
            except yaml.YAMLError as exc:
                failures.append((str(path), str(exc)))
                continue
            if not isinstance(parsed, dict):
                failures.append((str(path), f"parsed as {type(parsed).__name__}, expected dict"))
        assert not failures, f"Compatibility YAML parse failure(s): {failures}"
