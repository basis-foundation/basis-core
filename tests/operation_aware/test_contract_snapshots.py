"""
tests/operation_aware/test_contract_snapshots.py — compatibility-snapshot
scaffolding for the operation-aware model family (Milestone 3, PR 11 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Compatibility-snapshot scaffolding for operation-aware models").

This module establishes the first governed serialization snapshot for
`basis_core.decisions.operation_aware.OperationAwareDecisionRequest`,
mirroring the existing v0.1.0 pattern in `tests/test_contract_snapshots.py`
and `tests/helpers/contracts.py`: construct a model instance with fully
deterministic values, serialize it, and compare the result against a stored
JSON fixture. If the serialized shape drifts — a field renamed, removed, or
retyped — this test fails with a visible diff.

Deliberately separate from the v0.1.0 snapshot fixtures
─────────────────────────────────────────────────────────
The operation-aware model family is additive (see
`src/basis_core/decisions/operation_aware.py`'s module docstring). Its
compatibility fixture is stored under its own, clearly separated directory,
`tests/fixtures/contracts/operation_aware/`, never mixed with the existing
v0.1.0 `tests/fixtures/contracts/*.json` files that
`tests/test_contract_snapshots.py` protects. This module does not read,
write, or otherwise touch any v0.1.0 fixture, and `tests/test_contract_snapshots.py`
is not modified by this PR.

Not a tautological round-trip test
────────────────────────────────────
`tests/operation_aware/test_decision_request_roundtrip.py` (PR 9) already
proves fixture -> model -> JSON -> model round trips for every vendored
example. This module's job is different: it independently constructs the
request from production model code (not by loading and re-validating the
committed fixture) and asserts that construction's
`model_dump(mode="json")` output exactly equals the parsed fixture. The
fixture and the model-construction code are two independently reviewable
representations of the expected compatibility shape — this is what makes
the test able to catch silent serialization drift rather than merely
confirming the fixture is internally consistent.

Serialization call
───────────────────
Every comparison in this module uses `model_dump(mode="json")` directly —
never the bare `model_dump()`, and never a custom serializer or JSON
encoder — because the compatibility surface this snapshot protects is the
model's JSON-compatible serialized data (matching the convention already
established by PR 9's `test_decision_request_roundtrip.py`).

Snapshot subject
─────────────────
This PR snapshots only `OperationAwareDecisionRequest`, using one
deterministic, full-surface request that populates every currently
implemented field (including every PR 6 evidence-reference model and every
PR 7 context value object) so the fixture protects the complete, currently
governed compatibility surface. `RedactionClassification`,
`ReasonCode`, `IdentityEvidenceReference`, `AdapterEvidenceReference`, and
the six `OperationAware*Context`/`OperationAwareLocation`/
`OperationAwareDevice` types are exercised only as nested nodes of this one
request snapshot, not as separate top-level fixtures — those types are
already represented within the complete request shape. No policy, trace,
audit, or response model is snapshotted here; those models do not yet exist
in `basis-core` (later, separately-scoped roadmap PRs).

How to update this fixture deliberately
──────────────────────────────────────────
If you have made an intentional, reviewed additive change to
`OperationAwareDecisionRequest` (or a nested PR 6/PR 7 model) and need to
update the fixture:

    1. Run this test to see the field diff.
    2. If the change is additive and reviewed, update
       `tests/fixtures/contracts/operation_aware/operation_aware_decision_request.json`
       manually — never regenerate it with a script or test-time update mode.
    3. Commit the fixture change alongside the model change so the diff is
       visible in code review.

Breaking changes (field removal, rename, type change, required field
addition) require architecture review per `docs/schema-versioning.md`
before the fixture is updated — the same discipline
`tests/test_contract_snapshots.py` already follows for the v0.1.0 surface.

Cross-references
────────────────
docs/compatibility-testing.md         — overview of the v0.1.0 harness this
                                         module's pattern is mirrored from.
docs/schema-versioning.md             — breaking vs. additive change
                                         definitions.
docs/implementation/basis-core-v0.2-operation-aware-plan.md — PR 11 entry.
tests/test_contract_snapshots.py      — the v0.1.0 pattern this mirrors.
tests/operation_aware/test_decision_request_roundtrip.py — PR 9's exhaustive
                                         fixture round-trip coverage (a
                                         different guarantee than this
                                         module's; see above).
tests/operation_aware/test_contract_conformance.py — PR 10's exhaustive
                                         vendored-contract conformance (a
                                         different guarantee than this
                                         module's; see above).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest, OperationIntent
from basis_core.domain.evidence import (
    AdapterEvidenceReference,
    EvidenceDigest,
    IdentityEvidenceReference,
)
from basis_core.domain.operation_aware import (
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from basis_core.domain.operation_aware_vocabulary import RedactionClassification

# ---------------------------------------------------------------------------
# Fixture location — deliberately separate from tests/helpers/contracts.py's
# FIXTURES_DIR (tests/fixtures/contracts/), which protects only the v0.1.0
# fixtures. This module reads exclusively from its own
# tests/fixtures/contracts/operation_aware/ subdirectory.
# ---------------------------------------------------------------------------

_OPERATION_AWARE_FIXTURES_DIR = (
    Path(__file__).parent.parent / "fixtures" / "contracts" / "operation_aware"
)
_V01_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "contracts"

_REQUEST_FIXTURE_NAME = "operation_aware_decision_request"
_REQUEST_FIXTURE_PATH = _OPERATION_AWARE_FIXTURES_DIR / f"{_REQUEST_FIXTURE_NAME}.json"


def _load_fixture_text() -> str:
    """Read the raw fixture file text (used by the JSON-validity test)."""
    return _REQUEST_FIXTURE_PATH.read_text(encoding="utf-8")


def _load_fixture() -> dict[str, Any]:
    """Load and parse the committed `OperationAwareDecisionRequest` fixture."""
    return json.loads(_load_fixture_text())


# ---------------------------------------------------------------------------
# Deterministic, fully-populated request — fixed synthetic identifiers and a
# fixed, timezone-aware timestamp. No uuid.uuid4(), datetime.now()/utcnow(),
# date.today(), random, secrets, environment variables, system time, network
# data, or filesystem-derived values anywhere in this construction.
# ---------------------------------------------------------------------------

_EVALUATION_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _build_full_surface_request() -> OperationAwareDecisionRequest:
    """
    Independently construct a deterministic, full-surface
    `OperationAwareDecisionRequest` directly from production model code.

    "Independently" is the operative word: this function does not read
    `_REQUEST_FIXTURE_PATH` or any other stored fixture. It is a second,
    independently reviewable representation of the expected compatibility
    shape, built only from the current `OperationAwareDecisionRequest`,
    `IdentityEvidenceReference`, `AdapterEvidenceReference`, and PR 7
    context-object constructors — matching this PR's requirement that the
    snapshot test protect against silent serialization drift rather than
    merely proving the fixture can round-trip through the model that
    produced it.

    Every currently implemented request field is populated so the
    committed fixture protects the complete serialized shape: request
    identity/correlation, subject identity and attributes, identity
    evidence, action/resource targeting, location and device context,
    protocol evidence and operation intent, adapter evidence, safety/
    environment/risk context, the evaluation timestamp, and the expected
    policy version.
    """
    return OperationAwareDecisionRequest(
        request_id="snapshot-request-0001",
        correlation_id="snapshot-correlation-0001",
        subject_id="snapshot-subject-0001",
        subject_roles=["operator", "supervisor"],
        subject_attrs={"department": "facilities", "shift": "day"},
        identity_source="snapshot-identity-source",
        authority_mode="federated",
        identity_evidence_reference=IdentityEvidenceReference(
            reference_id="snapshot-identity-evidence-0001",
            evidence_digest=EvidenceDigest(algorithm="sha-256", value="a1b2c3d4e5f6"),
            identity_source="snapshot-identity-source",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
            normalization_version="snapshot-normalization-v1",
            mapping_version="snapshot-mapping-v1",
            request_id="snapshot-request-0001",
            correlation_id="snapshot-correlation-0001",
        ),
        action="write:hvac:setpoint",
        resource="hvac:zone-a",
        resource_type="hvac",
        location=OperationAwareLocation(
            site_id="snapshot-site-0001",
            building_id="snapshot-building-0001",
            zone_id="snapshot-zone-0001",
            area_id="snapshot-area-0001",
        ),
        device=OperationAwareDevice(
            device_id="snapshot-device-0001",
            device_class="controller",
        ),
        protocol_context=OperationAwareProtocolContext(
            protocol="bacnet",
            operation="writeProperty",
        ),
        operation_intent=OperationIntent.STATE_CHANGING,
        adapter_evidence_reference=AdapterEvidenceReference(
            reference_id="snapshot-adapter-evidence-0001",
            evidence_digest=EvidenceDigest(algorithm="sha-256", value="0123456789ab"),
            adapter_source="snapshot-adapter-source",
            redaction_classification=RedactionClassification.SAFE_AFTER_REDACTION,
            normalization_version="snapshot-normalization-v1",
            mapping_version="snapshot-mapping-v1",
            protocol="bacnet",
            request_id="snapshot-request-0001",
            correlation_id="snapshot-correlation-0001",
        ),
        safety_context=OperationAwareSafetyContext(
            mode="interlock-engaged",
            classification="elevated",
            constraint_ids=["snapshot-constraint-0001", "snapshot-constraint-0002"],
        ),
        environment_context=OperationAwareEnvironmentContext(
            mode="maintenance_mode",
            condition_ids=["snapshot-condition-0001"],
        ),
        risk_context=OperationAwareRiskContext(
            classification="elevated",
            score=0.62,
        ),
        evaluation_time=_EVALUATION_TIME,
        expected_policy_version="snapshot-policy-v1",
    )


# Every currently implemented top-level field on OperationAwareDecisionRequest.
_EXPECTED_TOP_LEVEL_FIELDS = frozenset(
    {
        "request_id",
        "correlation_id",
        "subject_id",
        "subject_roles",
        "subject_attrs",
        "identity_source",
        "authority_mode",
        "identity_evidence_reference",
        "action",
        "resource",
        "resource_type",
        "location",
        "device",
        "protocol_context",
        "operation_intent",
        "adapter_evidence_reference",
        "safety_context",
        "environment_context",
        "risk_context",
        "evaluation_time",
        "expected_policy_version",
    }
)


# ---------------------------------------------------------------------------
# Directory and fixture scaffolding
# ---------------------------------------------------------------------------


class TestOperationAwareSnapshotScaffolding:
    """The operation-aware snapshot directory and fixture exist, separate
    from the v0.1.0 fixture tree."""

    def test_operation_aware_fixture_directory_exists(self) -> None:
        assert _OPERATION_AWARE_FIXTURES_DIR.is_dir(), (
            f"Expected snapshot fixture directory not found: {_OPERATION_AWARE_FIXTURES_DIR}"
        )

    def test_request_fixture_file_exists(self) -> None:
        assert _REQUEST_FIXTURE_PATH.is_file(), (
            f"Expected OperationAwareDecisionRequest snapshot fixture not found: "
            f"{_REQUEST_FIXTURE_PATH}"
        )

    def test_fixture_contains_valid_json(self) -> None:
        parsed = json.loads(_load_fixture_text())
        assert isinstance(parsed, dict), (
            f"Fixture {_REQUEST_FIXTURE_PATH} must parse as a JSON object (dict), "
            f"got {type(parsed).__name__}."
        )

    def test_fixture_lives_only_beneath_operation_aware_subdirectory(self) -> None:
        """The new fixture is stored only under
        tests/fixtures/contracts/operation_aware/ — never directly beside
        the existing v0.1.0 JSON files in tests/fixtures/contracts/."""
        top_level_names = {p.name for p in _V01_FIXTURES_DIR.glob("*.json")}
        assert f"{_REQUEST_FIXTURE_NAME}.json" not in top_level_names, (
            "The operation-aware request fixture must not be placed directly "
            "under tests/fixtures/contracts/ — it belongs only in the "
            "operation_aware/ subdirectory."
        )
        assert _REQUEST_FIXTURE_PATH.parent == _OPERATION_AWARE_FIXTURES_DIR


# ---------------------------------------------------------------------------
# OperationAwareDecisionRequest snapshot
# ---------------------------------------------------------------------------


class TestOperationAwareDecisionRequestSnapshot:
    """Serialization shape of `OperationAwareDecisionRequest` must match the
    stored, independently-constructed fixture exactly."""

    def test_independently_constructed_request_matches_fixture(self) -> None:
        """The core PR 11 guarantee: a request built directly from
        production model code — never by loading and re-validating the
        stored fixture — serializes with `model_dump(mode="json")` to
        exactly the parsed fixture. This is what makes the test able to
        catch silent serialization drift rather than merely proving the
        fixture round-trips through the model that produced it."""
        request = _build_full_surface_request()
        actual = request.model_dump(mode="json")
        expected = _load_fixture()

        if actual != expected:
            all_keys = sorted(set(actual) | set(expected))
            diffs = [
                f"  {key!r}: actual={actual.get(key, '<missing>')!r}, "
                f"expected={expected.get(key, '<missing>')!r}"
                for key in all_keys
                if actual.get(key, "<missing>") != expected.get(key, "<missing>")
            ]
            diff_text = "\n".join(diffs) if diffs else "  (structural difference — check nesting)"
            raise AssertionError(
                "OperationAwareDecisionRequest.model_dump(mode='json') does not match "
                f"the committed snapshot fixture {_REQUEST_FIXTURE_PATH}.\n"
                f"Field differences:\n{diff_text}"
            )

    def test_fixture_validates_back_into_model(self) -> None:
        """The committed fixture is not just JSON — it validates back into
        `OperationAwareDecisionRequest` without error."""
        expected = _load_fixture()
        restored = OperationAwareDecisionRequest.model_validate(expected)
        assert type(restored) is OperationAwareDecisionRequest

    def test_reserialization_matches_original_fixture_structure(self) -> None:
        """Reconstructing the model from the fixture and re-serializing it
        reproduces the exact same fixture structure — the snapshot is
        stable under a validate -> dump cycle, not just a one-way dump."""
        expected = _load_fixture()
        restored = OperationAwareDecisionRequest.model_validate(expected)
        reserialized = restored.model_dump(mode="json")
        assert reserialized == expected

    def test_all_currently_implemented_fields_present(self) -> None:
        """Every field currently implemented on
        `OperationAwareDecisionRequest` is represented in the fixture — this
        is a full-surface snapshot, not a minimal three-field example."""
        fixture = _load_fixture()
        assert set(fixture.keys()) == _EXPECTED_TOP_LEVEL_FIELDS, (
            f"Fixture field set has changed.\n"
            f"  Extra:   {set(fixture.keys()) - _EXPECTED_TOP_LEVEL_FIELDS}\n"
            f"  Missing: {_EXPECTED_TOP_LEVEL_FIELDS - set(fixture.keys())}"
        )


# ---------------------------------------------------------------------------
# Nested evidence-reference and context-object shapes
# ---------------------------------------------------------------------------


class TestNestedShapesInSnapshot:
    """The full-surface snapshot exercises PR 6's evidence-reference models
    and PR 7's context value objects as nested structures — proving they
    serialize to the expected nested JSON shape within the request, without
    duplicating PR 6/PR 7's own exhaustive field-level validation tests."""

    def test_identity_evidence_reference_shape(self) -> None:
        fixture = _load_fixture()
        nested = fixture["identity_evidence_reference"]
        assert isinstance(nested, dict)
        assert set(nested.keys()) == {
            "reference_id",
            "evidence_digest",
            "identity_source",
            "redaction_classification",
            "normalization_version",
            "mapping_version",
            "request_id",
            "correlation_id",
        }
        assert nested["evidence_digest"] == {"algorithm": "sha-256", "value": "a1b2c3d4e5f6"}
        assert nested["redaction_classification"] == "reference_only"

    def test_adapter_evidence_reference_shape(self) -> None:
        fixture = _load_fixture()
        nested = fixture["adapter_evidence_reference"]
        assert isinstance(nested, dict)
        assert set(nested.keys()) == {
            "reference_id",
            "evidence_digest",
            "adapter_source",
            "redaction_classification",
            "normalization_version",
            "mapping_version",
            "protocol",
            "request_id",
            "correlation_id",
        }
        assert nested["evidence_digest"] == {"algorithm": "sha-256", "value": "0123456789ab"}
        assert nested["redaction_classification"] == "safe_after_redaction"

    def test_location_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["location"] == {
            "site_id": "snapshot-site-0001",
            "building_id": "snapshot-building-0001",
            "zone_id": "snapshot-zone-0001",
            "area_id": "snapshot-area-0001",
        }

    def test_device_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["device"] == {
            "device_id": "snapshot-device-0001",
            "device_class": "controller",
        }

    def test_protocol_context_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["protocol_context"] == {
            "protocol": "bacnet",
            "operation": "writeProperty",
        }

    def test_safety_context_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["safety_context"] == {
            "mode": "interlock-engaged",
            "classification": "elevated",
            "constraint_ids": ["snapshot-constraint-0001", "snapshot-constraint-0002"],
        }

    def test_environment_context_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["environment_context"] == {
            "mode": "maintenance_mode",
            "condition_ids": ["snapshot-condition-0001"],
        }

    def test_risk_context_shape(self) -> None:
        fixture = _load_fixture()
        assert fixture["risk_context"] == {
            "classification": "elevated",
            "score": 0.62,
        }


# ---------------------------------------------------------------------------
# Enum and datetime serialization
# ---------------------------------------------------------------------------


class TestEnumAndDatetimeSerialization:
    def test_operation_intent_serializes_as_contract_string(self) -> None:
        fixture = _load_fixture()
        assert fixture["operation_intent"] == "state_changing"
        assert isinstance(fixture["operation_intent"], str)

    def test_redaction_classification_serializes_as_contract_string(self) -> None:
        fixture = _load_fixture()
        assert fixture["identity_evidence_reference"]["redaction_classification"] == (
            "reference_only"
        )
        assert fixture["adapter_evidence_reference"]["redaction_classification"] == (
            "safe_after_redaction"
        )

    def test_evaluation_time_serializes_as_fixed_timezone_aware_string(self) -> None:
        fixture = _load_fixture()
        assert fixture["evaluation_time"] == "2026-01-15T12:00:00Z"

        # Confirm this is exactly what the current model produces for the
        # fixed construction-time value, rather than a hand-picked string
        # that happens to look plausible.
        request = _build_full_surface_request()
        assert request.model_dump(mode="json")["evaluation_time"] == fixture["evaluation_time"]


# ---------------------------------------------------------------------------
# Existing v0.1.0 fixtures remain untouched by this additive PR
# ---------------------------------------------------------------------------


class TestV01FixturesUnaffected:
    """PR 11 is additive: it must not modify, rename, reformat, or remove
    any existing v0.1.0 snapshot fixture."""

    _EXPECTED_V01_FIXTURES = frozenset(
        {
            "audit_event.allow",
            "audit_event.deny",
            "decision_request.allow",
            "decision_request.deny",
            "decision_response.allow",
            "decision_response.deny",
            "decision_response.fail_closed",
            "evaluation_trace.allow",
            "evaluation_trace.deny",
        }
    )

    def test_v01_fixture_inventory_unchanged(self) -> None:
        """The top-level tests/fixtures/contracts/ directory (non-recursive)
        still contains exactly the pre-existing v0.1.0 fixture set — the new
        operation-aware fixture lives one level deeper and does not appear
        in this listing."""
        actual = frozenset(p.stem for p in _V01_FIXTURES_DIR.glob("*.json"))
        assert actual == self._EXPECTED_V01_FIXTURES, (
            f"tests/fixtures/contracts/ top-level fixture inventory changed.\n"
            f"  Added:   {actual - self._EXPECTED_V01_FIXTURES}\n"
            f"  Removed: {self._EXPECTED_V01_FIXTURES - actual}"
        )
