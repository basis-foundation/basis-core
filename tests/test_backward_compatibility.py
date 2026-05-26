"""
tests/test_backward_compatibility.py — backward compatibility regression tests.

These tests verify two complementary guarantees:

1. **Old records stay valid.** Stored JSON fixtures (representing records
   produced by earlier code) are still valid against the current JSON schemas
   and can be deserialized by the current Python models. A fixture that can no
   longer be loaded is evidence of a breaking change.

2. **Round-trip stability.** Deserializing a fixture into a model and
   re-serializing it produces JSON that is schema-valid and structurally
   consistent with the original. If re-serialization drifts from the original,
   a field has changed its default, its serialization format, or its type
   coercion behavior.

Fixture sources
───────────────
Two fixture sources are tested:

  tests/fixtures/contracts/
      Contract snapshots created alongside the model code. These are the
      primary regression targets for model serialization stability.

  schemas/examples/
      Canonical schema-valid examples shipped with the JSON Schemas. These are
      validated by test_schema_validation.py against the schemas themselves; here
      they are additionally tested for round-trip stability through the Python
      models.

What a failure means
────────────────────
A failure in these tests is a signal that a compatibility-relevant change has
been made. Before updating a fixture to make a test pass, confirm the change is:

  - Additive (new optional field, new enum value) — generally safe.
  - Breaking (field removal, rename, type change) — requires architecture review
    and ADR per docs/schema-versioning.md before the fixture may be updated.

Cross-references
────────────────
docs/compatibility-testing.md   — overview of the full harness and update workflow.
docs/schema-versioning.md       — breaking vs. additive change definitions.
docs/kernel-constitution.md     — Invariant 9: compatibility is a public contract.
tests/test_contract_snapshots.py — companion test for model serialization shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from basis_core.audit.events import AuditEvent
from basis_core.audit.trace import DecisionTrace
from basis_core.decisions.models import DecisionRequest, DecisionResponse
from tests.helpers.contracts import (
    load_fixture,
)

try:
    from jsonschema import Draft202012Validator, FormatChecker

    JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    JSONSCHEMA_AVAILABLE = False

SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
SCHEMA_EXAMPLES_DIR = SCHEMAS_DIR / "examples"


def _load_schema(name: str) -> dict:  # type: ignore[type-arg]
    """Load a JSON Schema by base name (without .schema.json suffix)."""
    path = SCHEMAS_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_validate(instance: object, schema: dict) -> None:  # type: ignore[type-arg]
    """Validate instance against schema; skip if jsonschema is not installed."""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(instance)


# ---------------------------------------------------------------------------
# Contract fixture → schema validation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not JSONSCHEMA_AVAILABLE,
    reason="jsonschema not installed; add 'jsonschema[format-nongpl]>=4.18' to dev deps",
)
class TestContractFixturesValidateAgainstSchemas:
    """Stored contract fixtures must remain valid against the current JSON Schemas."""

    def test_decision_request_allow_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("decision-request")
        _schema_validate(load_fixture("decision_request.allow"), schema)

    def test_decision_request_deny_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("decision-request")
        _schema_validate(load_fixture("decision_request.deny"), schema)

    def test_decision_response_allow_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("decision-response")
        _schema_validate(load_fixture("decision_response.allow"), schema)

    def test_decision_response_deny_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("decision-response")
        _schema_validate(load_fixture("decision_response.deny"), schema)

    def test_audit_event_allow_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("audit-event")
        _schema_validate(load_fixture("audit_event.allow"), schema)

    def test_audit_event_deny_fixture_is_schema_valid(self) -> None:
        schema = _load_schema("audit-event")
        _schema_validate(load_fixture("audit_event.deny"), schema)


# ---------------------------------------------------------------------------
# Contract fixture → model deserialization
# ---------------------------------------------------------------------------


class TestContractFixturesDeserializeIntoModels:
    """Stored contract fixtures must be loadable by the current Python models."""

    def test_decision_request_allow_fixture_deserializes(self) -> None:
        """The allow fixture round-trips through DecisionRequest without error."""
        fixture = load_fixture("decision_request.allow")
        req = DecisionRequest.model_validate(fixture)
        assert req.request_id == fixture["request_id"]
        assert req.action == fixture["action"]
        assert req.resource_id == fixture["resource_id"]

    def test_decision_request_deny_fixture_deserializes(self) -> None:
        fixture = load_fixture("decision_request.deny")
        req = DecisionRequest.model_validate(fixture)
        assert req.request_id == fixture["request_id"]
        assert req.subject_roles == fixture["subject_roles"]

    def test_decision_response_allow_fixture_deserializes(self) -> None:
        fixture = load_fixture("decision_response.allow")
        resp = DecisionResponse.model_validate(fixture)
        assert resp.outcome.value == "allow"
        assert resp.failure_reason is None

    def test_decision_response_deny_fixture_deserializes(self) -> None:
        fixture = load_fixture("decision_response.deny")
        resp = DecisionResponse.model_validate(fixture)
        assert resp.outcome.value == "deny"
        assert resp.failure_reason is None

    def test_audit_event_allow_fixture_deserializes(self) -> None:
        fixture = load_fixture("audit_event.allow")
        event = AuditEvent.model_validate(fixture)
        assert event.schema_version == "1.1"
        assert event.outcome is not None
        assert event.outcome.value == "allowed"
        assert event.trace is not None
        assert event.trace.final_outcome == "allow"
        assert event.trace.short_circuited is False

    def test_audit_event_deny_fixture_deserializes(self) -> None:
        fixture = load_fixture("audit_event.deny")
        event = AuditEvent.model_validate(fixture)
        assert event.schema_version == "1.1"
        assert event.outcome is not None
        assert event.outcome.value == "denied"
        assert event.trace is not None
        assert event.trace.final_outcome == "deny"
        assert event.trace.short_circuited is True

    def test_evaluation_trace_allow_fixture_deserializes(self) -> None:
        fixture = load_fixture("evaluation_trace.allow")
        trace = DecisionTrace.model_validate(fixture)
        assert trace.final_outcome == "allow"
        assert len(trace.evaluated_rules) == 2
        assert trace.short_circuited is False

    def test_evaluation_trace_deny_fixture_deserializes(self) -> None:
        fixture = load_fixture("evaluation_trace.deny")
        trace = DecisionTrace.model_validate(fixture)
        assert trace.final_outcome == "deny"
        assert len(trace.evaluated_rules) == 1
        assert trace.short_circuited is True


# ---------------------------------------------------------------------------
# Contract fixture → round-trip stability
# ---------------------------------------------------------------------------


class TestContractFixtureRoundTrips:
    """
    Deserialize fixture → re-serialize → compare key fields to fixture.

    Full structural equality is not required here (the snapshot tests in
    test_contract_snapshots.py cover exact shape). These tests confirm that the
    semantically significant fields survive a round-trip without coercion or
    silent mutation.
    """

    def _round_trip_decision_request(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        req = DecisionRequest.model_validate(fixture)
        reserialised = json.loads(req.model_dump_json())
        # Semantically critical fields must survive round-trip unchanged.
        assert reserialised["request_id"] == fixture["request_id"]
        assert reserialised["subject_id"] == fixture["subject_id"]
        assert reserialised["action"] == fixture["action"]
        assert reserialised["resource_id"] == fixture["resource_id"]
        assert reserialised["subject_roles"] == fixture["subject_roles"]

    def _round_trip_decision_response(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        resp = DecisionResponse.model_validate(fixture)
        reserialised = json.loads(resp.model_dump_json())
        assert reserialised["request_id"] == fixture["request_id"]
        assert reserialised["outcome"] == fixture["outcome"]
        assert reserialised["reason"] == fixture["reason"]
        assert reserialised["evaluated_by"] == fixture["evaluated_by"]
        assert reserialised["failure_reason"] == fixture["failure_reason"]

    def _round_trip_audit_event(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        event = AuditEvent.model_validate(fixture)
        reserialised = json.loads(event.model_dump_json())
        assert reserialised["event_id"] == fixture["event_id"]
        assert reserialised["schema_version"] == fixture["schema_version"]
        assert reserialised["outcome"] == fixture["outcome"]
        assert reserialised["action"] == fixture["action"]
        assert reserialised["subject_type"] == fixture["subject_type"]
        assert reserialised["trace"]["final_outcome"] == fixture["trace"]["final_outcome"]
        assert reserialised["trace"]["short_circuited"] == fixture["trace"]["short_circuited"]

    def test_decision_request_allow_round_trip(self) -> None:
        self._round_trip_decision_request("decision_request.allow")

    def test_decision_request_deny_round_trip(self) -> None:
        self._round_trip_decision_request("decision_request.deny")

    def test_decision_response_allow_round_trip(self) -> None:
        self._round_trip_decision_response("decision_response.allow")

    def test_decision_response_deny_round_trip(self) -> None:
        self._round_trip_decision_response("decision_response.deny")

    def test_audit_event_allow_round_trip(self) -> None:
        self._round_trip_audit_event("audit_event.allow")

    def test_audit_event_deny_round_trip(self) -> None:
        self._round_trip_audit_event("audit_event.deny")


# ---------------------------------------------------------------------------
# schemas/examples/ → round-trip through models
# ---------------------------------------------------------------------------


class TestSchemaExamplesRoundTripThroughModels:
    """
    The canonical schema examples must be deserializable by the current models.

    These files are the primary consumer-facing reference examples. If a model
    change causes them to fail deserialization, the model has diverged from the
    documented contract.
    """

    def test_schema_example_decision_request_deserializes(self) -> None:
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "decision-request.json").read_text())
        req = DecisionRequest.model_validate(raw)
        assert req.action == raw["action"]
        assert req.subject_id == raw["subject_id"]

    def test_schema_example_decision_response_deserializes(self) -> None:
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "decision-response.json").read_text())
        resp = DecisionResponse.model_validate(raw)
        assert resp.request_id == raw["request_id"]
        assert resp.outcome.value == raw["outcome"]

    def test_schema_example_audit_event_deserializes(self) -> None:
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "audit-event.json").read_text())
        event = AuditEvent.model_validate(raw)
        assert event.event_id == raw["event_id"]
        assert event.schema_version == "1.1"

    def test_schema_example_decision_request_round_trip_preserves_fields(self) -> None:
        """Key fields survive model → re-serialize unchanged."""
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "decision-request.json").read_text())
        req = DecisionRequest.model_validate(raw)
        reserialised = json.loads(req.model_dump_json())
        for field in ("request_id", "subject_id", "action", "resource_id"):
            assert reserialised[field] == raw[field], (
                f"Field {field!r} changed during round-trip: "
                f"{raw[field]!r} → {reserialised[field]!r}"
            )

    def test_schema_example_decision_response_round_trip_preserves_fields(self) -> None:
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "decision-response.json").read_text())
        resp = DecisionResponse.model_validate(raw)
        reserialised = json.loads(resp.model_dump_json())
        for field in ("request_id", "outcome", "reason", "evaluated_by"):
            assert reserialised[field] == raw[field], (
                f"Field {field!r} changed during round-trip: "
                f"{raw[field]!r} → {reserialised[field]!r}"
            )

    def test_schema_example_audit_event_round_trip_preserves_fields(self) -> None:
        raw = json.loads((SCHEMA_EXAMPLES_DIR / "audit-event.json").read_text())
        event = AuditEvent.model_validate(raw)
        reserialised = json.loads(event.model_dump_json())
        for field in ("event_id", "schema_version", "action", "outcome", "evaluated_by"):
            assert reserialised[field] == raw[field], (
                f"Field {field!r} changed during round-trip: "
                f"{raw[field]!r} → {reserialised[field]!r}"
            )


# ---------------------------------------------------------------------------
# Audit record immutability
# ---------------------------------------------------------------------------


class TestAuditEventImmutability:
    """
    AuditEvent instances are frozen (immutable once created).

    Immutability is a constitutional guarantee (Invariant 8). Records that can
    be mutated after construction cannot be trusted as evidence.
    """

    def test_audit_event_is_frozen(self) -> None:
        """Attempting to mutate a loaded AuditEvent raises an exception."""
        fixture = load_fixture("audit_event.allow")
        event = AuditEvent.model_validate(fixture)
        with pytest.raises(Exception):
            event.outcome = None  # type: ignore[misc]

    def test_audit_event_trace_is_frozen(self) -> None:
        """Nested DecisionTrace is also frozen."""
        fixture = load_fixture("audit_event.allow")
        event = AuditEvent.model_validate(fixture)
        assert event.trace is not None
        with pytest.raises(Exception):
            event.trace.final_outcome = "deny"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DecisionRequest / DecisionResponse mutability contract
# ---------------------------------------------------------------------------


class TestDecisionModelsMutability:
    """
    DecisionRequest and DecisionResponse are NOT frozen.

    This is an explicit contract (documented in docs/extension-contracts.md).
    Enforcement points and test helpers that construct or modify these objects
    before submission depend on this mutability.
    """

    def test_decision_request_is_not_frozen(self) -> None:
        """DecisionRequest fields can be updated after construction."""
        fixture = load_fixture("decision_request.allow")
        req = DecisionRequest.model_validate(fixture)
        # Should not raise.
        req.context = {"key": "value"}
        assert req.context == {"key": "value"}

    def test_decision_response_is_not_frozen(self) -> None:
        """DecisionResponse fields can be updated after construction."""
        fixture = load_fixture("decision_response.allow")
        resp = DecisionResponse.model_validate(fixture)
        # Should not raise.
        resp.policy_version = "v2.0.0"
        assert resp.policy_version == "v2.0.0"
