"""
Schema validation and model-to-schema alignment tests.

These tests treat the JSON Schemas in ``schemas/`` as first-class compatibility
contracts. They verify:

1. **Schema validation** — known-valid payloads pass; known-invalid payloads
   (missing required fields, wrong types, bad enum values, bad patterns) fail.
2. **Model-to-schema alignment** — Pydantic model instances serialize to JSON
   that is valid against the corresponding schema, confirming the models stay
   aligned with the external contract as they evolve.
3. **Example file validity** — the canonical example files in
   ``schemas/examples/`` pass schema validation without modification.

Compatibility note
──────────────────
Schema field names and required-field sets are external stability contracts.
A test that starts failing because a required field was removed or renamed is
not a test to fix by updating the assertion — it is a signal that a breaking
change has occurred and must be handled as such.

See ``docs/schema-contracts.md`` for the full compatibility rules.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

try:
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError

    JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    JSONSCHEMA_AVAILABLE = False

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
    FailureReason,
)

# ── Fixtures and helpers ────────────────────────────────────────────────────

SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
SCHEMA_EXAMPLES_DIR = SCHEMAS_DIR / "examples"

# Timestamp used in fixtures — always timezone-aware.
TS = "2026-05-22T14:30:00Z"
NOW_UTC = datetime.now(timezone.utc)

pytestmark = pytest.mark.skipif(
    not JSONSCHEMA_AVAILABLE,
    reason="jsonschema not installed; add 'jsonschema[format-nongpl]>=4.18' to dev deps",
)


def load_schema(name: str) -> dict:  # type: ignore[type-arg]
    """Load a JSON Schema by base name (without .schema.json suffix)."""
    path = SCHEMAS_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: object, schema: dict) -> None:  # type: ignore[type-arg]
    """Validate *instance* against *schema* using Draft 2020-12 with format checking."""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(instance)


def assert_invalid(instance: object, schema: dict) -> None:  # type: ignore[type-arg]
    """Assert that *instance* fails validation against *schema*."""
    with pytest.raises(ValidationError):
        validate(instance, schema)


def strip_doc_fields(d: dict) -> dict:  # type: ignore[type-arg]
    """
    Remove documentation-only keys that appear in annotated example files.

    The ``examples/`` directory uses ``_comment`` and similar underscore-prefixed
    keys as inline documentation. These are not part of any schema (all schemas
    use ``additionalProperties: false``).  Strip them before validation.

    See ``docs/schema-contracts.md`` — "Example file convention" — for context.
    """
    return {k: v for k, v in d.items() if not k.startswith("_")}


def model_to_json(model: object) -> dict:  # type: ignore[type-arg]
    """Serialize a Pydantic model to a JSON-native dict via model_dump_json."""
    return json.loads(model.model_dump_json())  # type: ignore[attr-defined]


# ══════════════════════════════════════════════════════════════════════════════
# decision-request schema
# ══════════════════════════════════════════════════════════════════════════════


class TestDecisionRequestSchema:
    """Validates decision-request.schema.json as a structural contract."""

    @pytest.fixture(autouse=True)
    def schema(self) -> dict:  # type: ignore[type-arg]
        self._schema = load_schema("decision-request")
        return self._schema

    # ── Valid payloads ──────────────────────────────────────────────────────

    def test_minimal_valid_payload_passes(self) -> None:
        """Required fields only — no optional fields."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_full_valid_payload_passes(self) -> None:
        """All fields populated with valid values."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "a7b8c9d0-1234-5678-abcd-ef0123456789",
            "subject_roles": ["operator", "admin"],
            "subject_attrs": {"site": "bldg-a"},
            "resource_id": "hvac:zone-a",
            "action": "write:hvac:setpoint",
            "context": {"maintenance_window": "true"},
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_three_segment_action_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_two_segment_action_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "read:audit",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_null_resource_id_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "read:audit:log",
            "resource_id": None,
            "timestamp": TS,
        }
        validate(payload, self._schema)

    # ── Missing required fields ─────────────────────────────────────────────

    @pytest.mark.parametrize("field", ["request_id", "subject_id", "action", "timestamp"])
    def test_missing_required_field_fails(self, field: str) -> None:
        payload: dict = {  # type: ignore[type-arg]
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        del payload[field]
        assert_invalid(payload, self._schema)

    # ── Constraint violations ───────────────────────────────────────────────

    def test_empty_request_id_fails(self) -> None:
        payload = {
            "request_id": "",
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_empty_subject_id_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_action_without_colon_fails(self) -> None:
        """Action must have at least two colon-separated segments."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "writesetpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_action_with_uppercase_fails(self) -> None:
        """Action segments must be lowercase."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "Write:HVAC:Setpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_action_starting_with_colon_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": ":write:hvac",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_resource_id_without_colon_fails(self) -> None:
        """resource_id must match the {type}:{qualifier} pattern."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "resource_id": "invalidresource",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_additional_property_fails(self) -> None:
        """additionalProperties: false must reject unknown fields."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "_comment": "this is not allowed",
        }
        assert_invalid(payload, self._schema)

    def test_subject_roles_with_empty_string_fails(self) -> None:
        """Role items must be non-empty strings."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "subject_roles": [""],
        }
        assert_invalid(payload, self._schema)

    def test_duplicate_roles_fail(self) -> None:
        """subject_roles has uniqueItems: true."""
        payload = {
            "request_id": str(uuid.uuid4()),
            "subject_id": "u1",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "subject_roles": ["operator", "operator"],
        }
        assert_invalid(payload, self._schema)

    # ── Model-to-schema alignment ───────────────────────────────────────────

    def test_minimal_model_instance_passes_schema(self) -> None:
        """A minimal DecisionRequest serializes to schema-valid JSON."""
        req = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        validate(model_to_json(req), self._schema)

    def test_full_model_instance_passes_schema(self) -> None:
        """A fully populated DecisionRequest serializes to schema-valid JSON."""
        req = DecisionRequest(
            subject_id="a7b8c9d0-1234-5678-abcd-ef0123456789",
            subject_roles=["operator"],
            subject_attrs={"site": "bldg-a"},
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
            context={"maintenance_window": "true"},
        )
        validate(model_to_json(req), self._schema)

    def test_model_with_null_resource_id_passes_schema(self) -> None:
        """A DecisionRequest with resource_id=None serializes to schema-valid JSON."""
        req = DecisionRequest(subject_id="u1", action="read:audit:log")
        assert req.resource_id is None
        validate(model_to_json(req), self._schema)


# ══════════════════════════════════════════════════════════════════════════════
# decision-response schema
# ══════════════════════════════════════════════════════════════════════════════


class TestDecisionResponseSchema:
    """Validates decision-response.schema.json as a structural contract."""

    @pytest.fixture(autouse=True)
    def schema(self) -> dict:  # type: ignore[type-arg]
        self._schema = load_schema("decision-response")
        return self._schema

    # ── Valid payloads ──────────────────────────────────────────────────────

    def test_minimal_allow_payload_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "allow",
            "reason": "Subject holds a role permitted for 'write:hvac:setpoint'.",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_deny_with_failure_reason_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "deny",
            "reason": "Policy evaluation error; failed closed.",
            "evaluated_by": "EnforcementPoint",
            "failure_reason": "policy_error",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_not_applicable_outcome_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "not_applicable",
            "reason": "No policy rule is registered for this action.",
            "evaluated_by": "PolicyEngine",
            "policy_version": "v1.0.0",
            "failure_reason": None,
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_null_policy_version_passes(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "allow",
            "reason": "Permitted.",
            "evaluated_by": "RolePolicyRule",
            "policy_version": None,
            "timestamp": TS,
        }
        validate(payload, self._schema)

    # ── Missing required fields ─────────────────────────────────────────────

    @pytest.mark.parametrize(
        "field",
        ["request_id", "outcome", "reason", "evaluated_by", "timestamp"],
    )
    def test_missing_required_field_fails(self, field: str) -> None:
        payload: dict = {  # type: ignore[type-arg]
            "request_id": str(uuid.uuid4()),
            "outcome": "allow",
            "reason": "Permitted.",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
        }
        del payload[field]
        assert_invalid(payload, self._schema)

    # ── Constraint violations ───────────────────────────────────────────────

    def test_invalid_outcome_enum_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "permitted",  # not a valid enum value
            "reason": "Permitted.",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_invalid_failure_reason_enum_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "deny",
            "reason": "Denied.",
            "evaluated_by": "EnforcementPoint",
            "failure_reason": "unknown_error",  # not a valid enum value
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_empty_request_id_fails(self) -> None:
        payload = {
            "request_id": "",
            "outcome": "allow",
            "reason": "Permitted.",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_empty_reason_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "allow",
            "reason": "",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_additional_property_fails(self) -> None:
        payload = {
            "request_id": str(uuid.uuid4()),
            "outcome": "allow",
            "reason": "Permitted.",
            "evaluated_by": "RolePolicyRule",
            "timestamp": TS,
            "_comment": "this is not allowed",
        }
        assert_invalid(payload, self._schema)

    # ── Model-to-schema alignment ───────────────────────────────────────────

    def test_allow_response_model_passes_schema(self) -> None:
        resp = DecisionResponse(
            request_id=str(uuid.uuid4()),
            outcome=DecisionOutcome.ALLOW,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
        )
        validate(model_to_json(resp), self._schema)

    def test_deny_response_model_passes_schema(self) -> None:
        resp = DecisionResponse(
            request_id=str(uuid.uuid4()),
            outcome=DecisionOutcome.DENY,
            reason="Insufficient roles.",
            evaluated_by="RolePolicyRule",
        )
        validate(model_to_json(resp), self._schema)

    def test_not_applicable_response_model_passes_schema(self) -> None:
        resp = DecisionResponse(
            request_id=str(uuid.uuid4()),
            outcome=DecisionOutcome.NOT_APPLICABLE,
            reason="No policy rule is registered for this action.",
            evaluated_by="PolicyEngine",
        )
        validate(model_to_json(resp), self._schema)

    def test_fail_closed_response_model_passes_schema(self) -> None:
        resp = DecisionResponse(
            request_id=str(uuid.uuid4()),
            outcome=DecisionOutcome.DENY,
            reason="Policy evaluation error; failed closed.",
            evaluated_by="EnforcementPoint",
            failure_reason=FailureReason.POLICY_ERROR,
        )
        validate(model_to_json(resp), self._schema)


# ══════════════════════════════════════════════════════════════════════════════
# audit-event schema
# ══════════════════════════════════════════════════════════════════════════════


class TestAuditEventSchema:
    """Validates audit-event.schema.json as a structural contract."""

    @pytest.fixture(autouse=True)
    def schema(self) -> dict:  # type: ignore[type-arg]
        self._schema = load_schema("audit-event")
        return self._schema

    # ── Valid payloads ──────────────────────────────────────────────────────

    def test_minimal_valid_payload_passes(self) -> None:
        """Required fields only: event_id, event_type, action, timestamp."""
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_full_allow_event_passes(self) -> None:
        """Fully populated allow-decision audit event."""
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "timestamp": TS,
            "schema_version": "1.1",
            "request_id": str(uuid.uuid4()),
            "decision_id": str(uuid.uuid4()),
            "correlation_id": None,
            "subject_id": "a7b8c9d0-1234-5678-abcd-ef0123456789",
            "subject_name": "alice",
            "subject_type": "human",
            "subject_roles": ["operator"],
            "action": "write:hvac:setpoint",
            "resource_id": "hvac:zone-a",
            "resource_type": "hvac",
            "outcome": "allowed",
            "reason": "Subject holds a role permitted for 'write:hvac:setpoint'.",
            "evaluated_by": "RolePolicyRule",
            "policy_version": "v1.0.0",
            "matched_rules": ["RolePolicyRule"],
            "trace": {
                "final_outcome": "allow",
                "short_circuited": False,
                "evaluated_rules": [
                    {
                        "rule_name": "RolePolicyRule",
                        "outcome": "allow",
                        "reason": "Subject holds a role permitted for 'write:hvac:setpoint'.",
                    }
                ],
            },
            "detail": {},
        }
        validate(payload, self._schema)

    def test_system_event_type_passes(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "system_event",
            "action": "system:startup",
            "timestamp": TS,
        }
        validate(payload, self._schema)

    def test_null_trace_passes(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "trace": None,
        }
        validate(payload, self._schema)

    def test_denied_outcome_passes(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "outcome": "denied",
        }
        validate(payload, self._schema)

    def test_error_outcome_passes(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "outcome": "error",
        }
        validate(payload, self._schema)

    # ── Missing required fields ─────────────────────────────────────────────

    @pytest.mark.parametrize("field", ["event_id", "event_type", "action", "timestamp"])
    def test_missing_required_field_fails(self, field: str) -> None:
        payload: dict = {  # type: ignore[type-arg]
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        del payload[field]
        assert_invalid(payload, self._schema)

    # ── Constraint violations ───────────────────────────────────────────────

    def test_invalid_event_type_fails(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "access_decision",  # not a valid enum value
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_invalid_outcome_fails(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "outcome": "permit",  # not a valid enum value — schema uses "allowed"
        }
        assert_invalid(payload, self._schema)

    def test_invalid_subject_type_fails(self) -> None:
        """subject_type is constrained by enum."""
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "subject_type": "superhero",  # not in enum
        }
        assert_invalid(payload, self._schema)

    def test_additional_property_fails(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "_comment": "this is not allowed",
        }
        assert_invalid(payload, self._schema)

    def test_empty_event_id_fails(self) -> None:
        payload = {
            "event_id": "",
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_empty_action_fails(self) -> None:
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "",
            "timestamp": TS,
        }
        assert_invalid(payload, self._schema)

    def test_trace_with_invalid_outcome_fails(self) -> None:
        """Trace evaluated_rules outcome must be in its enum."""
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "trace": {
                "final_outcome": "allow",
                "short_circuited": False,
                "evaluated_rules": [
                    {
                        "rule_name": "SomeRule",
                        "outcome": "permitted",  # not valid — must be allow/deny/not_applicable
                        "reason": "OK",
                    }
                ],
            },
        }
        assert_invalid(payload, self._schema)

    def test_trace_missing_rule_name_fails(self) -> None:
        """evaluated_rules items require rule_name, outcome, reason."""
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "authorization_decision",
            "action": "write:hvac:setpoint",
            "timestamp": TS,
            "trace": {
                "final_outcome": "allow",
                "short_circuited": False,
                "evaluated_rules": [
                    {
                        "outcome": "allow",  # missing rule_name
                        "reason": "OK",
                    }
                ],
            },
        }
        assert_invalid(payload, self._schema)

    # ── Model-to-schema alignment ───────────────────────────────────────────

    def test_minimal_model_instance_passes_schema(self) -> None:
        """A minimal AuditEvent serializes to schema-valid JSON."""
        ev = AuditEvent(action="write:hvac:setpoint")
        validate(model_to_json(ev), self._schema)

    def test_full_allow_event_model_passes_schema(self) -> None:
        """A fully populated allow-decision AuditEvent passes schema validation."""
        ev = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            request_id=str(uuid.uuid4()),
            subject_id="a7b8c9d0-1234-5678-abcd-ef0123456789",
            subject_name="alice",
            subject_type="human",
            subject_roles=["operator"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.ALLOWED,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
            matched_rules=["RolePolicyRule"],
        )
        validate(model_to_json(ev), self._schema)

    def test_event_with_trace_passes_schema(self) -> None:
        """An AuditEvent with a DecisionTrace passes schema validation."""
        trace = DecisionTrace(
            final_outcome="allow",
            short_circuited=False,
            evaluated_rules=[
                RuleEvaluation(
                    rule_name="RolePolicyRule",
                    outcome="allow",
                    reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
                )
            ],
        )
        ev = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            request_id=str(uuid.uuid4()),
            subject_id="u1",
            action="write:hvac:setpoint",
            outcome=AuditOutcome.ALLOWED,
            reason="Permitted.",
            evaluated_by="RolePolicyRule",
            matched_rules=["RolePolicyRule"],
            trace=trace,
        )
        validate(model_to_json(ev), self._schema)

    def test_system_event_model_passes_schema(self) -> None:
        """An AuditEvent of event_type=system_event passes schema validation."""
        ev = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            action="system:startup",
        )
        validate(model_to_json(ev), self._schema)

    def test_deny_event_model_passes_schema(self) -> None:
        ev = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            request_id=str(uuid.uuid4()),
            subject_id="b8c9d0e1-2345-6789-bcde-f01234567890",
            subject_name="bob",
            subject_type="human",
            subject_roles=["viewer"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.DENIED,
            reason="Insufficient roles.",
            evaluated_by="RolePolicyRule",
            matched_rules=["RolePolicyRule"],
        )
        validate(model_to_json(ev), self._schema)


# ══════════════════════════════════════════════════════════════════════════════
# policy schema
# ══════════════════════════════════════════════════════════════════════════════


class TestPolicySchema:
    """
    Validates policy.schema.json as a structural contract.

    No Pydantic model exists for the Policy schema in basis-core — the schema
    describes serialized policy definitions that are loaded from configuration,
    not model instances produced by the kernel at evaluation time. The model
    alignment tests use fixture dicts that represent what a deserializer or
    policy distribution system would produce.
    """

    @pytest.fixture(autouse=True)
    def schema(self) -> dict:  # type: ignore[type-arg]
        self._schema = load_schema("policy")
        return self._schema

    # ── Valid payloads ──────────────────────────────────────────────────────

    def test_minimal_role_policy_passes(self) -> None:
        """Minimal required fields — no rules array."""
        payload = {
            "policy_id": "test-policy",
            "policy_type": "role_policy",
            "version": "v1.0.0",
            "created_at": TS,
        }
        validate(payload, self._schema)

    def test_full_role_policy_passes(self) -> None:
        """Fully populated role_policy with role rules."""
        payload = {
            "policy_id": "basis-core-default-role-policy",
            "policy_type": "role_policy",
            "version": "v1.1.0",
            "description": "Default RBAC policy for a single-zone deployment.",
            "evaluation_semantics": "deny_overrides",
            "created_at": TS,
            "created_by": "system",
            "rules": [
                {
                    "rule_type": "role",
                    "action": "write:hvac:setpoint",
                    "permitted_roles": ["operator", "admin"],
                },
                {
                    "rule_type": "role",
                    "action": "read:audit:log",
                    "permitted_roles": ["admin"],
                },
            ],
        }
        validate(payload, self._schema)

    def test_resource_type_policy_passes(self) -> None:
        payload = {
            "policy_id": "resource-type-policy",
            "policy_type": "resource_type_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "resource_type",
                    "permitted_resource_types": ["hvac", "sensor"],
                }
            ],
        }
        validate(payload, self._schema)

    def test_action_policy_passes(self) -> None:
        payload = {
            "policy_id": "action-policy",
            "policy_type": "action_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "action",
                    "action_outcomes": {
                        "write:hvac:setpoint": "allow",
                        "read:audit:log": "deny",
                    },
                }
            ],
        }
        validate(payload, self._schema)

    def test_composite_policy_passes(self) -> None:
        payload = {
            "policy_id": "composite-policy",
            "policy_type": "composite_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "resource_type",
                    "permitted_resource_types": ["hvac"],
                },
                {
                    "rule_type": "role",
                    "action": "write:hvac:setpoint",
                    "permitted_roles": ["operator", "admin"],
                },
            ],
        }
        validate(payload, self._schema)

    # ── Missing required fields ─────────────────────────────────────────────

    @pytest.mark.parametrize(
        "field",
        ["policy_id", "policy_type", "version", "created_at"],
    )
    def test_missing_required_field_fails(self, field: str) -> None:
        payload: dict = {  # type: ignore[type-arg]
            "policy_id": "test-policy",
            "policy_type": "role_policy",
            "version": "v1.0.0",
            "created_at": TS,
        }
        del payload[field]
        assert_invalid(payload, self._schema)

    # ── Constraint violations ───────────────────────────────────────────────

    def test_invalid_policy_type_fails(self) -> None:
        payload = {
            "policy_id": "test-policy",
            "policy_type": "custom_policy",  # not a valid enum value
            "version": "v1.0.0",
            "created_at": TS,
        }
        assert_invalid(payload, self._schema)

    def test_invalid_evaluation_semantics_fails(self) -> None:
        payload = {
            "policy_id": "test-policy",
            "policy_type": "role_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "evaluation_semantics": "first_match",  # not supported; only deny_overrides
        }
        assert_invalid(payload, self._schema)

    def test_invalid_rule_type_fails(self) -> None:
        payload = {
            "policy_id": "test-policy",
            "policy_type": "role_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "custom",  # not a valid enum value
                    "action": "write:hvac:setpoint",
                }
            ],
        }
        assert_invalid(payload, self._schema)

    def test_invalid_permitted_resource_type_fails(self) -> None:
        """permitted_resource_types must contain only recognized ResourceType values."""
        payload = {
            "policy_id": "test-policy",
            "policy_type": "resource_type_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "resource_type",
                    "permitted_resource_types": ["industrial_robot"],  # not in enum
                }
            ],
        }
        assert_invalid(payload, self._schema)

    def test_invalid_action_outcome_value_fails(self) -> None:
        payload = {
            "policy_id": "test-policy",
            "policy_type": "action_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "rules": [
                {
                    "rule_type": "action",
                    "action_outcomes": {
                        # "permit" is not valid — must be allow/deny/not_applicable
                        "write:hvac:setpoint": "permit",
                    },
                }
            ],
        }
        assert_invalid(payload, self._schema)

    def test_additional_property_fails(self) -> None:
        payload = {
            "policy_id": "test-policy",
            "policy_type": "role_policy",
            "version": "v1.0.0",
            "created_at": TS,
            "_comment": "this is not allowed",
        }
        assert_invalid(payload, self._schema)


# ══════════════════════════════════════════════════════════════════════════════
# schemas/examples/ canonical example files
# ══════════════════════════════════════════════════════════════════════════════


class TestSchemaExampleFiles:
    """
    Validates the canonical example files in ``schemas/examples/``.

    These files are the schema-valid reference examples — they do not use the
    ``_comment`` convention and must pass strict schema validation.
    """

    def _load_example(self, filename: str) -> dict:  # type: ignore[type-arg]
        path = SCHEMA_EXAMPLES_DIR / filename
        if not path.exists():
            pytest.skip(f"Example file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_decision_request_example_passes(self) -> None:
        schema = load_schema("decision-request")
        example = self._load_example("decision-request.json")
        validate(example, schema)

    def test_decision_response_example_passes(self) -> None:
        schema = load_schema("decision-response")
        example = self._load_example("decision-response.json")
        validate(example, schema)

    def test_audit_event_example_passes(self) -> None:
        schema = load_schema("audit-event")
        example = self._load_example("audit-event.json")
        validate(example, schema)

    def test_policy_example_passes(self) -> None:
        schema = load_schema("policy")
        example = self._load_example("policy.json")
        validate(example, schema)


# ══════════════════════════════════════════════════════════════════════════════
# Annotated examples/  — validated after stripping documentation fields
# ══════════════════════════════════════════════════════════════════════════════


class TestAnnotatedExampleFiles:
    """
    Validates the annotated example files in ``examples/`` after stripping
    documentation fields.

    These files use ``_comment`` and similar underscore-prefixed keys as inline
    documentation. Since all schemas enforce ``additionalProperties: false``,
    these keys must be removed before validation. The stripped payloads must
    pass schema validation.

    NOTE: ``examples/policies/deny-overrides-example.json`` uses an additional
    ``_evaluation_trace`` key at the top level. It is also stripped here.
    """

    EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

    def _load(self, *parts: str) -> dict:  # type: ignore[type-arg]
        path = self.EXAMPLES_DIR.joinpath(*parts)
        raw = json.loads(path.read_text(encoding="utf-8"))
        return strip_doc_fields(raw)

    def test_allow_decision_response_passes(self) -> None:
        schema = load_schema("decision-response")
        validate(self._load("decisions", "allow-basic.json"), schema)

    def test_deny_decision_response_passes(self) -> None:
        schema = load_schema("decision-response")
        validate(self._load("decisions", "deny-basic.json"), schema)

    def test_default_deny_response_passes(self) -> None:
        schema = load_schema("decision-response")
        validate(self._load("decisions", "default-deny.json"), schema)

    def test_policy_error_response_passes(self) -> None:
        schema = load_schema("decision-response")
        validate(self._load("decisions", "policy-error-fail-closed.json"), schema)

    def test_allow_audit_event_passes(self) -> None:
        schema = load_schema("audit-event")
        validate(self._load("audit-events", "allow-event.json"), schema)

    def test_deny_audit_event_passes(self) -> None:
        schema = load_schema("audit-event")
        validate(self._load("audit-events", "deny-event.json"), schema)

    def test_default_deny_audit_event_passes(self) -> None:
        schema = load_schema("audit-event")
        validate(self._load("audit-events", "default-deny-event.json"), schema)

    def test_deny_overrides_audit_event_passes(self) -> None:
        schema = load_schema("audit-event")
        validate(self._load("audit-events", "deny-overrides-event.json"), schema)

    def test_role_policy_basic_passes(self) -> None:
        schema = load_schema("policy")
        validate(self._load("policies", "role-policy-basic.json"), schema)

    def test_deny_overrides_policy_passes(self) -> None:
        schema = load_schema("policy")
        validate(self._load("policies", "deny-overrides-example.json"), schema)
