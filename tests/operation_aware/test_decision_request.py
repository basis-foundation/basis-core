"""
tests/operation_aware/test_decision_request.py — tests for
`basis_core.decisions.operation_aware` (Milestone 2, PR 8 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"OperationAwareDecisionRequest value object").

Covers `OperationAwareDecisionRequest` and `OperationIntent` construction,
defaults, required-field enforcement, pattern/enum validation, nested
composition of PR 6's evidence-reference models and PR 7's context value
objects, unknown/prohibited-field rejection, and conformance against every
vendored `basis-schemas` v0.2.0 `operation-aware-decision-request` (PR C)
example — via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests request *shape* only: construction, validation, defaults,
and schema alignment. It does not test, and must never test, evaluation,
policy matching, evidence retrieval/verification, protocol parsing, risk or
safety calculation, or any behavior belonging to
`OperationAwareDecisionResponse`, policy bundles/rules/conditions, traces,
or audit evidence — none of that exists in this module or this PR.

Exhaustive serialization/round-trip fixture coverage is PR 9's dedicated
scope (`tests/operation_aware/test_decision_request_roundtrip.py`) and is
deliberately not duplicated here; this file's "contract examples" tests only
prove construction succeeds/fails as expected, not full round-trip byte
equality.

Does not test any later, not-yet-implemented operation-aware model (policy,
trace, audit) — see `tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from basis_core.decisions.models import DecisionRequest
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionRequest,
    OperationIntent,
)
from basis_core.domain.evidence import AdapterEvidenceReference, IdentityEvidenceReference
from basis_core.domain.operation_aware import (
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

_CONTRACT_NAME = "operation-aware-decision-request"
_ROOT_SECTION = "operation_aware_decision_request"

# A structurally valid digest, reused across tests that need a nested
# evidence reference but are not themselves testing digest validation.
_VALID_DIGEST = {
    "algorithm": "sha-256",
    "value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
}

_VALID_IDENTITY_EVIDENCE_REFERENCE = {
    "reference_id": "idev-0001-0000-0000-000000000001",
    "evidence_digest": _VALID_DIGEST,
    "identity_source": "oidc:https://idp.example.com",
    "redaction_classification": "reference_only",
}

_VALID_ADAPTER_EVIDENCE_REFERENCE = {
    "reference_id": "adev-0001-0000-0000-000000000001",
    "evidence_digest": _VALID_DIGEST,
    "adapter_source": "basis-adapters:bacnet",
    "protocol": "bacnet",
    "redaction_classification": "reference_only",
}


def _minimal_kwargs() -> dict[str, object]:
    return {
        "request_id": "oadr-0001-0000-0000-000000000001",
        "subject_id": "svc-scheduler",
        "action": "browse:ahu",
    }


def _full_kwargs() -> dict[str, object]:
    return {
        "request_id": "oadr-0099-0000-0000-000000000099",
        "correlation_id": "corr-0099-0000-0000-000000000099",
        "subject_id": "a7b8c9d0-1234-5678-abcd-ef0123456789",
        "subject_roles": ["operator", "maintenance"],
        "subject_attrs": {"clearance": "level-2"},
        "identity_source": "oidc:https://idp.example.com",
        "authority_mode": "federated",
        "identity_evidence_reference": _VALID_IDENTITY_EVIDENCE_REFERENCE,
        "action": "write:hvac:setpoint",
        "resource": "hvac:zone-a",
        "resource_type": "hvac",
        "location": {
            "site_id": "west-campus",
            "building_id": "bldg-3",
            "zone_id": "zone-a",
            "area_id": "area-1",
        },
        "device": {"device_id": "ahu-14", "device_class": "controller"},
        "protocol_context": {"protocol": "bacnet", "operation": "WriteProperty"},
        "operation_intent": "state_changing",
        "adapter_evidence_reference": _VALID_ADAPTER_EVIDENCE_REFERENCE,
        "safety_context": {
            "mode": "interlock-engaged",
            "classification": "elevated",
            "constraint_ids": ["lockout-tagout-active"],
        },
        "environment_context": {
            "mode": "maintenance_mode",
            "condition_ids": ["scheduled-window-open"],
        },
        "risk_context": {"classification": "elevated", "score": 0.62},
        "evaluation_time": "2026-05-22T14:30:00Z",
        "expected_policy_version": "0.2.0",
    }


def _load_request_document() -> dict[str, object]:
    return load_contract(_CONTRACT_NAME)


def _load_root_section() -> dict[str, object]:
    return require_mapping_field(_load_request_document(), _ROOT_SECTION, context=_CONTRACT_NAME)


def _valid_examples() -> list[dict[str, object]]:
    root = _load_root_section()
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    return require_sequence_field(examples, "valid", context=f"{_ROOT_SECTION}.examples")  # type: ignore[return-value]


def _invalid_examples() -> list[dict[str, object]]:
    root = _load_root_section()
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    return require_sequence_field(examples, "invalid", context=f"{_ROOT_SECTION}.examples")  # type: ignore[return-value]


# ══════════════════════════════════════════════════════════════════════════
# Schema alignment
# ══════════════════════════════════════════════════════════════════════════


class TestSchemaAlignment:
    def test_required_and_optional_field_names_match_contract(self) -> None:
        root = _load_root_section()
        required = set(require_sequence_field(root, "required", context=_ROOT_SECTION))
        optional = set(require_sequence_field(root, "optional", context=_ROOT_SECTION))
        model_required = {
            name
            for name, info in OperationAwareDecisionRequest.model_fields.items()
            if info.is_required()
        }
        model_optional = {
            name
            for name, info in OperationAwareDecisionRequest.model_fields.items()
            if not info.is_required()
        }
        assert model_required == required
        assert model_optional == optional

    def test_operation_intent_values_match_closed_vocabulary(self) -> None:
        root = _load_root_section()
        values = require_sequence_field(root, "operation_intent_values", context=_ROOT_SECTION)
        assert set(values) == {member.value for member in OperationIntent}

    def test_action_pattern_matches_vendored_contract(self) -> None:
        from basis_core.decisions.models import _ACTION_RE

        root = _load_root_section()
        assert isinstance(root["action_pattern"], str)
        # decisions/models.py's pattern is a superset (2+ segments) of the
        # contract's reproduced pattern (2-3 segments); every contract
        # example and invalid case in this file only ever exercises 1-3
        # segment actions, so behavioral parity is confirmed directly by
        # the construction tests below rather than by string equality here.
        assert _ACTION_RE.match("write:hvac:setpoint")
        assert _ACTION_RE.match("browse:ahu")
        assert not _ACTION_RE.match("read")

    def test_resource_pattern_reused_from_decisions_models(self) -> None:
        from basis_core.decisions.models import _RESOURCE_ID_RE
        from basis_core.decisions.operation_aware import _RESOURCE_ID_RE as reused

        assert reused is _RESOURCE_ID_RE


# ══════════════════════════════════════════════════════════════════════════
# Construction
# ══════════════════════════════════════════════════════════════════════════


class TestMinimalConstruction:
    def test_minimal_request_constructs(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert req.request_id == "oadr-0001-0000-0000-000000000001"
        assert req.subject_id == "svc-scheduler"
        assert req.action == "browse:ahu"

    def test_request_id_is_not_auto_generated(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(subject_id="svc-scheduler", action="browse:ahu")  # type: ignore[call-arg]


class TestFullConstruction:
    def test_full_request_constructs(self) -> None:
        req = OperationAwareDecisionRequest(**_full_kwargs())  # type: ignore[arg-type]
        assert req.correlation_id == "corr-0099-0000-0000-000000000099"
        assert req.subject_roles == ["operator", "maintenance"]
        assert req.subject_attrs == {"clearance": "level-2"}
        assert req.identity_source == "oidc:https://idp.example.com"
        assert req.authority_mode == "federated"
        assert req.resource == "hvac:zone-a"
        assert req.resource_type == "hvac"
        assert req.operation_intent == OperationIntent.STATE_CHANGING
        assert req.expected_policy_version == "0.2.0"
        assert req.evaluation_time == datetime(2026, 5, 22, 14, 30, 0, tzinfo=timezone.utc)

    def test_nested_dicts_construct_correct_pr6_and_pr7_types(self) -> None:
        req = OperationAwareDecisionRequest(**_full_kwargs())  # type: ignore[arg-type]
        assert isinstance(req.identity_evidence_reference, IdentityEvidenceReference)
        assert isinstance(req.adapter_evidence_reference, AdapterEvidenceReference)
        assert isinstance(req.location, OperationAwareLocation)
        assert isinstance(req.device, OperationAwareDevice)
        assert isinstance(req.protocol_context, OperationAwareProtocolContext)
        assert isinstance(req.safety_context, OperationAwareSafetyContext)
        assert isinstance(req.environment_context, OperationAwareEnvironmentContext)
        assert isinstance(req.risk_context, OperationAwareRiskContext)

    def test_existing_model_instances_accepted_as_nested_values(self) -> None:
        location = OperationAwareLocation(site_id="west-campus")
        device = OperationAwareDevice(device_id="ahu-14", device_class="controller")
        identity_ref = IdentityEvidenceReference(**_VALID_IDENTITY_EVIDENCE_REFERENCE)  # type: ignore[arg-type]
        req = OperationAwareDecisionRequest(
            request_id="oadr-1",
            subject_id="svc",
            action="browse:ahu",
            location=location,
            device=device,
            identity_evidence_reference=identity_ref,
        )
        assert req.location is location
        assert req.device is device
        assert req.identity_evidence_reference is identity_ref


# ══════════════════════════════════════════════════════════════════════════
# Defaults
# ══════════════════════════════════════════════════════════════════════════


class TestDefaults:
    def test_subject_roles_defaults_to_empty_list(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert req.subject_roles == []

    def test_subject_attrs_defaults_to_empty_dict(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert req.subject_attrs == {}

    def test_collection_defaults_are_not_shared_between_instances(self) -> None:
        a = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        b = OperationAwareDecisionRequest(
            request_id="oadr-0002", subject_id="svc-2", action="browse:ahu"
        )
        assert a.subject_roles is not b.subject_roles
        assert a.subject_attrs is not b.subject_attrs

    @pytest.mark.parametrize(
        "field_name",
        [
            "correlation_id",
            "identity_source",
            "authority_mode",
            "identity_evidence_reference",
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
        ],
    )
    def test_all_other_optional_fields_default_to_none(self, field_name: str) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert getattr(req, field_name) is None


# ══════════════════════════════════════════════════════════════════════════
# Required fields
# ══════════════════════════════════════════════════════════════════════════


class TestRequiredFields:
    def test_missing_request_id_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        del kwargs["request_id"]
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_empty_request_id_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["request_id"] = ""
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_missing_subject_id_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        del kwargs["subject_id"]
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_empty_subject_id_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["subject_id"] = ""
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_missing_action_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        del kwargs["action"]
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_empty_action_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["action"] = ""
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_malformed_action_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["action"] = "read"
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Pattern validation
# ══════════════════════════════════════════════════════════════════════════


class TestActionPatternValidation:
    @pytest.mark.parametrize(
        "action",
        ["browse:ahu", "write:hvac:setpoint", "read:audit:log", "execute:hvac:reset"],
    )
    def test_valid_canonical_actions_construct(self, action: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["action"] = action
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.action == action

    @pytest.mark.parametrize(
        "action,description",
        [
            ("read", "single segment, no domain"),
            ("", "empty"),
            ("Read:Ahu", "uppercase"),
            (":ahu", "missing verb"),
            ("read:", "missing domain"),
            ("read ahu", "space instead of colon"),
        ],
    )
    def test_invalid_action_strings_are_rejected(self, action: str, description: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["action"] = action
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]


class TestResourcePatternValidation:
    @pytest.mark.parametrize("resource", ["hvac:zone-a", "ahu:rooftop-1", "sensor:co2-lobby"])
    def test_valid_canonical_resources_construct(self, resource: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["resource"] = resource
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.resource == resource

    def test_resource_is_none_by_default(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert req.resource is None

    @pytest.mark.parametrize(
        "resource,description",
        [
            ("rooftop-1", "no type prefix"),
            ("", "empty"),
            ("HVAC:zone-a", "uppercase type"),
            (":zone-a", "missing type"),
        ],
    )
    def test_malformed_resources_are_rejected(self, resource: str, description: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["resource"] = resource
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]


class TestResourceTypePatternValidation:
    @pytest.mark.parametrize("resource_type", ["ahu", "setpoint", "controller", "a"])
    def test_valid_open_resource_type_values_construct(self, resource_type: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["resource_type"] = resource_type
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.resource_type == resource_type

    @pytest.mark.parametrize(
        "resource_type,description",
        [
            ("", "empty"),
            ("AHU", "uppercase"),
            ("-ahu", "leading hyphen"),
            ("ahu setpoint", "contains space"),
        ],
    )
    def test_malformed_resource_type_values_are_rejected(
        self, resource_type: str, description: str
    ) -> None:
        kwargs = _minimal_kwargs()
        kwargs["resource_type"] = resource_type
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_resource_type_is_not_coerced_into_closed_resource_type_enum(self) -> None:
        # "controller" is not a member of basis_core.domain.resource.ResourceType
        # (a closed enum) but must still be accepted here — resource_type is
        # an intentionally open string classification on this contract.
        kwargs = _minimal_kwargs()
        kwargs["resource_type"] = "controller"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.resource_type == "controller"
        assert isinstance(req.resource_type, str)

    def test_no_cross_field_consistency_enforced_with_resource(self) -> None:
        # resource's type prefix ("hvac") intentionally need not match
        # resource_type ("setpoint") — no reconciliation is implemented.
        kwargs = _minimal_kwargs()
        kwargs["resource"] = "hvac:zone-a"
        kwargs["resource_type"] = "setpoint"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.resource == "hvac:zone-a"
        assert req.resource_type == "setpoint"


class TestAuthorityModePatternValidation:
    @pytest.mark.parametrize(
        "authority_mode", ["federated", "synchronized", "standalone-air-gapped"]
    )
    def test_valid_open_authority_mode_values_construct(self, authority_mode: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["authority_mode"] = authority_mode
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.authority_mode == authority_mode

    @pytest.mark.parametrize(
        "authority_mode,description",
        [
            ("Federated", "uppercase"),
            ("", "empty"),
            ("-federated", "leading hyphen"),
            ("federated mode", "contains space"),
        ],
    )
    def test_malformed_authority_mode_values_are_rejected(
        self, authority_mode: str, description: str
    ) -> None:
        kwargs = _minimal_kwargs()
        kwargs["authority_mode"] = authority_mode
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_authority_mode_is_not_a_governed_closed_vocabulary(self) -> None:
        # Any well-formed open-identifier label is accepted; this is not a
        # closed enum, unlike operation_intent.
        kwargs = _minimal_kwargs()
        kwargs["authority_mode"] = "some-deployment-defined-mode"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.authority_mode == "some-deployment-defined-mode"


class TestIdentitySourceValidation:
    def test_non_empty_identity_source_constructs(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["identity_source"] = "oidc:https://idp.example.com"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.identity_source == "oidc:https://idp.example.com"

    def test_empty_identity_source_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["identity_source"] = ""
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_no_provider_specific_behavior(self) -> None:
        # identity_source remains an opaque label — arbitrary provider
        # labels (not just "oidc:...") must be accepted without special
        # OIDC/SAML/JWT/Keycloak/Okta/Entra interpretation.
        for label in ["oidc:https://idp.example.com", "saml:acme-corp", "basis-local", "custom"]:
            kwargs = _minimal_kwargs()
            kwargs["identity_source"] = label
            req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
            assert req.identity_source == label


class TestExpectedPolicyVersionValidation:
    def test_non_empty_value_constructs(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["expected_policy_version"] = "0.2.0"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.expected_policy_version == "0.2.0"

    def test_empty_value_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["expected_policy_version"] = ""
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_no_semver_format_enforced(self) -> None:
        # No version-format is enforced — any non-empty string is accepted.
        kwargs = _minimal_kwargs()
        kwargs["expected_policy_version"] = "not-a-semver-string"
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.expected_policy_version == "not-a-semver-string"


# ══════════════════════════════════════════════════════════════════════════
# Closed vocabulary: operation_intent
# ══════════════════════════════════════════════════════════════════════════


class TestOperationIntentClosedVocabulary:
    @pytest.mark.parametrize("value", ["read_only", "state_changing", "control_affecting"])
    def test_each_supported_value_is_accepted(self, value: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["operation_intent"] = value
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.operation_intent == OperationIntent(value)

    def test_enum_member_is_accepted_directly(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["operation_intent"] = OperationIntent.READ_ONLY
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.operation_intent is OperationIntent.READ_ONLY

    @pytest.mark.parametrize("value", ["destructive", "READ_ONLY", "read-only", "", "unknown"])
    def test_unsupported_values_are_rejected(self, value: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["operation_intent"] = value
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_exactly_three_members_exist(self) -> None:
        assert {member.value for member in OperationIntent} == {
            "read_only",
            "state_changing",
            "control_affecting",
        }


# ══════════════════════════════════════════════════════════════════════════
# evaluation_time
# ══════════════════════════════════════════════════════════════════════════


class TestEvaluationTimeValidation:
    @pytest.mark.parametrize(
        "value",
        ["2026-05-22T14:30:00Z", "2026-05-22T14:30:00-06:00", "2026-05-22T14:30:00.123456Z"],
    )
    def test_timezone_aware_values_are_accepted(self, value: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs["evaluation_time"] = value
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.evaluation_time is not None
        assert req.evaluation_time.tzinfo is not None

    def test_timezone_naive_value_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["evaluation_time"] = "2026-05-22T14:30:00"
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_datetime_object_naive_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["evaluation_time"] = datetime(2026, 5, 22, 14, 30, 0)
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_datetime_object_tz_aware_is_accepted(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["evaluation_time"] = datetime(2026, 5, 22, 14, 30, 0, tzinfo=timezone.utc)
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.evaluation_time == datetime(2026, 5, 22, 14, 30, 0, tzinfo=timezone.utc)

    def test_evaluation_time_is_none_by_default_no_clock_read(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert req.evaluation_time is None


# ══════════════════════════════════════════════════════════════════════════
# Nested composition
# ══════════════════════════════════════════════════════════════════════════


class TestNestedComposition:
    def test_identity_evidence_reference_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["identity_evidence_reference"] = _VALID_IDENTITY_EVIDENCE_REFERENCE
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.identity_evidence_reference, IdentityEvidenceReference)
        assert req.identity_evidence_reference.reference_id == "idev-0001-0000-0000-000000000001"

    def test_malformed_identity_evidence_reference_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        bad = dict(_VALID_IDENTITY_EVIDENCE_REFERENCE)
        del bad["reference_id"]
        kwargs["identity_evidence_reference"] = bad
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_adapter_evidence_reference_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["adapter_evidence_reference"] = _VALID_ADAPTER_EVIDENCE_REFERENCE
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.adapter_evidence_reference, AdapterEvidenceReference)

    def test_malformed_adapter_evidence_reference_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        bad = dict(_VALID_ADAPTER_EVIDENCE_REFERENCE)
        bad["evidence_digest"] = {"algorithm": "SHA256", "value": "1f825aa2"}
        kwargs["adapter_evidence_reference"] = bad
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_location_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["location"] = {"site_id": "west-campus", "building_id": "bldg-3"}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.location, OperationAwareLocation)
        assert req.location.site_id == "west-campus"

    def test_malformed_location_unknown_key_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["location"] = {"site_id": "west-campus", "country": "unsupported-nested-key"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_device_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["device"] = {"device_id": "ahu-14", "device_class": "controller"}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.device, OperationAwareDevice)

    def test_malformed_device_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["device"] = {"device_id": "ahu-14", "device_class": "Controller"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_protocol_context_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["protocol_context"] = {"protocol": "bacnet", "operation": "WriteProperty"}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.protocol_context, OperationAwareProtocolContext)

    def test_malformed_protocol_context_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["protocol_context"] = {"protocol": "BACnet"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_safety_context_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["safety_context"] = {"mode": "interlock-engaged", "constraint_ids": ["x"]}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.safety_context, OperationAwareSafetyContext)

    def test_malformed_safety_context_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["safety_context"] = {"mode": "Interlock-Engaged"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_environment_context_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["environment_context"] = {"mode": "maintenance_mode"}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.environment_context, OperationAwareEnvironmentContext)

    def test_malformed_environment_context_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["environment_context"] = {"mode": "Maintenance Mode"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_risk_context_composes(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["risk_context"] = {"classification": "elevated", "score": 0.62}
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert isinstance(req.risk_context, OperationAwareRiskContext)

    def test_malformed_risk_context_score_bool_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["risk_context"] = {"score": True}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_no_cross_field_reconciliation_between_identity_source_and_reference(self) -> None:
        # identity_source need not equal identity_evidence_reference.identity_source.
        kwargs = _minimal_kwargs()
        kwargs["identity_source"] = "a-different-label"
        kwargs["identity_evidence_reference"] = _VALID_IDENTITY_EVIDENCE_REFERENCE
        req = OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]
        assert req.identity_source == "a-different-label"
        assert req.identity_evidence_reference is not None
        assert req.identity_evidence_reference.identity_source == "oidc:https://idp.example.com"


# ══════════════════════════════════════════════════════════════════════════
# Unknown and prohibited fields
# ══════════════════════════════════════════════════════════════════════════


class TestUnknownAndProhibitedFields:
    def test_unknown_top_level_field_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["confidence"] = 0.97
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_legacy_context_field_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["context"] = {"site": "bldg-a"}
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_legacy_resource_id_field_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["resource_id"] = "hvac:zone-a"
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_legacy_timestamp_field_is_rejected(self) -> None:
        kwargs = _minimal_kwargs()
        kwargs["timestamp"] = "2026-05-22T14:30:00Z"
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "field_name",
        [
            "access_token",
            "id_token",
            "refresh_token",
            "jwt",
            "bearer_token",
            "authorization_header",
            "cookie",
            "session_secret",
            "client_secret",
            "password",
            "private_key",
            "api_key",
            "raw_claims",
            "full_claim_set",
            "raw_payload",
            "raw_protocol_payload",
            "packet",
            "frame",
            "device_secret",
        ],
    )
    def test_raw_secret_and_credential_fields_are_rejected(self, field_name: str) -> None:
        kwargs = _minimal_kwargs()
        kwargs[field_name] = "inert-placeholder-value"
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest(**kwargs)  # type: ignore[arg-type]

    def test_no_prohibited_field_is_declared_on_the_model(self) -> None:
        prohibited = {
            "context",
            "resource_id",
            "timestamp",
            "reason_code",
            "redaction_classification",
            "metadata",
            "extensions",
            "extra",
            "custom_fields",
            "access_token",
            "id_token",
            "refresh_token",
            "jwt",
            "bearer_token",
            "authorization_header",
            "cookie",
            "session_secret",
            "client_secret",
            "password",
            "private_key",
            "api_key",
            "raw_claims",
            "full_claim_set",
            "raw_payload",
            "raw_protocol_payload",
            "packet",
            "frame",
            "device_secret",
        }
        declared_fields = set(OperationAwareDecisionRequest.model_fields)
        assert declared_fields.isdisjoint(prohibited)

    def test_model_rejects_extra_fields_configuration(self) -> None:
        assert OperationAwareDecisionRequest.model_config.get("extra") == "forbid"


# ══════════════════════════════════════════════════════════════════════════
# Immutability
# ══════════════════════════════════════════════════════════════════════════


class TestImmutability:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        req = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            req.subject_id = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        a = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        b = OperationAwareDecisionRequest(**_minimal_kwargs())  # type: ignore[arg-type]
        assert a == b
        assert a is not b


# ══════════════════════════════════════════════════════════════════════════
# Compatibility: DecisionRequest is untouched
# ══════════════════════════════════════════════════════════════════════════


class TestDecisionRequestUnaffected:
    def test_decision_request_still_auto_generates_request_id(self) -> None:
        # DecisionRequest.request_id retains its default factory —
        # OperationAwareDecisionRequest's "no auto-generation" behavior must
        # not have leaked into the v0.1-era model.
        req = DecisionRequest(subject_id="svc", action="browse:ahu")
        assert req.request_id

    def test_decision_request_still_has_context_field(self) -> None:
        req = DecisionRequest(subject_id="svc", action="browse:ahu")
        assert req.context == {}

    def test_decision_request_and_operation_aware_request_are_unrelated_types(self) -> None:
        assert not issubclass(OperationAwareDecisionRequest, DecisionRequest)
        assert not issubclass(DecisionRequest, OperationAwareDecisionRequest)


# ══════════════════════════════════════════════════════════════════════════
# Contract examples (vendored basis-schemas v0.2.0, PR C)
# ══════════════════════════════════════════════════════════════════════════


class TestVendoredContractExamples:
    def test_every_vendored_valid_example_constructs(self) -> None:
        examples = _valid_examples()
        assert len(examples) >= 4
        for example in examples:
            req = OperationAwareDecisionRequest(**example)  # type: ignore[arg-type]
            assert req.request_id == example["request_id"]

    def test_every_vendored_invalid_example_is_rejected(self) -> None:
        entries = _invalid_examples()
        assert len(entries) >= 10
        for entry in entries:
            value = entry["value"]
            assert isinstance(value, dict)
            reason = entry.get("reason", "<no reason recorded>")
            with pytest.raises(ValidationError, match=".*"):
                OperationAwareDecisionRequest(**value)  # type: ignore[arg-type]
            # `reason` participates only in the failure message above via
            # pytest's context on assertion failure; asserting on it
            # directly would encode the contract's prose into this test.
            assert reason  # sanity: every invalid example documents why.
