"""
tests/operation_aware/test_audit_evidence.py — tests for
`basis_core.audit.operation_aware.audit_evidence.AuditEvidence` (Milestone
10, PR 30 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"AuditEvidence model").

Covers `AuditEvidence` construction, validation, the published
required-key/nullable-key distinctions, the completed/failed
evaluation-state invariant, `matched_rule_ids` validation (non-empty items,
uniqueness, order preservation), typed evidence-reference reuse,
`recorded_at` (caller-supplied, timezone-aware, never generated),
immutability, boundedness, and serialization — cross-checked against every
vendored `basis-schemas` v0.2.1 `audit-evidence` contract example (6 valid,
20 invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`), and against all five
vendored canonical compatibility-scenario `expected-audit-evidence.yaml`
artifacts.

This file tests `AuditEvidence` *shape* only: construction, validation,
immutability, and schema alignment. It does not test, and must never test,
audit-evidence assembly from a response/trace pair (PR 31), full
response/trace/audit-evidence agreement (PR 32), persistence, or any
`AuditWriter`-shaped behavior for this type — none of that exists in this
module or this PR. `TestV01Compatibility` is the mandatory,
mechanically-checked proof that `basis_core.audit.events.AuditEvent` and
`basis_core.audit.writer.AuditWriter` (the existing v0.1.0 types) are
unaffected by anything added here.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, ValidationError

from basis_core.audit.operation_aware.audit_evidence import (
    AUDIT_EVIDENCE_SCHEMA_VERSION,
    AuditEvidence,
)
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from tests.helpers.basis_schemas_snapshot import COMPATIBILITY_SCENARIOS
from tests.helpers.operation_aware_contracts import (
    load_contract,
    load_scenario_artifact,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _audit_evidence_examples() -> tuple[list[object], list[object]]:
    document = load_contract("audit-evidence")
    section = require_mapping_field(document, "audit_evidence", context="audit-evidence")
    examples = require_mapping_field(section, "examples", context="audit-evidence.audit_evidence")
    valid = require_sequence_field(examples, "valid", context="audit-evidence.examples")
    invalid = require_sequence_field(examples, "invalid", context="audit-evidence.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _audit_evidence_examples()


def _invalid_example_value(entry: object) -> object:
    if isinstance(entry, dict) and "value" in entry and "reason" in entry:
        return entry["value"]
    return entry


def _invalid_example_reason(entry: object, index: int) -> str:
    if isinstance(entry, dict):
        reason = entry.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return f"example-{index}"


def _valid_example_id(example: object, index: int) -> str:
    if isinstance(example, dict):
        evidence_id = example.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id:
            return evidence_id
    return f"example-{index}"


# Minimal structurally valid records reused across tests that need one but
# are not themselves testing the field under test.
_MINIMAL_COMPLETED_ALLOW_KWARGS: dict[str, object] = {
    "evidence_id": "audev-test-completed-allow",
    "request_id": "oadr-test-completed-allow",
    "evaluation_status": "completed",
    "outcome": "allow",
    "failure_reason": None,
    "recorded_at": "2026-05-22T14:30:01Z",
}

_MINIMAL_FAILED_KWARGS: dict[str, object] = {
    "evidence_id": "audev-test-failed",
    "request_id": "oadr-test-failed",
    "evaluation_status": "failed",
    "outcome": None,
    "failure_reason": "internal_evaluation_error",
    "recorded_at": "2026-05-22T14:30:01Z",
}

_VALID_IDENTITY_EVIDENCE_REFERENCE: dict[str, object] = {
    "reference_id": "idev-0002-0000-0000-000000000002",
    "evidence_digest": {
        "algorithm": "sha-256",
        "value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    },
    "identity_source": "oidc:https://idp.example.com",
    "redaction_classification": "reference_only",
}

_VALID_ADAPTER_EVIDENCE_REFERENCE: dict[str, object] = {
    "reference_id": "adev-0003-0000-0000-000000000003",
    "evidence_digest": {
        "algorithm": "sha-256",
        "value": "1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab",
    },
    "adapter_source": "basis-adapters:bacnet",
    "protocol": "bacnet",
    "redaction_classification": "reference_only",
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_six_valid_examples_are_vendored(self) -> None:
        assert len(_VALID_EXAMPLES) == 6

    def test_twenty_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 20

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        evidence = AuditEvidence.model_validate(example)
        assert type(evidence) is AuditEvidence

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            AuditEvidence.model_validate(value)

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip(self, example: object) -> None:
        assert isinstance(example, dict)
        evidence = AuditEvidence.model_validate(example)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        restored = AuditEvidence.model_validate(dumped)
        assert restored == evidence

    def test_no_example_is_silently_skipped(self) -> None:
        assert len(_VALID_EXAMPLES) + len(_INVALID_EXAMPLES) == 26

    def test_allow_example_preserves_matched_rule_ids_and_reason_code(self) -> None:
        example = _VALID_EXAMPLES[0]
        assert isinstance(example, dict)
        evidence = AuditEvidence.model_validate(example)
        assert evidence.matched_rule_ids == ["rule-operator-read-ahu-telemetry"]
        assert evidence.reason_code == "allow_rule_matched"

    def test_failed_example_retains_required_nulls(self) -> None:
        example = _VALID_EXAMPLES[3]
        assert isinstance(example, dict)
        assert example["evaluation_status"] == "failed"
        evidence = AuditEvidence.model_validate(example)
        assert evidence.outcome is None
        assert evidence.failure_reason == OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None

    def test_evidence_reference_example_constructs_typed_references(self) -> None:
        example = _VALID_EXAMPLES[5]
        assert isinstance(example, dict)
        evidence = AuditEvidence.model_validate(example)
        assert evidence.identity_evidence_reference is not None
        assert evidence.adapter_evidence_reference is not None
        assert (
            evidence.identity_evidence_reference.identity_source == "oidc:https://idp.example.com"
        )
        assert evidence.adapter_evidence_reference.protocol == "bacnet"


# ══════════════════════════════════════════════════════════════════════════
# Model configuration and exact field inventory
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_model_is_frozen(self) -> None:
        assert AuditEvidence.model_config.get("frozen") is True

    def test_model_forbids_extra_fields(self) -> None:
        assert AuditEvidence.model_config.get("extra") == "forbid"

    def test_only_the_sixteen_published_fields_exist(self) -> None:
        assert set(AuditEvidence.model_fields) == {
            "evidence_id",
            "request_id",
            "correlation_id",
            "trace_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "bundle_id",
            "bundle_version",
            "matched_rule_ids",
            "identity_evidence_reference",
            "adapter_evidence_reference",
            "reason_code",
            "explanation",
            "recorded_at",
            "schema_version",
        }

    def test_unknown_top_level_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS, confidence=0.97)  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Required-key behavior
# ══════════════════════════════════════════════════════════════════════════


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field_name",
        [
            "evidence_id",
            "request_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "recorded_at",
        ],
    )
    def test_required_fields_are_required(self, field_name: str) -> None:
        assert AuditEvidence.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name",
        [
            "correlation_id",
            "trace_id",
            "bundle_id",
            "bundle_version",
            "matched_rule_ids",
            "identity_evidence_reference",
            "adapter_evidence_reference",
            "reason_code",
            "explanation",
            "schema_version",
        ],
    )
    def test_optional_fields_are_not_required(self, field_name: str) -> None:
        assert not AuditEvidence.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name",
        [
            "evidence_id",
            "request_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "recorded_at",
        ],
    )
    def test_missing_each_required_key_is_rejected(self, field_name: str) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs[field_name]
        with pytest.raises(ValidationError):
            AuditEvidence(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_rejected_for_non_nullable_required_fields(self) -> None:
        for field_name in ("evidence_id", "request_id", "evaluation_status", "recorded_at"):
            kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: None})
            with pytest.raises(ValidationError):
                AuditEvidence(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_accepted_for_required_nullable_fields_in_valid_state(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        assert evidence.outcome is None

    def test_optional_fields_default_to_none_or_empty_when_omitted(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert evidence.correlation_id is None
        assert evidence.trace_id is None
        assert evidence.bundle_id is None
        assert evidence.bundle_version is None
        assert evidence.matched_rule_ids == []
        assert evidence.identity_evidence_reference is None
        assert evidence.adapter_evidence_reference is None
        assert evidence.reason_code is None
        assert evidence.explanation is None
        assert evidence.schema_version == AUDIT_EVIDENCE_SCHEMA_VERSION

    def test_no_evidence_id_auto_generation(self) -> None:
        assert not AuditEvidence.model_fields["evidence_id"].default_factory

    def test_no_request_id_auto_generation(self) -> None:
        assert not AuditEvidence.model_fields["request_id"].default_factory

    def test_evidence_id_is_caller_supplied_not_derived(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evidence_id="caller-supplied-id")
        )
        assert evidence.evidence_id == "caller-supplied-id"

    def test_empty_evidence_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evidence_id=""))

    def test_whitespace_only_evidence_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evidence_id="   "))

    def test_empty_request_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id=""))


# ══════════════════════════════════════════════════════════════════════════
# Evaluation-state matrix — the invariant this record's own fields enforce
# ══════════════════════════════════════════════════════════════════════════


class TestEvaluationStateMatrix:
    # ── Valid combinations ───────────────────────────────────────────────

    def test_completed_allow_valid(self) -> None:
        AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="allow"))

    def test_completed_deny_valid(self) -> None:
        AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="deny"))

    def test_completed_not_applicable_valid(self) -> None:
        AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="not_applicable"))

    @pytest.mark.parametrize(
        "reason",
        [
            "invalid_request",
            "unsupported_schema_version",
            "invalid_policy_bundle",
            "policy_validation_failure",
            "condition_evaluation_error",
            "internal_evaluation_error",
        ],
    )
    def test_failed_null_outcome_valid_for_every_governed_failure_reason(self, reason: str) -> None:
        evidence = AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=reason))
        assert evidence.outcome is None
        assert evidence.failure_reason == OperationAwareFailureReason(reason)

    # ── Invalid combinations ─────────────────────────────────────────────

    def test_completed_null_outcome_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome=None))

    def test_completed_non_null_failure_reason_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, failure_reason="internal_evaluation_error")
            )

    def test_failed_allow_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, outcome="allow"))

    def test_failed_deny_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, outcome="deny"))

    def test_failed_not_applicable_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, outcome="not_applicable"))

    def test_failed_null_failure_reason_invalid(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=None))

    def test_evaluation_never_normalizes_failed_null_into_completed_deny(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        assert evidence.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert evidence.outcome is None
        assert evidence.outcome != OperationAwareDecisionOutcome.DENY


# ══════════════════════════════════════════════════════════════════════════
# Field behavior — bundle identity, reason_code, explanation, trace_id,
# schema_version
# ══════════════════════════════════════════════════════════════════════════


class TestFieldBehavior:
    def test_valid_bundle_id_and_version_accepted(self) -> None:
        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                bundle_id="baseline-read-only-telemetry",
                bundle_version="1.0.0",
            )
        )
        assert evidence.bundle_id == "baseline-read-only-telemetry"
        assert evidence.bundle_version == "1.0.0"

    def test_empty_bundle_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_id=""))

    @pytest.mark.parametrize("version", ["v1", "1.0", "1.0.0.0", "1.0.0-rc1", "latest"])
    def test_invalid_bundle_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_version=version))

    def test_reason_code_validated_through_governed_reason_code_type(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, reason_code="allow_rule_matched")
        )
        assert evidence.reason_code == "allow_rule_matched"

    def test_malformed_reason_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, reason_code="ALLOW_RULE_MATCHED"))

    def test_valid_explanation_accepted(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, explanation="Operator role matched.")
        )
        assert evidence.explanation == "Operator role matched."

    def test_empty_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, explanation=""))

    def test_valid_trace_id_accepted(self) -> None:
        evidence = AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id="trace-0001"))
        assert evidence.trace_id == "trace-0001"

    def test_empty_trace_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id=""))

    def test_this_pr_does_not_generate_a_trace_id(self) -> None:
        assert not AuditEvidence.model_fields["trace_id"].default_factory

    def test_schema_version_defaults_to_published_constant(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert evidence.schema_version == "0.1.0"
        assert evidence.schema_version == AUDIT_EVIDENCE_SCHEMA_VERSION

    def test_custom_schema_version_accepted(self) -> None:
        evidence = AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, schema_version="0.2.0"))
        assert evidence.schema_version == "0.2.0"

    @pytest.mark.parametrize("version", ["v1", "1.0", "latest", ""])
    def test_malformed_schema_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, schema_version=version))


# ══════════════════════════════════════════════════════════════════════════
# matched_rule_ids — validated, not derived
# ══════════════════════════════════════════════════════════════════════════


class TestMatchedRuleIds:
    def test_defaults_to_empty_list(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert evidence.matched_rule_ids == []

    def test_explicit_empty_list_accepted(self) -> None:
        evidence = AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, matched_rule_ids=[]))
        assert evidence.matched_rule_ids == []

    def test_single_rule_id_accepted(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, matched_rule_ids=["rule-a"])
        )
        assert evidence.matched_rule_ids == ["rule-a"]

    def test_multiple_rule_ids_preserve_caller_supplied_order(self) -> None:
        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                matched_rule_ids=["rule-z", "rule-a", "rule-m"],
            )
        )
        assert evidence.matched_rule_ids == ["rule-z", "rule-a", "rule-m"]

    def test_this_model_does_not_sort_matched_rule_ids(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, matched_rule_ids=["rule-b", "rule-a"])
        )
        assert evidence.matched_rule_ids != sorted(
            evidence.matched_rule_ids
        ) or evidence.matched_rule_ids == [
            "rule-b",
            "rule-a",
        ]
        assert evidence.matched_rule_ids == ["rule-b", "rule-a"]

    def test_empty_string_rule_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, matched_rule_ids=[""]))

    def test_whitespace_only_rule_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, matched_rule_ids=["   "]))

    def test_duplicate_rule_ids_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    matched_rule_ids=["rule-duplicate", "rule-duplicate"],
                )
            )

    def test_failed_evaluation_with_empty_matched_rule_ids_valid(self) -> None:
        evidence = AuditEvidence(**dict(_MINIMAL_FAILED_KWARGS, matched_rule_ids=[]))
        assert evidence.matched_rule_ids == []

    def test_this_model_does_not_derive_matched_rule_ids_from_anything(self) -> None:
        # There is no evaluation_trace, rule_evidence, or policy field on
        # this model at all — matched_rule_ids can only ever come from the
        # caller. This test documents that absence positively.
        assert "evaluation_trace" not in AuditEvidence.model_fields
        assert "rule_evidence" not in AuditEvidence.model_fields


# ══════════════════════════════════════════════════════════════════════════
# Evidence references — typed, reference-only
# ══════════════════════════════════════════════════════════════════════════


class TestEvidenceReferences:
    def test_valid_identity_evidence_reference_accepted(self) -> None:
        from basis_core.domain.evidence import IdentityEvidenceReference

        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                identity_evidence_reference=_VALID_IDENTITY_EVIDENCE_REFERENCE,
            )
        )
        assert type(evidence.identity_evidence_reference) is IdentityEvidenceReference
        assert (
            evidence.identity_evidence_reference.reference_id == "idev-0002-0000-0000-000000000002"
        )

    def test_valid_adapter_evidence_reference_accepted(self) -> None:
        from basis_core.domain.evidence import AdapterEvidenceReference

        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                adapter_evidence_reference=_VALID_ADAPTER_EVIDENCE_REFERENCE,
            )
        )
        assert type(evidence.adapter_evidence_reference) is AdapterEvidenceReference
        assert evidence.adapter_evidence_reference.protocol == "bacnet"

    def test_both_evidence_references_together_accepted(self) -> None:
        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                identity_evidence_reference=_VALID_IDENTITY_EVIDENCE_REFERENCE,
                adapter_evidence_reference=_VALID_ADAPTER_EVIDENCE_REFERENCE,
            )
        )
        assert evidence.identity_evidence_reference is not None
        assert evidence.adapter_evidence_reference is not None

    def test_malformed_identity_evidence_reference_rejected(self) -> None:
        malformed = dict(_VALID_IDENTITY_EVIDENCE_REFERENCE)
        del malformed["reference_id"]
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, identity_evidence_reference=malformed)
            )

    def test_malformed_adapter_evidence_reference_rejected(self) -> None:
        malformed = dict(_VALID_ADAPTER_EVIDENCE_REFERENCE)
        del malformed["adapter_source"]
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, adapter_evidence_reference=malformed)
            )

    def test_unsupported_redaction_classification_rejected(self) -> None:
        malformed = dict(_VALID_IDENTITY_EVIDENCE_REFERENCE, redaction_classification="public")
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, identity_evidence_reference=malformed)
            )

    def test_raw_evidence_field_rejected_on_identity_reference(self) -> None:
        malformed = dict(
            _VALID_IDENTITY_EVIDENCE_REFERENCE, access_token="eyJhbGciOiJSUzI1NiJ9.x.y"
        )
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, identity_evidence_reference=malformed)
            )

    def test_this_model_never_fetches_or_resolves_a_reference(self) -> None:
        # Structural-only guarantee: constructing an AuditEvidence with a
        # reference performs no I/O and does not require the referenced
        # evidence to exist anywhere. This is inherently true of a pure
        # Pydantic model with no such method — documented positively here.
        assert not hasattr(AuditEvidence, "resolve_identity_evidence")
        assert not hasattr(AuditEvidence, "fetch_adapter_evidence")


# ══════════════════════════════════════════════════════════════════════════
# recorded_at — caller-supplied, timezone-aware, never generated
# ══════════════════════════════════════════════════════════════════════════


class TestRecordedAt:
    def test_valid_recorded_at_accepted(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, recorded_at="2026-05-22T14:30:01Z")
        )
        assert evidence.recorded_at.tzinfo is not None

    def test_recorded_at_accepts_offset_timezone(self) -> None:
        evidence = AuditEvidence(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, recorded_at="2026-05-22T14:30:01-06:00")
        )
        assert evidence.recorded_at.tzinfo is not None

    def test_timezone_naive_recorded_at_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, recorded_at="2026-05-22T14:30:01")
            )

    def test_recorded_at_is_required(self) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs["recorded_at"]
        with pytest.raises(ValidationError):
            AuditEvidence(**kwargs)  # type: ignore[arg-type]

    def test_no_recorded_at_default_factory(self) -> None:
        assert not AuditEvidence.model_fields["recorded_at"].default_factory

    def test_recorded_at_accepts_a_python_datetime_object(self) -> None:
        evidence = AuditEvidence(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                recorded_at=datetime(2026, 5, 22, 14, 30, 1, tzinfo=timezone.utc),
            )
        )
        assert evidence.recorded_at == datetime(2026, 5, 22, 14, 30, 1, tzinfo=timezone.utc)

    def test_recorded_at_is_caller_supplied_not_derived_from_evaluation_time(self) -> None:
        # There is no evaluation_time or request-side timestamp field on
        # this model at all — recorded_at can only ever come from the
        # caller. Documented positively, since there is nothing to derive
        # it from even if this model wanted to.
        assert "evaluation_time" not in AuditEvidence.model_fields

    def test_this_module_does_not_call_the_system_clock(self) -> None:
        # Constructing two records back to back with the same explicit
        # recorded_at must yield identical values — nothing here
        # substitutes a wall-clock read at construction time.
        first = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        second = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert first.recorded_at == second.recorded_at


# ══════════════════════════════════════════════════════════════════════════
# Boundedness and security
# ══════════════════════════════════════════════════════════════════════════


class TestBoundednessAndSecurity:
    @pytest.mark.parametrize(
        "field_name",
        [
            "enforcement_action",
            "enforcement_result",
            "enforcement_status",
            "gateway_enforcement",
            "event_type",
            "event_id",
            "http_status",
            "response_status",
            "full_request",
            "request_snapshot",
            "full_policy",
            "policy_document",
            "policy_source",
            "raw_claims",
            "full_claim_set",
            "raw_payload",
            "raw_protocol_payload",
            "packet",
            "frame",
            "device_secret",
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
            "credential",
            "debug",
            "debug_data",
            "exception",
            "stack_trace",
            "traceback",
            "signature",
            "signature_algorithm",
            "hash_chain",
            "previous_hash",
            "merkle_root",
            "storage_uri",
            "bucket_name",
            "object_key",
            "retention_policy",
            "rule_evidence",
            "condition_results",
        ],
    )
    def test_raw_or_sensitive_or_gateway_or_persistence_field_rejected_as_unknown(
        self, field_name: str
    ) -> None:
        with pytest.raises(ValidationError):
            AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: "x"})  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Frozen-model behavior
# ══════════════════════════════════════════════════════════════════════════


class TestImmutability:
    def test_top_level_field_reassignment_rejected(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        with pytest.raises(ValidationError):
            evidence.outcome = OperationAwareDecisionOutcome.DENY  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    def test_plain_model_dump_names_every_published_field(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = evidence.model_dump(mode="json")
        assert set(dumped) == {
            "evidence_id",
            "request_id",
            "correlation_id",
            "trace_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "bundle_id",
            "bundle_version",
            "matched_rule_ids",
            "identity_evidence_reference",
            "adapter_evidence_reference",
            "reason_code",
            "explanation",
            "recorded_at",
            "schema_version",
        }

    def test_direct_model_dump_retains_required_nullable_keys(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None
        assert dumped["failure_reason"] == "internal_evaluation_error"
        assert "correlation_id" not in dumped
        assert "bundle_id" not in dumped
        assert "trace_id" not in dumped

    def test_direct_model_dump_json_retains_required_nullable_keys(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        raw = evidence.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        assert "outcome" in parsed
        assert parsed["outcome"] is None
        assert "correlation_id" not in parsed

    def test_completed_response_retains_required_nullable_failure_reason_under_exclude_none(
        self,
    ) -> None:
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert "failure_reason" in dumped
        assert dumped["failure_reason"] is None
        assert "correlation_id" not in dumped

    def test_matched_rule_ids_empty_list_survives_exclude_none(self) -> None:
        # matched_rule_ids defaults to [] (not None), so exclude_none never
        # drops it — an empty list is not a None value.
        evidence = AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert dumped["matched_rule_ids"] == []


# ══════════════════════════════════════════════════════════════════════════
# Nested serialization — record nested inside a further wrapper model
# ══════════════════════════════════════════════════════════════════════════


class _EvidenceWrapper(BaseModel):
    """Local, test-only wrapper standing in for a future parent envelope
    that embeds `AuditEvidence`."""

    evidence: AuditEvidence


def _failed_evidence_for_serialization_regressions() -> AuditEvidence:
    return AuditEvidence(
        evidence_id="audev-serialization-regression",
        request_id="oadr-serialization-regression",
        evaluation_status="failed",
        outcome=None,
        failure_reason="internal_evaluation_error",
        recorded_at="2026-05-22T14:30:01Z",
    )


class TestNestedSerialization:
    def test_required_nullable_keys_survive_wrapper_dump(self) -> None:
        evidence = _failed_evidence_for_serialization_regressions()
        wrapper = _EvidenceWrapper(evidence=evidence)
        dumped = wrapper.model_dump(mode="json", exclude_none=True)
        nested = dumped["evidence"]
        assert "outcome" in nested
        assert nested["outcome"] is None
        assert nested["failure_reason"] == "internal_evaluation_error"

    def test_required_nullable_keys_survive_wrapper_dump_json(self) -> None:
        evidence = _failed_evidence_for_serialization_regressions()
        wrapper = _EvidenceWrapper(evidence=evidence)
        raw = wrapper.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        nested = parsed["evidence"]
        assert nested["outcome"] is None
        assert nested["failure_reason"] == "internal_evaluation_error"

    def test_wrapper_round_trip_preserves_full_structure(self) -> None:
        evidence = _failed_evidence_for_serialization_regressions()
        wrapper = _EvidenceWrapper(evidence=evidence)
        dumped = wrapper.model_dump(mode="json", exclude_none=True)
        restored = _EvidenceWrapper.model_validate(dumped)
        assert restored == wrapper


# ══════════════════════════════════════════════════════════════════════════
# Explicit include/exclude take precedence over required-nullable
# restoration
# ══════════════════════════════════════════════════════════════════════════


class TestIncludeExcludeTakePrecedence:
    def test_include_selects_only_named_fields(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        dumped = evidence.model_dump(
            mode="json", include={"evidence_id", "outcome"}, exclude_none=True
        )
        assert dumped == {"evidence_id": "audev-test-failed", "outcome": None}

    def test_include_does_not_reintroduce_unselected_required_nullable_fields(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        dumped = evidence.model_dump(mode="json", include={"evidence_id"}, exclude_none=True)
        assert dumped == {"evidence_id": "audev-test-failed"}
        assert "outcome" not in dumped
        assert "failure_reason" not in dumped

    def test_exclude_is_not_overridden_by_required_nullable_restoration(self) -> None:
        evidence = AuditEvidence(**_MINIMAL_FAILED_KWARGS)
        dumped = evidence.model_dump(mode="json", exclude={"outcome"}, exclude_none=True)
        assert "outcome" not in dumped
        assert dumped["failure_reason"] == "internal_evaluation_error"


# ══════════════════════════════════════════════════════════════════════════
# Shared vocabulary reuse — decisions-owned, not audit-redefined
# ══════════════════════════════════════════════════════════════════════════


class TestSharedVocabularyReuse:
    def test_evaluation_status_field_uses_decisions_owned_enum(self) -> None:
        assert (
            AuditEvidence.model_fields["evaluation_status"].annotation
            is OperationAwareEvaluationStatus
        )
        assert OperationAwareEvaluationStatus.__module__ == "basis_core.decisions.operation_aware"

    def test_outcome_and_failure_reason_do_not_redefine_local_enums(self) -> None:
        # Unlike EvaluationTrace (PR 25), this module holds no local
        # TraceOutcome/TraceFailureReason-shaped duplicate — it imports and
        # reuses the decisions-owned enums directly (see the module
        # docstring, "Shared evaluation-state vocabulary").
        import basis_core.audit.operation_aware.audit_evidence as audit_evidence_module

        assert not hasattr(audit_evidence_module, "TraceOutcome")
        assert not hasattr(audit_evidence_module, "TraceFailureReason")
        assert not hasattr(audit_evidence_module, "EvaluationStatus")


# ══════════════════════════════════════════════════════════════════════════
# Canonical compatibility-scenario artifacts — independent model-shape
# conformance only (no engine, no policy, no response/trace comparison)
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalCompatibilityArtifacts:
    @pytest.mark.parametrize("scenario", COMPATIBILITY_SCENARIOS)
    def test_expected_audit_evidence_constructs(self, scenario: str) -> None:
        document = load_scenario_artifact(scenario, "expected_audit_evidence")
        assert isinstance(document, dict)
        evidence = AuditEvidence.model_validate(document)
        assert type(evidence) is AuditEvidence

    def test_invalid_policy_bundle_scenario_uses_corrected_v021_failure_reason(self) -> None:
        document = load_scenario_artifact("invalid-policy-bundle", "expected_audit_evidence")
        assert isinstance(document, dict)
        evidence = AuditEvidence.model_validate(document)
        assert evidence.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert evidence.outcome is None
        assert evidence.failure_reason == OperationAwareFailureReason.POLICY_VALIDATION_FAILURE

    def test_allow_basic_scenario_carries_evidence_references(self) -> None:
        document = load_scenario_artifact("allow-basic", "expected_audit_evidence")
        assert isinstance(document, dict)
        evidence = AuditEvidence.model_validate(document)
        assert evidence.identity_evidence_reference is not None
        assert evidence.adapter_evidence_reference is not None

    def test_not_applicable_scenario_has_empty_matched_rule_ids(self) -> None:
        document = load_scenario_artifact("not-applicable", "expected_audit_evidence")
        assert isinstance(document, dict)
        evidence = AuditEvidence.model_validate(document)
        assert evidence.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE
        assert evidence.matched_rule_ids == []

    def test_deny_precedence_scenario_has_two_matched_rule_ids(self) -> None:
        document = load_scenario_artifact("deny-precedence", "expected_audit_evidence")
        assert isinstance(document, dict)
        evidence = AuditEvidence.model_validate(document)
        assert evidence.outcome is OperationAwareDecisionOutcome.DENY
        assert len(evidence.matched_rule_ids) == 2

    def test_all_five_canonical_scenarios_are_covered(self) -> None:
        assert set(COMPATIBILITY_SCENARIOS) == {
            "allow-basic",
            "deny-precedence",
            "default-deny",
            "not-applicable",
            "invalid-policy-bundle",
        }


# ══════════════════════════════════════════════════════════════════════════
# v0.1 compatibility — AuditEvidence is separate from AuditEvent; no
# persistence or writer was added
# ══════════════════════════════════════════════════════════════════════════


class TestV01Compatibility:
    """Mandatory regression: the existing v0.1.0
    `basis_core.audit.events.AuditEvent` type (and
    `basis_core.audit.writer.AuditWriter`/`NullAuditWriter`/`LogAuditWriter`)
    are untouched by anything added in this PR. `AuditEvidence` is a distinct
    symbol, never aliased to `AuditEvent`, never a subclass of it, never
    accepted by the existing `AuditWriter` protocol implementations beyond
    what structural typing would already permit by coincidence, and never
    exported from the same module."""

    def test_audit_event_import_still_resolves(self) -> None:
        from basis_core.audit.events import AuditEvent

        assert AuditEvent.__module__ == "basis_core.audit.events"

    def test_audit_event_fields_unchanged(self) -> None:
        from basis_core.audit.events import AuditEvent

        assert set(AuditEvent.model_fields) == {
            "event_id",
            "event_type",
            "timestamp",
            "schema_version",
            "request_id",
            "decision_id",
            "correlation_id",
            "subject_id",
            "subject_name",
            "subject_type",
            "subject_roles",
            "action",
            "resource_id",
            "resource_type",
            "outcome",
            "reason",
            "evaluated_by",
            "policy_version",
            "matched_rules",
            "trace",
            "detail",
        }

    def test_audit_event_still_constructs_and_serializes(self) -> None:
        from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome

        event = AuditEvent(
            action="write:hvac:setpoint",
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            outcome=AuditOutcome.ALLOWED,
        )
        dumped = event.model_dump(mode="json")
        assert dumped["outcome"] == "allowed"
        assert dumped["action"] == "write:hvac:setpoint"

    def test_audit_event_still_auto_generates_event_id_and_timestamp(self) -> None:
        from basis_core.audit.events import AuditEvent

        event = AuditEvent(action="read:audit:log")
        assert event.event_id
        assert event.timestamp.tzinfo is not None

    def test_audit_schema_version_constant_unchanged(self) -> None:
        from basis_core.audit.events import AUDIT_SCHEMA_VERSION

        assert AUDIT_SCHEMA_VERSION == "1.1"

    def test_audit_evidence_is_not_audit_event(self) -> None:
        from basis_core.audit.events import AuditEvent

        assert AuditEvidence is not AuditEvent
        assert not issubclass(AuditEvidence, AuditEvent)
        assert not issubclass(AuditEvent, AuditEvidence)

    def test_null_audit_writer_still_accepts_audit_event(self) -> None:
        from basis_core.audit.events import AuditEvent
        from basis_core.audit.writer import NullAuditWriter

        writer = NullAuditWriter()
        writer.write(AuditEvent(action="read:audit:log"))

    def test_log_audit_writer_still_serializes_audit_event(self) -> None:
        import logging

        from basis_core.audit.events import AuditEvent
        from basis_core.audit.writer import LogAuditWriter

        captured: list[str] = []

        class _CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record.getMessage())

        logger = logging.getLogger("test_audit_evidence_v01_compat")
        logger.addHandler(_CapturingHandler())
        logger.setLevel(logging.INFO)
        writer = LogAuditWriter(logger=logger)
        writer.write(AuditEvent(action="read:audit:log"))
        assert len(captured) == 1
        assert "read:audit:log" in captured[0]

    def test_no_persistence_or_writer_method_exists_on_audit_evidence(self) -> None:
        forbidden_method_names = (
            "write",
            "save",
            "store",
            "append",
            "publish",
            "emit",
            "persist",
        )
        for name in forbidden_method_names:
            assert not hasattr(AuditEvidence, name), (
                f"AuditEvidence must not define a {name!r} method — this PR adds no "
                "persistence mechanism or AuditWriter-shaped protocol for this type."
            )

    def test_constructing_audit_evidence_has_no_shared_mutable_state(self) -> None:
        from basis_core.audit.events import AuditEvent

        AuditEvidence(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        event = AuditEvent(action="read:audit:log")
        assert event.action == "read:audit:log"


# ══════════════════════════════════════════════════════════════════════════
# Public API boundary — AuditEvidence is not prematurely public
# ══════════════════════════════════════════════════════════════════════════


class TestPublicAPIBoundary:
    """As of PR 35 (Milestone 11), `AuditEvidence` and
    `AUDIT_EVIDENCE_SCHEMA_VERSION` are stabilized as part of
    `basis_core.audit`'s package-level public API. Supersedes the prior
    "not prematurely public" guard, which asserted the pre-PR-35 state."""

    def test_exported_from_basis_core_audit(self) -> None:
        import basis_core.audit as audit_package
        import basis_core.audit.operation_aware.audit_evidence as concrete

        assert "AuditEvidence" in audit_package.__all__
        assert "AUDIT_EVIDENCE_SCHEMA_VERSION" in audit_package.__all__
        assert audit_package.AuditEvidence is concrete.AuditEvidence

    def test_not_exported_from_operation_aware_package_init(self) -> None:
        """`basis_core.audit.operation_aware` (the internal orchestration
        subpackage's own __init__) remains un-exported from — only the
        top-level `basis_core.audit` package gained the export."""
        import basis_core.audit.operation_aware as oa_audit_package

        assert not hasattr(oa_audit_package, "AuditEvidence")

    def test_public_api_doc_lists_audit_evidence_as_stable(self) -> None:
        from pathlib import Path

        public_api_doc = Path(__file__).parent.parent.parent / "docs" / "public-api.md"
        text = public_api_doc.read_text(encoding="utf-8")
        assert "| `AuditEvidence` |" in text
